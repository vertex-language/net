// The operating system's TCP sockets, for package net/tcp. It is the only
// part of net/tcp that knows what a sockaddr is.
//
// Every socket handed back is non-blocking. An operation that cannot be
// finished now returns Code::wouldBlock rather than waiting, and the
// caller waits for readiness however it wants to -- net/tcp hands that to
// the Vertex runtime, so that waiting inside a task suspends the task
// rather than the thread. Nothing here waits on a descriptor, and nothing
// here knows about tasks.
module;
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
    #define CLOSE_SOCKET(s) closesocket(s)
    #define GET_LAST_ERROR() WSAGetLastError()
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <poll.h>
    #include <errno.h>
    #define CLOSE_SOCKET(s) ::close(s)
    #define GET_LAST_ERROR() errno
#endif

export module net.tcp;
import vertex.task;

// Error codes. Every function here returns a negative one of these on
// failure, and 0 or a useful count on success.
export namespace Code {
    constexpr int32_t ok = 0;
    constexpr int32_t generic = -1;
    constexpr int32_t refused = -2;
    constexpr int32_t timedOut = -3;
    constexpr int32_t addressInUse = -4;
    constexpr int32_t reset = -5;
    constexpr int32_t brokenPipe = -6;
    constexpr int32_t unreachable = -7;
    constexpr int32_t invalidAddress = -8;
    constexpr int32_t wouldBlock = -9;
}

// Socket options for sockListen. Every listener is non-blocking, so there
// is no flag for that.
export namespace ListenFlag {
    constexpr int32_t reuseAddress = 1;
    constexpr int32_t reusePort = 2;
}

// What a wait is waiting for, as sockWait takes it.
export namespace Ready {
    constexpr int32_t readable = 1;
    constexpr int32_t writable = 2;
}

namespace {

static void init_network() {
#if defined(_WIN32)
    static bool initialized = false;
    if (!initialized) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        initialized = true;
    }
#endif
}

// map_error turns what the OS reported into one of ours. "Nothing is
// ready" is its own code: everything else here is a failure, and that one
// is a caller that has to wait and ask again.
static int map_error(int err) {
#if defined(_WIN32)
    switch (err) {
        case WSAECONNREFUSED: return Code::refused;
        case WSAETIMEDOUT:    return Code::timedOut;
        case WSAEADDRINUSE:   return Code::addressInUse;
        case WSAECONNRESET:   return Code::reset;
        case WSAENETUNREACH:  return Code::unreachable;
        case WSAEHOSTUNREACH: return Code::unreachable;
        case WSAEWOULDBLOCK:  return Code::wouldBlock;
        case WSAEINPROGRESS:  return Code::wouldBlock;
        case WSAEALREADY:     return Code::wouldBlock;
        default:              return Code::generic;
    }
#else
    switch (err) {
        case ECONNREFUSED: return Code::refused;
        case ETIMEDOUT:    return Code::timedOut;
        case EADDRINUSE:   return Code::addressInUse;
        case ECONNRESET:   return Code::reset;
        case EPIPE:        return Code::brokenPipe;
        case ENETUNREACH:  return Code::unreachable;
        case EHOSTUNREACH: return Code::unreachable;
        case EAGAIN:       return Code::wouldBlock;
        case EINPROGRESS:  return Code::wouldBlock;
        case EALREADY:     return Code::wouldBlock;
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:  return Code::wouldBlock;
#endif
        default:           return Code::generic;
    }
#endif
}

static int set_nonblocking(int fd) {
#if defined(_WIN32)
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ? -1 : 0;
#endif
}

// A write to a socket whose peer has gone must come back as an error, not
// as SIGPIPE killing the process. BSD does it with a socket option; Linux
// has no such option and does it per send, with MSG_NOSIGNAL.
static void suppress_sigpipe(int fd) {
#if defined(SO_NOSIGPIPE)
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    (void)fd;
#endif
}

static void format_address(const struct sockaddr_storage* addr, char* ip_out, int32_t ip_max_len,
                           int32_t* port_out) {
    if (ip_out && ip_max_len > 0) {
        ip_out[0] = '\0';
    }
    if (port_out) {
        *port_out = 0;
    }
    if (addr->ss_family == AF_INET) {
        auto* v4 = reinterpret_cast<const struct sockaddr_in*>(addr);
        if (ip_out && ip_max_len > 0) {
            inet_ntop(AF_INET, &(v4->sin_addr), ip_out, ip_max_len);
        }
        if (port_out) {
            *port_out = ntohs(v4->sin_port);
        }
    } else if (addr->ss_family == AF_INET6) {
        auto* v6 = reinterpret_cast<const struct sockaddr_in6*>(addr);
        if (ip_out && ip_max_len > 0) {
            inet_ntop(AF_INET6, &(v6->sin6_addr), ip_out, ip_max_len);
        }
        if (port_out) {
            *port_out = ntohs(v6->sin6_port);
        }
    }
}

// lookup resolves host and port to a list the caller frees with
// freeaddrinfo. passive asks for an address to bind rather than connect.
static int lookup(const char* host, int32_t port, bool passive, struct addrinfo** out) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (passive) {
        hints.ai_flags = AI_PASSIVE;
    }

    const char* node = (host && host[0] != '\0') ? host : nullptr;
    if (!passive && node == nullptr) {
        return Code::invalidAddress;
    }
    *out = nullptr;
    if (getaddrinfo(node, port_str, &hints, out) != 0 || *out == nullptr) {
        return Code::invalidAddress;
    }
    return Code::ok;
}

} // anonymous namespace

// Binds host ("0.0.0.0", "127.0.0.1", or NULL/"" for any) and port and
// listens. Port 0 asks the kernel for a free one; sockGetSockname says
// which. Returns the listening socket, or a negative error code.
export int32_t sockListen(const char* host, int32_t port, int32_t backlog, int32_t flags) noexcept {
    init_network();

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, true, &res);
    if (rc != Code::ok) {
        return rc;
    }

    int fd = -1;
    int last_err = 0;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            last_err = GET_LAST_ERROR();
            continue;
        }

        int opt = 1;
        if (flags & ListenFlag::reuseAddress) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }
#if defined(SO_REUSEPORT)
        if (flags & ListenFlag::reusePort) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }
#endif
        suppress_sigpipe(fd);

        if (bind(fd, p->ai_addr, static_cast<socklen_t>(p->ai_addrlen)) == 0) {
            break;
        }
        last_err = GET_LAST_ERROR();
        CLOSE_SOCKET(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        return map_error(last_err);
    }
    if (listen(fd, backlog > 0 ? backlog : 128) < 0) {
        int e = GET_LAST_ERROR();
        CLOSE_SOCKET(fd);
        return map_error(e);
    }
    if (set_nonblocking(fd) != 0) {
        int e = GET_LAST_ERROR();
        CLOSE_SOCKET(fd);
        return map_error(e);
    }
    return fd;
}

// Takes the next connection off the listener's queue. Fills client_ip_out
// (null-terminated) and client_port_out when they are not NULL. Returns
// the accepted socket, Code::wouldBlock when none is waiting, or
// another negative error code.
export int32_t sockAccept(int32_t listener_fd, char* client_ip_out, int32_t ip_max_len,
                          int32_t* client_port_out) noexcept {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = sizeof(addr);
    int client_fd = -1;
    while (true) {
        client_fd = accept(listener_fd, reinterpret_cast<struct sockaddr*>(&addr), &len);
        if (client_fd >= 0) {
            break;
        }
        int e = GET_LAST_ERROR();
#if !defined(_WIN32)
        if (e == EINTR) {
            continue;
        }
        if (e == ECONNABORTED || e == EPROTO) {
            continue;
        }
#endif
        return map_error(e);
    }
    suppress_sigpipe(client_fd);
    // The accepted socket does not inherit the listener's flags everywhere,
    // so it is set here rather than assumed.
    if (set_nonblocking(client_fd) != 0) {
        int e = GET_LAST_ERROR();
        CLOSE_SOCKET(client_fd);
        return map_error(e);
    }
    int nodelay = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    if (client_ip_out != nullptr && ip_max_len > 0) {
        format_address(&addr, client_ip_out, ip_max_len, client_port_out);
    }
    return client_fd;
}

// Starts connecting to host and port. Returns a socket on which the
// connection is either already established or still in progress -- wait
// for it to become writable, then ask sockConnectCheck -- or a negative
// error code if it could not be started at all.
export int32_t sockConnectBegin(const char* host, int32_t port) noexcept {
    init_network();

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != Code::ok) {
        return rc;
    }

    int fd = -1;
    int last_err = 0;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            last_err = GET_LAST_ERROR();
            continue;
        }
        suppress_sigpipe(fd);
        if (set_nonblocking(fd) != 0) {
            last_err = GET_LAST_ERROR();
            CLOSE_SOCKET(fd);
            fd = -1;
            continue;
        }
        if (connect(fd, p->ai_addr, static_cast<socklen_t>(p->ai_addrlen)) == 0) {
            break;  // connected straight away, as loopback often does
        }
        if (map_error(GET_LAST_ERROR()) == Code::wouldBlock) {
            break;  // under way; the caller waits for it to become writable
        }
        last_err = GET_LAST_ERROR();
        CLOSE_SOCKET(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        return map_error(last_err);
    }
    return fd;
}

// Whether a socket from sockConnectBegin is connected: Code::ok, or the
// negative error code the attempt failed with.
export int32_t sockConnectCheck(int32_t fd) noexcept {
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    if (so_error != 0) {
        return map_error(so_error);
    }
    return Code::ok;
}

// Reads up to count bytes into buf. Returns the number read, 0 at the end
// of the stream, Code::wouldBlock when nothing has arrived, or
// another negative error code.
export int32_t sockRead(int32_t fd, void* buf, int32_t count) noexcept {
    if (fd < 0 || !buf || count <= 0) {
        return Code::generic;
    }
    ssize_t n = recv(fd, reinterpret_cast<char*>(buf), static_cast<size_t>(count), 0);
    if (n < 0) {
        return map_error(GET_LAST_ERROR());
    }
    return static_cast<int32_t>(n);
}

// Writes up to count bytes from buf. Returns the number written, which
// may be fewer than asked, Code::wouldBlock when the socket cannot
// take any, or another negative error code.
export int32_t sockWrite(int32_t fd, const void* buf, int32_t count) noexcept {
    if (fd < 0 || !buf || count < 0) {
        return Code::generic;
    }
    int flags = 0;
#if defined(MSG_NOSIGNAL)
    flags = MSG_NOSIGNAL;
#endif
    ssize_t n = send(fd, reinterpret_cast<const char*>(buf), static_cast<size_t>(count), flags);
    if (n < 0) {
        return map_error(GET_LAST_ERROR());
    }
    return static_cast<int32_t>(n);
}

// Closes a socket. Returns Code::ok, or a negative error code.
export int32_t sockClose(int32_t fd) noexcept {
    if (fd < 0) {
        return Code::ok;
    }
    return CLOSE_SOCKET(fd) == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

// Closes the reading half (0), the writing half (1), or both (2).
export int32_t sockShutdown(int32_t fd, int32_t how) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
#if defined(_WIN32)
    int sh = (how == 0) ? SD_RECEIVE : (how == 1 ? SD_SEND : SD_BOTH);
#else
    int sh = (how == 0) ? SHUT_RD : (how == 1 ? SHUT_WR : SHUT_RDWR);
#endif
    return shutdown(fd, sh) == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

// Waits with this thread until fd is ready, up to timeout_ms (negative:
// for as long as it takes). 1 ready, 0 timed out, negative error.
//
// net/tcp does not call this -- it waits through the Vertex runtime, so
// that a task waiting does not stop the thread. It is here for C callers
// and as the plain meaning of what the runtime does.
export int32_t sockWait(int32_t fd, int32_t events, int32_t timeout_ms) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
#if defined(_WIN32)
    WSAPOLLFD p;
    p.fd = fd;
    p.events = (events == Ready::writable) ? POLLWRNORM : POLLRDNORM;
    p.revents = 0;
    int n = WSAPoll(&p, 1, timeout_ms);
#else
    struct pollfd p;
    p.fd = fd;
    p.events = (events == Ready::writable) ? POLLOUT : POLLIN;
    p.revents = 0;
    int n = poll(&p, 1, timeout_ms);
#endif
    if (n < 0) {
        return map_error(GET_LAST_ERROR());
    }
    return n > 0 ? 1 : 0;
}

// Sets TCP_NODELAY (1 sends small writes at once, 0 lets Nagle collect them).
export int32_t sockSetNodelay(int32_t fd, int32_t enabled) noexcept {
    int opt = enabled ? 1 : 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&opt), sizeof(opt)) == 0
        ? Code::ok : map_error(GET_LAST_ERROR());
}

// Sets SO_KEEPALIVE, and the idle seconds before the first probe.
export int32_t sockSetKeepalive(int32_t fd, int32_t enabled, int32_t idle_secs) noexcept {
    int opt = enabled ? 1 : 0;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                   reinterpret_cast<const char*>(&opt), sizeof(opt)) != 0) {
        return map_error(GET_LAST_ERROR());
    }
#if defined(TCP_KEEPALIVE)
    if (enabled && idle_secs > 0) {
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
                   reinterpret_cast<const char*>(&idle_secs), sizeof(idle_secs));
    }
#elif defined(TCP_KEEPIDLE)
    if (enabled && idle_secs > 0) {
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
                   reinterpret_cast<const char*>(&idle_secs), sizeof(idle_secs));
    }
#endif
    return Code::ok;
}

// Sets SO_RCVBUF and SO_SNDBUF in bytes. 0 leaves that one alone.
export int32_t sockSetBufferSizes(int32_t fd, int32_t rcvbuf, int32_t sndbuf) noexcept {
    if (rcvbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                                 reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf)) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    if (sndbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                                 reinterpret_cast<const char*>(&sndbuf), sizeof(sndbuf)) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    return Code::ok;
}

// The address a socket is bound to, and the one it is connected to.
export int32_t sockGetSockname(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out) noexcept {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = sizeof(addr);
    if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    format_address(&addr, ip_out, ip_max_len, port_out);
    return Code::ok;
}

// sockGetPeername is sockGetSockname for the address a socket is
// connected to.
export int32_t sockGetPeername(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out) noexcept {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = sizeof(addr);
    if (getpeername(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    format_address(&addr, ip_out, ip_max_len, port_out);
    return Code::ok;
}

// Resolves host to at most max_results stream addresses for port. Result
// i is written null-terminated at ips_out + i * ip_max_len, and its
// family (4 or 6) at families_out[i]. Returns how many were written, or a
// negative error code.
//
// This is the one call here that waits: the platform's resolver is
// blocking, and a lookup stops the thread. A program that cannot afford
// that should resolve before it starts serving.
export int32_t sockResolve(const char* host, int32_t port, char* ips_out, int32_t ip_max_len,
                           int32_t max_results, int32_t* families_out) noexcept {
    init_network();

    if (!ips_out || ip_max_len <= 0 || max_results <= 0) {
        return Code::invalidAddress;
    }
    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != Code::ok) {
        return rc;
    }

    int32_t n = 0;
    for (struct addrinfo* p = res; p != nullptr && n < max_results; p = p->ai_next) {
        if (p->ai_family != AF_INET && p->ai_family != AF_INET6) {
            continue;
        }
        struct sockaddr_storage addr;
        memset(&addr, 0, sizeof(addr));
        memcpy(&addr, p->ai_addr, p->ai_addrlen);
        char* slot = ips_out + static_cast<ptrdiff_t>(n) * ip_max_len;
        format_address(&addr, slot, ip_max_len, nullptr);
        if (families_out) {
            families_out[n] = p->ai_family == AF_INET6 ? 6 : 4;
        }
        n++;
    }
    freeaddrinfo(res);
    return n;
}

// The last error the operating system reported, as its own number: errno,
// or WSAGetLastError. For a message alongside a mapped code, never for
// deciding what went wrong.
export int32_t sockLastError() noexcept {
    return GET_LAST_ERROR();
}

// Whether the kernel spreads connections across sockets bound with
// SO_REUSEPORT. Linux hashes each connection to one of them; Darwin and
// the BSDs hand every connection to a single socket, so a listener per
// worker does nothing there and a server distributes connections itself.
export int32_t sockReuseportBalances() noexcept {
#if defined(__linux__)
    return 1;
#else
    return 0;
#endif
}

// sockWorkers is how many workers the runtime's pool has -- VERTEX_WORKERS,
// or one per processor but the main thread's -- as the runtime says: it is
// what Serve binds a listener per, on a kernel that balances SO_REUSEPORT.
// 0 where there is no pool.
export int32_t sockWorkers() noexcept {
    return vertex_task_workers();
}

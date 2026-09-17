#include "ctcp.h"

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
        case WSAECONNREFUSED: return CTCP_ERR_REFUSED;
        case WSAETIMEDOUT:    return CTCP_ERR_TIMED_OUT;
        case WSAEADDRINUSE:   return CTCP_ERR_ADDR_IN_USE;
        case WSAECONNRESET:   return CTCP_ERR_RESET;
        case WSAENETUNREACH:  return CTCP_ERR_UNREACHABLE;
        case WSAEHOSTUNREACH: return CTCP_ERR_UNREACHABLE;
        case WSAEWOULDBLOCK:  return CTCP_ERR_WOULD_BLOCK;
        case WSAEINPROGRESS:  return CTCP_ERR_WOULD_BLOCK;
        case WSAEALREADY:     return CTCP_ERR_WOULD_BLOCK;
        default:              return CTCP_ERR_GENERIC;
    }
#else
    switch (err) {
        case ECONNREFUSED: return CTCP_ERR_REFUSED;
        case ETIMEDOUT:    return CTCP_ERR_TIMED_OUT;
        case EADDRINUSE:   return CTCP_ERR_ADDR_IN_USE;
        case ECONNRESET:   return CTCP_ERR_RESET;
        case EPIPE:        return CTCP_ERR_BROKEN_PIPE;
        case ENETUNREACH:  return CTCP_ERR_UNREACHABLE;
        case EHOSTUNREACH: return CTCP_ERR_UNREACHABLE;
        case EAGAIN:       return CTCP_ERR_WOULD_BLOCK;
        case EINPROGRESS:  return CTCP_ERR_WOULD_BLOCK;
        case EALREADY:     return CTCP_ERR_WOULD_BLOCK;
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:  return CTCP_ERR_WOULD_BLOCK;
#endif
        default:           return CTCP_ERR_GENERIC;
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
        return CTCP_ERR_INVALID_ADDR;
    }
    *out = nullptr;
    if (getaddrinfo(node, port_str, &hints, out) != 0 || *out == nullptr) {
        return CTCP_ERR_INVALID_ADDR;
    }
    return CTCP_OK;
}

} // anonymous namespace

extern "C" {

int32_t ctcp_listen(const char* host, int32_t port, int32_t backlog, int32_t flags) {
    init_network();

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, true, &res);
    if (rc != CTCP_OK) {
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
        if (flags & CTCP_LISTEN_REUSE_ADDR) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }
#if defined(SO_REUSEPORT)
        if (flags & CTCP_LISTEN_REUSE_PORT) {
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

int32_t ctcp_accept(int32_t listener_fd, char* client_ip_out, int32_t ip_max_len,
                    int32_t* client_port_out) {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = sizeof(addr);
    int client_fd = accept(listener_fd, reinterpret_cast<struct sockaddr*>(&addr), &len);
    if (client_fd < 0) {
        return map_error(GET_LAST_ERROR());
    }
    suppress_sigpipe(client_fd);
    // The accepted socket does not inherit the listener's flags everywhere,
    // so it is set here rather than assumed.
    if (set_nonblocking(client_fd) != 0) {
        int e = GET_LAST_ERROR();
        CLOSE_SOCKET(client_fd);
        return map_error(e);
    }
    format_address(&addr, client_ip_out, ip_max_len, client_port_out);
    return client_fd;
}

int32_t ctcp_connect_begin(const char* host, int32_t port) {
    init_network();

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != CTCP_OK) {
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
        if (map_error(GET_LAST_ERROR()) == CTCP_ERR_WOULD_BLOCK) {
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

int32_t ctcp_connect_check(int32_t fd) {
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    if (so_error != 0) {
        return map_error(so_error);
    }
    return CTCP_OK;
}

int32_t ctcp_read(int32_t fd, void* buf, int32_t count) {
    if (fd < 0 || !buf || count <= 0) {
        return CTCP_ERR_GENERIC;
    }
    ssize_t n = recv(fd, reinterpret_cast<char*>(buf), static_cast<size_t>(count), 0);
    if (n < 0) {
        return map_error(GET_LAST_ERROR());
    }
    return static_cast<int32_t>(n);
}

int32_t ctcp_write(int32_t fd, const void* buf, int32_t count) {
    if (fd < 0 || !buf || count < 0) {
        return CTCP_ERR_GENERIC;
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

int32_t ctcp_close(int32_t fd) {
    if (fd < 0) {
        return CTCP_OK;
    }
    return CLOSE_SOCKET(fd) == 0 ? CTCP_OK : map_error(GET_LAST_ERROR());
}

int32_t ctcp_shutdown(int32_t fd, int32_t how) {
    if (fd < 0) {
        return CTCP_ERR_GENERIC;
    }
#if defined(_WIN32)
    int sh = (how == 0) ? SD_RECEIVE : (how == 1 ? SD_SEND : SD_BOTH);
#else
    int sh = (how == 0) ? SHUT_RD : (how == 1 ? SHUT_WR : SHUT_RDWR);
#endif
    return shutdown(fd, sh) == 0 ? CTCP_OK : map_error(GET_LAST_ERROR());
}

int32_t ctcp_wait(int32_t fd, int32_t events, int32_t timeout_ms) {
    if (fd < 0) {
        return CTCP_ERR_GENERIC;
    }
#if defined(_WIN32)
    WSAPOLLFD p;
    p.fd = fd;
    p.events = (events == CTCP_WRITABLE) ? POLLWRNORM : POLLRDNORM;
    p.revents = 0;
    int n = WSAPoll(&p, 1, timeout_ms);
#else
    struct pollfd p;
    p.fd = fd;
    p.events = (events == CTCP_WRITABLE) ? POLLOUT : POLLIN;
    p.revents = 0;
    int n = poll(&p, 1, timeout_ms);
#endif
    if (n < 0) {
        return map_error(GET_LAST_ERROR());
    }
    return n > 0 ? 1 : 0;
}

int32_t ctcp_set_nodelay(int32_t fd, int32_t enabled) {
    int opt = enabled ? 1 : 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&opt), sizeof(opt)) == 0
        ? CTCP_OK : map_error(GET_LAST_ERROR());
}

int32_t ctcp_set_keepalive(int32_t fd, int32_t enabled, int32_t idle_secs) {
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
    return CTCP_OK;
}

int32_t ctcp_set_buffer_sizes(int32_t fd, int32_t rcvbuf, int32_t sndbuf) {
    if (rcvbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                                 reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf)) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    if (sndbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                                 reinterpret_cast<const char*>(&sndbuf), sizeof(sndbuf)) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    return CTCP_OK;
}

int32_t ctcp_get_sockname(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out) {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = sizeof(addr);
    if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    format_address(&addr, ip_out, ip_max_len, port_out);
    return CTCP_OK;
}

int32_t ctcp_get_peername(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out) {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = sizeof(addr);
    if (getpeername(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    format_address(&addr, ip_out, ip_max_len, port_out);
    return CTCP_OK;
}

int32_t ctcp_resolve(const char* host, int32_t port, char* ips_out, int32_t ip_max_len,
                     int32_t max_results, int32_t* families_out) {
    init_network();

    if (!ips_out || ip_max_len <= 0 || max_results <= 0) {
        return CTCP_ERR_INVALID_ADDR;
    }
    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != CTCP_OK) {
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

int32_t ctcp_last_error(void) {
    return GET_LAST_ERROR();
}

} // extern "C"

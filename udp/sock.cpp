// The operating system's UDP sockets, for package net/udp. It is the only
// part of net/udp that knows what a sockaddr is.
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
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <poll.h>
    #include <errno.h>
    #include <ifaddrs.h>
    #define CLOSE_SOCKET(s) ::close(s)
    #define GET_LAST_ERROR() errno
#endif

export module net.udp;

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
    constexpr int32_t tooLarge = -10;
    constexpr int32_t notConnected = -11;
}

// Flags for sockBind.
export namespace BindFlag {
    constexpr int32_t reuseAddress = 1;
    constexpr int32_t reusePort = 2;
}

// What a wait is waiting for.
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
        case WSAEMSGSIZE:     return Code::tooLarge;
        case WSAENOTCONN:     return Code::notConnected;
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
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:  return Code::wouldBlock;
#endif
        case EMSGSIZE:     return Code::tooLarge;
        case ENOTCONN:     return Code::notConnected;
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

static int lookup(const char* host, int32_t port, bool passive, struct addrinfo** out) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
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

// Binds host ("0.0.0.0", "127.0.0.1", or NULL/"" for any) and port.
// Port 0 asks the kernel for a free one; sockGetSockname says which.
// Returns the socket file descriptor, or a negative error code.
export int32_t sockBind(const char* host, int32_t port, int32_t flags) noexcept {
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
        if (flags & BindFlag::reuseAddress) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }
#if defined(SO_REUSEPORT)
        if (flags & BindFlag::reusePort) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }
#endif

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
    if (set_nonblocking(fd) < 0) {
        int err = GET_LAST_ERROR();
        CLOSE_SOCKET(fd);
        return map_error(err);
    }
    return fd;
}

// Connects a UDP socket to a remote host and port.
export int32_t sockConnect(int32_t fd, const char* host, int32_t port) noexcept {
    init_network();
    if (fd < 0) {
        return Code::generic;
    }

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != Code::ok) {
        return rc;
    }

    int result = -1;
    int last_err = 0;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (connect(fd, p->ai_addr, static_cast<socklen_t>(p->ai_addrlen)) == 0) {
            result = 0;
            break;
        }
        last_err = GET_LAST_ERROR();
    }
    freeaddrinfo(res);

    if (result != 0) {
        return map_error(last_err);
    }
    return Code::ok;
}

// Disconnects a previously connected UDP socket.
export int32_t sockDisconnect(int32_t fd) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
#if defined(_WIN32)
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_UNSPEC;
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
        return map_error(GET_LAST_ERROR());
    }
#else
    struct sockaddr sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_UNSPEC;
    if (connect(fd, &sa, sizeof(sa)) != 0) {
        int err = GET_LAST_ERROR();
        if (err != EAFNOSUPPORT) {
            return map_error(err);
        }
    }
#endif
    return Code::ok;
}

// Receives a datagram into buf. Fills sender_ip_out and sender_port_out
// when non-null. Returns the number of bytes read, Code::wouldBlock
// when nothing has arrived, or another negative error code.
export int32_t sockRecvFrom(int32_t fd, void* buf, int32_t count, char* sender_ip_out,
                            int32_t ip_max_len, int32_t* sender_port_out) noexcept {
    if (fd < 0 || buf == nullptr || count <= 0) {
        return 0;
    }
    struct sockaddr_storage src;
    socklen_t srclen = sizeof(src);
    memset(&src, 0, sizeof(src));

#if defined(_WIN32)
    int n = recvfrom(fd, static_cast<char*>(buf), count, 0,
                     reinterpret_cast<struct sockaddr*>(&src), &srclen);
#else
    ssize_t n = recvfrom(fd, buf, static_cast<size_t>(count), 0,
                         reinterpret_cast<struct sockaddr*>(&src), &srclen);
#endif

    if (n < 0) {
        return map_error(GET_LAST_ERROR());
    }
    format_address(&src, sender_ip_out, ip_max_len, sender_port_out);
    return static_cast<int32_t>(n);
}

// Sends a datagram to host and port. Returns the number of bytes sent,
// Code::wouldBlock when socket cannot take any, or negative error code.
export int32_t sockSendTo(int32_t fd, const void* buf, int32_t count, const char* host, int32_t port) noexcept {
    if (fd < 0 || buf == nullptr) {
        return Code::generic;
    }
    if (count == 0) {
        return 0;
    }

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != Code::ok) {
        return rc;
    }

#if defined(_WIN32)
    int n = sendto(fd, static_cast<const char*>(buf), count, 0,
                   res->ai_addr, static_cast<int>(res->ai_addrlen));
#else
    ssize_t n = sendto(fd, buf, static_cast<size_t>(count), 0,
                       res->ai_addr, static_cast<socklen_t>(res->ai_addrlen));
#endif
    int last_err = GET_LAST_ERROR();
    freeaddrinfo(res);

    if (n < 0) {
        return map_error(last_err);
    }
    return static_cast<int32_t>(n);
}

// Reads a datagram on a connected UDP socket.
export int32_t sockRecv(int32_t fd, void* buf, int32_t count) noexcept {
    if (fd < 0 || buf == nullptr || count <= 0) {
        return 0;
    }
#if defined(_WIN32)
    int n = recv(fd, static_cast<char*>(buf), count, 0);
#else
    ssize_t n = recv(fd, buf, static_cast<size_t>(count), 0);
#endif
    if (n < 0) {
        return map_error(GET_LAST_ERROR());
    }
    return static_cast<int32_t>(n);
}

// Sends a datagram on a connected UDP socket.
export int32_t sockSend(int32_t fd, const void* buf, int32_t count) noexcept {
    if (fd < 0 || buf == nullptr) {
        return Code::generic;
    }
    if (count == 0) {
        return 0;
    }
#if defined(_WIN32)
    int n = send(fd, static_cast<const char*>(buf), count, 0);
#else
    ssize_t n = send(fd, buf, static_cast<size_t>(count), 0);
#endif
    if (n < 0) {
        return map_error(GET_LAST_ERROR());
    }
    return static_cast<int32_t>(n);
}

// Closes a socket descriptor.
export int32_t sockClose(int32_t fd) noexcept {
    if (fd < 0) {
        return Code::ok;
    }
    return CLOSE_SOCKET(fd) == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

// Socket options:
export int32_t sockSetBroadcast(int32_t fd, int32_t enabled) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
    int opt = enabled ? 1 : 0;
    int rc = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&opt), sizeof(opt));
    return rc == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

export int32_t sockSetBufferSizes(int32_t fd, int32_t rcvbuf, int32_t sndbuf) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
    if (rcvbuf > 0) {
        int r = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
        if (r != 0) {
            return map_error(GET_LAST_ERROR());
        }
    }
    if (sndbuf > 0) {
        int r = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&sndbuf), sizeof(sndbuf));
        if (r != 0) {
            return map_error(GET_LAST_ERROR());
        }
    }
    return Code::ok;
}

export int32_t sockSetTtl(int32_t fd, int32_t ttl) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
    int rc = setsockopt(fd, IPPROTO_IP, IP_TTL, reinterpret_cast<const char*>(&ttl), sizeof(ttl));
    return rc == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

// Multicast options:
export int32_t sockJoinMulticast(int32_t fd, const char* group, const char* iface) noexcept {
    if (fd < 0 || group == nullptr) {
        return Code::generic;
    }
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    if (inet_pton(AF_INET, group, &mreq.imr_multiaddr) <= 0) {
        return Code::invalidAddress;
    }
    if (iface && iface[0] != '\0') {
        if (inet_pton(AF_INET, iface, &mreq.imr_interface) <= 0) {
            return Code::invalidAddress;
        }
    } else {
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    }
    int rc = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<const char*>(&mreq), sizeof(mreq));
    return rc == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

export int32_t sockLeaveMulticast(int32_t fd, const char* group, const char* iface) noexcept {
    if (fd < 0 || group == nullptr) {
        return Code::generic;
    }
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    if (inet_pton(AF_INET, group, &mreq.imr_multiaddr) <= 0) {
        return Code::invalidAddress;
    }
    if (iface && iface[0] != '\0') {
        if (inet_pton(AF_INET, iface, &mreq.imr_interface) <= 0) {
            return Code::invalidAddress;
        }
    } else {
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    }
    int rc = setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, reinterpret_cast<const char*>(&mreq), sizeof(mreq));
    return rc == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

export int32_t sockSetMulticastLoopback(int32_t fd, int32_t enabled) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
#if defined(_WIN32)
    BOOL opt = enabled ? TRUE : FALSE;
    int rc = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    u_char opt = enabled ? 1 : 0;
    int rc = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<const char*>(&opt), sizeof(opt));
#endif
    return rc == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

export int32_t sockSetMulticastTtl(int32_t fd, int32_t ttl) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
#if defined(_WIN32)
    int opt = ttl;
    int rc = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    u_char opt = static_cast<u_char>(ttl);
    int rc = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&opt), sizeof(opt));
#endif
    return rc == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

// Query socket address and peer address:
export int32_t sockGetSockname(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    format_address(&addr, ip_out, ip_max_len, port_out);
    return Code::ok;
}

export int32_t sockGetPeername(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out) noexcept {
    if (fd < 0) {
        return Code::generic;
    }
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getpeername(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    format_address(&addr, ip_out, ip_max_len, port_out);
    return Code::ok;
}

// Resolves host to datagram addresses for port:
export int32_t sockResolve(const char* host, int32_t port, char* ips_out, int32_t ip_max_len,
                           int32_t max_results, int32_t* families_out) noexcept {
    init_network();

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != Code::ok) {
        return rc;
    }

    int written = 0;
    for (struct addrinfo* p = res; p != nullptr && written < max_results; p = p->ai_next) {
        char* slot = ips_out + written * ip_max_len;
        if (p->ai_family == AF_INET) {
            auto* v4 = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &(v4->sin_addr), slot, ip_max_len);
            families_out[written] = 4;
            written++;
        } else if (p->ai_family == AF_INET6) {
            auto* v6 = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
            inet_ntop(AF_INET6, &(v6->sin6_addr), slot, ip_max_len);
            families_out[written] = 6;
            written++;
        }
    }
    freeaddrinfo(res);
    return written;
}

// Last error reported by OS:
export int32_t sockLastError() noexcept {
    return GET_LAST_ERROR();
}

// Enumerates local network interfaces:
export int32_t sockGetInterfaces(char* names_out, int32_t name_max_len,
                                 char* ips_out, int32_t ip_max_len,
                                 int32_t max_results,
                                 int32_t* families_out,
                                 int32_t* flags_out) noexcept {
#if !defined(_WIN32)
    init_network();
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) {
        return map_error(GET_LAST_ERROR());
    }

    int written = 0;
    for (struct ifaddrs* cur = ifap; cur != nullptr && written < max_results; cur = cur->ifa_next) {
        if (!cur->ifa_addr) continue;
        int family = cur->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;

        char* name_slot = names_out + written * name_max_len;
        strncpy(name_slot, cur->ifa_name ? cur->ifa_name : "", name_max_len - 1);
        name_slot[name_max_len - 1] = '\0';

        char* ip_slot = ips_out + written * ip_max_len;
        if (family == AF_INET) {
            auto* v4 = reinterpret_cast<struct sockaddr_in*>(cur->ifa_addr);
            inet_ntop(AF_INET, &(v4->sin_addr), ip_slot, ip_max_len);
            families_out[written] = 4;
        } else {
            auto* v6 = reinterpret_cast<struct sockaddr_in6*>(cur->ifa_addr);
            inet_ntop(AF_INET6, &(v6->sin6_addr), ip_slot, ip_max_len);
            families_out[written] = 6;
        }

        int32_t flags = 0;
        if (cur->ifa_flags & 0x1) flags |= 1;  // UP
        if (cur->ifa_flags & 0x8) flags |= 2;  // LOOPBACK
        if (cur->ifa_flags & 0x10) flags |= 4; // POINTOPOINT
        flags_out[written] = flags;

        written++;
    }
    freeifaddrs(ifap);
    return written;
#else
    return 0;
#endif
}


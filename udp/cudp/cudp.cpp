#include "cudp.h"

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
        case WSAECONNREFUSED: return CUDP_ERR_REFUSED;
        case WSAETIMEDOUT:    return CUDP_ERR_TIMED_OUT;
        case WSAEADDRINUSE:   return CUDP_ERR_ADDR_IN_USE;
        case WSAECONNRESET:   return CUDP_ERR_RESET;
        case WSAENETUNREACH:  return CUDP_ERR_UNREACHABLE;
        case WSAEHOSTUNREACH: return CUDP_ERR_UNREACHABLE;
        case WSAEWOULDBLOCK:  return CUDP_ERR_WOULD_BLOCK;
        case WSAEMSGSIZE:     return CUDP_ERR_TOO_LARGE;
        case WSAENOTCONN:     return CUDP_ERR_NOT_CONNECTED;
        default:              return CUDP_ERR_GENERIC;
    }
#else
    switch (err) {
        case ECONNREFUSED: return CUDP_ERR_REFUSED;
        case ETIMEDOUT:    return CUDP_ERR_TIMED_OUT;
        case EADDRINUSE:   return CUDP_ERR_ADDR_IN_USE;
        case ECONNRESET:   return CUDP_ERR_RESET;
        case EPIPE:        return CUDP_ERR_BROKEN_PIPE;
        case ENETUNREACH:  return CUDP_ERR_UNREACHABLE;
        case EHOSTUNREACH: return CUDP_ERR_UNREACHABLE;
        case EAGAIN:       return CUDP_ERR_WOULD_BLOCK;
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:  return CUDP_ERR_WOULD_BLOCK;
#endif
        case EMSGSIZE:     return CUDP_ERR_TOO_LARGE;
        case ENOTCONN:     return CUDP_ERR_NOT_CONNECTED;
        default:           return CUDP_ERR_GENERIC;
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
        return CUDP_ERR_INVALID_ADDR;
    }
    *out = nullptr;
    if (getaddrinfo(node, port_str, &hints, out) != 0 || *out == nullptr) {
        return CUDP_ERR_INVALID_ADDR;
    }
    return CUDP_OK;
}

} // anonymous namespace

extern "C" {

int32_t cudp_bind(const char* host, int32_t port, int32_t flags) {
    init_network();

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, true, &res);
    if (rc != CUDP_OK) {
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
        if (flags & CUDP_BIND_REUSE_ADDR) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }
#if defined(SO_REUSEPORT)
        if (flags & CUDP_BIND_REUSE_PORT) {
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

int32_t cudp_connect(int32_t fd, const char* host, int32_t port) {
    init_network();
    if (fd < 0) {
        return CUDP_ERR_GENERIC;
    }

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != CUDP_OK) {
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
    return CUDP_OK;
}

int32_t cudp_disconnect(int32_t fd) {
    if (fd < 0) {
        return CUDP_ERR_GENERIC;
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
    return CUDP_OK;
}

int32_t cudp_recvfrom(int32_t fd, void* buf, int32_t count, char* sender_ip_out,
                      int32_t ip_max_len, int32_t* sender_port_out) {
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

int32_t cudp_sendto(int32_t fd, const void* buf, int32_t count, const char* host, int32_t port) {
    if (fd < 0 || buf == nullptr) {
        return CUDP_ERR_GENERIC;
    }
    if (count == 0) {
        return 0;
    }

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != CUDP_OK) {
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

int32_t cudp_recv(int32_t fd, void* buf, int32_t count) {
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

int32_t cudp_send(int32_t fd, const void* buf, int32_t count) {
    if (fd < 0 || buf == nullptr) {
        return CUDP_ERR_GENERIC;
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

int32_t cudp_close(int32_t fd) {
    if (fd < 0) {
        return CUDP_OK;
    }
    return CLOSE_SOCKET(fd) == 0 ? CUDP_OK : map_error(GET_LAST_ERROR());
}

int32_t cudp_set_broadcast(int32_t fd, int32_t enabled) {
    if (fd < 0) {
        return CUDP_ERR_GENERIC;
    }
    int opt = enabled ? 1 : 0;
    int rc = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&opt), sizeof(opt));
    return rc == 0 ? CUDP_OK : map_error(GET_LAST_ERROR());
}

int32_t cudp_set_buffer_sizes(int32_t fd, int32_t rcvbuf, int32_t sndbuf) {
    if (fd < 0) {
        return CUDP_ERR_GENERIC;
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
    return CUDP_OK;
}

int32_t cudp_set_ttl(int32_t fd, int32_t ttl) {
    if (fd < 0) {
        return CUDP_ERR_GENERIC;
    }
    int rc = setsockopt(fd, IPPROTO_IP, IP_TTL, reinterpret_cast<const char*>(&ttl), sizeof(ttl));
    return rc == 0 ? CUDP_OK : map_error(GET_LAST_ERROR());
}

int32_t cudp_join_multicast(int32_t fd, const char* group, const char* iface) {
    if (fd < 0 || group == nullptr) {
        return CUDP_ERR_GENERIC;
    }
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    if (inet_pton(AF_INET, group, &mreq.imr_multiaddr) <= 0) {
        return CUDP_ERR_INVALID_ADDR;
    }
    if (iface && iface[0] != '\0') {
        if (inet_pton(AF_INET, iface, &mreq.imr_interface) <= 0) {
            return CUDP_ERR_INVALID_ADDR;
        }
    } else {
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    }
    int rc = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<const char*>(&mreq), sizeof(mreq));
    return rc == 0 ? CUDP_OK : map_error(GET_LAST_ERROR());
}

int32_t cudp_leave_multicast(int32_t fd, const char* group, const char* iface) {
    if (fd < 0 || group == nullptr) {
        return CUDP_ERR_GENERIC;
    }
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    if (inet_pton(AF_INET, group, &mreq.imr_multiaddr) <= 0) {
        return CUDP_ERR_INVALID_ADDR;
    }
    if (iface && iface[0] != '\0') {
        if (inet_pton(AF_INET, iface, &mreq.imr_interface) <= 0) {
            return CUDP_ERR_INVALID_ADDR;
        }
    } else {
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    }
    int rc = setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, reinterpret_cast<const char*>(&mreq), sizeof(mreq));
    return rc == 0 ? CUDP_OK : map_error(GET_LAST_ERROR());
}

int32_t cudp_set_multicast_loopback(int32_t fd, int32_t enabled) {
    if (fd < 0) {
        return CUDP_ERR_GENERIC;
    }
#if defined(_WIN32)
    BOOL opt = enabled ? TRUE : FALSE;
    int rc = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    u_char opt = enabled ? 1 : 0;
    int rc = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<const char*>(&opt), sizeof(opt));
#endif
    return rc == 0 ? CUDP_OK : map_error(GET_LAST_ERROR());
}

int32_t cudp_set_multicast_ttl(int32_t fd, int32_t ttl) {
    if (fd < 0) {
        return CUDP_ERR_GENERIC;
    }
#if defined(_WIN32)
    int opt = ttl;
    int rc = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    u_char opt = static_cast<u_char>(ttl);
    int rc = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&opt), sizeof(opt));
#endif
    return rc == 0 ? CUDP_OK : map_error(GET_LAST_ERROR());
}

int32_t cudp_get_sockname(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out) {
    if (fd < 0) {
        return CUDP_ERR_GENERIC;
    }
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    format_address(&addr, ip_out, ip_max_len, port_out);
    return CUDP_OK;
}

int32_t cudp_get_peername(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out) {
    if (fd < 0) {
        return CUDP_ERR_GENERIC;
    }
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getpeername(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    format_address(&addr, ip_out, ip_max_len, port_out);
    return CUDP_OK;
}

int32_t cudp_resolve(const char* host, int32_t port, char* ips_out, int32_t ip_max_len,
                     int32_t max_results, int32_t* families_out) {
    init_network();

    struct addrinfo* res = nullptr;
    int rc = lookup(host, port, false, &res);
    if (rc != CUDP_OK) {
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

int32_t cudp_last_error(void) {
    return GET_LAST_ERROR();
}

int32_t cudp_get_interfaces(char* names_out, int32_t name_max_len,
                           char* ips_out, int32_t ip_max_len,
                           int32_t max_results,
                           int32_t* families_out,
                           int32_t* flags_out) {
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

} // extern "C"

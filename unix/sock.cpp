// The operating system's Unix-domain stream sockets, for package net/unix.
// It is the only part of net/unix that knows what a sockaddr_un is.
//
// As in net/tcp, every socket handed back is non-blocking: an operation
// that cannot finish now returns Code::wouldBlock, and the Vertex side
// waits for readiness through the runtime. Windows 10 and later have
// AF_UNIX too (afunix.h), with the same calls.
module;
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(_WIN32)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <afunix.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
    #define CLOSE_SOCKET(s) closesocket(s)
    #define GET_LAST_ERROR() WSAGetLastError()
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #define CLOSE_SOCKET(s) ::close(s)
    #define GET_LAST_ERROR() errno
#endif

export module net.unix;

// Error codes: every function returns a negative one of these on failure,
// and 0 or a useful count on success.
export namespace Code {
    constexpr int32_t ok = 0;
    constexpr int32_t generic = -1;
    constexpr int32_t refused = -2;        // nothing listening at the path
    constexpr int32_t notFound = -3;       // no socket file at the path
    constexpr int32_t addressInUse = -4;
    constexpr int32_t reset = -5;
    constexpr int32_t brokenPipe = -6;
    constexpr int32_t pathTooLong = -7;
    constexpr int32_t wouldBlock = -8;
    constexpr int32_t denied = -9;
}

// What a wait is for, as the runtime's wait takes it.
export namespace Ready {
    constexpr int32_t readable = 1;
    constexpr int32_t writable = 2;
}

namespace {

void init_network() {
#if defined(_WIN32)
    static bool initialized = false;
    if (!initialized) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        initialized = true;
    }
#endif
}

int map_error(int err) {
#if defined(_WIN32)
    switch (err) {
        case WSAECONNREFUSED: return Code::refused;
        case WSAEADDRINUSE:   return Code::addressInUse;
        case WSAECONNRESET:   return Code::reset;
        case WSAEWOULDBLOCK:  return Code::wouldBlock;
        case WSAEINPROGRESS:  return Code::wouldBlock;
        case WSAEALREADY:     return Code::wouldBlock;
        case WSAEACCES:       return Code::denied;
        default:              return Code::generic;
    }
#else
    switch (err) {
        case ECONNREFUSED: return Code::refused;
        case ENOENT:       return Code::notFound;
        case EADDRINUSE:   return Code::addressInUse;
        case ECONNRESET:   return Code::reset;
        case EPIPE:        return Code::brokenPipe;
        case EACCES:       return Code::denied;
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

int set_nonblocking(int fd) {
#if defined(_WIN32)
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ? -1 : 0;
#endif
}

void suppress_sigpipe(int fd) {
#if defined(SO_NOSIGPIPE)
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#else
    (void)fd;
#endif
}

// fill_address writes path into addr; false if it doesn't fit.
bool fill_address(const char* path, struct sockaddr_un* addr) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(addr->sun_path)) return false;
    memcpy(addr->sun_path, path, n);
    return true;
}

} // namespace

// Binds a socket to path and listens on it. The path must not exist: a
// stale socket file is the caller's to remove.
export int32_t unixListen(const char* path, int32_t backlog) noexcept {
    init_network();
    struct sockaddr_un addr;
    if (!fill_address(path, &addr)) return Code::pathTooLong;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return map_error(GET_LAST_ERROR());
    suppress_sigpipe(fd);
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0 ||
        listen(fd, backlog > 0 ? backlog : 16) != 0 || set_nonblocking(fd) != 0) {
        int e = GET_LAST_ERROR();
        CLOSE_SOCKET(fd);
        return map_error(e);
    }
    return fd;
}

// The next connection on a listener, or Code::wouldBlock when none waits.
export int32_t unixAccept(int32_t listener) noexcept {
    while (true) {
        int fd = accept(listener, nullptr, nullptr);
        if (fd >= 0) {
            suppress_sigpipe(fd);
            if (set_nonblocking(fd) != 0) {
                int e = GET_LAST_ERROR();
                CLOSE_SOCKET(fd);
                return map_error(e);
            }
            return fd;
        }
        int e = GET_LAST_ERROR();
#if !defined(_WIN32)
        if (e == EINTR || e == ECONNABORTED) continue;
#endif
        return map_error(e);
    }
}

// Starts connecting to path: a socket whose connection is made or under
// way (wait until writable, then unixConnectCheck), or an error.
export int32_t unixConnectBegin(const char* path) noexcept {
    init_network();
    struct sockaddr_un addr;
    if (!fill_address(path, &addr)) return Code::pathTooLong;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return map_error(GET_LAST_ERROR());
    suppress_sigpipe(fd);
    if (set_nonblocking(fd) != 0) {
        int e = GET_LAST_ERROR();
        CLOSE_SOCKET(fd);
        return map_error(e);
    }
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        int rc = map_error(GET_LAST_ERROR());
        if (rc != Code::wouldBlock) {
            CLOSE_SOCKET(fd);
            return rc;
        }
    }
    return fd;
}

// Whether a connection unixConnectBegin started succeeded.
export int32_t unixConnectCheck(int32_t fd) noexcept {
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) != 0) {
        return map_error(GET_LAST_ERROR());
    }
    return err == 0 ? Code::ok : map_error(err);
}

export int32_t unixRead(int32_t fd, void* buf, int32_t count) noexcept {
    while (true) {
        auto n = recv(fd, static_cast<char*>(buf), count, 0);
        if (n >= 0) return static_cast<int32_t>(n);
        int e = GET_LAST_ERROR();
#if !defined(_WIN32)
        if (e == EINTR) continue;
#endif
        return map_error(e);
    }
}

export int32_t unixWrite(int32_t fd, const void* buf, int32_t count) noexcept {
#if defined(MSG_NOSIGNAL)
    int flags = MSG_NOSIGNAL;
#else
    int flags = 0;
#endif
    while (true) {
        auto n = send(fd, static_cast<const char*>(buf), count, flags);
        if (n >= 0) return static_cast<int32_t>(n);
        int e = GET_LAST_ERROR();
#if !defined(_WIN32)
        if (e == EINTR) continue;
#endif
        return map_error(e);
    }
}

// how: 0 read, 1 write, 2 both.
export int32_t unixShutdown(int32_t fd, int32_t how) noexcept {
#if defined(_WIN32)
    int h = how == 0 ? SD_RECEIVE : (how == 1 ? SD_SEND : SD_BOTH);
#else
    int h = how == 0 ? SHUT_RD : (how == 1 ? SHUT_WR : SHUT_RDWR);
#endif
    return shutdown(fd, h) == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

export int32_t unixClose(int32_t fd) noexcept {
    return CLOSE_SOCKET(fd) == 0 ? Code::ok : map_error(GET_LAST_ERROR());
}

// Removes a socket file, so that a path can be listened on again.
export int32_t unixUnlink(const char* path) noexcept {
#if defined(_WIN32)
    return DeleteFileA(path) ? Code::ok : Code::generic;
#else
    return ::unlink(path) == 0 ? Code::ok : map_error(errno);
#endif
}

export int32_t unixLastError() noexcept {
    return GET_LAST_ERROR();
}

// ctcp: the operating system's TCP sockets, as a C ABI the tcp target
// calls. It is the only part of net/tcp that knows what a sockaddr is.
//
// Every socket ctcp hands back is non-blocking. An operation that cannot
// be finished now returns CTCP_ERR_WOULD_BLOCK rather than waiting, and
// the caller waits for readiness however it wants to -- net/tcp hands
// that to the Vertex runtime, so that waiting inside a task suspends the
// task rather than the thread. Nothing here waits on a descriptor, and
// nothing here knows about tasks.
#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes. Every ctcp_* function returns a negative one of these on
// failure, and 0 or a useful count on success.
enum {
    CTCP_OK                 = 0,
    CTCP_ERR_GENERIC        = -1,
    CTCP_ERR_REFUSED        = -2,
    CTCP_ERR_TIMED_OUT      = -3,
    CTCP_ERR_ADDR_IN_USE    = -4,
    CTCP_ERR_RESET          = -5,
    CTCP_ERR_BROKEN_PIPE    = -6,
    CTCP_ERR_UNREACHABLE    = -7,
    CTCP_ERR_INVALID_ADDR   = -8,
    // Nothing is ready yet, and nothing has gone wrong: wait for the
    // descriptor and ask again. Distinct from CTCP_ERR_TIMED_OUT, which
    // is a deadline the caller set having passed.
    CTCP_ERR_WOULD_BLOCK    = -9
};

// Socket options for ctcp_listen. Every listener is non-blocking, so
// there is no flag for that.
enum {
    CTCP_LISTEN_REUSE_ADDR = 1,   // SO_REUSEADDR
    CTCP_LISTEN_REUSE_PORT = 2    // SO_REUSEPORT, where the platform has it
};

// What a wait is waiting for, as ctcp_wait takes it.
enum {
    CTCP_READABLE = 1,
    CTCP_WRITABLE = 2
};

// Binds host ("0.0.0.0", "127.0.0.1", or NULL/"" for any) and port and
// listens. Port 0 asks the kernel for a free one; ctcp_get_sockname says
// which. Returns the listening socket, or a negative error code.
int32_t ctcp_listen(const char* host, int32_t port, int32_t backlog, int32_t flags);

// Takes the next connection off the listener's queue. Fills client_ip_out
// (null-terminated) and client_port_out when they are not NULL. Returns
// the accepted socket, CTCP_ERR_WOULD_BLOCK when none is waiting, or
// another negative error code.
int32_t ctcp_accept(int32_t listener_fd, char* client_ip_out, int32_t ip_max_len,
                    int32_t* client_port_out);

// Starts connecting to host and port. Returns a socket on which the
// connection is either already established or still in progress -- wait
// for it to become writable, then ask ctcp_connect_check -- or a negative
// error code if it could not be started at all.
int32_t ctcp_connect_begin(const char* host, int32_t port);

// Whether a socket from ctcp_connect_begin is connected: CTCP_OK, or the
// negative error code the attempt failed with.
int32_t ctcp_connect_check(int32_t fd);

// Reads up to count bytes into buf. Returns the number read, 0 at the end
// of the stream, CTCP_ERR_WOULD_BLOCK when nothing has arrived, or
// another negative error code.
int32_t ctcp_read(int32_t fd, void* buf, int32_t count);

// Writes up to count bytes from buf. Returns the number written, which
// may be fewer than asked, CTCP_ERR_WOULD_BLOCK when the socket cannot
// take any, or another negative error code.
int32_t ctcp_write(int32_t fd, const void* buf, int32_t count);

// Closes a socket. Returns CTCP_OK, or a negative error code.
int32_t ctcp_close(int32_t fd);

// Closes the reading half (0), the writing half (1), or both (2).
int32_t ctcp_shutdown(int32_t fd, int32_t how);

// Waits with this thread until fd is ready, up to timeout_ms (negative:
// for as long as it takes). 1 ready, 0 timed out, negative error.
//
// net/tcp does not call this -- it waits through the Vertex runtime, so
// that a task waiting does not stop the thread. It is here for C callers
// and as the plain meaning of what the runtime does.
int32_t ctcp_wait(int32_t fd, int32_t events, int32_t timeout_ms);

// Resolves host to at most max_results stream addresses for port. Result
// i is written null-terminated at ips_out + i * ip_max_len, and its
// family (4 or 6) at families_out[i]. Returns how many were written, or a
// negative error code.
//
// This is the one call here that waits: the platform's resolver is
// blocking, and a lookup stops the thread. A program that cannot afford
// that should resolve before it starts serving.
int32_t ctcp_resolve(const char* host, int32_t port, char* ips_out, int32_t ip_max_len,
                     int32_t max_results, int32_t* families_out);

// Sets TCP_NODELAY (1 sends small writes at once, 0 lets Nagle collect them).
int32_t ctcp_set_nodelay(int32_t fd, int32_t enabled);

// Sets SO_KEEPALIVE, and the idle seconds before the first probe.
int32_t ctcp_set_keepalive(int32_t fd, int32_t enabled, int32_t idle_secs);

// Sets SO_RCVBUF and SO_SNDBUF in bytes. 0 leaves that one alone.
int32_t ctcp_set_buffer_sizes(int32_t fd, int32_t rcvbuf, int32_t sndbuf);

// The address a socket is bound to, and the one it is connected to.
int32_t ctcp_get_sockname(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out);
int32_t ctcp_get_peername(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out);

// The last error the operating system reported, as its own number: errno,
// or WSAGetLastError. For a message alongside a mapped code, never for
// deciding what went wrong.
int32_t ctcp_last_error(void);

#ifdef __cplusplus
}
#endif

// cudp: the operating system's UDP sockets, as a C ABI the udp target
// calls. It is the only part of net/udp that knows what a sockaddr is.
#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes. Every cudp_* function returns a negative one of these on
// failure, and 0 or a useful count on success.
enum {
    CUDP_OK                 = 0,
    CUDP_ERR_GENERIC        = -1,
    CUDP_ERR_REFUSED        = -2,
    CUDP_ERR_TIMED_OUT      = -3,
    CUDP_ERR_ADDR_IN_USE    = -4,
    CUDP_ERR_RESET          = -5,
    CUDP_ERR_BROKEN_PIPE    = -6,
    CUDP_ERR_UNREACHABLE    = -7,
    CUDP_ERR_INVALID_ADDR   = -8,
    // Nothing is ready yet: wait for the descriptor and ask again.
    CUDP_ERR_WOULD_BLOCK    = -9,
    CUDP_ERR_TOO_LARGE      = -10,
    CUDP_ERR_NOT_CONNECTED  = -11
};

// Flags for cudp_bind.
enum {
    CUDP_BIND_REUSE_ADDR = 1,
    CUDP_BIND_REUSE_PORT = 2
};

// What a wait is waiting for.
enum {
    CUDP_READABLE = 1,
    CUDP_WRITABLE = 2
};

// Binds host ("0.0.0.0", "127.0.0.1", or NULL/"" for any) and port.
// Port 0 asks the kernel for a free one; cudp_get_sockname says which.
// Returns the socket file descriptor, or a negative error code.
int32_t cudp_bind(const char* host, int32_t port, int32_t flags);

// Connects a UDP socket to a remote host and port.
int32_t cudp_connect(int32_t fd, const char* host, int32_t port);

// Disconnects a previously connected UDP socket.
int32_t cudp_disconnect(int32_t fd);

// Receives a datagram into buf. Fills sender_ip_out and sender_port_out
// when non-null. Returns the number of bytes read, CUDP_ERR_WOULD_BLOCK
// when nothing has arrived, or another negative error code.
int32_t cudp_recvfrom(int32_t fd, void* buf, int32_t count, char* sender_ip_out,
                      int32_t ip_max_len, int32_t* sender_port_out);

// Sends a datagram to host and port. Returns the number of bytes sent,
// CUDP_ERR_WOULD_BLOCK when socket cannot take any, or negative error code.
int32_t cudp_sendto(int32_t fd, const void* buf, int32_t count, const char* host, int32_t port);

// Reads a datagram on a connected UDP socket.
int32_t cudp_recv(int32_t fd, void* buf, int32_t count);

// Sends a datagram on a connected UDP socket.
int32_t cudp_send(int32_t fd, const void* buf, int32_t count);

// Closes a socket descriptor.
int32_t cudp_close(int32_t fd);

// Socket options:
int32_t cudp_set_broadcast(int32_t fd, int32_t enabled);
int32_t cudp_set_buffer_sizes(int32_t fd, int32_t rcvbuf, int32_t sndbuf);
int32_t cudp_set_ttl(int32_t fd, int32_t ttl);

// Multicast options:
int32_t cudp_join_multicast(int32_t fd, const char* group, const char* iface);
int32_t cudp_leave_multicast(int32_t fd, const char* group, const char* iface);
int32_t cudp_set_multicast_loopback(int32_t fd, int32_t enabled);
int32_t cudp_set_multicast_ttl(int32_t fd, int32_t ttl);

// Query socket address and peer address:
int32_t cudp_get_sockname(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out);
int32_t cudp_get_peername(int32_t fd, char* ip_out, int32_t ip_max_len, int32_t* port_out);

// Resolves host to datagram addresses for port:
int32_t cudp_resolve(const char* host, int32_t port, char* ips_out, int32_t ip_max_len,
                     int32_t max_results, int32_t* families_out);

// Last error reported by OS:
int32_t cudp_last_error(void);

// Enumerates local network interfaces:
int32_t cudp_get_interfaces(char* names_out, int32_t name_max_len,
                           char* ips_out, int32_t ip_max_len,
                           int32_t max_results,
                           int32_t* families_out,
                           int32_t* flags_out);

#ifdef __cplusplus
}
#endif

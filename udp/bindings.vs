package udp

// The cudp target's C ABI (cudp/include/cudp.h), and the runtime call a
// socket operation waits on.
//
// These are written out by symbol rather than imported from the header.
// Nothing here is public; the package's surface is the Vertex types over it.

// Error codes (CUDP_ERR_*).
enum Code {
    static let ok: int32 = 0
    static let generic: int32 = -1
    static let refused: int32 = -2
    static let timedOut: int32 = -3
    static let addressInUse: int32 = -4
    static let reset: int32 = -5
    static let brokenPipe: int32 = -6
    static let unreachable: int32 = -7
    static let invalidAddress: int32 = -8
    static let wouldBlock: int32 = -9
    static let tooLarge: int32 = -10
    static let notConnected: int32 = -11
}

// cudp_bind flags (CUDP_BIND_*).
enum BindFlag {
    static let reuseAddress: int32 = 1
    static let reusePort: int32 = 2
}

// What a wait waits for.
enum Ready {
    static let readable: int32 = 1
    static let writable: int32 = 2
}

// Room for any address cudp formats: INET6_ADDRSTRLEN is 46.
var addressTextCapacity: int { return 64 }

@_silgen_name("cudp_bind")
func cudp_bind(_ host: UnsafePointer<CChar>?, _ port: int32, _ flags: int32) -> int32

@_silgen_name("cudp_connect")
func cudp_connect(_ fd: int32, _ host: UnsafePointer<CChar>, _ port: int32) -> int32

@_silgen_name("cudp_disconnect")
func cudp_disconnect(_ fd: int32) -> int32

@_silgen_name("cudp_recvfrom")
func cudp_recvfrom(_ fd: int32, _ buf: UnsafeMutableRawPointer, _ count: int32,
                   _ ipOut: UnsafeMutablePointer<CChar>?, _ ipMaxLen: int32,
                   _ portOut: UnsafeMutablePointer<int32>?) -> int32

@_silgen_name("cudp_sendto")
func cudp_sendto(_ fd: int32, _ buf: UnsafeRawPointer, _ count: int32,
                 _ host: UnsafePointer<CChar>, _ port: int32) -> int32

@_silgen_name("cudp_recv")
func cudp_recv(_ fd: int32, _ buf: UnsafeMutableRawPointer, _ count: int32) -> int32

@_silgen_name("cudp_send")
func cudp_send(_ fd: int32, _ buf: UnsafeRawPointer, _ count: int32) -> int32

@_silgen_name("cudp_close")
func cudp_close(_ fd: int32) -> int32

@_silgen_name("cudp_set_broadcast")
func cudp_set_broadcast(_ fd: int32, _ enabled: int32) -> int32

@_silgen_name("cudp_set_buffer_sizes")
func cudp_set_buffer_sizes(_ fd: int32, _ rcvbuf: int32, _ sndbuf: int32) -> int32

@_silgen_name("cudp_set_ttl")
func cudp_set_ttl(_ fd: int32, _ ttl: int32) -> int32

@_silgen_name("cudp_join_multicast")
func cudp_join_multicast(_ fd: int32, _ group: UnsafePointer<CChar>,
                         _ iface: UnsafePointer<CChar>?) -> int32

@_silgen_name("cudp_leave_multicast")
func cudp_leave_multicast(_ fd: int32, _ group: UnsafePointer<CChar>,
                          _ iface: UnsafePointer<CChar>?) -> int32

@_silgen_name("cudp_set_multicast_loopback")
func cudp_set_multicast_loopback(_ fd: int32, _ enabled: int32) -> int32

@_silgen_name("cudp_set_multicast_ttl")
func cudp_set_multicast_ttl(_ fd: int32, _ ttl: int32) -> int32

@_silgen_name("cudp_get_sockname")
func cudp_get_sockname(_ fd: int32, _ ipOut: UnsafeMutablePointer<CChar>?,
                       _ ipMaxLen: int32, _ portOut: UnsafeMutablePointer<int32>?) -> int32

@_silgen_name("cudp_get_peername")
func cudp_get_peername(_ fd: int32, _ ipOut: UnsafeMutablePointer<CChar>?,
                       _ ipMaxLen: int32, _ portOut: UnsafeMutablePointer<int32>?) -> int32

@_silgen_name("cudp_resolve")
func cudp_resolve(_ host: UnsafePointer<CChar>, _ port: int32,
                  _ ipsOut: UnsafeMutablePointer<CChar>?, _ ipMaxLen: int32,
                  _ maxResults: int32, _ familiesOut: UnsafeMutablePointer<int32>?) -> int32

@_silgen_name("cudp_last_error")
func cudp_last_error() -> int32

// The runtime's wait: suspends the task on the executor until fd is ready.
@_silgen_name("vertex_task_wait_fd")
func waitFd(_ fd: int32, _ events: int32, _ timeoutNanos: int64) async -> int32

// waitReady waits until a socket can be read from or written to.
func waitReady(_ fd: int32, _ events: int32, _ timeoutMs: int32) async -> bool {
    var nanos: int64 = -1
    if timeoutMs > 0 {
        nanos = int64(timeoutMs) * 1_000_000
    }
    return (await waitFd(fd, events, nanos)) == 1
}

// chunk holds a byte count inside int32 range.
func chunk(_ count: int) -> int32 {
    return count < 0x7fff_ffff ? int32(count) : 0x7fff_ffff
}

// socketAddress reads the address a socket is bound to, or the one it is connected to.
func socketAddress(of fd: int32, peer: bool) -> SocketAddress {
    var text = [CChar](repeating: 0, count: addressTextCapacity)
    var port: int32 = 0
    let rc = text.withUnsafeMutableBufferPointer { bp -> int32 in
        if peer {
            return cudp_get_peername(fd, bp.baseAddress, int32(bp.count), &port)
        }
        return cudp_get_sockname(fd, bp.baseAddress, int32(bp.count), &port)
    }
    if rc != Code.ok {
        return .v4(ip: "0.0.0.0", port: 0)
    }
    return SocketAddress.fromC(ip: string(cString: text), port: port)
}

func peerAddress(of fd: int32) -> SocketAddress? {
    var text = [CChar](repeating: 0, count: addressTextCapacity)
    var port: int32 = 0
    let rc = text.withUnsafeMutableBufferPointer { bp -> int32 in
        cudp_get_peername(fd, bp.baseAddress, int32(bp.count), &port)
    }
    if rc != Code.ok {
        return nil
    }
    return SocketAddress.fromC(ip: string(cString: text), port: port)
}

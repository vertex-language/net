package tcp

// The ctcp target's C ABI (ctcp/include/ctcp.h), and the runtime call a
// socket operation waits on.
//
// These are written out by symbol rather than imported from the header:
// most of ctcp takes a pointer, and a header import brings in the scalar
// signatures only. Nothing here is public. The package's surface is the
// Vertex types over it.

// Error codes (CTCP_ERR_*).
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
}

// ctcp_listen flags (CTCP_LISTEN_*).
enum ListenFlag {
    static let reuseAddress: int32 = 1
    static let reusePort: int32 = 2
}

// What a wait waits for.
enum Ready {
    static let readable: int32 = 1
    static let writable: int32 = 2
}

// Room for any address ctcp formats: INET6_ADDRSTRLEN is 46.
var addressTextCapacity: int { return 64 }

@_silgen_name("ctcp_listen")
func ctcp_listen(_ host: UnsafePointer<CChar>?, _ port: int32, _ backlog: int32,
                 _ flags: int32) -> int32

@_silgen_name("ctcp_accept")
func ctcp_accept(_ listenerFd: int32, _ ipOut: UnsafeMutablePointer<CChar>?, _ ipMaxLen: int32,
                 _ portOut: UnsafeMutablePointer<int32>?) -> int32

@_silgen_name("ctcp_connect_begin")
func ctcp_connect_begin(_ host: UnsafePointer<CChar>, _ port: int32) -> int32

@_silgen_name("ctcp_connect_check")
func ctcp_connect_check(_ fd: int32) -> int32

@_silgen_name("ctcp_read")
func ctcp_read(_ fd: int32, _ buf: UnsafeMutableRawPointer, _ count: int32) -> int32

@_silgen_name("ctcp_write")
func ctcp_write(_ fd: int32, _ buf: UnsafeRawPointer, _ count: int32) -> int32

@_silgen_name("ctcp_close")
func ctcp_close(_ fd: int32) -> int32

@_silgen_name("ctcp_shutdown")
func ctcp_shutdown(_ fd: int32, _ how: int32) -> int32

@_silgen_name("ctcp_set_nodelay")
func ctcp_set_nodelay(_ fd: int32, _ enabled: int32) -> int32

@_silgen_name("ctcp_set_keepalive")
func ctcp_set_keepalive(_ fd: int32, _ enabled: int32, _ idleSecs: int32) -> int32

@_silgen_name("ctcp_set_buffer_sizes")
func ctcp_set_buffer_sizes(_ fd: int32, _ rcvbuf: int32, _ sndbuf: int32) -> int32

@_silgen_name("ctcp_get_sockname")
func ctcp_get_sockname(_ fd: int32, _ ipOut: UnsafeMutablePointer<CChar>?, _ ipMaxLen: int32,
                       _ portOut: UnsafeMutablePointer<int32>?) -> int32

@_silgen_name("ctcp_get_peername")
func ctcp_get_peername(_ fd: int32, _ ipOut: UnsafeMutablePointer<CChar>?, _ ipMaxLen: int32,
                       _ portOut: UnsafeMutablePointer<int32>?) -> int32

@_silgen_name("ctcp_resolve")
func ctcp_resolve(_ host: UnsafePointer<CChar>, _ port: int32,
                  _ ipsOut: UnsafeMutablePointer<CChar>?, _ ipMaxLen: int32,
                  _ maxResults: int32, _ familiesOut: UnsafeMutablePointer<int32>?) -> int32

@_silgen_name("ctcp_last_error")
func ctcp_last_error() -> int32

@_silgen_name("ctcp_reuseport_balances")
func ctcp_reuseport_balances() -> int32

// The runtime's wait. It is `async` because it suspends, and in Vertex --
// as in Swift -- only an async function can: a synchronous one has no
// context, no frame of its own, and nowhere to be resumed to, so there is
// nothing for an executor to write down. That is the rule `await` stands
// for and it is why every operation in this package that can wait is
// async too. See the README.
//
// Given a task, it hands the socket to the executor and parks: every
// other task runs while this one waits. Given no task -- or a platform
// with no readiness registration -- the thread waits, which is what a
// blocking socket would have done anyway.
@_silgen_name("vertex_task_wait_fd")
func waitFd(_ fd: int32, _ events: int32, _ timeoutNanos: int64) async -> int32

// waitReady waits until a socket can be read from or written to. It is
// true where the socket became ready and false where the deadline passed;
// timeoutMs of 0 waits for as long as it takes.
func waitReady(_ fd: int32, _ events: int32, _ timeoutMs: int32) async -> bool {
    var nanos: int64 = -1
    if timeoutMs > 0 {
        nanos = int64(timeoutMs) * 1_000_000
    }
    return (await waitFd(fd, events, nanos)) == 1
}

// chunk is a byte count as the int32 ctcp takes, held inside its range: a
// larger buffer is read or written a chunk at a time.
func chunk(_ count: int) -> int32 {
    return count < 0x7fff_ffff ? int32(count) : 0x7fff_ffff
}

// socketAddress reads the address a socket is bound to, or the one it is
// connected to. An unbound or unconnected socket has neither, and reads
// as the unspecified address.
func socketAddress(of fd: int32, peer: bool) -> SocketAddress {
    var text = [CChar](repeating: 0, count: addressTextCapacity)
    var port: int32 = 0
    let rc = text.withUnsafeMutableBufferPointer { bp -> int32 in
        if peer {
            return ctcp_get_peername(fd, bp.baseAddress, int32(bp.count), &port)
        }
        return ctcp_get_sockname(fd, bp.baseAddress, int32(bp.count), &port)
    }
    if rc != Code.ok {
        return .v4(ip: "0.0.0.0", port: 0)
    }
    return SocketAddress.fromC(ip: string(cString: text), port: port)
}

@_silgen_name("vertex_task_workers")
func vertex_task_workers() -> int32

// poolSize is how many workers the runtime's pool has -- VERTEX_WORKERS,
// or one per processor but the main thread's -- as the runtime says: it
// is what `Serve` binds a listener per, on a kernel that balances
// SO_REUSEPORT. 0 where there is no pool.
func poolSize() -> int {
    return int(vertex_task_workers())
}

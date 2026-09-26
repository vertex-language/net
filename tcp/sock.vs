package tcp

// What sock.cpp (module net.tcp) does not say for itself: the runtime
// call a socket operation waits on, and the Vertex helpers over sock.cpp.
// Nothing here is public. The package's surface is the Vertex types over
// it.

// Room for any address sock.cpp formats: INET6_ADDRSTRLEN is 46.
var addressTextCapacity: int { return 64 }

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

// chunk is a byte count as the int32 sock.cpp takes, held inside its range: a
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
            return sockGetPeername(fd, bp.baseAddress, int32(bp.count), &port)
        }
        return sockGetSockname(fd, bp.baseAddress, int32(bp.count), &port)
    }
    if rc != Code.ok {
        return .v4(ip: "0.0.0.0", port: 0)
    }
    return SocketAddress.fromC(ip: string(cString: text), port: port)
}

// poolSize is how many workers the runtime's pool has -- VERTEX_WORKERS,
// or one per processor but the main thread's -- as the runtime says: it
// is what `Serve` binds a listener per, on a kernel that balances
// SO_REUSEPORT. 0 where there is no pool.
func poolSize() -> int {
    return int(sockWorkers())
}

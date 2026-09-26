package udp

// What sock.cpp (module net.udp) does not say for itself: the runtime
// call a socket operation waits on, and the Vertex helpers over sock.cpp.
// Nothing here is public; the package's surface is the Vertex types over it.

// Room for any address sock.cpp formats: INET6_ADDRSTRLEN is 46.
var addressTextCapacity: int { return 64 }

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
            return sockGetPeername(fd, bp.baseAddress, int32(bp.count), &port)
        }
        return sockGetSockname(fd, bp.baseAddress, int32(bp.count), &port)
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
        sockGetPeername(fd, bp.baseAddress, int32(bp.count), &port)
    }
    if rc != Code.ok {
        return nil
    }
    return SocketAddress.fromC(ip: string(cString: text), port: port)
}

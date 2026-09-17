package udp

/// Socket configuration options for binding.
public struct SocketOptions {
    /// Lets the address be bound again while an old socket is still winding down.
    public var ReuseAddress: bool = true
    /// Lets several sockets bind the same port.
    public var ReusePort: bool = false

    public init() {}
    public static let `default` = SocketOptions()
}

/// A UDP datagram socket for connectionless or connected packet communication.
public struct UdpSocket {
    /// The underlying OS socket file descriptor.
    public let SocketFd: int32

    /// Millisecond timeout for receive operations (0 waits indefinitely).
    public var ReadTimeoutMs: int32 = 0
    /// Millisecond timeout for send operations (0 waits indefinitely).
    public var WriteTimeoutMs: int32 = 0

    /// The local address this socket is bound to.
    public var LocalAddress: SocketAddress {
        return socketAddress(of: SocketFd, peer: false)
    }
}

// MARK: - Binding

/// Binds a UDP socket on an address written as text: "127.0.0.1:8080", ":9000",
/// or a port of 0 to request an ephemeral port from the kernel.
public func Bind(_ address: string,
                 options: SocketOptions = .default) throws -> UdpSocket {
    let parsed = try SocketAddress.Parse(address)
    return try Bind(host: parsed.Host(), port: parsed.Port(), options: options)
}

/// Binds a UDP socket on a specific host and port.
public func Bind(host: string = "0.0.0.0", port: uint16,
                 options: SocketOptions = .default) throws -> UdpSocket {
    var flags: int32 = 0
    if options.ReuseAddress {
        flags |= BindFlag.reuseAddress
    }
    if options.ReusePort {
        flags |= BindFlag.reusePort
    }
    let fd = host.withCString { h in
        cudp_bind(h, int32(port), flags)
    }
    if fd < 0 {
        throw errorFor(fd, "\(host):\(port)")
    }
    return UdpSocket(SocketFd: fd)
}

/// Binds a UDP socket on an already parsed address.
public func Bind(address: SocketAddress,
                 options: SocketOptions = .default) throws -> UdpSocket {
    return try Bind(host: address.Host(), port: address.Port(), options: options)
}

// MARK: - Receiving

/// Receives a datagram into buffer. Returns the number of bytes read and the
/// sender's remote address.
public func (s: borrowing UdpSocket) ReceiveFrom(
    into buffer: inout [uint8]) async throws -> (int, SocketAddress) {
    if buffer.isEmpty {
        return (0, .v4(ip: "0.0.0.0", port: 0))
    }
    let fd = s.SocketFd
    while true {
        var text = [CChar](repeating: 0, count: addressTextCapacity)
        var port: int32 = 0
        let n = buffer.withUnsafeMutableBytes { raw in
            text.withUnsafeMutableBufferPointer { tp in
                cudp_recvfrom(fd, raw.baseAddress!, chunk(raw.count), tp.baseAddress,
                              int32(tp.count), &port)
            }
        }
        if n >= 0 {
            let sender = SocketAddress.fromC(ip: string(cString: text), port: port)
            return (int(n), sender)
        }
        if n != Code.wouldBlock {
            throw errorFor(n, "receiving on \(s.LocalAddress.ToString())")
        }
        if !(await waitReady(fd, Ready.readable, s.ReadTimeoutMs)) {
            throw UdpError.timedOut("receiving on \(s.LocalAddress.ToString())")
        }
    }
}

/// Receives a datagram on a connected UDP socket.
public func (s: borrowing UdpSocket) Receive(into buffer: inout [uint8]) async throws -> int {
    if buffer.isEmpty {
        return 0
    }
    let fd = s.SocketFd
    while true {
        let n = buffer.withUnsafeMutableBytes { raw in
            cudp_recv(fd, raw.baseAddress!, chunk(raw.count))
        }
        if n >= 0 {
            return int(n)
        }
        if n != Code.wouldBlock {
            throw errorFor(n, "receiving on connected socket")
        }
        if !(await waitReady(fd, Ready.readable, s.ReadTimeoutMs)) {
            throw UdpError.timedOut("receiving on connected socket")
        }
    }
}

// MARK: - Sending

/// Sends a datagram to target address.
public func (s: borrowing UdpSocket) SendTo(
    _ data: borrowing [uint8], to address: SocketAddress) async throws -> int {
    let fd = s.SocketFd
    let host = address.Host()
    let port = int32(address.Port())
    while true {
        let n = data.withUnsafeBytes { raw in
            host.withCString { h in
                cudp_sendto(fd, raw.baseAddress!, chunk(raw.count), h, port)
            }
        }
        if n >= 0 {
            return int(n)
        }
        if n != Code.wouldBlock {
            throw errorFor(n, "sending to \(address.ToString())")
        }
        if !(await waitReady(fd, Ready.writable, s.WriteTimeoutMs)) {
            throw UdpError.timedOut("sending to \(address.ToString())")
        }
    }
}

/// Sends a datagram to an address string: "127.0.0.1:9000".
public func (s: borrowing UdpSocket) SendTo(
    _ data: borrowing [uint8], to address: string) async throws -> int {
    let parsed = try SocketAddress.Parse(address)
    let n = try await s.SendTo(data, to: parsed)
    return n
}

/// Sends a slice of bytes to target address.
public func (s: borrowing UdpSocket) SendTo(
    _ data: borrowing ArraySlice<uint8>, to address: SocketAddress) async throws -> int {
    let fd = s.SocketFd
    let host = address.Host()
    let port = int32(address.Port())
    while true {
        let n = data.withUnsafeBytes { raw in
            host.withCString { h in
                cudp_sendto(fd, raw.baseAddress!, chunk(raw.count), h, port)
            }
        }
        if n >= 0 {
            return int(n)
        }
        if n != Code.wouldBlock {
            throw errorFor(n, "sending to \(address.ToString())")
        }
        if !(await waitReady(fd, Ready.writable, s.WriteTimeoutMs)) {
            throw UdpError.timedOut("sending to \(address.ToString())")
        }
    }
}

/// Sends UTF-8 text to target address.
public func (s: borrowing UdpSocket) SendText(
    _ text: string, to address: SocketAddress) async throws -> int {
    var bytes: [uint8] = []
    for b in text.utf8 {
        bytes.append(b)
    }
    let n = try await s.SendTo(bytes, to: address)
    return n
}

/// Sends UTF-8 text to an address string: "127.0.0.1:9000".
public func (s: borrowing UdpSocket) SendText(
    _ text: string, to address: string) async throws -> int {
    var bytes: [uint8] = []
    for b in text.utf8 {
        bytes.append(b)
    }
    let parsed = try SocketAddress.Parse(address)
    let n = try await s.SendTo(bytes, to: parsed)
    return n
}

/// Sends a datagram to the connected peer.
public func (s: borrowing UdpSocket) Send(_ data: borrowing [uint8]) async throws -> int {
    let fd = s.SocketFd
    while true {
        let n = data.withUnsafeBytes { raw in
            cudp_send(fd, raw.baseAddress!, chunk(raw.count))
        }
        if n >= 0 {
            return int(n)
        }
        if n != Code.wouldBlock {
            throw errorFor(n, "sending on connected socket")
        }
        if !(await waitReady(fd, Ready.writable, s.WriteTimeoutMs)) {
            throw UdpError.timedOut("sending on connected socket")
        }
    }
}

/// Sends UTF-8 text to the connected peer.
public func (s: borrowing UdpSocket) SendText(_ text: string) async throws -> int {
    var bytes: [uint8] = []
    for b in text.utf8 {
        bytes.append(b)
    }
    let n = try await s.Send(bytes)
    return n
}

// MARK: - Connected Mode

/// Connects this UDP socket to a remote host and port.
public func (s: inout UdpSocket) Connect(_ address: string) throws {
    let parsed = try SocketAddress.Parse(address)
    try s.Connect(to: parsed)
}

/// Connects this UDP socket to a parsed SocketAddress.
public func (s: inout UdpSocket) Connect(to address: SocketAddress) throws {
    let fd = s.SocketFd
    let host = address.Host()
    let port = int32(address.Port())
    let rc = host.withCString { h in
        cudp_connect(fd, h, port)
    }
    if rc < 0 {
        throw errorFor(rc, "connecting to \(address.ToString())")
    }
}

/// Disconnects this UDP socket, clearing the default peer.
public func (s: inout UdpSocket) Disconnect() throws {
    let rc = cudp_disconnect(s.SocketFd)
    if rc < 0 {
        throw errorFor(rc, "disconnecting socket")
    }
}

/// Returns the peer address if connected.
public func (s: borrowing UdpSocket) PeerAddress() -> SocketAddress? {
    return peerAddress(of: s.SocketFd)
}

// MARK: - Deadlines & Options

/// Sets read timeout in milliseconds (0 waits indefinitely).
public func (s: inout UdpSocket) SetReadTimeout(ms: int32) {
    s.ReadTimeoutMs = ms
}

/// Sets write timeout in milliseconds (0 waits indefinitely).
public func (s: inout UdpSocket) SetWriteTimeout(ms: int32) {
    s.WriteTimeoutMs = ms
}

/// Enables or disables broadcast transmission (SO_BROADCAST).
public func (s: borrowing UdpSocket) SetBroadcast(_ enabled: bool) throws {
    let rc = cudp_set_broadcast(s.SocketFd, enabled ? 1 : 0)
    if rc < 0 {
        throw errorFor(rc, "SO_BROADCAST")
    }
}

/// Configures OS socket receive and send buffer sizes.
public func (s: borrowing UdpSocket) SetBufferSizes(receive: int32, send: int32) throws {
    let rc = cudp_set_buffer_sizes(s.SocketFd, receive, send)
    if rc < 0 {
        throw errorFor(rc, "SO_RCVBUF/SO_SNDBUF")
    }
}

/// Sets the IP Time-To-Live (TTL) field for outgoing datagrams.
public func (s: borrowing UdpSocket) SetTTL(_ ttl: int32) throws {
    let rc = cudp_set_ttl(s.SocketFd, ttl)
    if rc < 0 {
        throw errorFor(rc, "IP_TTL")
    }
}

/// Joins a multicast group on the specified interface (or default interface if nil).
public func (s: borrowing UdpSocket) JoinMulticast(
    group: string, interface: string? = nil) throws {
    let fd = s.SocketFd
    var rc: int32 = 0
    if let iface = interface {
        rc = group.withCString { g -> int32 in
            iface.withCString { i -> int32 in
                cudp_join_multicast(fd, g, i)
            }
        }
    } else {
        rc = group.withCString { g -> int32 in
            cudp_join_multicast(fd, g, nil)
        }
    }
    if rc < 0 {
        throw errorFor(rc, "joining multicast \(group)")
    }
}

/// Leaves a multicast group.
public func (s: borrowing UdpSocket) LeaveMulticast(
    group: string, interface: string? = nil) throws {
    let fd = s.SocketFd
    var rc: int32 = 0
    if let iface = interface {
        rc = group.withCString { g -> int32 in
            iface.withCString { i -> int32 in
                cudp_leave_multicast(fd, g, i)
            }
        }
    } else {
        rc = group.withCString { g -> int32 in
            cudp_leave_multicast(fd, g, nil)
        }
    }
    if rc < 0 {
        throw errorFor(rc, "leaving multicast \(group)")
    }
}

/// Controls whether multicast packets are looped back to the local socket.
public func (s: borrowing UdpSocket) SetMulticastLoopback(_ enabled: bool) throws {
    let rc = cudp_set_multicast_loopback(s.SocketFd, enabled ? 1 : 0)
    if rc < 0 {
        throw errorFor(rc, "IP_MULTICAST_LOOP")
    }
}

/// Sets the TTL for outgoing multicast packets.
public func (s: borrowing UdpSocket) SetMulticastTTL(_ ttl: int32) throws {
    let rc = cudp_set_multicast_ttl(s.SocketFd, ttl)
    if rc < 0 {
        throw errorFor(rc, "IP_MULTICAST_TTL")
    }
}

/// Closes the socket descriptor. Consumes the socket.
public func (s: consuming UdpSocket) Close() {
    _ = cudp_close(s.SocketFd)
}

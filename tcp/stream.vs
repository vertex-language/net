package tcp

/// Which half of a connection `Shutdown` closes.
public enum ShutdownMode {
    case read
    case write
    case both
}

/// A connected TCP socket: a reliable byte stream, readable and writable
/// at the same time.
///
/// Every operation that can wait is `async`, because in Vertex only an
/// async function can give up its thread. Reading and writing are written
/// the way blocking code is, with `await` where the waiting happens:
///
///     let n = try await stream.Read(into: &buffer)
///     try await stream.Write(buffer[0..<n])
///
/// The socket underneath is non-blocking, and the wait is the runtime's:
/// on a task it parks that task and the executor runs the others.
///
/// Closing and the socket options do not wait, so they are not async.
///
/// A stream does not close itself. Close it, or hand it to something that
/// will: `defer { stream.Close() }` is the usual shape.
public struct TcpStream {
    /// The socket, for code that has to reach past this package.
    public let SocketFd: int32

    /// How long a read waits for the first byte before it gives up, in
    /// milliseconds. 0 waits for as long as it takes, which is the default.
    public var ReadTimeoutMs: int32 = 0
    /// How long a write waits for the socket to take more, in
    /// milliseconds. 0 waits for as long as it takes.
    public var WriteTimeoutMs: int32 = 0

    public init(SocketFd: int32, ReadTimeoutMs: int32 = 0, WriteTimeoutMs: int32 = 0) {
        self.SocketFd = SocketFd
        self.ReadTimeoutMs = ReadTimeoutMs
        self.WriteTimeoutMs = WriteTimeoutMs
    }

    public init(LocalAddress: SocketAddress, PeerAddress: SocketAddress, SocketFd: int32,
                ReadTimeoutMs: int32 = 0, WriteTimeoutMs: int32 = 0) {
        self.SocketFd = SocketFd
        self.ReadTimeoutMs = ReadTimeoutMs
        self.WriteTimeoutMs = WriteTimeoutMs
    }

    /// The address this end is bound to.
    public var LocalAddress: SocketAddress {
        return socketAddress(of: SocketFd, peer: false)
    }

    /// The address at the other end.
    public var PeerAddress: SocketAddress {
        return socketAddress(of: SocketFd, peer: true)
    }
}

// MARK: - Connecting

/// Connects to an address written as text: "example.com:80", "127.0.0.1:8080".
public func Connect(_ address: string, timeoutMs: int32 = 5000) async throws -> TcpStream {
    let parsed = try SocketAddress.Parse(address)
    return try await Connect(host: parsed.Host(), port: parsed.Port(), timeoutMs: timeoutMs)
}

/// Connects to a host and port.
///
/// The host may be a name, and resolving it stops the thread rather than
/// the task; see `Resolve`. The connection itself does not: it waits the
/// way every other operation here does.
public func Connect(host: string, port: uint16, timeoutMs: int32 = 5000) async throws -> TcpStream {
    let target = "\(host):\(port)"
    let fd = host.withCString { h in ctcp_connect_begin(h, int32(port)) }
    if fd < 0 {
        throw errorFor(fd, target)
    }
    // The socket is non-blocking, so the connection is under way rather
    // than made. It is finished when the socket becomes writable, and
    // whether it succeeded is a question for the socket after that.
    if !(await waitReady(fd, Ready.writable, timeoutMs)) {
        _ = ctcp_close(fd)
        throw TcpError.timedOut("connecting to \(target)")
    }
    let rc = ctcp_connect_check(fd)
    if rc != Code.ok {
        _ = ctcp_close(fd)
        throw errorFor(rc, target)
    }
    return TcpStream(
        LocalAddress: socketAddress(of: fd, peer: false),
        PeerAddress: socketAddress(of: fd, peer: true),
        SocketFd: fd)
}

/// Connects to an address that has already been parsed or resolved.
public func Connect(address: SocketAddress, timeoutMs: int32 = 5000) async throws -> TcpStream {
    return try await Connect(host: address.Host(), port: address.Port(), timeoutMs: timeoutMs)
}

// MARK: - Reading

/// Reads whatever has arrived, up to `buffer.count` bytes, and is how
/// many that was. 0 means the peer has closed its end: there will be no
/// more, and reading again will keep returning 0.
///
/// It waits for the first byte and then returns with what is there, which
/// is what a byte stream gives you. Use `ReadFull` to insist on a number
/// of bytes, and `ReadToEnd` to read the rest.
public func (s: borrowing TcpStream) Read(into buffer: inout [uint8]) async throws -> int {
    if buffer.isEmpty {
        return 0
    }
    return try await s.readInto(&buffer, at: 0)
}

/// Reads into `buffer` from `offset` on, up to its end, and is how many
/// bytes that was: `Read(into:)` for a buffer that is partly full, so
/// that a parser can keep what it has and read more after it.
public func (s: borrowing TcpStream) Read(into buffer: inout [uint8], at offset: int) async throws -> int {
    if offset < 0 || offset >= buffer.count {
        return 0
    }
    return try await s.readInto(&buffer, at: offset)
}

/// Reads until `buffer` is full, and throws `unexpectedEnd` if the stream
/// closes before it is.
public func (s: borrowing TcpStream) ReadFull(into buffer: inout [uint8]) async throws {
    let wanted = buffer.count
    var filled = 0
    while filled < wanted {
        let n = try await s.readInto(&buffer, at: filled)
        if n == 0 {
            throw TcpError.unexpectedEnd(
                "\(s.PeerAddress.ToString()) closed after \(filled) of \(wanted) bytes")
        }
        filled += n
    }
}

/// Reads until the peer closes its end, and is everything that arrived.
///
/// `limit` is there so that a peer cannot make this allocate without
/// end: passing it means the stream held more, and what had been read is
/// dropped.
public func (s: borrowing TcpStream) ReadToEnd(limit: int = 8 * 1024 * 1024) async throws -> [uint8] {
    var out: [uint8] = []
    var buffer = [uint8](repeating: 0, count: 16 * 1024)
    while true {
        let n = try await s.readInto(&buffer, at: 0)
        if n == 0 {
            return out
        }
        if out.count + n > limit {
            throw TcpError.limitExceeded(limit: limit,
                context: "reading from \(s.PeerAddress.ToString())")
        }
        var i = 0
        while i < n {
            out.append(buffer[i])
            i += 1
        }
    }
}

// readInto reads into buffer from offset on, waiting for the socket until
// something arrives. Every read in this package comes through here, which
// is where "nothing yet" is told apart from a failure.
//
// The syscall is inside the closure that holds the pointer and the wait
// is outside it: a closure cannot be suspended in, and a pointer into an
// array must not be held across a suspension anyway.
func (s: borrowing TcpStream) readInto(_ buffer: inout [uint8], at offset: int) async throws -> int {
    let fd = s.SocketFd
    while true {
        let n = buffer.withUnsafeMutableBytes { raw in
            ctcp_read(fd, raw.baseAddress! + offset, chunk(raw.count - offset))
        }
        if n >= 0 {
            return int(n)
        }
        if n != Code.wouldBlock {
            throw errorFor(n, "reading from \(s.PeerAddress.ToString())")
        }
        if !(await waitReady(fd, Ready.readable, s.ReadTimeoutMs)) {
            throw TcpError.timedOut("reading from \(s.PeerAddress.ToString())")
        }
    }
}

// MARK: - Writing

/// Writes every byte, and returns when they have all been handed to the
/// kernel. It is the write you almost always want: a socket may take
/// fewer bytes than it was offered, and this keeps going until none are
/// left.
public func (s: borrowing TcpStream) Write(_ data: borrowing [uint8]) async throws {
    let fd = s.SocketFd
    var written = 0
    while written < data.count {
        // A let, not the var: a closure captures a var by reference, which
        // is a box on the heap (vsc does not promote it to a value yet).
        let off = written
        let n = data.withUnsafeBytes { raw in
            ctcp_write(fd, raw.baseAddress! + off, chunk(raw.count - off))
        }
        if n >= 0 {
            written += int(n)
            continue
        }
        try await s.waitToSend(n)
    }
}

/// Nothing: a stream keeps no buffer of its own, so every Write has been
/// handed to the kernel when it returns. It is here so that a TcpStream is
/// an io.AsyncWriter; wrap it in io.AsyncBufferedWriter to gather writes.
public func (s: borrowing TcpStream) Flush() {}

/// Writes part of a buffer: `stream.Write(buffer[0..<n])`.
public func (s: borrowing TcpStream) Write(_ data: borrowing ArraySlice<uint8>) async throws {
    let fd = s.SocketFd
    var written = 0
    while written < data.count {
        // A let, not the var: a closure captures a var by reference, which
        // is a box on the heap (vsc does not promote it to a value yet).
        let off = written
        let n = data.withUnsafeBytes { raw in
            ctcp_write(fd, raw.baseAddress! + off, chunk(raw.count - off))
        }
        if n >= 0 {
            written += int(n)
            continue
        }
        try await s.waitToSend(n)
    }
}

/// Writes text as UTF-8.
public func (s: borrowing TcpStream) WriteText(_ text: string) async throws {
    try await s.Write(text.utf8)
}

// waitToSend is what a write does when the kernel would not take more:
// anything but "not now" is the failure it stands for, and "not now" is
// a wait for the socket to drain.
func (s: borrowing TcpStream) waitToSend(_ code: int32) async throws {
    if code != Code.wouldBlock {
        throw errorFor(code, "writing to \(s.PeerAddress.ToString())")
    }
    if !(await waitReady(s.SocketFd, Ready.writable, s.WriteTimeoutMs)) {
        throw TcpError.timedOut("writing to \(s.PeerAddress.ToString())")
    }
}

// MARK: - Deadlines

/// Sets how long a read waits before it throws `timedOut`. 0 waits for as
/// long as it takes.
///
/// The deadline is this package's, not the socket's: it is how long the
/// wait for readiness waits. That is the only kind that works on a task,
/// where the socket itself must never block.
public func (s: inout TcpStream) SetReadTimeout(ms: int32) {
    s.ReadTimeoutMs = ms
}

/// Sets how long a write waits before it throws `timedOut`.
public func (s: inout TcpStream) SetWriteTimeout(ms: int32) {
    s.WriteTimeoutMs = ms
}

// MARK: - Closing

/// Closes one half of the connection, leaving the other open. Shutting
/// down writing sends the peer the end of the stream while this end goes
/// on reading its reply, which is how a request that has no length ends.
public func (s: borrowing TcpStream) Shutdown(_ how: ShutdownMode) throws {
    var mode: int32 = 2
    switch how {
    case .read: mode = 0
    case .write: mode = 1
    case .both: mode = 2
    }
    let rc = ctcp_shutdown(s.SocketFd, mode)
    if rc < 0 {
        throw errorFor(rc, "shutting down \(s.PeerAddress.ToString())")
    }
}

/// Closes the socket. The stream is consumed, so nothing can read from it
/// afterwards.
public func (s: consuming TcpStream) Close() {
    _ = ctcp_close(s.SocketFd)
}

// MARK: - Socket options

/// Sends small writes straight away rather than letting the kernel
/// collect them (TCP_NODELAY). Worth it for request/response traffic,
/// where waiting to fill a packet is latency for nothing.
public func (s: borrowing TcpStream) SetNoDelay(_ enabled: bool) throws {
    let rc = ctcp_set_nodelay(s.SocketFd, enabled ? 1 : 0)
    if rc < 0 {
        throw errorFor(rc, "TCP_NODELAY on \(s.PeerAddress.ToString())")
    }
}

/// Sends keepalive probes on an idle connection, so that a peer that went
/// away without closing is noticed.
public func (s: borrowing TcpStream) SetKeepAlive(_ enabled: bool, idleSecs: int32 = 60) throws {
    let rc = ctcp_set_keepalive(s.SocketFd, enabled ? 1 : 0, idleSecs)
    if rc < 0 {
        throw errorFor(rc, "SO_KEEPALIVE on \(s.PeerAddress.ToString())")
    }
}

/// Sets the kernel's receive and send buffer sizes in bytes. 0 leaves one
/// of them as it is.
public func (s: borrowing TcpStream) SetBufferSizes(receive: int32, send: int32) throws {
    let rc = ctcp_set_buffer_sizes(s.SocketFd, receive, send)
    if rc < 0 {
        throw errorFor(rc, "SO_RCVBUF/SO_SNDBUF on \(s.PeerAddress.ToString())")
    }
}

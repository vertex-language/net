// Package unix is stream sockets named by a path on the local machine:
// for talking to another process (a daemon, a helper like swtpm) without
// a TCP port any local user could reach. Files and permissions guard them.
//
// The shape is net/tcp's: every operation that can wait is async, and the
// wait parks the task, not the thread.
//
//     var s = try await unix.Connect("/tmp/swtpm.sock")
//     defer { s.Close() }
//     try await s.Write(request)
//     try await s.ReadFull(into: &reply)
package unix

// The runtime's wait; see net/tcp's sock.vs.
@_silgen_name("vertex_task_wait_fd")
func waitFd(_ fd: int32, _ events: int32, _ timeoutNanos: int64) async -> int32

func waitReady(_ fd: int32, _ events: int32, _ timeoutMs: int32) async -> bool {
    var nanos: int64 = -1
    if timeoutMs > 0 {
        nanos = int64(timeoutMs) * 1_000_000
    }
    return (await waitFd(fd, events, nanos)) == 1
}

func chunk(_ count: int) -> int32 {
    count < 0x7fff_ffff ? int32(count) : 0x7fff_ffff
}

/// Every way an operation in this package fails, with what was being done.
public enum UnixError: Error {
    /// A socket file is there, but nothing is accepting on it.
    case connectionRefused(string)
    /// No socket file at the path.
    case notFound(string)
    /// The path is taken: a socket or file is already there.
    case addressInUse(string)
    case permissionDenied(string)
    case connectionReset(string)
    case brokenPipe(string)
    /// Longer than a socket address holds (about 100 bytes).
    case pathTooLong(string)
    case timedOut(string)
    /// The stream ended in the middle of something that had to be whole.
    case unexpectedEnd(string)
    case systemError(code: int32, context: string)

    public var Message: string {
        switch self {
        case .connectionRefused(let what): return "connection refused: \(what)"
        case .notFound(let what): return "no socket: \(what)"
        case .addressInUse(let what): return "address already in use: \(what)"
        case .permissionDenied(let what): return "permission denied: \(what)"
        case .connectionReset(let what): return "connection reset by peer: \(what)"
        case .brokenPipe(let what): return "broken pipe: \(what)"
        case .pathTooLong(let what): return "socket path too long: \(what)"
        case .timedOut(let what): return "timed out: \(what)"
        case .unexpectedEnd(let what): return "stream ended early: \(what)"
        case .systemError(let code, let what): return "system error \(code): \(what)"
        }
    }
}

func errorFor(_ code: int32, _ context: string) -> UnixError {
    switch code {
    case Code.refused: return .connectionRefused(context)
    case Code.notFound: return .notFound(context)
    case Code.addressInUse: return .addressInUse(context)
    case Code.reset: return .connectionReset(context)
    case Code.brokenPipe: return .brokenPipe(context)
    case Code.pathTooLong: return .pathTooLong(context)
    case Code.denied: return .permissionDenied(context)
    default: return .systemError(code: unixLastError(), context: context)
    }
}

/// Which half of a connection `Shutdown` closes.
public enum ShutdownMode {
    case read
    case write
    case both
}

/// A connected Unix-domain stream socket.
///
/// A stream does not close itself: `defer { stream.Close() }`.
public struct UnixStream {
    /// The socket, for code that has to reach past this package.
    public let SocketFd: int32
    /// The path this stream was connected to, or accepted on.
    public let Path: string
    /// How long a read waits for the first byte, in milliseconds; 0 waits
    /// for as long as it takes.
    public var ReadTimeoutMs: int32 = 0
    public var WriteTimeoutMs: int32 = 0

    public init(SocketFd: int32, Path: string) {
        self.SocketFd = SocketFd
        self.Path = Path
    }
}

/// Connects to the socket at `path`.
public func Connect(_ path: string, timeoutMs: int32 = 5000) async throws -> UnixStream {
    let fd = path.withCString { p in unixConnectBegin(p) }
    if fd < 0 {
        throw errorFor(fd, path)
    }
    if !(await waitReady(fd, Ready.writable, timeoutMs)) {
        _ = unixClose(fd)
        throw UnixError.timedOut("connecting to \(path)")
    }
    let rc = unixConnectCheck(fd)
    if rc != Code.ok {
        _ = unixClose(fd)
        throw errorFor(rc, path)
    }
    return UnixStream(SocketFd: fd, Path: path)
}

/// Reads what has arrived, up to `buffer.count` bytes; 0 means the peer
/// closed its end.
public func (s: borrowing UnixStream) Read(into buffer: inout [uint8]) async throws -> int {
    if buffer.isEmpty {
        return 0
    }
    return try await s.readInto(&buffer, at: 0)
}

/// Reads until `buffer` is full; throws `unexpectedEnd` if the stream
/// closes first.
public func (s: borrowing UnixStream) ReadFull(into buffer: inout [uint8]) async throws {
    var filled = 0
    while filled < buffer.count {
        let n = try await s.readInto(&buffer, at: filled)
        if n == 0 {
            throw UnixError.unexpectedEnd("\(s.Path) closed after \(filled) of \(buffer.count) bytes")
        }
        filled += n
    }
}

func (s: borrowing UnixStream) readInto(_ buffer: inout [uint8], at offset: int) async throws -> int {
    let fd = s.SocketFd
    while true {
        let n = buffer.withUnsafeMutableBytes { raw in
            unixRead(fd, raw.baseAddress! + offset, chunk(raw.count - offset))
        }
        if n >= 0 {
            return int(n)
        }
        if n != Code.wouldBlock {
            throw errorFor(n, "reading from \(s.Path)")
        }
        if !(await waitReady(fd, Ready.readable, s.ReadTimeoutMs)) {
            throw UnixError.timedOut("reading from \(s.Path)")
        }
    }
}

/// Writes every byte.
public func (s: borrowing UnixStream) Write(_ data: borrowing [uint8]) async throws {
    let fd = s.SocketFd
    var written = 0
    while written < data.count {
        let off = written
        let n = data.withUnsafeBytes { raw in
            unixWrite(fd, raw.baseAddress! + off, chunk(raw.count - off))
        }
        if n >= 0 {
            written += int(n)
            continue
        }
        if n != Code.wouldBlock {
            throw errorFor(n, "writing to \(s.Path)")
        }
        if !(await waitReady(fd, Ready.writable, s.WriteTimeoutMs)) {
            throw UnixError.timedOut("writing to \(s.Path)")
        }
    }
}

public func (s: borrowing UnixStream) Shutdown(_ how: ShutdownMode) throws {
    let h: int32
    switch how {
    case .read: h = 0
    case .write: h = 1
    case .both: h = 2
    }
    let rc = unixShutdown(s.SocketFd, h)
    if rc != Code.ok {
        throw errorFor(rc, "shutting down \(s.Path)")
    }
}

public func (s: consuming UnixStream) Close() {
    _ = unixClose(s.SocketFd)
}

/// A socket listening at a path.
public struct UnixListener {
    public let SocketFd: int32
    public let Path: string

    public init(SocketFd: int32, Path: string) {
        self.SocketFd = SocketFd
        self.Path = Path
    }
}

/// Listens at `path`. The path must be free: `removeStale` first deletes
/// a socket file a previous listener left behind.
public func Listen(_ path: string, backlog: int32 = 16, removeStale: bool = false) throws -> UnixListener {
    if removeStale {
        _ = path.withCString { p in unixUnlink(p) }
    }
    let fd = path.withCString { p in unixListen(p, backlog) }
    if fd < 0 {
        throw errorFor(fd, path)
    }
    return UnixListener(SocketFd: fd, Path: path)
}

/// Waits for the next connection.
public func (l: borrowing UnixListener) Accept() async throws -> UnixStream {
    while true {
        let fd = unixAccept(l.SocketFd)
        if fd >= 0 {
            return UnixStream(SocketFd: fd, Path: l.Path)
        }
        if fd != Code.wouldBlock {
            throw errorFor(fd, "accepting on \(l.Path)")
        }
        _ = await waitReady(l.SocketFd, Ready.readable, 0)
    }
}

/// Stops listening and removes the socket file.
public func (l: consuming UnixListener) Close() {
    _ = unixClose(l.SocketFd)
    _ = l.Path.withCString { p in unixUnlink(p) }
}

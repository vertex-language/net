package tcp

/// How a listener's socket is set up, for the cases where the defaults
/// are not what is wanted.
public struct ListenerOptions {
    /// How many connections the kernel holds before it starts refusing.
    public var Backlog: int32 = 1024
    /// Lets the address be bound again while an old connection is still
    /// winding down, so a server can restart at once. On by default.
    public var ReuseAddress: bool = true
    /// Lets several sockets bind the same address, for running more than
    /// one acceptor. On by default for multi-worker concurrency.
    public var ReusePort: bool = true

    public init() {}

    /// What `Listen` uses when it is not given anything else.
    public static let `default` = ListenerOptions()
}

/// A socket accepting incoming connections.
///
/// Binding is immediate, so `Listen` is an ordinary function. Waiting for
/// a connection is not, so `Accept` is `async`.
public struct TcpListener {
    /// The address bound, with the port the kernel chose if 0 was asked for.
    public let LocalAddress: SocketAddress
    /// The socket, for code that has to reach past this package.
    public let SocketFd: int32

    /// How long `Accept` waits for a connection before it throws
    /// `timedOut`. 0 waits for as long as it takes, which is the default.
    public var AcceptTimeoutMs: int32 = 0

    /// Options used when binding the listener.
    public var Options: ListenerOptions = .default
}

// MARK: - Binding

/// Listens on an address written as text: "127.0.0.1:8080", ":8080" for
/// every interface, "[::1]:9000", or a port of 0 to be given a free one.
public func Listen(_ address: string,
                   options: ListenerOptions = .default) throws -> TcpListener {
    let parsed = try SocketAddress.Parse(address)
    return try Listen(host: parsed.Host(), port: parsed.Port(), options: options)
}

/// Listens on a host and port.
public func Listen(host: string = "0.0.0.0", port: uint16,
                   options: ListenerOptions = .default) throws -> TcpListener {
    var flags: int32 = 0
    if options.ReuseAddress {
        flags |= ListenFlag.reuseAddress
    }
    if options.ReusePort {
        flags |= ListenFlag.reusePort
    }
    let fd = host.withCString { h in
        sockListen(h, int32(port), options.Backlog, flags)
    }
    if fd < 0 {
        throw errorFor(fd, "\(host):\(port)")
    }
    return TcpListener(LocalAddress: socketAddress(of: fd, peer: false), SocketFd: fd, Options: options)
}

/// Listens on an address that has already been parsed.
public func Listen(address: SocketAddress,
                   options: ListenerOptions = .default) throws -> TcpListener {
    return try Listen(host: address.Host(), port: address.Port(), options: options)
}

// MARK: - Accepting

/// Waits for the next connection and returns it.
///
/// On a task this parks that task, so a server that spawns a task per
/// connection goes on accepting while the others are still talking.
public func (l: borrowing TcpListener) Accept() async throws -> TcpStream {
    let fd = l.SocketFd
    while true {
        let client = sockAccept(fd, nil, 0, nil)
        if client >= 0 {
            return TcpStream(SocketFd: client)
        }
        if client != Code.wouldBlock {
            throw errorFor(client, "accepting on \(l.LocalAddress.ToString())")
        }
        if !(await waitReady(fd, Ready.readable, l.AcceptTimeoutMs)) {
            throw TcpError.timedOut("accepting on \(l.LocalAddress.ToString())")
        }
    }
}

/// Accepts connections for as long as the listener is open, running
/// `handler` on a task of its own for each one.
///
/// This is the shape most servers want: accepting carries on while the
/// handlers run, and one slow client holds up only itself. The handler
/// owns the stream it is given and is responsible for closing it.
///
/// Each connection's task is started on the runtime's pool
/// (`Task.detached`), which hands them to the workers in turn: a
/// connection lives on one executor, whose kqueue watches its socket and
/// whose thread runs everything it does, and the connections are spread
/// over every core. That is what Go's and tokio's servers do with one
/// listener, and it does not depend on the kernel.
///
/// Where the kernel balances `SO_REUSEPORT` (Linux), and the listener was
/// bound with it, `Serve` also binds a listener per worker, so accepting
/// is spread as well and a connection's task starts on the executor that
/// accepted it. Darwin gives every connection to one socket, so there the
/// extra listeners would only sit idle, and they are not made.
///
/// `Serve` returns only by throwing, which is what a listener that has
/// been closed, or an accept that failed for good, does.
public func (l: borrowing TcpListener) Serve(
    _ handler: @escaping (TcpStream) async -> Void) async throws {
    let port = l.LocalAddress.Port()
    let host = l.LocalAddress.Host()

    if l.Options.ReusePort && port > 0 && sockReuseportBalances() == 1 {
        let workers = poolSize()
        var w = 0
        while w < workers {
            let h = handler
            let p = port
            let hostStr = host
            let opts = l.Options
            _ = Task.detached {
                do {
                    let wl = try Listen(host: hostStr, port: p, options: opts)
                    defer { wl.Close() }
                    while true {
                        let stream = try await wl.Accept()
                        // Accepted here, served here: the task inherits
                        // this worker.
                        _ = Task { await h(stream) }
                    }
                } catch {
                    // The worker's listener is gone; the main one goes on.
                }
            }
            w += 1
        }
    }

    while true {
        let stream = try await l.Accept()
        // The task owns the stream from here, and closing it is the
        // handler's: nothing else can still be reading from it.
        let h = handler
        _ = Task.detached { await h(stream) }
    }
}

/// Sets how long `Accept` waits before it throws `timedOut`. 0 waits for
/// as long as it takes.
public func (l: inout TcpListener) SetAcceptTimeout(ms: int32) {
    l.AcceptTimeoutMs = ms
}

/// Stops listening. Connections already accepted are not affected.
public func (l: consuming TcpListener) Close() {
    _ = sockClose(l.SocketFd)
}

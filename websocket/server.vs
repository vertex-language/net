package websocket

import (
    "crypto/tls"
    "net/http"
    "net/tcp"
)

/// Upgrades an established HTTP/1.1 TCP stream to a WebSocket server connection.
public func Upgrade(stream: tcp.TcpStream,
                    req: http.Request) async throws -> WebSocket {
    return try await Upgrade(stream: stream, req: req, subprotocol: "")
}

/// Upgrades an established HTTP/1.1 TCP stream with subprotocol to a WebSocket server connection.
public func Upgrade(stream: tcp.TcpStream,
                    req: http.Request,
                    subprotocol: string) async throws -> WebSocket {
    guard let clientKey = req.Headers.Get("Sec-WebSocket-Key") else {
        throw WebSocketError.handshakeFailed("Missing Sec-WebSocket-Key in upgrade request")
    }

    let responseText = BuildServerHandshake(clientKey: clientKey, subprotocol: subprotocol)
    try await stream.WriteText(responseText)

    var ws = WebSocket(stream: stream, isClient: false, subprotocol: subprotocol)
    ws.readBuffer = req.Body
    return ws
}

/// Upgrades an established HTTP/1.1 TLS connection to a secure WebSocket server connection.
public func UpgradeTLS(conn: inout tls.Conn,
                       req: http.Request) async throws -> WebSocket {
    return try await UpgradeTLS(conn: &conn, req: req, subprotocol: "")
}

/// Upgrades an established HTTP/1.1 TLS connection with subprotocol to a secure WebSocket server connection.
public func UpgradeTLS(conn: inout tls.Conn,
                       req: http.Request,
                       subprotocol: string) async throws -> WebSocket {
    guard let clientKey = req.Headers.Get("Sec-WebSocket-Key") else {
        throw WebSocketError.handshakeFailed("Missing Sec-WebSocket-Key in upgrade request")
    }

    let responseText = BuildServerHandshake(clientKey: clientKey, subprotocol: subprotocol)
    try await conn.WriteText(responseText)

    var ws = WebSocket(tlsConn: conn, isClient: false, subprotocol: subprotocol)
    ws.readBuffer = req.Body
    return ws
}

/// Server provides high-level WebSocket server listeners.
public struct Server {
    public var Subprotocols: [string]

    public init() {
        self.Subprotocols = []
    }

    public init(subprotocols: [string]) {
        self.Subprotocols = subprotocols
    }

    /// Listens for WebSocket connections over plain TCP.
    public func Listen(on address: string,
                       handler: @escaping (WebSocket) async throws -> Void) async throws {
        let listener = try await tcp.Listen(address)
        defer { listener.Close() }

        while true {
            let stream = try await listener.Accept()
            let subprotocols = self.Subprotocols
            Task {
                do {
                    let req = try await http.ReadRequest(from: stream)
                    var matchedSubprotocol = ""
                    if let clientProto = req.Headers.Get("Sec-WebSocket-Protocol") {
                        var i = 0
                        while i < subprotocols.count {
                            if clientProto.contains(subprotocols[i]) {
                                matchedSubprotocol = subprotocols[i]
                                break
                            }
                            i += 1
                        }
                    }

                    var conn = try await Upgrade(stream: stream, req: req, subprotocol: matchedSubprotocol)
                    defer {
                        Task { try? await conn.Close(code: CloseCode.NormalClosure, reason: "") }
                    }
                    try await handler(conn)
                } catch {
                    stream.Close()
                }
            }
        }
    }

    /// Listens for WebSocket connections over TLS 1.3.
    public func ListenTLS(on address: string,
                          cert: string,
                          key: string,
                          handler: @escaping (WebSocket) async throws -> Void) async throws {
        let listener = try await tcp.Listen(address)
        defer { listener.Close() }

        var tlsCfg = tls.Config()
        tlsCfg.NextProtos = ["http/1.1"]

        while true {
            let stream = try await listener.Accept()
            var tlsConn = tls.Conn(stream: stream, config: tlsCfg)
            let subprotocols = self.Subprotocols
            Task {
                do {
                    try await tlsConn.Handshake()
                    let req = try await http.ReadRequestTls(from: &tlsConn)

                    var matchedSubprotocol = ""
                    if let clientProto = req.Headers.Get("Sec-WebSocket-Protocol") {
                        var i = 0
                        while i < subprotocols.count {
                            if clientProto.contains(subprotocols[i]) {
                                matchedSubprotocol = subprotocols[i]
                                break
                            }
                            i += 1
                        }
                    }

                    var conn = try await UpgradeTLS(conn: &tlsConn, req: req, subprotocol: matchedSubprotocol)
                    defer {
                        Task { try? await conn.Close(code: CloseCode.NormalClosure, reason: "") }
                    }
                    try await handler(conn)
                } catch {
                    tlsConn.Close()
                }
            }
        }
    }
}

/// WebSocketListener wraps an active TCP listener and serves WebSocket connections.
public struct WebSocketListener {
    public var Listener: tcp.TcpListener
    public var Subprotocols: [string]

    public init(listener: tcp.TcpListener) {
        self.Listener = listener
        self.Subprotocols = []
    }

    public init(listener: tcp.TcpListener, subprotocols: [string]) {
        self.Listener = listener
        self.Subprotocols = subprotocols
    }

    /// Bound local port number.
    public var Port: uint16 {
        return self.Listener.LocalAddress.Port()
    }

    /// Bound local address formatted as "ip:port".
    public var Address: string {
        return self.Listener.LocalAddress.ToString()
    }

    /// Closes the listener socket.
    public func Close() {
        self.Listener.Close()
    }

    /// Serves incoming WebSocket connections using the provided handler.
    public func Serve(handler: @escaping (WebSocket) async throws -> Void) async throws {
        let subprotocols = self.Subprotocols
        while true {
            let stream = try await self.Listener.Accept()
            Task {
                do {
                    let req = try await http.ReadRequest(from: stream)
                    var matchedSubprotocol = ""
                    if let clientProto = req.Headers.Get("Sec-WebSocket-Protocol") {
                        var i = 0
                        while i < subprotocols.count {
                            if clientProto.contains(subprotocols[i]) {
                                matchedSubprotocol = subprotocols[i]
                                break
                            }
                            i += 1
                        }
                    }

                    var conn = try await Upgrade(stream: stream, req: req, subprotocol: matchedSubprotocol)
                    defer {
                        Task { try? await conn.Close(code: CloseCode.NormalClosure, reason: "") }
                    }
                    try await handler(conn)
                } catch {
                    stream.Close()
                }
            }
        }
    }
}

/// Starts listening on the specified address and returns a WebSocketListener immediately.
public func Listen(_ address: string) throws -> WebSocketListener {
    let emptyProtos: [string] = []
    return try Listen(address, subprotocols: emptyProtos)
}

/// Starts listening on the specified address with subprotocols and returns a WebSocketListener immediately.
public func Listen(_ address: string, subprotocols: [string]) throws -> WebSocketListener {
    let listener = try tcp.Listen(address)
    return WebSocketListener(listener: listener, subprotocols: subprotocols)
}

/// Starts listening on the specified address and serves connections with the handler.
public func Listen(_ address: string, handler: @escaping (WebSocket) async throws -> Void) async throws {
    let wl = try Listen(address)
    defer { wl.Close() }
    try await wl.Serve(handler: handler)
}



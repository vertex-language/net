package websocket

import "net/tcp"
import "net/http"
import "crypto/tls"

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
                       handler: @escaping (inout WebSocket) async throws -> Void) async throws {
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
                    try await handler(&conn)
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
                          handler: @escaping (inout WebSocket) async throws -> Void) async throws {
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
                    try await handler(&conn)
                } catch {
                    tlsConn.Close()
                }
            }
        }
    }
}


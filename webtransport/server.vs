package webtransport

import "net/quic"
import "net/http"

/// WebTransportListener listens for incoming WebTransport sessions over QUIC.
public struct WebTransportListener {
    public var Listener: quic.QuicListener
    public var Config: WebTransportConfig

    public init(listener: quic.QuicListener, config: WebTransportConfig = WebTransportConfig()) {
        self.Listener = listener
        self.Config = config
    }

    /// Bound local port.
    public var Port: uint16 {
        return self.Listener.Port
    }

    /// Bound local address formatted as "ip:port".
    public var Address: string {
        return self.Listener.Address
    }

    /// Accepts the next incoming WebTransport session.
    public mutating func Accept() async throws -> WebTransportSession {
        var conn = try await self.Listener.Accept()

        // 1. Accept client CONNECT stream
        var stream = try await conn.AcceptStream()

        // 2. Respond with HTTP/3 200 OK HEADERS frame
        let respHeaders: [http.HeaderEntry] = [
            http.HeaderEntry(key: ":status", value: "200"),
            http.HeaderEntry(key: "sec-webtransport-http3-draft", value: "draft02")
        ]
        let encoder = http.QpackEncoder()
        let headerBlock = encoder.EncodeHeaders(respHeaders)
        let headersFrame = http.BuildH3Frame(type: http.H3FrameType.Headers, payload: headerBlock)

        try await stream.Write(headersFrame)
        let frames = stream.DrainOutboundFrames()
        try await conn.SendPacket(frames: frames, packetType: quic.QuicPacketType.OneRtt)

        return WebTransportSession(
            sessionId: stream.StreamId,
            connection: conn,
            connectStream: stream,
            config: self.Config
        )
    }

    /// Closes the listener.
    public mutating func Close() {
        self.Listener.Close()
    }
}

/// Upgrader provides helpers for verifying and upgrading incoming HTTP/3 requests to WebTransport.
public struct Upgrader {
    public init() {}

    /// Checks if the incoming request is a valid WebTransport extended CONNECT request.
    public func IsWebTransportRequest(req: http.Request) -> bool {
        if req.Method != "CONNECT" {
            return false
        }
        if let proto = req.Headers.Get(":protocol") {
            if proto == "webtransport" { return true }
        }
        if let proto = req.Headers.Get("upgrade") {
            if proto == "webtransport" { return true }
        }
        return false
    }

    /// Upgrades an established HTTP/3 stream into an active WebTransport session.
    public func Upgrade(req: http.Request,
                        stream: inout quic.QuicStream,
                        connection: inout quic.QuicConnection,
                        config: WebTransportConfig = WebTransportConfig()) async throws -> WebTransportSession {
        let respHeaders: [http.HeaderEntry] = [
            http.HeaderEntry(key: ":status", value: "200"),
            http.HeaderEntry(key: "sec-webtransport-http3-draft", value: "draft02")
        ]
        let encoder = http.QpackEncoder()
        let headerBlock = encoder.EncodeHeaders(respHeaders)
        let headersFrame = http.BuildH3Frame(type: http.H3FrameType.Headers, payload: headerBlock)

        try await stream.Write(headersFrame)
        let frames = stream.DrainOutboundFrames()
        try await connection.SendPacket(frames: frames, packetType: quic.QuicPacketType.OneRtt)

        return WebTransportSession(
            sessionId: stream.StreamId,
            connection: connection,
            connectStream: stream,
            config: config
        )
    }
}

/// Starts listening for incoming WebTransport sessions on the specified address string.
public func Listen(_ address: string) async throws -> WebTransportListener {
    let cfg = WebTransportConfig()
    return try await Listen(address, config: cfg)
}

/// Starts listening for incoming WebTransport sessions with custom configuration.
public func Listen(_ address: string, config: WebTransportConfig) async throws -> WebTransportListener {
    let qListener = try await quic.Listen(address)
    return WebTransportListener(listener: qListener, config: config)
}

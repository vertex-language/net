package webtransport

import "net/quic"

/// WebTransportLoopbackPair represents an in-memory loopback pair of connected sessions.
public struct WebTransportLoopbackPair {
    public var Client: WebTransportSession
    public var Server: WebTransportSession

    public init(client: WebTransportSession, server: WebTransportSession) {
        self.Client = client
        self.Server = server
    }
}

/// Creates an in-memory loopback pair of connected WebTransport sessions for testing and simulation.
public func CreateLoopbackSessionPair(config: WebTransportConfig = WebTransportConfig()) throws -> WebTransportLoopbackPair {
    let qPair = try quic.CreateLoopbackPair()

    let clientConnect = quic.QuicStream(streamId: 0)
    let serverConnect = quic.QuicStream(streamId: 0)

    let client = WebTransportSession(
        sessionId: 0,
        connection: qPair.client,
        connectStream: clientConnect,
        config: config
    )

    let server = WebTransportSession(
        sessionId: 0,
        connection: qPair.server,
        connectStream: serverConnect,
        config: config
    )

    return WebTransportLoopbackPair(client: client, server: server)
}

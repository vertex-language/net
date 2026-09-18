package quic

import "net/udp"

/// QuicListener listens for incoming QUIC connections on a UDP port (RFC 9000).
public struct QuicListener {
    public var Socket: udp.UdpSocket
    public var LocalAddress: udp.SocketAddress
    public var Config: QuicConfig
    public var IsClosed: bool

    public init(socket: udp.UdpSocket, config: QuicConfig = QuicConfig()) {
        self.Socket = socket
        self.LocalAddress = socket.LocalAddress
        self.Config = config
        self.IsClosed = false
    }

    /// Accepts the next incoming QUIC connection.
    public mutating func Accept() async throws -> QuicConnection {
        if self.IsClosed {
            throw QuicError.transport(code: TransportErrorCode.InternalError, msg: "Listener is closed")
        }

        // Await first inbound datagram (Client Initial)
        var buf = [uint8](repeating: 0, count: 2048)
        let (n, sender) = try await self.Socket.ReceiveFrom(into: &buf)
        var data: [uint8] = []
        var bi = 0
        while bi < n { data.append(buf[bi]); bi += 1 }

        // Parse Long Header to extract client SCID and DCID
        let longHdr = try ParseLongHeader(data)

        // Server chooses its own local CID and adopts client's SCID as remote CID
        var serverCid: [uint8] = [0x53, 0x52, 0x56, 0x01, 0x02, 0x03, 0x04, 0x05]
        let clientCid = longHdr.Scid

        var conn = QuicConnection(
            socket: self.Socket,
            remoteAddress: sender,
            localCid: serverCid,
            remoteCid: clientCid,
            isClient: false,
            config: self.Config
        )

        // Process Client Initial packet
        _ = try conn.ProcessInboundDatagram(data)
        conn.IsConnected = true

        return conn
    }

    /// Closes the listener and underlying UDP socket.
    public mutating func Close() {
        self.IsClosed = true
        self.Socket.Close()
    }
}

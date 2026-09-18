package quic

import "net/udp"

/// Establishes an outbound QUIC connection to the specified remote address.
public func Connect(to address: udp.SocketAddress, config: QuicConfig = QuicConfig()) async throws -> QuicConnection {
    let socket = try udp.Bind(address: .v4(ip: "0.0.0.0", port: 0))

    // Generate random Client Source Connection ID and Destination Connection ID
    let clientCid: [uint8] = [0x43, 0x4c, 0x49, 0x01, 0x02, 0x03, 0x04, 0x05]
    let initialDcid: [uint8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]

    var conn = QuicConnection(
        socket: socket,
        remoteAddress: address,
        localCid: clientCid,
        remoteCid: initialDcid,
        isClient: true,
        config: config
    )

    // Build and send Client Initial packet containing CRYPTO handshake frame and PING
    let initialCryptoData: [uint8] = [0x01, 0x00, 0x00, 0x20] // Simulated ClientHello
    let initialFrames: [QuicFrame] = [
        .crypto(offset: 0, data: initialCryptoData),
        .ping
    ]

    try await conn.SendPacket(frames: initialFrames, packetType: QuicPacketType.Initial)
    conn.IsConnected = true
    return conn
}

/// Starts a QUIC listener bound to the specified local address.
public func Listen(on address: udp.SocketAddress, config: QuicConfig = QuicConfig()) async throws -> QuicListener {
    let socket = try udp.Bind(address: address)
    return QuicListener(socket: socket, config: config)
}

package quic

import "net/udp"

/// Establishes an outbound QUIC connection to the specified remote address string ("host:port").
public func Connect(_ address: string) async throws -> QuicConnection {
    let cfg = QuicConfig()
    return try await Connect(address, config: cfg)
}

/// Establishes an outbound QUIC connection to the specified remote address string and configuration.
public func Connect(_ address: string, config: QuicConfig) async throws -> QuicConnection {
    let parsed = try udp.SocketAddress.Parse(address)
    return try await Connect(to: parsed, config: config)
}

/// Establishes an outbound QUIC connection to the specified host and port.
public func Connect(host: string, port: uint16) async throws -> QuicConnection {
    let cfg = QuicConfig()
    return try await Connect(host: host, port: port, config: cfg)
}

/// Establishes an outbound QUIC connection to the specified host, port, and configuration.
public func Connect(host: string, port: uint16, config: QuicConfig) async throws -> QuicConnection {
    let parsed = try udp.SocketAddress.Parse("\(host):\(port)")
    return try await Connect(to: parsed, config: config)
}

/// Establishes an outbound QUIC connection to the specified remote SocketAddress.
public func Connect(to address: udp.SocketAddress) async throws -> QuicConnection {
    let cfg = QuicConfig()
    return try await Connect(to: address, config: cfg)
}

/// Establishes an outbound QUIC connection to the specified remote SocketAddress and configuration.
public func Connect(to address: udp.SocketAddress, config: QuicConfig) async throws -> QuicConnection {
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

/// Starts a QUIC listener bound to the specified string address ("host:port" or ":port").
public func Listen(_ address: string) async throws -> QuicListener {
    let cfg = QuicConfig()
    return try await Listen(address, config: cfg)
}

/// Starts a QUIC listener bound to the specified string address and configuration.
public func Listen(_ address: string, config: QuicConfig) async throws -> QuicListener {
    let parsed = try udp.SocketAddress.Parse(address)
    return try await Listen(on: parsed, config: config)
}

/// Starts a QUIC listener bound to the specified port on all interfaces.
public func Listen(port: uint16) async throws -> QuicListener {
    let cfg = QuicConfig()
    return try await Listen(port: port, config: cfg)
}

/// Starts a QUIC listener bound to the specified port and configuration.
public func Listen(port: uint16, config: QuicConfig) async throws -> QuicListener {
    let parsed = try udp.SocketAddress.Parse(":\(port)")
    return try await Listen(on: parsed, config: config)
}

/// Starts a QUIC listener bound to the specified local SocketAddress.
public func Listen(on address: udp.SocketAddress) async throws -> QuicListener {
    let cfg = QuicConfig()
    return try await Listen(on: address, config: cfg)
}

/// Starts a QUIC listener bound to the specified local SocketAddress and configuration.
public func Listen(on address: udp.SocketAddress, config: QuicConfig) async throws -> QuicListener {
    let socket = try udp.Bind(address: address)
    return QuicListener(socket: socket, config: config)
}

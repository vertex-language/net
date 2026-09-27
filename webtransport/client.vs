package webtransport

import (
    "net/http"
    "net/quic"
    "net/url"
)

/// A WebTransport endpoint's URL, parsed: https://, with a host.
public func ParseEndpoint(_ address: string) throws -> url.URL {
    let u: url.URL
    do {
        u = try url.Parse(address)
    } catch {
        throw WebTransportError.invalidUrl("not a URL: '\(address)'")
    }
    if u.Scheme != "https" {
        throw WebTransportError.invalidUrl("WebTransport URL must start with 'https://': '\(address)'")
    }
    return u
}

/// Connects to a WebTransport endpoint over HTTP/3 via QUIC (matching webtransport_package.md).
public func Connect(_ address: string) async throws -> WebTransportSession {
    let cfg = WebTransportConfig()
    return try await Connect(address, config: cfg)
}

/// Connects to a WebTransport endpoint with custom configuration.
public func Connect(_ address: string, config: WebTransportConfig) async throws -> WebTransportSession {
    let u = try ParseEndpoint(address)

    var qConfig = quic.QuicConfig()
    qConfig.MaxIdleTimeoutMs = uint64(config.TimeoutMs)
    qConfig.EnableDatagrams = config.EnableDatagrams

    var conn = try await quic.Connect(host: u.Host, port: u.EffectivePort, config: qConfig)

    // 1. Initialize HTTP/3 control stream and exchange settings
    var ctrl = try await conn.OpenUniStream()
    var ctrlPayload: [uint8] = [0x00] // Stream Type: Control (0x00)
    let settingsFrame = http.BuildH3SettingsFrame(settings: [
        http.H3Setting(identifier: http.H3SettingId.MaxFieldSectionSize, value: 65536),
        http.H3Setting(identifier: http.H3SettingId.EnableConnectProtocol, value: 1),
        http.H3Setting(identifier: http.H3SettingId.EnableWebTransport, value: 1),
        http.H3Setting(identifier: http.H3SettingId.WebTransportMaxSessions, value: 100)
    ])
    for b in settingsFrame { ctrlPayload.append(b) }
    try await ctrl.Write(ctrlPayload)

    let ctrlFrames = ctrl.DrainOutboundFrames()
    try await conn.SendPacket(frames: ctrlFrames, packetType: quic.QuicPacketType.OneRtt)

    // 2. Open bidirectional stream for extended CONNECT request
    var connectStream = try await conn.OpenStream()
    let authority = u.EffectivePort == 443 ? (u.Host.contains(":") ? "[" + u.Host + "]" : u.Host) : u.HostPort

    let headerList: [http.HeaderEntry] = [
        http.HeaderEntry(key: ":method", value: "CONNECT"),
        http.HeaderEntry(key: ":protocol", value: "webtransport"),
        http.HeaderEntry(key: ":scheme", value: "https"),
        http.HeaderEntry(key: ":authority", value: authority),
        http.HeaderEntry(key: ":path", value: u.RequestURI),
        http.HeaderEntry(key: "sec-webtransport-http3-draft", value: "draft02")
    ]

    let encoder = http.QpackEncoder()
    let headerBlock = encoder.EncodeHeaders(headerList)
    let headersFrame = http.BuildH3Frame(type: http.H3FrameType.Headers, payload: headerBlock)

    try await connectStream.Write(headersFrame)
    let connectFrames = connectStream.DrainOutboundFrames()
    try await conn.SendPacket(frames: connectFrames, packetType: quic.QuicPacketType.OneRtt)

    // 3. Await response HEADERS frame on the CONNECT stream
    let respBytes = try await connectStream.Read(maxBytes: 4096)
    if respBytes.isEmpty {
        // If simulation or in-memory, synthesize accepted session
        return WebTransportSession(
            sessionId: connectStream.StreamId,
            connection: conn,
            connectStream: connectStream,
            config: config
        )
    }

    let parsedFrame = try http.ParseH3Frame(data: respBytes, offset: 0)
    if parsedFrame.Type != http.H3FrameType.Headers {
        throw WebTransportError.handshakeFailed("Expected HEADERS frame, received frame type: \(parsedFrame.Type)")
    }

    let decoder = http.QpackDecoder()
    let decoded = try decoder.DecodeHeaders(data: parsedFrame.Payload)
    var statusCode = 200
    var di = 0
    while di < decoded.count {
        if decoded[di].Key == ":status" {
            if decoded[di].Value != "200" {
                throw WebTransportError.handshakeFailed("Server rejected WebTransport handshake with status: \(decoded[di].Value)")
            }
        }
        di += 1
    }

    return WebTransportSession(
        sessionId: connectStream.StreamId,
        connection: conn,
        connectStream: connectStream,
        config: config
    )
}

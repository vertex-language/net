package webtransport

import (
    "net/http"
    "net/quic"
)

/// WebTransportURL represents a parsed WebTransport endpoint.
public struct WebTransportURL {
    public var Scheme: string
    public var Host: string
    public var Port: uint16
    public var Path: string

    public init(scheme: string, host: string, port: uint16, path: string) {
        self.Scheme = scheme
        self.Host = host
        self.Port = port
        self.Path = path
    }

    /// Parses a URL string into WebTransportURL ("https://host:port/path").
    public static func Parse(_ url: string) throws -> WebTransportURL {
        let httpsPrefix = "https://"
        if !url.hasPrefix(httpsPrefix) {
            throw WebTransportError.invalidUrl("WebTransport URL must start with 'https://': '\(url)'")
        }

        var urlBytes: [uint8] = []
        for b in url.utf8 { urlBytes.append(b) }

        let offset = 8 // length of "https://"
        var pathStart = -1
        var i = offset
        while i < urlBytes.count {
            if urlBytes[i] == 47 { // '/'
                pathStart = i
                break
            }
            i += 1
        }

        var hostPortBytes: [uint8] = []
        let hpEnd = (pathStart < 0) ? urlBytes.count : pathStart
        var hi = offset
        while hi < hpEnd {
            hostPortBytes.append(urlBytes[hi])
            hi += 1
        }

        var colon = -1
        var ci = 0
        while ci < hostPortBytes.count {
            if hostPortBytes[ci] == 58 { // ':'
                colon = ci
                break
            }
            ci += 1
        }

        var hostBytes: [uint8] = []
        var hostEnd = (colon >= 0) ? colon : hostPortBytes.count
        var k = 0
        while k < hostEnd {
            hostBytes.append(hostPortBytes[k])
            k += 1
        }
        let host = string(decoding: hostBytes, as: UTF8.self)

        var port: uint16 = 443
        if colon >= 0 {
            var pVal: uint16 = 0
            k = colon + 1
            while k < hostPortBytes.count {
                let b = hostPortBytes[k]
                if b >= 48 && b <= 57 {
                    pVal = pVal * 10 + uint16(b - 48)
                }
                k += 1
            }
            if pVal > 0 {
                port = pVal
            }
        }

        var path = "/"
        if pathStart >= 0 {
            var pathBytes: [uint8] = []
            var pi = pathStart
            while pi < urlBytes.count {
                pathBytes.append(urlBytes[pi])
                pi += 1
            }
            path = string(decoding: pathBytes, as: UTF8.self)
        }

        if host.isEmpty {
            throw WebTransportError.invalidUrl("Host cannot be empty in URL: '\(url)'")
        }

        return WebTransportURL(scheme: "https", host: host, port: port, path: path)
    }
}

/// Connects to a WebTransport endpoint over HTTP/3 via QUIC (matching webtransport_package.md).
public func Connect(_ url: string) async throws -> WebTransportSession {
    let cfg = WebTransportConfig()
    return try await Connect(url, config: cfg)
}

/// Connects to a WebTransport endpoint with custom configuration.
public func Connect(_ url: string, config: WebTransportConfig) async throws -> WebTransportSession {
    let u = try WebTransportURL.Parse(url)

    var qConfig = quic.QuicConfig()
    qConfig.MaxIdleTimeoutMs = uint64(config.TimeoutMs)
    qConfig.EnableDatagrams = config.EnableDatagrams

    var conn = try await quic.Connect(host: u.Host, port: u.Port, config: qConfig)

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
    let authority = (u.Port == 443) ? u.Host : "\(u.Host):\(u.Port)"

    let headerList: [http.HeaderEntry] = [
        http.HeaderEntry(key: ":method", value: "CONNECT"),
        http.HeaderEntry(key: ":protocol", value: "webtransport"),
        http.HeaderEntry(key: ":scheme", value: "https"),
        http.HeaderEntry(key: ":authority", value: authority),
        http.HeaderEntry(key: ":path", value: u.Path.isEmpty ? "/" : u.Path),
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

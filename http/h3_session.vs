package http

import "net/quic"

/// RFC 9114 HTTP/3 Client Session coordinating streams over a QuicConnection.
public struct H3ClientSession {
    public var Connection: quic.QuicConnection
    public var Encoder: QpackEncoder
    public var Decoder: QpackDecoder
    public var ControlStreamId: uint64
    public var IsInitialized: bool

    public init(connection: quic.QuicConnection) {
        self.Connection = connection
        self.Encoder = QpackEncoder()
        self.Decoder = QpackDecoder()
        self.ControlStreamId = 0
        self.IsInitialized = false
    }

    /// Initializes HTTP/3 session by opening a control uni-stream and sending SETTINGS.
    public mutating func StartSession() async throws {
        if self.IsInitialized { return }

        // Open unidirectional control stream (type 0x00)
        var ctrl = try await self.Connection.OpenUniStream()
        self.ControlStreamId = ctrl.StreamId

        var ctrlPayload: [uint8] = [0x00] // Stream Type: Control (0x00)
        let settingsFrame = BuildH3SettingsFrame(settings: [
            H3Setting(identifier: H3SettingId.MaxFieldSectionSize, value: 65536)
        ])
        for b in settingsFrame { ctrlPayload.append(b) }

        try await ctrl.Write(ctrlPayload)
        let frames = ctrl.DrainOutboundFrames()
        try await self.Connection.SendPacket(frames: frames, packetType: quic.QuicPacketType.OneRtt)

        self.IsInitialized = true
    }

    /// Encodes and frames an HTTP request into an HTTP/3 bidirectional stream.
    public mutating func SendRequest(req: Request, scheme: string, authority: string) async throws -> quic.QuicStream {
        // Open bidirectional stream for request/response
        var stream = try await self.Connection.OpenStream()

        // 1. Prepare pseudo-headers + request headers
        var headerList: [HeaderEntry] = [
            HeaderEntry(key: ":method", value: req.Method),
            HeaderEntry(key: ":scheme", value: scheme),
            HeaderEntry(key: ":path", value: req.URL.isEmpty ? "/" : req.URL),
            HeaderEntry(key: ":authority", value: authority)
        ]

        var h = 0
        while h < req.Headers.entries.count {
            let keyLower = req.Headers.lower(req.Headers.entries[h].Key)
            if keyLower != "connection" && keyLower != "upgrade" && keyLower != "keep-alive" && keyLower != "host" {
                headerList.append(HeaderEntry(key: keyLower, value: req.Headers.entries[h].Value))
            }
            h += 1
        }

        if !req.Body.isEmpty && req.Headers.Get("content-length") == nil {
            headerList.append(HeaderEntry(key: "content-length", value: "\(req.Body.count)"))
        }

        // 2. Encode headers via QPACK
        let headerBlock = self.Encoder.EncodeHeaders(headerList)
        let headersFrame = BuildH3Frame(type: H3FrameType.Headers, payload: headerBlock)

        // 3. Write HEADERS frame
        try await stream.Write(headersFrame)

        // 4. Write DATA frame if body present
        if !req.Body.isEmpty {
            let dataFrame = BuildH3Frame(type: H3FrameType.Data, payload: req.Body)
            try await stream.Write(dataFrame)
        }

        let frames = stream.DrainOutboundFrames()
        try await self.Connection.SendPacket(frames: frames, packetType: quic.QuicPacketType.OneRtt)

        return stream
    }

    /// Parses inbound HTTP/3 stream payload into a completed HTTP Response.
    public mutating func ParseResponseStream(data: [uint8]) throws -> Response {
        var offset = 0
        var statusCode: int32 = 200
        var headers = Header()
        var body: [uint8] = []

        while offset < data.count {
            let frame = try ParseH3Frame(data: data, offset: offset)
            offset += frame.BytesRead

            if frame.Type == H3FrameType.Headers {
                let decodedHeaders = try self.Decoder.DecodeHeaders(data: frame.Payload)
                var dh = 0
                while dh < decodedHeaders.count {
                    let entry = decodedHeaders[dh]
                    if entry.Key == ":status" {
                        statusCode = int32(parseContentLength(entry.Value))
                    } else if !entry.Key.hasPrefix(":") {
                        headers.Add(entry.Key, entry.Value)
                    }
                    dh += 1
                }
            } else if frame.Type == H3FrameType.Data {
                for b in frame.Payload {
                    body.append(b)
                }
            }
        }

        var res = Response(statusCode: statusCode, version: HttpVersion.http3)
        res.Headers = headers
        res.Body = body
        return res
    }
}

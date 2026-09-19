package http

/// RFC 9113 HTTP/2 Multiplexing Client & Server Session.

public struct H2StreamState {
    public static let Idle = 0
    public static let Open = 1
    public static let HalfClosedLocal = 2
    public static let HalfClosedRemote = 3
    public static let Closed = 4
}

public struct H2Stream {
    public var StreamId: uint32
    public var State: int
    public var InboundHeaders: [HeaderEntry]
    public var InboundBody: [uint8]
    public var WindowSize: int

    public init(streamId: uint32, initialWindowSize: int = 65535) {
        self.StreamId = streamId
        self.State = H2StreamState.Idle
        self.InboundHeaders = []
        self.InboundBody = []
        self.WindowSize = initialWindowSize
    }
}

public struct H2ClientSession {
    public var NextStreamId: uint32
    public var Encoder: HpackEncoder
    public var Decoder: HpackDecoder
    public var Streams: [H2Stream]
    public var OutboundQueue: [uint8]
    public var PeerWindowSize: int
    public var LocalWindowSize: int
    public var IsClosed: bool

    public init() {
        self.NextStreamId = 1
        self.Encoder = HpackEncoder()
        self.Decoder = HpackDecoder()
        self.Streams = []
        self.OutboundQueue = []
        self.PeerWindowSize = 65535
        self.LocalWindowSize = 65535
        self.IsClosed = false
    }

    /// Initializes connection by generating client connection preface and initial SETTINGS frame.
    public mutating func StartHandshake() -> [uint8] {
        var out = H2ClientPreface()
        let settingsFrame = BuildH2SettingsFrame(settings: [
            H2Setting(identifier: H2SettingId.InitialWindowSize, value: 65535),
            H2Setting(identifier: H2SettingId.MaxFrameSize, value: 16384)
        ])
        for b in settingsFrame { out.append(b) }
        return out
    }

    /// Formulates an HTTP/2 request into HEADERS (and optional DATA) frames.
    public mutating func CreateRequestFrames(req: Request, scheme: string, authority: string) -> [uint8] {
        let streamId = self.NextStreamId
        self.NextStreamId += 2

        var stream = H2Stream(streamId: streamId, initialWindowSize: self.PeerWindowSize)
        stream.State = req.Body.isEmpty ? H2StreamState.HalfClosedLocal : H2StreamState.Open
        self.Streams.append(stream)

        // 1. Prepare pseudo-headers + standard headers
        var headerList: [HeaderEntry] = [
            HeaderEntry(key: ":method", value: req.Method),
            HeaderEntry(key: ":scheme", value: scheme),
            HeaderEntry(key: ":path", value: req.URL.isEmpty ? "/" : req.URL),
            HeaderEntry(key: ":authority", value: authority)
        ]

        var h = 0
        let reqEntries = req.Headers.Materialized()
        while h < reqEntries.count {
            let keyLower = req.Headers.lower(reqEntries[h].Key)
            // HTTP/2 prohibits connection-specific headers
            if keyLower != "connection" && keyLower != "upgrade" && keyLower != "keep-alive" && keyLower != "host" {
                headerList.append(HeaderEntry(key: keyLower, value: reqEntries[h].Value))
            }
            h += 1
        }

        if !req.Body.isEmpty && req.Headers.Get("content-length") == nil {
            headerList.append(HeaderEntry(key: "content-length", value: "\(req.Body.count)"))
        }

        // 2. Encode headers via HPACK
        let headerBlock = self.Encoder.EncodeHeaders(headerList)

        // 3. Emit HEADERS frame
        var flags = H2Flag.EndHeaders
        if req.Body.isEmpty {
            flags = flags | H2Flag.EndStream
        }

        var out = BuildH2Frame(type: H2FrameType.Headers, flags: flags, streamId: streamId, payload: headerBlock)

        // 4. Emit DATA frame if body present
        if !req.Body.isEmpty {
            let dataFrame = BuildH2Frame(
                type: H2FrameType.Data,
                flags: H2Flag.EndStream,
                streamId: streamId,
                payload: req.Body
            )
            for b in dataFrame { out.append(b) }
        }

        return out
    }

    /// Processes an inbound HTTP/2 frame from the server.
    /// If the frame completes a response on a stream, returns the reconstructed Response.
    public mutating func ProcessFrame(_ frame: H2Frame) throws -> Response? {
        let streamId = frame.Header.StreamId

        // Control stream 0
        if streamId == 0 {
            if frame.Header.Type == H2FrameType.Settings {
                if (frame.Header.Flags & H2Flag.Ack) == 0 {
                    // Send SETTINGS ACK
                    let ack = BuildH2SettingsFrame(settings: [], ack: true)
                    for b in ack { self.OutboundQueue.append(b) }
                }
            } else if frame.Header.Type == H2FrameType.Ping {
                if (frame.Header.Flags & H2Flag.Ack) == 0 {
                    let pong = BuildH2Ping(opaqueData: frame.Payload, ack: true)
                    for b in pong { self.OutboundQueue.append(b) }
                }
            } else if frame.Header.Type == H2FrameType.GoAway {
                self.IsClosed = true
            }
            return nil
        }

        // Find target stream
        var streamIdx = -1
        var i = 0
        while i < self.Streams.count {
            if self.Streams[i].StreamId == streamId {
                streamIdx = i
                break
            }
            i += 1
        }

        if streamIdx < 0 {
            return nil
        }

        var isEndStream = (frame.Header.Flags & H2Flag.EndStream) != 0

        if frame.Header.Type == H2FrameType.Headers {
            let decoded = try self.Decoder.DecodeHeaders(data: frame.Payload)
            for d in decoded {
                self.Streams[streamIdx].InboundHeaders.append(d)
            }
        } else if frame.Header.Type == H2FrameType.Data {
            for b in frame.Payload {
                self.Streams[streamIdx].InboundBody.append(b)
            }
            // Auto-acknowledge stream and connection window
            if frame.Payload.count > 0 {
                let streamWu = BuildH2WindowUpdate(streamId: streamId, increment: uint32(frame.Payload.count))
                let connWu = BuildH2WindowUpdate(streamId: 0, increment: uint32(frame.Payload.count))
                for b in streamWu { self.OutboundQueue.append(b) }
                for b in connWu { self.OutboundQueue.append(b) }
            }
        } else if frame.Header.Type == H2FrameType.RstStream {
            self.Streams[streamIdx].State = H2StreamState.Closed
            throw HttpError.streamError
        }

        if isEndStream {
            self.Streams[streamIdx].State = H2StreamState.Closed

            // Construct Response
            var statusCode: int32 = 200
            var headers = Header()
            var h = 0
            while h < self.Streams[streamIdx].InboundHeaders.count {
                let entry = self.Streams[streamIdx].InboundHeaders[h]
                if entry.Key == ":status" {
                    statusCode = int32(parseContentLength(entry.Value))
                } else if !entry.Key.hasPrefix(":") {
                    headers.Add(entry.Key, entry.Value)
                }
                h += 1
            }

            var res = Response(statusCode: statusCode, version: HttpVersion.http2)
            res.Headers = headers
            res.Body = self.Streams[streamIdx].InboundBody
            return res
        }

        return nil
    }

    /// Drains any pending outbound control frames (e.g. SETTINGS ACKs, PINGs, WINDOW_UPDATEs).
    public mutating func DrainOutbound() -> [uint8] {
        let out = self.OutboundQueue
        self.OutboundQueue = []
        return out
    }
}

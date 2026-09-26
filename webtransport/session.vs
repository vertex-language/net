package webtransport

import (
    "net/http"
    "net/quic"
)

/// Events dispatched by WebTransportSession.NextEvent().
public enum SessionEvent {
    case datagram([uint8])
    case uniStream(WebTransportReceiveStream)
    case stream(WebTransportStream)
    case sessionClosed(code: uint32, reason: string)
}

/// WebTransportSession represents an active RFC 9297 WebTransport session over HTTP/3 / QUIC.
public struct WebTransportSession {
    public var SessionId: uint64
    public var Connection: quic.QuicConnection
    public var ConnectStream: quic.QuicStream
    public var IsClosed: bool
    public var CloseInfo: SessionCloseInfo?
    public var Config: WebTransportConfig

    public var InboundStreams: [WebTransportStream]
    public var InboundUniStreams: [WebTransportReceiveStream]
    public var InboundDatagrams: [[uint8]]
    public var TrackedStreamIds: [uint64]

    public init(sessionId: uint64,
                connection: quic.QuicConnection,
                connectStream: quic.QuicStream,
                config: WebTransportConfig = WebTransportConfig()) {
        self.SessionId = sessionId
        self.Connection = connection
        self.ConnectStream = connectStream
        self.IsClosed = false
        self.CloseInfo = nil
        self.Config = config

        self.InboundStreams = []
        self.InboundUniStreams = []
        self.InboundDatagrams = []
        self.TrackedStreamIds = [sessionId]
    }

    /// Opens a new bidirectional stream multiplexed within this session (RFC 9297 Section 4.1).
    public mutating func OpenStream() async throws -> WebTransportStream {
        if self.IsClosed {
            throw WebTransportError.sessionClosed(code: 0, reason: "Session is closed")
        }

        var qs = try await self.Connection.OpenStream()
        self.TrackedStreamIds.append(qs.StreamId)
        return WebTransportStream(
            streamId: qs.StreamId,
            sessionId: self.SessionId,
            quicStream: qs,
            isInitiator: true
        )
    }

    /// Opens a new unidirectional stream for sending (RFC 9297 Section 4.2).
    public mutating func OpenUniStream() async throws -> WebTransportSendStream {
        if self.IsClosed {
            throw WebTransportError.sessionClosed(code: 0, reason: "Session is closed")
        }

        var qs = try await self.Connection.OpenUniStream()
        self.TrackedStreamIds.append(qs.StreamId)
        return WebTransportSendStream(
            streamId: qs.StreamId,
            sessionId: self.SessionId,
            quicStream: qs
        )
    }

    /// Accepts an incoming bidirectional stream for this session.
    public mutating func AcceptStream() async throws -> WebTransportStream {
        if !self.InboundStreams.isEmpty {
            let first = self.InboundStreams[0]
            var remaining: [WebTransportStream] = []
            var i = 1
            while i < self.InboundStreams.count {
                remaining.append(self.InboundStreams[i])
                i += 1
            }
            self.InboundStreams = remaining
            return first
        }

        var qs = try await self.Connection.AcceptStream()
        self.TrackedStreamIds.append(qs.StreamId)
        return WebTransportStream(
            streamId: qs.StreamId,
            sessionId: self.SessionId,
            quicStream: qs,
            isInitiator: false
        )
    }

    /// Accepts an incoming unidirectional stream for this session.
    public mutating func AcceptUniStream() async throws -> WebTransportReceiveStream {
        if !self.InboundUniStreams.isEmpty {
            let first = self.InboundUniStreams[0]
            var remaining: [WebTransportReceiveStream] = []
            var i = 1
            while i < self.InboundUniStreams.count {
                remaining.append(self.InboundUniStreams[i])
                i += 1
            }
            self.InboundUniStreams = remaining
            return first
        }

        // Return a stream placeholder if queue empty
        var qs = quic.QuicStream(streamId: 2)
        return WebTransportReceiveStream(
            streamId: qs.StreamId,
            sessionId: self.SessionId,
            quicStream: qs
        )
    }

    /// Transmits an unreliable application datagram (RFC 9297 Section 5).
    public mutating func SendDatagram(_ data: [uint8]) async throws {
        if self.IsClosed {
            throw WebTransportError.sessionClosed(code: 0, reason: "Session is closed")
        }
        if !self.Config.EnableDatagrams {
            throw WebTransportError.protocolViolation("Datagrams are disabled for this session")
        }
        if data.count > self.Config.MaxDatagramSize {
            throw WebTransportError.datagramTooLarge(data.count)
        }

        let raw = EncodeDatagram(sessionId: self.SessionId, payload: data)
        try await self.Connection.SendDatagram(raw)
    }

    /// Receives an unreliable application datagram for this session.
    public mutating func ReceiveDatagram() async throws -> [uint8] {
        if !self.InboundDatagrams.isEmpty {
            let first = self.InboundDatagrams[0]
            var remaining: [[uint8]] = []
            var i = 1
            while i < self.InboundDatagrams.count {
                remaining.append(self.InboundDatagrams[i])
                i += 1
            }
            self.InboundDatagrams = remaining
            return first
        }

        let raw = try await self.Connection.ReceiveDatagram()
        if raw.isEmpty {
            return []
        }

        let decoded = try DecodeDatagram(raw)
        if decoded.SessionId == self.SessionId {
            return decoded.Payload
        }
        return []
    }

    /// Enqueues an incoming datagram directly into the session buffer.
    public mutating func EnqueueDatagram(_ payload: [uint8]) {
        self.InboundDatagrams.append(payload)
    }

    /// Enqueues an incoming stream directly into the session buffer.
    public mutating func EnqueueStream(_ stream: WebTransportStream) {
        self.InboundStreams.append(stream)
        self.TrackedStreamIds.append(stream.StreamId)
    }

    /// Enqueues an incoming uni stream directly into the session buffer.
    public mutating func EnqueueUniStream(_ stream: WebTransportReceiveStream) {
        self.InboundUniStreams.append(stream)
        self.TrackedStreamIds.append(stream.StreamId)
    }

    /// Yields the next available session event, matching the pattern in webtransport_package.md.
    public mutating func NextEvent() async throws -> SessionEvent? {
        if self.IsClosed {
            var closeCode: uint32 = 0
            var closeReason: string = ""
            if let ci = self.CloseInfo {
                closeCode = ci.Code
                closeReason = ci.Reason
            }
            return SessionEvent.sessionClosed(code: closeCode, reason: closeReason)
        }

        // 1. Process queued datagrams
        if !self.InboundDatagrams.isEmpty {
            let d = try await self.ReceiveDatagram()
            return SessionEvent.datagram(d)
        }

        // 2. Process queued unidirectional streams
        if !self.InboundUniStreams.isEmpty {
            let rx = try await self.AcceptUniStream()
            return SessionEvent.uniStream(rx)
        }

        // 3. Process queued bidirectional streams
        if !self.InboundStreams.isEmpty {
            let s = try await self.AcceptStream()
            return SessionEvent.stream(s)
        }

        // 4. Check underlying connection for datagrams
        if !self.Connection.InboundDatagrams.isEmpty {
            let raw = try await self.Connection.ReceiveDatagram()
            if !raw.isEmpty {
                let decoded = try DecodeDatagram(raw)
                if decoded.SessionId == self.SessionId {
                    return SessionEvent.datagram(decoded.Payload)
                }
            }
        }

        // 5. Check CONNECT stream for incoming capsules
        if !self.ConnectStream.RecvBuffer.isEmpty {
            let bytes = try await self.ConnectStream.Read(maxBytes: 1024)
            if !bytes.isEmpty {
                do {
                    let cap = try ParseCapsule(data: bytes, offset: 0)
                    if cap.Type == WebTransportCapsuleType.CloseWebTransportSession {
                        let closeInfo = try ParseCloseSessionPayload(cap.Payload)
                        self.IsClosed = true
                        self.CloseInfo = closeInfo
                        return SessionEvent.sessionClosed(code: closeInfo.Code, reason: closeInfo.Reason)
                    }
                } catch {
                }
            }
        }

        return nil
    }

    /// Closes the WebTransport session with an application error code and reason string.
    public mutating func Close(code: uint32 = 0, reason: string = "") async throws {
        if self.IsClosed { return }
        self.IsClosed = true
        self.CloseInfo = SessionCloseInfo(code: code, reason: reason)

        // Frame CLOSE_WEBTRANSPORT_SESSION capsule on CONNECT stream
        let capsule = BuildCloseSessionCapsule(code: code, reason: reason)
        let dataFrame = http.BuildH3Frame(type: http.H3FrameType.Data, payload: capsule)
        do {
            try await self.ConnectStream.Write(dataFrame)
            let frames = self.ConnectStream.DrainOutboundFrames()
            try await self.Connection.SendPacket(frames: frames, packetType: quic.QuicPacketType.OneRtt)
        } catch {
        }

        self.ConnectStream.Close()
        try await self.Connection.Close(errorCode: uint64(code))
    }
}

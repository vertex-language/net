package webtransport

import "net/quic"

/// WebTransportStream represents a bidirectional stream multiplexed within a WebTransport session (RFC 9297 Section 4.1).
public struct WebTransportStream {
    public var StreamId: uint64
    public var SessionId: uint64
    public var QuicStream: quic.QuicStream
    public var HeaderSent: bool
    public var HeaderReceived: bool

    public init(streamId: uint64, sessionId: uint64, quicStream: quic.QuicStream, isInitiator: bool = false) {
        self.StreamId = streamId
        self.SessionId = sessionId
        self.QuicStream = quicStream
        self.HeaderSent = !isInitiator // If we are initiator, we must send header on first write
        self.HeaderReceived = isInitiator // Initiator doesn't wait for header from peer
    }

    /// True if the underlying stream is closed.
    public var IsClosed: bool {
        return self.QuicStream.IsClosed
    }

    /// Sends the RFC 9297 Section 4.1 WEBTRANSPORT_STREAM (0x41) header prefix.
    mutating func ensureHeaderSent() async throws {
        if self.HeaderSent { return }
        let typeBytes = quic.EncodeVarint(WebTransportFrameType.Stream)
        let sessBytes = quic.EncodeVarint(self.SessionId)
        var prefix: [uint8] = []
        for b in typeBytes { prefix.append(b) }
        for b in sessBytes { prefix.append(b) }
        try await self.QuicStream.Write(prefix)
        self.HeaderSent = true
    }

    /// Writes raw byte payload to the stream.
    public mutating func Write(_ data: [uint8]) async throws {
        if self.QuicStream.IsClosed {
            throw WebTransportError.streamClosed
        }
        try await self.ensureHeaderSent()
        try await self.QuicStream.Write(data)
    }

    /// Writes a UTF-8 string payload to the stream.
    public mutating func WriteText(_ text: string) async throws {
        var bytes: [uint8] = []
        for b in text.utf8 { bytes.append(b) }
        try await self.Write(bytes)
    }

    /// Writes payload and closes the sending side of the stream (FIN bit).
    public mutating func WriteAndClose(_ data: [uint8]) async throws {
        if self.QuicStream.IsClosed {
            throw WebTransportError.streamClosed
        }
        try await self.ensureHeaderSent()
        try await self.QuicStream.WriteAndClose(data)
    }

    /// Reads up to maxBytes from the stream.
    public mutating func Read(maxBytes: int = 4096) async throws -> [uint8] {
        if !self.HeaderReceived {
            let raw = try await self.QuicStream.Read(maxBytes: maxBytes)
            if raw.isEmpty { return [] }

            var offset = 0
            let typeDec = try quic.DecodeVarint(raw, offset: offset)
            offset += typeDec.BytesRead

            if typeDec.Value != WebTransportFrameType.Stream {
                throw WebTransportError.protocolViolation("Invalid WebTransport bidi stream type: expected 0x41")
            }

            let sessDec = try quic.DecodeVarint(raw, offset: offset)
            offset += sessDec.BytesRead

            self.HeaderReceived = true

            var remainder: [uint8] = []
            var i = offset
            while i < raw.count {
                remainder.append(raw[i])
                i += 1
            }
            return remainder
        }

        return try await self.QuicStream.Read(maxBytes: maxBytes)
    }

    /// Reads incoming bytes and decodes them as a UTF-8 string.
    public mutating func ReadText(maxBytes: int = 4096) async throws -> string {
        let bytes = try await self.Read(maxBytes: maxBytes)
        if bytes.isEmpty { return "" }
        return string(decoding: bytes, as: UTF8.self)
    }

    /// Closes the stream.
    public mutating func Close() async throws {
        self.QuicStream.Close()
    }
}

/// WebTransportSendStream represents an outgoing unidirectional stream (RFC 9297 Section 4.2).
public struct WebTransportSendStream {
    public var StreamId: uint64
    public var SessionId: uint64
    public var QuicStream: quic.QuicStream
    public var HeaderSent: bool

    public init(streamId: uint64, sessionId: uint64, quicStream: quic.QuicStream) {
        self.StreamId = streamId
        self.SessionId = sessionId
        self.QuicStream = quicStream
        self.HeaderSent = false
    }

    public var IsClosed: bool {
        return self.QuicStream.IsClosed
    }

    mutating func ensureHeaderSent() async throws {
        if self.HeaderSent { return }
        let typeBytes = quic.EncodeVarint(WebTransportStreamType.Uni)
        let sessBytes = quic.EncodeVarint(self.SessionId)
        var prefix: [uint8] = []
        for b in typeBytes { prefix.append(b) }
        for b in sessBytes { prefix.append(b) }
        try await self.QuicStream.Write(prefix)
        self.HeaderSent = true
    }

    public mutating func Write(_ data: [uint8]) async throws {
        if self.QuicStream.IsClosed {
            throw WebTransportError.streamClosed
        }
        try await self.ensureHeaderSent()
        try await self.QuicStream.Write(data)
    }

    public mutating func WriteText(_ text: string) async throws {
        var bytes: [uint8] = []
        for b in text.utf8 { bytes.append(b) }
        try await self.Write(bytes)
    }

    public mutating func WriteAndClose(_ data: [uint8]) async throws {
        if self.QuicStream.IsClosed {
            throw WebTransportError.streamClosed
        }
        try await self.ensureHeaderSent()
        try await self.QuicStream.WriteAndClose(data)
    }

    public mutating func Close() async throws {
        self.QuicStream.Close()
    }
}

/// WebTransportReceiveStream represents an incoming unidirectional stream (RFC 9297 Section 4.2).
public struct WebTransportReceiveStream {
    public var StreamId: uint64
    public var SessionId: uint64
    public var QuicStream: quic.QuicStream
    public var HeaderReceived: bool

    public init(streamId: uint64, sessionId: uint64, quicStream: quic.QuicStream) {
        self.StreamId = streamId
        self.SessionId = sessionId
        self.QuicStream = quicStream
        self.HeaderReceived = false
    }

    public var IsClosed: bool {
        return self.QuicStream.IsClosed
    }

    public mutating func Read(maxBytes: int = 4096) async throws -> [uint8] {
        if !self.HeaderReceived {
            let raw = try await self.QuicStream.Read(maxBytes: maxBytes)
            if raw.isEmpty { return [] }

            var offset = 0
            let typeDec = try quic.DecodeVarint(raw, offset: offset)
            offset += typeDec.BytesRead

            if typeDec.Value != WebTransportStreamType.Uni {
                throw WebTransportError.protocolViolation("Invalid WebTransport uni stream type: expected 0x54")
            }

            let sessDec = try quic.DecodeVarint(raw, offset: offset)
            offset += sessDec.BytesRead

            self.HeaderReceived = true

            var remainder: [uint8] = []
            var i = offset
            while i < raw.count {
                remainder.append(raw[i])
                i += 1
            }
            return remainder
        }

        return try await self.QuicStream.Read(maxBytes: maxBytes)
    }

    public mutating func ReadText(maxBytes: int = 4096) async throws -> string {
        let bytes = try await self.Read(maxBytes: maxBytes)
        if bytes.isEmpty { return "" }
        return string(decoding: bytes, as: UTF8.self)
    }

    public mutating func Close() async throws {
        self.QuicStream.Close()
    }
}

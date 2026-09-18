package quic

/// Represents an individual multiplexed QUIC stream (RFC 9000 Section 2).
public struct QuicStream {
    public var StreamId: uint64
    public var IsClientInitiated: bool
    public var IsBidirectional: bool

    public var SendOffset: uint64
    public var RecvOffset: uint64
    public var MaxSendData: uint64
    public var MaxRecvData: uint64

    public var SendFin: bool
    public var RecvFin: bool
    public var IsClosed: bool

    public var RecvBuffer: [uint8]
    public var OutboundFrames: [StreamFrameData]

    public init(streamId: uint64,
                initialMaxSendData: uint64 = 262144,
                initialMaxRecvData: uint64 = 262144) {
        self.StreamId = streamId
        self.IsClientInitiated = (streamId & 0x01) == 0
        self.IsBidirectional = (streamId & 0x02) == 0

        self.SendOffset = 0
        self.RecvOffset = 0
        self.MaxSendData = initialMaxSendData
        self.MaxRecvData = initialMaxRecvData

        self.SendFin = false
        self.RecvFin = false
        self.IsClosed = false

        self.RecvBuffer = []
        self.OutboundFrames = []
    }

    /// Appends data to be sent on this stream.
    public mutating func Write(_ data: [uint8]) async throws {
        if self.IsClosed || self.SendFin {
            throw QuicError.transport(code: TransportErrorCode.StreamStateError, msg: "Cannot write to closed stream")
        }

        let frame = StreamFrameData(streamId: self.StreamId, offset: self.SendOffset, fin: false, data: data)
        self.OutboundFrames.append(frame)
        self.SendOffset += uint64(data.count)
    }

    /// Writes data and terminates the sending side of this stream (FIN bit).
    public mutating func WriteAndClose(_ data: [uint8]) async throws {
        if self.IsClosed || self.SendFin {
            throw QuicError.transport(code: TransportErrorCode.StreamStateError, msg: "Cannot write to closed stream")
        }

        let frame = StreamFrameData(streamId: self.StreamId, offset: self.SendOffset, fin: true, data: data)
        self.OutboundFrames.append(frame)
        self.SendOffset += uint64(data.count)
        self.SendFin = true
    }

    /// Reads up to maxBytes from the stream buffer.
    public mutating func Read(maxBytes: int = 4096) async throws -> [uint8] {
        if self.RecvBuffer.isEmpty {
            return []
        }

        let count = (self.RecvBuffer.count < maxBytes) ? self.RecvBuffer.count : maxBytes
        var result: [uint8] = []
        var i = 0
        while i < count {
            result.append(self.RecvBuffer[i])
            i += 1
        }

        var remaining: [uint8] = []
        while i < self.RecvBuffer.count {
            remaining.append(self.RecvBuffer[i])
            i += 1
        }
        self.RecvBuffer = remaining
        return result
    }

    /// Processes inbound stream data from a received STREAM frame.
    public mutating func ReceiveStreamData(offset: uint64, fin: bool, data: [uint8]) {
        for b in data {
            self.RecvBuffer.append(b)
        }
        self.RecvOffset += uint64(data.count)
        if fin {
            self.RecvFin = true
        }
    }

    /// Pops and converts pending outbound stream frames into QuicFrame values.
    public mutating func DrainOutboundFrames() -> [QuicFrame] {
        var frames: [QuicFrame] = []
        var i = 0
        while i < self.OutboundFrames.count {
            frames.append(.stream(self.OutboundFrames[i]))
            i += 1
        }
        self.OutboundFrames = []
        return frames
    }

    /// Closes this stream.
    public mutating func Close() {
        self.IsClosed = true
        self.SendFin = true
    }
}

package quic

/// ACK range gap and count pair.
public struct AckRange {
    public var Gap: uint64
    public var RangeLength: uint64

    public init(gap: uint64, rangeLength: uint64) {
        self.Gap = gap
        self.RangeLength = rangeLength
    }
}

/// Payload for ACK frame (RFC 9000 Section 19.3).
public struct AckFrameData {
    public var LargestAcked: uint64
    public var AckDelay: uint64
    public var FirstRange: uint64
    public var Ranges: [AckRange]

    public init(largestAcked: uint64, ackDelay: uint64, firstRange: uint64, ranges: [AckRange] = []) {
        self.LargestAcked = largestAcked
        self.AckDelay = ackDelay
        self.FirstRange = firstRange
        self.Ranges = ranges
    }
}

/// Payload for STREAM frame (RFC 9000 Section 19.8).
public struct StreamFrameData {
    public var StreamId: uint64
    public var Offset: uint64
    public var Fin: bool
    public var Data: [uint8]

    public init(streamId: uint64, offset: uint64 = 0, fin: bool = false, data: [uint8] = []) {
        self.StreamId = streamId
        self.Offset = offset
        self.Fin = fin
        self.Data = data
    }
}

/// Payload for RESET_STREAM frame (RFC 9000 Section 19.4).
public struct ResetStreamData {
    public var StreamId: uint64
    public var ErrorCode: uint64
    public var FinalSize: uint64

    public init(streamId: uint64, errorCode: uint64, finalSize: uint64) {
        self.StreamId = streamId
        self.ErrorCode = errorCode
        self.FinalSize = finalSize
    }
}

/// Payload for NEW_CONNECTION_ID frame (RFC 9000 Section 19.15).
public struct NewConnectionIdData {
    public var Sequence: uint64
    public var RetirePriorTo: uint64
    public var Cid: [uint8]
    public var StatelessResetToken: [uint8]

    public init(sequence: uint64, retirePriorTo: uint64, cid: [uint8], token: [uint8]) {
        self.Sequence = sequence
        self.RetirePriorTo = retirePriorTo
        self.Cid = cid
        self.StatelessResetToken = token
    }
}

/// Payload for CONNECTION_CLOSE frame (RFC 9000 Section 19.19).
public struct ConnectionCloseData {
    public var IsApp: bool
    public var ErrorCode: uint64
    public var FrameType: uint64

    public init(isApp: bool, errorCode: uint64, frameType: uint64 = 0) {
        self.IsApp = isApp
        self.ErrorCode = errorCode
        self.FrameType = frameType
    }
}

/// QUIC Frames per RFC 9000 and RFC 9221.
public enum QuicFrame {
    case padding
    case ping
    case ack(AckFrameData)
    case resetStream(ResetStreamData)
    case stopSending(streamId: uint64, errorCode: uint64)
    case crypto(offset: uint64, data: [uint8])
    case newToken([uint8])
    case stream(StreamFrameData)
    case maxData(uint64)
    case maxStreamData(streamId: uint64, maxData: uint64)
    case maxStreams(isBidi: bool, maxStreams: uint64)
    case dataBlocked(uint64)
    case streamDataBlocked(streamId: uint64, maxData: uint64)
    case streamsBlocked(isBidi: bool, maxStreams: uint64)
    case newConnectionId(NewConnectionIdData)
    case retireConnectionId(sequence: uint64)
    case pathChallenge([uint8])
    case pathResponse([uint8])
    case connectionClose(ConnectionCloseData)
    case handshakeDone
    case datagram([uint8])
}

/// Serializes a single QUIC frame into wire format bytes.
public func EncodeFrame(_ frame: QuicFrame) -> [uint8] {
    var buf: [uint8] = []

    switch frame {
    case .padding:
        buf.append(0x00)

    case .ping:
        buf.append(0x01)

    case .ack(let ackData):
        buf.append(0x02) // ACK without ECN
        for b in EncodeVarint(ackData.LargestAcked) { buf.append(b) }
        for b in EncodeVarint(ackData.AckDelay) { buf.append(b) }
        for b in EncodeVarint(uint64(ackData.Ranges.count)) { buf.append(b) }
        for b in EncodeVarint(ackData.FirstRange) { buf.append(b) }
        var i = 0
        while i < ackData.Ranges.count {
            let r = ackData.Ranges[i]
            for b in EncodeVarint(r.Gap) { buf.append(b) }
            for b in EncodeVarint(r.RangeLength) { buf.append(b) }
            i += 1
        }

    case .resetStream(let r):
        buf.append(0x04)
        for b in EncodeVarint(r.StreamId) { buf.append(b) }
        for b in EncodeVarint(r.ErrorCode) { buf.append(b) }
        for b in EncodeVarint(r.FinalSize) { buf.append(b) }

    case .stopSending(let streamId, let errorCode):
        buf.append(0x05)
        for b in EncodeVarint(streamId) { buf.append(b) }
        for b in EncodeVarint(errorCode) { buf.append(b) }

    case .crypto(let offset, let data):
        buf.append(0x06)
        for b in EncodeVarint(offset) { buf.append(b) }
        for b in EncodeVarint(uint64(data.count)) { buf.append(b) }
        for b in data { buf.append(b) }

    case .newToken(let token):
        buf.append(0x07)
        for b in EncodeVarint(uint64(token.count)) { buf.append(b) }
        for b in token { buf.append(b) }

    case .stream(let s):
        var typeByte: uint8 = 0x08
        if s.Offset > 0 { typeByte |= 0x04 } // OFF bit
        typeByte |= 0x02                      // LEN bit always present for robust framing
        if s.Fin { typeByte |= 0x01 }        // FIN bit
        buf.append(typeByte)
        for b in EncodeVarint(s.StreamId) { buf.append(b) }
        if s.Offset > 0 {
            for b in EncodeVarint(s.Offset) { buf.append(b) }
        }
        for b in EncodeVarint(uint64(s.Data.count)) { buf.append(b) }
        for b in s.Data { buf.append(b) }

    case .maxData(let maxData):
        buf.append(0x10)
        for b in EncodeVarint(maxData) { buf.append(b) }

    case .maxStreamData(let streamId, let maxData):
        buf.append(0x11)
        for b in EncodeVarint(streamId) { buf.append(b) }
        for b in EncodeVarint(maxData) { buf.append(b) }

    case .maxStreams(let isBidi, let maxStreams):
        buf.append(isBidi ? 0x12 : 0x13)
        for b in EncodeVarint(maxStreams) { buf.append(b) }

    case .dataBlocked(let maxData):
        buf.append(0x14)
        for b in EncodeVarint(maxData) { buf.append(b) }

    case .streamDataBlocked(let streamId, let maxData):
        buf.append(0x15)
        for b in EncodeVarint(streamId) { buf.append(b) }
        for b in EncodeVarint(maxData) { buf.append(b) }

    case .streamsBlocked(let isBidi, let maxStreams):
        buf.append(isBidi ? 0x16 : 0x17)
        for b in EncodeVarint(maxStreams) { buf.append(b) }

    case .newConnectionId(let nid):
        buf.append(0x18)
        for b in EncodeVarint(nid.Sequence) { buf.append(b) }
        for b in EncodeVarint(nid.RetirePriorTo) { buf.append(b) }
        buf.append(uint8(nid.Cid.count))
        for b in nid.Cid { buf.append(b) }
        var ti = 0
        while ti < 16 && ti < nid.StatelessResetToken.count {
            buf.append(nid.StatelessResetToken[ti])
            ti += 1
        }
        while ti < 16 {
            buf.append(0)
            ti += 1
        }

    case .retireConnectionId(let seq):
        buf.append(0x19)
        for b in EncodeVarint(seq) { buf.append(b) }

    case .pathChallenge(let data):
        buf.append(0x1a)
        var i = 0
        while i < 8 && i < data.count {
            buf.append(data[i])
            i += 1
        }
        while i < 8 {
            buf.append(0)
            i += 1
        }

    case .pathResponse(let data):
        buf.append(0x1b)
        var i = 0
        while i < 8 && i < data.count {
            buf.append(data[i])
            i += 1
        }
        while i < 8 {
            buf.append(0)
            i += 1
        }

    case .connectionClose(let cc):
        buf.append(cc.IsApp ? 0x1d : 0x1c)
        for b in EncodeVarint(cc.ErrorCode) { buf.append(b) }
        if !cc.IsApp {
            for b in EncodeVarint(cc.FrameType) { buf.append(b) }
        }
        buf.append(0x00) // 0-length reason phrase

    case .handshakeDone:
        buf.append(0x1e)

    case .datagram(let data):
        buf.append(0x31) // DATAGRAM with Length bit set
        for b in EncodeVarint(uint64(data.count)) { buf.append(b) }
        for b in data { buf.append(b) }
    }

    return buf
}

/// Serializes an array of QUIC frames into a single payload buffer.
public func EncodeFrames(_ frames: [QuicFrame]) -> [uint8] {
    var buf: [uint8] = []
    var i = 0
    while i < frames.count {
        let fBytes = EncodeFrame(frames[i])
        for b in fBytes {
            buf.append(b)
        }
        i += 1
    }
    return buf
}

/// Parses an array of QUIC frames from a decrypted payload buffer.
public func ParseFrames(_ data: [uint8]) throws -> [QuicFrame] {
    var frames: [QuicFrame] = []
    var offset = 0

    while offset < data.count {
        let typeDec = try DecodeVarint(data, offset: offset)
        let frameType = typeDec.Value
        offset += typeDec.BytesRead

        if frameType == 0x00 {
            frames.append(.padding)
        } else if frameType == 0x01 {
            frames.append(.ping)
        } else if frameType == 0x02 || frameType == 0x03 {
            let largestDec = try DecodeVarint(data, offset: offset)
            offset += largestDec.BytesRead
            let delayDec = try DecodeVarint(data, offset: offset)
            offset += delayDec.BytesRead
            let countDec = try DecodeVarint(data, offset: offset)
            offset += countDec.BytesRead
            let firstRangeDec = try DecodeVarint(data, offset: offset)
            offset += firstRangeDec.BytesRead

            var ranges: [AckRange] = []
            var r = 0
            while r < Int(countDec.Value) {
                let gapDec = try DecodeVarint(data, offset: offset)
                offset += gapDec.BytesRead
                let lenDec = try DecodeVarint(data, offset: offset)
                offset += lenDec.BytesRead
                ranges.append(AckRange(gap: gapDec.Value, rangeLength: lenDec.Value))
                r += 1
            }

            if frameType == 0x03 {
                // Skip ECN counts
                let e1 = try DecodeVarint(data, offset: offset); offset += e1.BytesRead
                let e2 = try DecodeVarint(data, offset: offset); offset += e2.BytesRead
                let e3 = try DecodeVarint(data, offset: offset); offset += e3.BytesRead
            }

            let ack = AckFrameData(largestAcked: largestDec.Value, ackDelay: delayDec.Value, firstRange: firstRangeDec.Value, ranges: ranges)
            frames.append(.ack(ack))
        } else if frameType == 0x04 {
            let stDec = try DecodeVarint(data, offset: offset); offset += stDec.BytesRead
            let errDec = try DecodeVarint(data, offset: offset); offset += errDec.BytesRead
            let sizeDec = try DecodeVarint(data, offset: offset); offset += sizeDec.BytesRead
            frames.append(.resetStream(ResetStreamData(streamId: stDec.Value, errorCode: errDec.Value, finalSize: sizeDec.Value)))
        } else if frameType == 0x05 {
            let stDec = try DecodeVarint(data, offset: offset); offset += stDec.BytesRead
            let errDec = try DecodeVarint(data, offset: offset); offset += errDec.BytesRead
            frames.append(.stopSending(streamId: stDec.Value, errorCode: errDec.Value))
        } else if frameType == 0x06 {
            let offDec = try DecodeVarint(data, offset: offset); offset += offDec.BytesRead
            let lenDec = try DecodeVarint(data, offset: offset); offset += lenDec.BytesRead
            let len = Int(lenDec.Value)
            if offset + len > data.count {
                throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated CRYPTO frame")
            }
            var cBytes: [uint8] = []
            var j = 0
            while j < len { cBytes.append(data[offset + j]); j += 1 }
            offset += len
            frames.append(.crypto(offset: offDec.Value, data: cBytes))
        } else if frameType == 0x07 {
            let lenDec = try DecodeVarint(data, offset: offset); offset += lenDec.BytesRead
            let len = Int(lenDec.Value)
            if offset + len > data.count {
                throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated NEW_TOKEN frame")
            }
            var tBytes: [uint8] = []
            var j = 0
            while j < len { tBytes.append(data[offset + j]); j += 1 }
            offset += len
            frames.append(.newToken(tBytes))
        } else if frameType >= 0x08 && frameType <= 0x0f {
            let hasOff = (frameType & 0x04) != 0
            let hasLen = (frameType & 0x02) != 0
            let isFin = (frameType & 0x01) != 0

            let stDec = try DecodeVarint(data, offset: offset); offset += stDec.BytesRead
            var streamOffset: uint64 = 0
            if hasOff {
                let offDec = try DecodeVarint(data, offset: offset); offset += offDec.BytesRead
                streamOffset = offDec.Value
            }

            var sBytes: [uint8] = []
            if hasLen {
                let lenDec = try DecodeVarint(data, offset: offset); offset += lenDec.BytesRead
                let len = Int(lenDec.Value)
                if offset + len > data.count {
                    throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated STREAM frame")
                }
                var j = 0
                while j < len { sBytes.append(data[offset + j]); j += 1 }
                offset += len
            } else {
                // Extends to end of packet
                while offset < data.count {
                    sBytes.append(data[offset])
                    offset += 1
                }
            }
            frames.append(.stream(StreamFrameData(streamId: stDec.Value, offset: streamOffset, fin: isFin, data: sBytes)))
        } else if frameType == 0x10 {
            let dDec = try DecodeVarint(data, offset: offset); offset += dDec.BytesRead
            frames.append(.maxData(dDec.Value))
        } else if frameType == 0x11 {
            let stDec = try DecodeVarint(data, offset: offset); offset += stDec.BytesRead
            let dDec = try DecodeVarint(data, offset: offset); offset += dDec.BytesRead
            frames.append(.maxStreamData(streamId: stDec.Value, maxData: dDec.Value))
        } else if frameType == 0x12 || frameType == 0x13 {
            let sDec = try DecodeVarint(data, offset: offset); offset += sDec.BytesRead
            frames.append(.maxStreams(isBidi: frameType == 0x12, maxStreams: sDec.Value))
        } else if frameType == 0x14 {
            let dDec = try DecodeVarint(data, offset: offset); offset += dDec.BytesRead
            frames.append(.dataBlocked(dDec.Value))
        } else if frameType == 0x15 {
            let stDec = try DecodeVarint(data, offset: offset); offset += stDec.BytesRead
            let dDec = try DecodeVarint(data, offset: offset); offset += dDec.BytesRead
            frames.append(.streamDataBlocked(streamId: stDec.Value, maxData: dDec.Value))
        } else if frameType == 0x16 || frameType == 0x17 {
            let sDec = try DecodeVarint(data, offset: offset); offset += sDec.BytesRead
            frames.append(.streamsBlocked(isBidi: frameType == 0x16, maxStreams: sDec.Value))
        } else if frameType == 0x18 {
            let seqDec = try DecodeVarint(data, offset: offset); offset += seqDec.BytesRead
            let retDec = try DecodeVarint(data, offset: offset); offset += retDec.BytesRead
            if offset >= data.count { throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated NEW_CONNECTION_ID") }
            let cidLen = Int(data[offset]); offset += 1
            if offset + cidLen + 16 > data.count { throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated NEW_CONNECTION_ID payload") }
            var cid: [uint8] = []
            var j = 0
            while j < cidLen { cid.append(data[offset + j]); j += 1 }
            offset += cidLen
            var token: [uint8] = []
            j = 0
            while j < 16 { token.append(data[offset + j]); j += 1 }
            offset += 16
            frames.append(.newConnectionId(NewConnectionIdData(sequence: seqDec.Value, retirePriorTo: retDec.Value, cid: cid, token: token)))
        } else if frameType == 0x19 {
            let seqDec = try DecodeVarint(data, offset: offset); offset += seqDec.BytesRead
            frames.append(.retireConnectionId(sequence: seqDec.Value))
        } else if frameType == 0x1a {
            if offset + 8 > data.count { throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated PATH_CHALLENGE") }
            var p: [uint8] = []
            var j = 0
            while j < 8 { p.append(data[offset + j]); j += 1 }
            offset += 8
            frames.append(.pathChallenge(p))
        } else if frameType == 0x1b {
            if offset + 8 > data.count { throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated PATH_RESPONSE") }
            var p: [uint8] = []
            var j = 0
            while j < 8 { p.append(data[offset + j]); j += 1 }
            offset += 8
            frames.append(.pathResponse(p))
        } else if frameType == 0x1c || frameType == 0x1d {
            let isApp = (frameType == 0x1d)
            let errDec = try DecodeVarint(data, offset: offset); offset += errDec.BytesRead
            var fType: uint64 = 0
            if !isApp {
                let ftDec = try DecodeVarint(data, offset: offset); offset += ftDec.BytesRead
                fType = ftDec.Value
            }
            let lenDec = try DecodeVarint(data, offset: offset); offset += lenDec.BytesRead
            let len = Int(lenDec.Value)
            if offset + len > data.count { throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated CONNECTION_CLOSE") }
            offset += len
            frames.append(.connectionClose(ConnectionCloseData(isApp: isApp, errorCode: errDec.Value, frameType: fType)))
        } else if frameType == 0x1e {
            frames.append(.handshakeDone)
        } else if frameType == 0x30 || frameType == 0x31 {
            var dBytes: [uint8] = []
            if frameType == 0x31 {
                let lenDec = try DecodeVarint(data, offset: offset); offset += lenDec.BytesRead
                let len = Int(lenDec.Value)
                if offset + len > data.count { throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated DATAGRAM frame") }
                var j = 0
                while j < len { dBytes.append(data[offset + j]); j += 1 }
                offset += len
            } else {
                while offset < data.count {
                    dBytes.append(data[offset])
                    offset += 1
                }
            }
            frames.append(.datagram(dBytes))
        } else {
            // Unknown or unsupported frame type
            throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Unknown frame type: \(frameType)")
        }
    }

    return frames
}

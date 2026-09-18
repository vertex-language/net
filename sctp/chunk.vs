package sctp

/// RawChunk represents an SCTP chunk with a 4-byte header and raw value bytes.
public struct RawChunk {
    public var Type: uint8
    public var Flags: uint8
    public var Length: int
    public var Value: [uint8]

    public init(type: uint8, flags: uint8, value: [uint8]) {
        self.Type = type
        self.Flags = flags
        self.Length = 4 + value.count
        self.Value = value
    }

    public init(type: uint8, flags: uint8, length: int, value: [uint8]) {
        self.Type = type
        self.Flags = flags
        self.Length = length
        self.Value = value
    }

    /// Serialize writes the chunk header, value, and pad bytes to align to a 4-byte boundary.
    public func Serialize() -> [uint8] {
        let pad = (4 - (self.Length % 4)) % 4
        var out = [uint8](repeating: 0, count: self.Length + pad)

        out[0] = self.Type
        out[1] = self.Flags
        out[2] = uint8(truncatingIfNeeded: (self.Length >> 8) & 0xff)
        out[3] = uint8(truncatingIfNeeded: self.Length & 0xff)

        var i = 0
        while i < self.Value.count {
            out[4 + i] = self.Value[i]
            i += 1
        }

        return out
    }
}

/// InitChunk represents an INIT (1) or INIT ACK (2) chunk.
public struct InitChunk {
    public var InitiateTag: uint32
    public var a_rwnd: uint32
    public var OutboundStreams: uint16
    public var InboundStreams: uint16
    public var InitialTSN: uint32
    public var Cookie: [uint8]

    public init(initiateTag: uint32,
                a_rwnd: uint32,
                outboundStreams: uint16,
                inboundStreams: uint16,
                initialTSN: uint32,
                cookie: [uint8] = []) {
        self.InitiateTag = initiateTag
        self.a_rwnd = a_rwnd
        self.OutboundStreams = outboundStreams
        self.InboundStreams = inboundStreams
        self.InitialTSN = initialTSN
        self.Cookie = cookie
    }

    public func ToRawChunk(isAck: bool = false) -> RawChunk {
        var val = [uint8](repeating: 0, count: 16)
        // Initiate Tag
        val[0] = uint8(truncatingIfNeeded: (self.InitiateTag >> 24) & 0xff)
        val[1] = uint8(truncatingIfNeeded: (self.InitiateTag >> 16) & 0xff)
        val[2] = uint8(truncatingIfNeeded: (self.InitiateTag >> 8) & 0xff)
        val[3] = uint8(truncatingIfNeeded: self.InitiateTag & 0xff)

        // a_rwnd
        val[4] = uint8(truncatingIfNeeded: (self.a_rwnd >> 24) & 0xff)
        val[5] = uint8(truncatingIfNeeded: (self.a_rwnd >> 16) & 0xff)
        val[6] = uint8(truncatingIfNeeded: (self.a_rwnd >> 8) & 0xff)
        val[7] = uint8(truncatingIfNeeded: self.a_rwnd & 0xff)

        // Outbound Streams
        val[8] = uint8(truncatingIfNeeded: (self.OutboundStreams >> 8) & 0xff)
        val[9] = uint8(truncatingIfNeeded: self.OutboundStreams & 0xff)

        // Inbound Streams
        val[10] = uint8(truncatingIfNeeded: (self.InboundStreams >> 8) & 0xff)
        val[11] = uint8(truncatingIfNeeded: self.InboundStreams & 0xff)

        // Initial TSN
        val[12] = uint8(truncatingIfNeeded: (self.InitialTSN >> 24) & 0xff)
        val[13] = uint8(truncatingIfNeeded: (self.InitialTSN >> 16) & 0xff)
        val[14] = uint8(truncatingIfNeeded: (self.InitialTSN >> 8) & 0xff)
        val[15] = uint8(truncatingIfNeeded: self.InitialTSN & 0xff)

        // Optional State Cookie parameter for INIT ACK (Type = 7)
        if !self.Cookie.isEmpty {
            val.append(0x00)
            val.append(0x07) // Parameter Type = 7 (State Cookie)
            let paramLen = 4 + self.Cookie.count
            val.append(uint8(truncatingIfNeeded: (paramLen >> 8) & 0xff))
            val.append(uint8(truncatingIfNeeded: paramLen & 0xff))
            var c = 0
            while c < self.Cookie.count {
                val.append(self.Cookie[c])
                c += 1
            }
            // Pad parameter to 4 bytes
            let pad = (4 - (paramLen % 4)) % 4
            var p = 0
            while p < pad {
                val.append(0)
                p += 1
            }
        }

        let chunkType = isAck ? ChunkType.InitAck : ChunkType.Init
        return RawChunk(type: chunkType, flags: 0, value: val)
    }

    public static func Parse(_ raw: RawChunk) -> InitChunk {
        var dummy = InitChunk(initiateTag: 0, a_rwnd: 0, outboundStreams: 0, inboundStreams: 0, initialTSN: 0)
        if raw.Value.count < 16 {
            return dummy
        }

        let tag = (uint32(raw.Value[0]) << 24) | (uint32(raw.Value[1]) << 16) | (uint32(raw.Value[2]) << 8) | uint32(raw.Value[3])
        let arwnd = (uint32(raw.Value[4]) << 24) | (uint32(raw.Value[5]) << 16) | (uint32(raw.Value[6]) << 8) | uint32(raw.Value[7])
        let os = (uint16(raw.Value[8]) << 8) | uint16(raw.Value[9])
        let mis = (uint16(raw.Value[10]) << 8) | uint16(raw.Value[11])
        let tsn = (uint32(raw.Value[12]) << 24) | (uint32(raw.Value[13]) << 16) | (uint32(raw.Value[14]) << 8) | uint32(raw.Value[15])

        var cookie: [uint8] = []
        var pos = 16
        while pos + 4 <= raw.Value.count {
            let pType = (uint16(raw.Value[pos]) << 8) | uint16(raw.Value[pos + 1])
            let pLen = (int(raw.Value[pos + 2]) << 8) | int(raw.Value[pos + 3])
            let valLen = pLen - 4
            if pType == 7 && valLen > 0 && pos + 4 + valLen <= raw.Value.count {
                var c = 0
                while c < valLen {
                    cookie.append(raw.Value[pos + 4 + c])
                    c += 1
                }
            }
            let pad = (4 - (pLen % 4)) % 4
            pos += pLen + pad
        }

        return InitChunk(initiateTag: tag, a_rwnd: arwnd, outboundStreams: os, inboundStreams: mis, initialTSN: tsn, cookie: cookie)
    }
}

/// DataChunk represents an SCTP DATA (0) chunk.
public struct DataChunk {
    public var Flags: uint8
    public var TSN: uint32
    public var StreamId: uint16
    public var StreamSeq: uint16
    public var PPID: uint32
    public var UserData: [uint8]

    public init(flags: uint8,
                tsn: uint32,
                streamId: uint16,
                streamSeq: uint16,
                ppid: uint32,
                userData: [uint8]) {
        self.Flags = flags
        self.TSN = tsn
        self.StreamId = streamId
        self.StreamSeq = streamSeq
        self.PPID = ppid
        self.UserData = userData
    }

    public func ToRawChunk() -> RawChunk {
        var val = [uint8](repeating: 0, count: 12 + self.UserData.count)

        // TSN (4 bytes)
        val[0] = uint8(truncatingIfNeeded: (self.TSN >> 24) & 0xff)
        val[1] = uint8(truncatingIfNeeded: (self.TSN >> 16) & 0xff)
        val[2] = uint8(truncatingIfNeeded: (self.TSN >> 8) & 0xff)
        val[3] = uint8(truncatingIfNeeded: self.TSN & 0xff)

        // Stream ID (2 bytes)
        val[4] = uint8(truncatingIfNeeded: (self.StreamId >> 8) & 0xff)
        val[5] = uint8(truncatingIfNeeded: self.StreamId & 0xff)

        // Stream Seq (2 bytes)
        val[6] = uint8(truncatingIfNeeded: (self.StreamSeq >> 8) & 0xff)
        val[7] = uint8(truncatingIfNeeded: self.StreamSeq & 0xff)

        // PPID (4 bytes)
        val[8] = uint8(truncatingIfNeeded: (self.PPID >> 24) & 0xff)
        val[9] = uint8(truncatingIfNeeded: (self.PPID >> 16) & 0xff)
        val[10] = uint8(truncatingIfNeeded: (self.PPID >> 8) & 0xff)
        val[11] = uint8(truncatingIfNeeded: self.PPID & 0xff)

        var i = 0
        while i < self.UserData.count {
            val[12 + i] = self.UserData[i]
            i += 1
        }

        return RawChunk(type: ChunkType.Data, flags: self.Flags, value: val)
    }

    public static func Parse(_ raw: RawChunk) -> DataChunk {
        var dummy = DataChunk(flags: 0, tsn: 0, streamId: 0, streamSeq: 0, ppid: 0, userData: [])
        if raw.Value.count < 12 {
            return dummy
        }

        let tsn = (uint32(raw.Value[0]) << 24) | (uint32(raw.Value[1]) << 16) | (uint32(raw.Value[2]) << 8) | uint32(raw.Value[3])
        let sId = (uint16(raw.Value[4]) << 8) | uint16(raw.Value[5])
        let sSeq = (uint16(raw.Value[6]) << 8) | uint16(raw.Value[7])
        let ppid = (uint32(raw.Value[8]) << 24) | (uint32(raw.Value[9]) << 16) | (uint32(raw.Value[10]) << 8) | uint32(raw.Value[11])

        let userLen = raw.Value.count - 12
        var userBytes = [uint8](repeating: 0, count: userLen)
        var i = 0
        while i < userLen {
            userBytes[i] = raw.Value[12 + i]
            i += 1
        }

        return DataChunk(flags: raw.Flags, tsn: tsn, streamId: sId, streamSeq: sSeq, ppid: ppid, userData: userBytes)
    }
}

/// SackChunk represents an SCTP Selective Acknowledgement (3) chunk.
public struct SackChunk {
    public var CumulativeTSNAck: uint32
    public var a_rwnd: uint32
    public var GapAckBlocks: [uint32]
    public var DuplicateTSNs: [uint32]

    public init(cumulativeTSNAck: uint32,
                a_rwnd: uint32,
                gapAckBlocks: [uint32] = [],
                duplicateTSNs: [uint32] = []) {
        self.CumulativeTSNAck = cumulativeTSNAck
        self.a_rwnd = a_rwnd
        self.GapAckBlocks = gapAckBlocks
        self.DuplicateTSNs = duplicateTSNs
    }

    public func ToRawChunk() -> RawChunk {
        let numGaps = self.GapAckBlocks.count / 2
        let numDups = self.DuplicateTSNs.count
        let totalLen = 12 + (numGaps * 4) + (numDups * 4)
        var val = [uint8](repeating: 0, count: totalLen)

        // Cumulative TSN Ack
        val[0] = uint8(truncatingIfNeeded: (self.CumulativeTSNAck >> 24) & 0xff)
        val[1] = uint8(truncatingIfNeeded: (self.CumulativeTSNAck >> 16) & 0xff)
        val[2] = uint8(truncatingIfNeeded: (self.CumulativeTSNAck >> 8) & 0xff)
        val[3] = uint8(truncatingIfNeeded: self.CumulativeTSNAck & 0xff)

        // a_rwnd
        val[4] = uint8(truncatingIfNeeded: (self.a_rwnd >> 24) & 0xff)
        val[5] = uint8(truncatingIfNeeded: (self.a_rwnd >> 16) & 0xff)
        val[6] = uint8(truncatingIfNeeded: (self.a_rwnd >> 8) & 0xff)
        val[7] = uint8(truncatingIfNeeded: self.a_rwnd & 0xff)

        // Number of Gap Ack Blocks
        val[8] = uint8(truncatingIfNeeded: (numGaps >> 8) & 0xff)
        val[9] = uint8(truncatingIfNeeded: numGaps & 0xff)

        // Number of Duplicate TSNs
        val[10] = uint8(truncatingIfNeeded: (numDups >> 8) & 0xff)
        val[11] = uint8(truncatingIfNeeded: numDups & 0xff)

        var pos = 12
        var g = 0
        while g < numGaps {
            let start = self.GapAckBlocks[g * 2]
            let end = self.GapAckBlocks[g * 2 + 1]
            val[pos] = uint8(truncatingIfNeeded: (start >> 8) & 0xff)
            val[pos + 1] = uint8(truncatingIfNeeded: start & 0xff)
            val[pos + 2] = uint8(truncatingIfNeeded: (end >> 8) & 0xff)
            val[pos + 3] = uint8(truncatingIfNeeded: end & 0xff)
            pos += 4
            g += 1
        }

        var d = 0
        while d < numDups {
            let dup = self.DuplicateTSNs[d]
            val[pos] = uint8(truncatingIfNeeded: (dup >> 24) & 0xff)
            val[pos + 1] = uint8(truncatingIfNeeded: (dup >> 16) & 0xff)
            val[pos + 2] = uint8(truncatingIfNeeded: (dup >> 8) & 0xff)
            val[pos + 3] = uint8(truncatingIfNeeded: dup & 0xff)
            pos += 4
            d += 1
        }

        return RawChunk(type: ChunkType.Sack, flags: 0, value: val)
    }

    public static func Parse(_ raw: RawChunk) -> SackChunk {
        var dummy = SackChunk(cumulativeTSNAck: 0, a_rwnd: 0)
        if raw.Value.count < 12 {
            return dummy
        }

        let cumAck = (uint32(raw.Value[0]) << 24) | (uint32(raw.Value[1]) << 16) | (uint32(raw.Value[2]) << 8) | uint32(raw.Value[3])
        let arwnd = (uint32(raw.Value[4]) << 24) | (uint32(raw.Value[5]) << 16) | (uint32(raw.Value[6]) << 8) | uint32(raw.Value[7])
        let numGaps = (int(raw.Value[8]) << 8) | int(raw.Value[9])
        let numDups = (int(raw.Value[10]) << 8) | int(raw.Value[11])

        var gaps: [uint32] = []
        var pos = 12
        var g = 0
        while g < numGaps && pos + 4 <= raw.Value.count {
            let start = (uint32(raw.Value[pos]) << 8) | uint32(raw.Value[pos + 1])
            let end = (uint32(raw.Value[pos + 2]) << 8) | uint32(raw.Value[pos + 3])
            gaps.append(start)
            gaps.append(end)
            pos += 4
            g += 1
        }

        var dups: [uint32] = []
        var d = 0
        while d < numDups && pos + 4 <= raw.Value.count {
            let dup = (uint32(raw.Value[pos]) << 24) | (uint32(raw.Value[pos + 1]) << 16) | (uint32(raw.Value[pos + 2]) << 8) | uint32(raw.Value[pos + 3])
            dups.append(dup)
            pos += 4
            d += 1
        }

        return SackChunk(cumulativeTSNAck: cumAck, a_rwnd: arwnd, gapAckBlocks: gaps, duplicateTSNs: dups)
    }
}

/// CookieEchoChunk represents a COOKIE ECHO (10) chunk.
public struct CookieEchoChunk {
    public var Cookie: [uint8]

    public init(cookie: [uint8]) {
        self.Cookie = cookie
    }

    public func ToRawChunk() -> RawChunk {
        return RawChunk(type: ChunkType.CookieEcho, flags: 0, value: self.Cookie)
    }

    public static func Parse(_ raw: RawChunk) -> CookieEchoChunk {
        return CookieEchoChunk(cookie: raw.Value)
    }
}

/// CookieAckChunk represents a COOKIE ACK (11) chunk.
public struct CookieAckChunk {
    public init() {}

    public func ToRawChunk() -> RawChunk {
        return RawChunk(type: ChunkType.CookieAck, flags: 0, value: [])
    }

    public static func Parse(_ raw: RawChunk) -> CookieAckChunk {
        return CookieAckChunk()
    }
}

/// HeartbeatChunk represents a HEARTBEAT (4) or HEARTBEAT ACK (5) chunk.
public struct HeartbeatChunk {
    public var Info: [uint8]

    public init(info: [uint8]) {
        self.Info = info
    }

    public func ToRawChunk(isAck: bool = false) -> RawChunk {
        var val = [uint8](repeating: 0, count: 4 + self.Info.count)
        // Parameter Type = 1 (Heartbeat Info)
        val[0] = 0x00
        val[1] = 0x01
        let pLen = 4 + self.Info.count
        val[2] = uint8(truncatingIfNeeded: (pLen >> 8) & 0xff)
        val[3] = uint8(truncatingIfNeeded: pLen & 0xff)
        var i = 0
        while i < self.Info.count {
            val[4 + i] = self.Info[i]
            i += 1
        }
        let chunkType = isAck ? ChunkType.HeartbeatAck : ChunkType.Heartbeat
        return RawChunk(type: chunkType, flags: 0, value: val)
    }

    public static func Parse(_ raw: RawChunk) -> HeartbeatChunk {
        var info: [uint8] = []
        if raw.Value.count >= 4 {
            var i = 4
            while i < raw.Value.count {
                info.append(raw.Value[i])
                i += 1
            }
        }
        return HeartbeatChunk(info: info)
    }
}

/// AbortChunk represents an ABORT (6) chunk.
public struct AbortChunk {
    public var Reason: string

    public init(reason: string = "") {
        self.Reason = reason
    }

    public func ToRawChunk() -> RawChunk {
        var val: [uint8] = []
        for b in self.Reason.utf8 {
            val.append(b)
        }
        return RawChunk(type: ChunkType.Abort, flags: 0, value: val)
    }
}

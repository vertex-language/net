package quic

/// Packet Number reconstruction and truncation (RFC 9000 Appendix A).

/// Determines the minimal number of bytes needed to encode a packet number.
public func PacketNumberLength(pn: uint64, largestAcked: uint64) -> int {
    var diff: uint64 = 0
    if pn > largestAcked {
        diff = pn - largestAcked
    } else {
        diff = largestAcked - pn
    }
    if diff < 64 {
        return 1
    } else if diff < 16384 {
        return 2
    } else if diff < 4194304 {
        return 3
    } else {
        return 4
    }
}

/// Decodes a truncated packet number using the largest acknowledged packet number.
public func DecodePacketNumber(largestPn: uint64, truncatedPn: uint64, pnLen: int) -> uint64 {
    let expectedPn: uint64 = largestPn + 1
    let pnWin: uint64 = uint64(1) << uint64(pnLen * 8)
    let pnHwin: uint64 = pnWin / 2
    let pnMask: uint64 = pnWin - 1
    let candidatePn: uint64 = (expectedPn & ~pnMask) | truncatedPn

    if (candidatePn + pnHwin <= expectedPn) && (candidatePn + pnWin < (uint64(1) << 62)) {
        return candidatePn + pnWin
    }
    if (candidatePn > expectedPn + pnHwin) && (candidatePn >= pnWin) {
        return candidatePn - pnWin
    }
    return candidatePn
}

/// Encodes a packet number into 1, 2, 3, or 4 big-endian bytes.
public func EncodePacketNumber(pn: uint64, len: int) -> [uint8] {
    if len == 1 {
        return [uint8(pn & 0xff)]
    } else if len == 2 {
        return [
            uint8((pn >> 8) & 0xff),
            uint8(pn & 0xff)
        ]
    } else if len == 3 {
        return [
            uint8((pn >> 16) & 0xff),
            uint8((pn >> 8) & 0xff),
            uint8(pn & 0xff)
        ]
    } else {
        return [
            uint8((pn >> 24) & 0xff),
            uint8((pn >> 16) & 0xff),
            uint8((pn >> 8) & 0xff),
            uint8(pn & 0xff)
        ]
    }
}

/// Parsed Long Header metadata.
public struct LongHeader {
    public var PacketType: uint8
    public var Version: uint32
    public var Dcid: [uint8]
    public var Scid: [uint8]
    public var Token: [uint8]
    public var PacketNumber: uint64
    public var PnLength: int
    public var PayloadLength: int
    public var HeaderBytes: [uint8]

    public init(packetType: uint8,
                version: uint32 = 1,
                dcid: [uint8],
                scid: [uint8],
                token: [uint8] = [],
                packetNumber: uint64 = 0,
                pnLength: int = 4,
                payloadLength: int = 0,
                headerBytes: [uint8] = []) {
        self.PacketType = packetType
        self.Version = version
        self.Dcid = dcid
        self.Scid = scid
        self.Token = token
        self.PacketNumber = packetNumber
        self.PnLength = pnLength
        self.PayloadLength = payloadLength
        self.HeaderBytes = headerBytes
    }
}

/// Parsed Short Header metadata.
public struct ShortHeader {
    public var Spin: bool
    public var KeyPhase: bool
    public var Dcid: [uint8]
    public var PacketNumber: uint64
    public var PnLength: int
    public var HeaderBytes: [uint8]

    public init(spin: bool = false,
                keyPhase: bool = false,
                dcid: [uint8],
                packetNumber: uint64 = 0,
                pnLength: int = 4,
                headerBytes: [uint8] = []) {
        self.Spin = spin
        self.KeyPhase = keyPhase
        self.Dcid = dcid
        self.PacketNumber = packetNumber
        self.PnLength = pnLength
        self.HeaderBytes = headerBytes
    }
}

/// Serializes an unprotected Long Header packet (prior to AEAD and Header Protection).
public func BuildLongHeader(packetType: uint8,
                            version: uint32,
                            dcid: [uint8],
                            scid: [uint8],
                            token: [uint8] = [],
                            packetNumber: uint64,
                            pnLength: int,
                            payloadLength: int) -> [uint8] {
    var buf: [uint8] = []

    // First byte: 1 (Long) | 1 (Fixed) | Type (2 bits) | Reserved (2 bits = 0) | PnLength - 1 (2 bits)
    let firstByte = uint8(0xc0 | ((packetType & 0x03) << 4) | uint8((pnLength - 1) & 0x03))
    buf.append(firstByte)

    // Version (32-bit big endian)
    buf.append(uint8((version >> 24) & 0xff))
    buf.append(uint8((version >> 16) & 0xff))
    buf.append(uint8((version >> 8) & 0xff))
    buf.append(uint8(version & 0xff))

    // DCID
    buf.append(uint8(dcid.count))
    for b in dcid { buf.append(b) }

    // SCID
    buf.append(uint8(scid.count))
    for b in scid { buf.append(b) }

    // Type-specific
    if packetType == QuicPacketType.Initial {
        let tokLenBytes = EncodeVarint(uint64(token.count))
        for b in tokLenBytes { buf.append(b) }
        for b in token { buf.append(b) }
    }

    // Length field (length of packet number + payload)
    let totalLen = uint64(pnLength + payloadLength)
    let lenBytes = EncodeVarint(totalLen)
    for b in lenBytes { buf.append(b) }

    // Packet Number
    let pnBytes = EncodePacketNumber(pn: packetNumber, len: pnLength)
    for b in pnBytes { buf.append(b) }

    return buf
}

/// Serializes an unprotected Short Header (1-RTT) packet.
public func BuildShortHeader(dcid: [uint8],
                             spin: bool = false,
                             keyPhase: bool = false,
                             packetNumber: uint64,
                             pnLength: int) -> [uint8] {
    var buf: [uint8] = []

    // First byte: 0 (Short) | 1 (Fixed) | Spin (1 bit) | Reserved (2 bits = 0) | KeyPhase (1 bit) | PnLength - 1 (2 bits)
    var firstByte: uint8 = 0x40
    if spin { firstByte |= 0x20 }
    if keyPhase { firstByte |= 0x04 }
    firstByte |= uint8((pnLength - 1) & 0x03)
    buf.append(firstByte)

    // Destination Connection ID
    for b in dcid { buf.append(b) }

    // Packet Number
    let pnBytes = EncodePacketNumber(pn: packetNumber, len: pnLength)
    for b in pnBytes { buf.append(b) }

    return buf
}

/// Parses an unencrypted Long Header from raw packet bytes.
public func ParseLongHeader(_ data: [uint8]) throws -> LongHeader {
    if data.count < 7 {
        throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Long header packet too short")
    }

    let firstByte = data[0]
    if (firstByte & 0x80) == 0 {
        throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Not a long header packet")
    }

    let pType = (firstByte >> 4) & 0x03
    let pnLen = int(firstByte & 0x03) + 1

    let v0 = uint32(data[1])
    let v1 = uint32(data[2])
    let v2 = uint32(data[3])
    let v3 = uint32(data[4])
    let version = (v0 << 24) | (v1 << 16) | (v2 << 8) | v3

    var offset = 5
    let dcidLen = int(data[offset]); offset += 1
    if offset + dcidLen > data.count {
        throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated DCID in long header")
    }
    var dcid: [uint8] = []
    var i = 0
    while i < dcidLen { dcid.append(data[offset + i]); i += 1 }
    offset += dcidLen

    if offset >= data.count {
        throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Missing SCID in long header")
    }
    let scidLen = int(data[offset]); offset += 1
    if offset + scidLen > data.count {
        throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated SCID in long header")
    }
    var scid: [uint8] = []
    i = 0
    while i < scidLen { scid.append(data[offset + i]); i += 1 }
    offset += scidLen

    var token: [uint8] = []
    if pType == QuicPacketType.Initial {
        let tokDec = try DecodeVarint(data, offset: offset); offset += tokDec.BytesRead
        let tLen = Int(tokDec.Value)
        if offset + tLen > data.count {
            throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated Token in Initial packet")
        }
        i = 0
        while i < tLen { token.append(data[offset + i]); i += 1 }
        offset += tLen
    }

    let lenDec = try DecodeVarint(data, offset: offset); offset += lenDec.BytesRead
    let totalLen = Int(lenDec.Value)

    if offset + pnLen > data.count {
        throw QuicError.transport(code: TransportErrorCode.FrameEncodingError, msg: "Truncated packet number in long header")
    }

    var rawPn: uint64 = 0
    i = 0
    while i < pnLen {
        rawPn = (rawPn << 8) | uint64(data[offset + i])
        i += 1
    }
    offset += pnLen

    var headerBytes: [uint8] = []
    i = 0
    while i < offset {
        headerBytes.append(data[i])
        i += 1
    }

    let payloadLen = totalLen - pnLen

    return LongHeader(
        packetType: pType,
        version: version,
        dcid: dcid,
        scid: scid,
        token: token,
        packetNumber: rawPn,
        pnLength: pnLen,
        payloadLength: payloadLen,
        headerBytes: headerBytes
    )
}

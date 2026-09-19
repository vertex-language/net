package webtransport

import "net/quic"

/// RFC 9297 Capsule Protocol Framing.
/// A capsule consists of a varint Type, varint Length, and Capsule Value.

/// Parsed representation of an RFC 9297 Capsule.
public struct ParsedCapsule {
    public var Type: uint64
    public var Payload: [uint8]
    public var BytesRead: int

    public init(type: uint64, payload: [uint8], bytesRead: int) {
        self.Type = type
        self.Payload = payload
        self.BytesRead = bytesRead
    }
}

/// Serializes an RFC 9297 Capsule given its type identifier and payload.
public func BuildCapsule(type: uint64, payload: [uint8]) -> [uint8] {
    let typeBytes = quic.EncodeVarint(type)
    let lenBytes = quic.EncodeVarint(uint64(payload.count))

    var out: [uint8] = []
    for b in typeBytes { out.append(b) }
    for b in lenBytes { out.append(b) }
    for b in payload { out.append(b) }
    return out
}

/// Parses an RFC 9297 Capsule from a byte buffer starting at offset.
public func ParseCapsule(data: [uint8], offset: int = 0) throws -> ParsedCapsule {
    if offset >= data.count {
        throw WebTransportError.protocolViolation("Capsule buffer underflow")
    }

    var curr = offset
    let typeDec = try quic.DecodeVarint(data, offset: curr)
    curr += typeDec.BytesRead

    let lenDec = try quic.DecodeVarint(data, offset: curr)
    curr += lenDec.BytesRead

    let len = Int(lenDec.Value)
    if curr + len > data.count {
        throw WebTransportError.protocolViolation("Truncated capsule payload")
    }

    var payload: [uint8] = []
    var i = 0
    while i < len {
        payload.append(data[curr + i])
        i += 1
    }
    curr += len

    return ParsedCapsule(type: typeDec.Value, payload: payload, bytesRead: curr - offset)
}

/// Serializes a CLOSE_WEBTRANSPORT_SESSION (0x2843) capsule payload.
public func BuildCloseSessionPayload(code: uint32, reason: string) -> [uint8] {
    var payload: [uint8] = [
        uint8((code >> 24) & 0xff),
        uint8((code >> 16) & 0xff),
        uint8((code >> 8) & 0xff),
        uint8(code & 0xff)
    ]
    for b in reason.utf8 {
        payload.append(b)
    }
    return payload
}

/// Builds a complete CLOSE_WEBTRANSPORT_SESSION capsule frame.
public func BuildCloseSessionCapsule(code: uint32, reason: string) -> [uint8] {
    let payload = BuildCloseSessionPayload(code: code, reason: reason)
    return BuildCapsule(type: WebTransportCapsuleType.CloseWebTransportSession, payload: payload)
}

/// Parses a CLOSE_WEBTRANSPORT_SESSION capsule payload into SessionCloseInfo.
public func ParseCloseSessionPayload(_ payload: [uint8]) throws -> SessionCloseInfo {
    if payload.count < 4 {
        throw WebTransportError.protocolViolation("CLOSE_WEBTRANSPORT_SESSION payload must be at least 4 bytes")
    }

    let b0 = uint32(payload[0])
    let b1 = uint32(payload[1])
    let b2 = uint32(payload[2])
    let b3 = uint32(payload[3])
    let code: uint32 = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

    var reasonBytes: [uint8] = []
    var i = 4
    while i < payload.count {
        reasonBytes.append(payload[i])
        i += 1
    }
    let reason = string(decoding: reasonBytes, as: UTF8.self)

    return SessionCloseInfo(code: code, reason: reason)
}

/// Builds a complete DRAIN_WEBTRANSPORT_SESSION capsule frame.
public func BuildDrainSessionCapsule() -> [uint8] {
    let empty: [uint8] = []
    return BuildCapsule(type: WebTransportCapsuleType.DrainWebTransportSession, payload: empty)
}

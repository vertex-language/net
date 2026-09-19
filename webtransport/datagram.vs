package webtransport

import "net/quic"

/// RFC 9297 Section 5: WebTransport Datagram Multiplexing.
/// Datagrams are encapsulated within QUIC DATAGRAM frames (RFC 9221).
/// The datagram payload is prefixed with a Quarter Stream ID (Session ID / 4) encoded as a varint.

/// Represents a decoded WebTransport datagram.
public struct DecodedDatagram {
    public var SessionId: uint64
    public var Payload: [uint8]

    public init(sessionId: uint64, payload: [uint8]) {
        self.SessionId = sessionId
        self.Payload = payload
    }
}

/// Encapsulates application data into an RFC 9297 WebTransport datagram.
public func EncodeDatagram(sessionId: uint64, payload: [uint8]) -> [uint8] {
    let quarterStreamId = sessionId / 4
    let prefix = quic.EncodeVarint(quarterStreamId)

    var out: [uint8] = []
    for b in prefix { out.append(b) }
    for b in payload { out.append(b) }
    return out
}

/// Decodes an RFC 9297 WebTransport datagram into its Session ID and inner payload.
public func DecodeDatagram(_ raw: [uint8]) throws -> DecodedDatagram {
    if raw.isEmpty {
        throw WebTransportError.protocolViolation("Empty datagram")
    }

    let dec = try quic.DecodeVarint(raw, offset: 0)
    let sessionId = dec.Value * 4

    var payload: [uint8] = []
    var i = dec.BytesRead
    while i < raw.count {
        payload.append(raw[i])
        i += 1
    }

    return DecodedDatagram(sessionId: sessionId, payload: payload)
}

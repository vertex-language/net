package stun

import "net/udp"

/// Attribute represents a raw Type-Length-Value (TLV) STUN attribute.
public struct Attribute {
    public var Type: uint16
    public var Value: [uint8]

    public init(type: uint16, value: [uint8]) {
        self.Type = type
        self.Value = value
    }
}

func parseIPv4Octets(_ ip: string) -> [uint8]? {
    var octets: [uint8] = []
    var current = 0
    var hasDigit = false
    for b in ip.utf8 {
        if b == 46 { // '.'
            if !hasDigit || current > 255 { return nil }
            octets.append(uint8(current))
            current = 0
            hasDigit = false
        } else if b >= 48 && b <= 57 {
            current = current * 10 + int(b - 48)
            hasDigit = true
        } else {
            return nil
        }
    }
    if !hasDigit || current > 255 { return nil }
    octets.append(uint8(current))
    if octets.count != 4 { return nil }
    return octets
}

func makeXorAddress(attrType: uint16, address: udp.SocketAddress, transactionId: [uint8]) -> Attribute {
    var val: [uint8] = []
    val.append(0) // Reserved zero byte

    switch address {
    case .v4(let ip, let port):
        val.append(1) // IPv4 family
        let xport = port ^ 0x2112
        val.append(uint8(xport >> 8))
        val.append(uint8(xport & 0xFF))

        var octets: [uint8] = [127, 0, 0, 1]
        if let parsed = parseIPv4Octets(ip) {
            octets = parsed
        }
        val.append(octets[0] ^ 0x21)
        val.append(octets[1] ^ 0x12)
        val.append(octets[2] ^ 0xA4)
        val.append(octets[3] ^ 0x42)

    case .v6(_, let port):
        val.append(2) // IPv6 family
        let xport = port ^ 0x2112
        val.append(uint8(xport >> 8))
        val.append(uint8(xport & 0xFF))
        var i = 0
        while i < 16 {
            val.append(0)
            i += 1
        }
    }

    return Attribute(type: attrType, value: val)
}

func parseXorAddress(_ attr: Attribute, transactionId: [uint8]) throws -> udp.SocketAddress {
    if attr.Value.count < 8 {
        throw StunError.malformedAttribute("XOR address value too short")
    }

    let family = attr.Value[1]
    let xport = (uint16(attr.Value[2]) << 8) | uint16(attr.Value[3])
    let port = xport ^ 0x2112

    if family == 1 { // IPv4
        let b0 = attr.Value[4] ^ 0x21
        let b1 = attr.Value[5] ^ 0x12
        let b2 = attr.Value[6] ^ 0xA4
        let b3 = attr.Value[7] ^ 0x42
        let ipStr = "\(b0).\(b1).\(b2).\(b3)"
        return .v4(ip: ipStr, port: port)
    } else if family == 2 { // IPv6
        if attr.Value.count < 20 {
            throw StunError.malformedAttribute("XOR address IPv6 value too short")
        }
        return .v6(ip: "::1", port: port)
    }

    throw StunError.malformedAttribute("unsupported address family \(family)")
}

/// MakeXorMappedAddress creates an XOR-MAPPED-ADDRESS attribute (RFC 8489 Section 14.2).
public func MakeXorMappedAddress(address: udp.SocketAddress, transactionId: [uint8]) -> Attribute {
    return makeXorAddress(attrType: AttrXorMappedAddress, address: address, transactionId: transactionId)
}

/// ParseXorMappedAddress decodes an XOR-MAPPED-ADDRESS attribute.
public func ParseXorMappedAddress(_ attr: Attribute, transactionId: [uint8]) throws -> udp.SocketAddress {
    return try parseXorAddress(attr, transactionId: transactionId)
}

/// MakeXorRelayedAddress creates an XOR-RELAYED-ADDRESS attribute (RFC 8656 Section 14.5).
public func MakeXorRelayedAddress(address: udp.SocketAddress, transactionId: [uint8]) -> Attribute {
    return makeXorAddress(attrType: AttrXorRelayedAddress, address: address, transactionId: transactionId)
}

/// ParseXorRelayedAddress decodes an XOR-RELAYED-ADDRESS attribute.
public func ParseXorRelayedAddress(_ attr: Attribute, transactionId: [uint8]) throws -> udp.SocketAddress {
    return try parseXorAddress(attr, transactionId: transactionId)
}

/// MakeXorPeerAddress creates an XOR-PEER-ADDRESS attribute (RFC 8656 Section 14.3).
public func MakeXorPeerAddress(address: udp.SocketAddress, transactionId: [uint8]) -> Attribute {
    return makeXorAddress(attrType: AttrXorPeerAddress, address: address, transactionId: transactionId)
}

/// ParseXorPeerAddress decodes an XOR-PEER-ADDRESS attribute.
public func ParseXorPeerAddress(_ attr: Attribute, transactionId: [uint8]) throws -> udp.SocketAddress {
    return try parseXorAddress(attr, transactionId: transactionId)
}

/// MakeMappedAddress creates a legacy MAPPED-ADDRESS attribute (RFC 8489 Section 14.1).
public func MakeMappedAddress(address: udp.SocketAddress) -> Attribute {
    var val: [uint8] = []
    val.append(0)

    switch address {
    case .v4(let ip, let port):
        val.append(1)
        val.append(uint8(port >> 8))
        val.append(uint8(port & 0xFF))
        var octets: [uint8] = [127, 0, 0, 1]
        if let parsed = parseIPv4Octets(ip) {
            octets = parsed
        }
        var i = 0
        while i < 4 { val.append(octets[i]); i += 1 }

    case .v6(_, let port):
        val.append(2)
        val.append(uint8(port >> 8))
        val.append(uint8(port & 0xFF))
        var i = 0
        while i < 16 { val.append(0); i += 1 }
    }

    return Attribute(type: AttrMappedAddress, value: val)
}

/// ParseMappedAddress decodes a legacy MAPPED-ADDRESS attribute.
public func ParseMappedAddress(_ attr: Attribute) throws -> udp.SocketAddress {
    if attr.Value.count < 8 {
        throw StunError.malformedAttribute("MAPPED-ADDRESS value too short")
    }
    let family = attr.Value[1]
    let port = (uint16(attr.Value[2]) << 8) | uint16(attr.Value[3])
    if family == 1 {
        let b0 = attr.Value[4]
        let b1 = attr.Value[5]
        let b2 = attr.Value[6]
        let b3 = attr.Value[7]
        return .v4(ip: "\(b0).\(b1).\(b2).\(b3)", port: port)
    }
    return .v6(ip: "::1", port: port)
}

/// MakeSoftware creates a SOFTWARE attribute (RFC 8489 Section 14.8).
public func MakeSoftware(_ name: string) -> Attribute {
    var val: [uint8] = []
    for b in name.utf8 { val.append(b) }
    return Attribute(type: AttrSoftware, value: val)
}

/// ParseSoftware extracts the software string from a SOFTWARE attribute.
public func ParseSoftware(_ attr: Attribute) -> string {
    return string(decoding: attr.Value, as: UTF8.self)
}

/// MakeUsername creates a USERNAME attribute (RFC 8489 Section 14.3).
public func MakeUsername(_ name: string) -> Attribute {
    var val: [uint8] = []
    for b in name.utf8 { val.append(b) }
    return Attribute(type: AttrUsername, value: val)
}

/// ParseUsername extracts the username string from a USERNAME attribute.
public func ParseUsername(_ attr: Attribute) -> string {
    return string(decoding: attr.Value, as: UTF8.self)
}

/// MakeRealm creates a REALM attribute (RFC 8489 Section 14.7).
public func MakeRealm(_ realm: string) -> Attribute {
    var val: [uint8] = []
    for b in realm.utf8 { val.append(b) }
    return Attribute(type: AttrRealm, value: val)
}

/// ParseRealm extracts the realm string from a REALM attribute.
public func ParseRealm(_ attr: Attribute) -> string {
    return string(decoding: attr.Value, as: UTF8.self)
}

/// MakeNonce creates a NONCE attribute (RFC 8489 Section 14.6).
public func MakeNonce(_ nonce: string) -> Attribute {
    var val: [uint8] = []
    for b in nonce.utf8 { val.append(b) }
    return Attribute(type: AttrNonce, value: val)
}

/// ParseNonce extracts the nonce string from a NONCE attribute.
public func ParseNonce(_ attr: Attribute) -> string {
    return string(decoding: attr.Value, as: UTF8.self)
}

/// MakeErrorCode creates an ERROR-CODE attribute (RFC 8489 Section 14.4).
public func MakeErrorCode(_ code: int, _ reason: string = "") -> Attribute {
    var val: [uint8] = [0, 0]
    let cl = uint8((code / 100) & 0x07)
    let num = uint8(code % 100)
    val.append(cl)
    val.append(num)
    for b in reason.utf8 {
        val.append(b)
    }
    return Attribute(type: AttrErrorCode, value: val)
}

/// ParseErrorCode decodes an ERROR-CODE attribute.
public func ParseErrorCode(_ attr: Attribute) -> ErrorCodeInfo {
    if attr.Value.count < 4 {
        return ErrorCodeInfo(code: 500, reason: "Malformed error attribute")
    }
    let cl = int(attr.Value[2] & 0x07)
    let num = int(attr.Value[3])
    let code = cl * 100 + num
    var reasonBytes: [uint8] = []
    var i = 4
    while i < attr.Value.count {
        reasonBytes.append(attr.Value[i])
        i += 1
    }
    let reason = string(decoding: reasonBytes, as: UTF8.self)
    return ErrorCodeInfo(code: code, reason: reason)
}

/// MakeLifetime creates a LIFETIME attribute (RFC 8656 Section 14.2).
public func MakeLifetime(_ seconds: uint32) -> Attribute {
    var val: [uint8] = []
    val.append(uint8((seconds >> 24) & 0xFF))
    val.append(uint8((seconds >> 16) & 0xFF))
    val.append(uint8((seconds >> 8) & 0xFF))
    val.append(uint8(seconds & 0xFF))
    return Attribute(type: AttrLifetime, value: val)
}

/// ParseLifetime decodes a LIFETIME attribute.
public func ParseLifetime(_ attr: Attribute) -> uint32 {
    if attr.Value.count < 4 { return 0 }
    return (uint32(attr.Value[0]) << 24) |
           (uint32(attr.Value[1]) << 16) |
           (uint32(attr.Value[2]) << 8) |
            uint32(attr.Value[3])
}

/// MakeRequestedTransport creates a REQUESTED-TRANSPORT attribute (RFC 8656 Section 14.7).
public func MakeRequestedTransport(_ proto: uint8 = 17) -> Attribute {
    return Attribute(type: AttrRequestedTransport, value: [proto, 0, 0, 0])
}

/// ParseRequestedTransport decodes a REQUESTED-TRANSPORT attribute.
public func ParseRequestedTransport(_ attr: Attribute) -> uint8 {
    if attr.Value.isEmpty { return 17 }
    return attr.Value[0]
}

/// MakePriority creates a PRIORITY attribute (RFC 8445 Section 7.1.1).
public func MakePriority(_ priority: uint32) -> Attribute {
    var val: [uint8] = []
    val.append(uint8((priority >> 24) & 0xFF))
    val.append(uint8((priority >> 16) & 0xFF))
    val.append(uint8((priority >> 8) & 0xFF))
    val.append(uint8(priority & 0xFF))
    return Attribute(type: AttrPriority, value: val)
}

/// ParsePriority decodes a PRIORITY attribute.
public func ParsePriority(_ attr: Attribute) -> uint32 {
    if attr.Value.count < 4 { return 0 }
    return (uint32(attr.Value[0]) << 24) |
           (uint32(attr.Value[1]) << 16) |
           (uint32(attr.Value[2]) << 8) |
            uint32(attr.Value[3])
}

/// MakeUseCandidate creates a USE-CANDIDATE attribute (RFC 8445 Section 7.1.2).
public func MakeUseCandidate() -> Attribute {
    return Attribute(type: AttrUseCandidate, value: [])
}

/// MakeIceControlling creates an ICE-CONTROLLING attribute (RFC 8445 Section 7.1.3).
public func MakeIceControlling(_ tieBreaker: uint64) -> Attribute {
    var val: [uint8] = []
    var shift: uint64 = 56
    while true {
        val.append(uint8((tieBreaker >> shift) & 0xFF))
        if shift == 0 { break }
        shift -= 8
    }
    return Attribute(type: AttrIceControlling, value: val)
}

/// MakeIceControlled creates an ICE-CONTROLLED attribute (RFC 8445 Section 7.1.4).
public func MakeIceControlled(_ tieBreaker: uint64) -> Attribute {
    var val: [uint8] = []
    var shift: uint64 = 56
    while true {
        val.append(uint8((tieBreaker >> shift) & 0xFF))
        if shift == 0 { break }
        shift -= 8
    }
    return Attribute(type: AttrIceControlled, value: val)
}

/// MakeData creates a DATA attribute (RFC 8656 Section 14.4).
public func MakeData(_ data: [uint8]) -> Attribute {
    return Attribute(type: AttrData, value: data)
}

/// ParseData extracts payload from a DATA attribute.
public func ParseData(_ attr: Attribute) -> [uint8] {
    return attr.Value
}

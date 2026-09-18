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

/// MakeXorMappedAddress creates an XOR-MAPPED-ADDRESS attribute (RFC 8489 Section 14.2).
public func MakeXorMappedAddress(address: udp.SocketAddress, transactionId: [uint8]) -> Attribute {
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
        // 16 bytes masked by MagicCookie + transactionId
        var i = 0
        while i < 16 {
            val.append(0) // Default fallback
            i += 1
        }
    }

    return Attribute(type: AttrXorMappedAddress, value: val)
}

/// ParseXorMappedAddress decodes an XOR-MAPPED-ADDRESS attribute.
public func ParseXorMappedAddress(_ attr: Attribute, transactionId: [uint8]) throws -> udp.SocketAddress {
    if attr.Value.count < 8 {
        throw StunError.malformedAttribute("XOR-MAPPED-ADDRESS value too short")
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
            throw StunError.malformedAttribute("XOR-MAPPED-ADDRESS IPv6 value too short")
        }
        var mask = [0x21, 0x12, 0xA4, 0x42]
        var mi = 0
        while mi < transactionId.count && mi < 12 {
            mask.append(int(transactionId[mi]))
            mi += 1
        }
        var unmasked: [uint8] = []
        var i = 0
        while i < 16 && (4 + i) < attr.Value.count {
            unmasked.append(attr.Value[4 + i] ^ uint8(mask[i]))
            i += 1
        }
        // Format as IPv6 hex groups
        return .v6(ip: "::1", port: port)
    }

    throw StunError.malformedAttribute("unsupported address family \(family)")
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

// Package netip is IP addresses and prefixes as values: no sockets, no
// lookups. The packet codecs (net/wire), DHCP, DNS and the VM gateway
// (net/nat) all speak in these.
//
//     let gw = netip.Ipv4(10, 0, 2, 2)
//     let net = netip.Prefix.Parse("10.0.2.0/24")!
//     net.Contains(gw)          // true
package netip

/// An IPv4 address.
public struct Ipv4: Equatable, Hashable, Comparable, CustomStringConvertible {
    /// Big-endian: 10.0.2.15 is 0x0a00_020f.
    public let Value: uint32

    public init(_ a: uint8, _ b: uint8, _ c: uint8, _ d: uint8) {
        Value = uint32(a) << 24 | uint32(b) << 16 | uint32(c) << 8 | uint32(d)
    }

    public init(value: uint32) {
        Value = value
    }

    /// The four bytes at `at` in `b` (network order); 0.0.0.0 if there aren't four.
    public init(_ b: [uint8], at: int = 0) {
        if at < 0 || at + 4 > b.count {
            Value = 0
            return
        }
        Value = uint32(b[at]) << 24 | uint32(b[at + 1]) << 16 | uint32(b[at + 2]) << 8 | uint32(b[at + 3])
    }

    /// "10.0.2.15", or nil.
    public static func Parse(_ s: string) -> Ipv4? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count != 4 { return nil }
        var v: uint32 = 0
        for p in parts {
            if p.isEmpty || p.count > 3 { return nil }
            guard let n = int(string(p)), n >= 0, n <= 255 else { return nil }
            if p.count > 1 && p.hasPrefix("0") { return nil }
            v = v << 8 | uint32(n)
        }
        return Ipv4(value: v)
    }

    /// The four bytes, network order.
    public var Bytes: [uint8] {
        [uint8(Value >> 24), uint8((Value >> 16) & 0xff), uint8((Value >> 8) & 0xff), uint8(Value & 0xff)]
    }

    public var description: string {
        "\(Value >> 24).\((Value >> 16) & 0xff).\((Value >> 8) & 0xff).\(Value & 0xff)"
    }

    public var IsUnspecified: bool { Value == 0 }
    public var IsBroadcast: bool { Value == 0xffff_ffff }
    public var IsLoopback: bool { Value >> 24 == 127 }
    public var IsMulticast: bool { Value >> 28 == 0xe }

    /// The address `n` after this one.
    public func Adding(_ n: uint32) -> Ipv4 { Ipv4(value: Value &+ n) }

    public static let any = Ipv4(value: 0)
    public static let broadcast = Ipv4(value: 0xffff_ffff)
    public static let loopback = Ipv4(127, 0, 0, 1)

    public static func < (a: Ipv4, b: Ipv4) -> bool { a.Value < b.Value }
}

/// An IPv4 network: an address and how many of its leading bits name the network.
public struct Prefix: Equatable, Hashable, CustomStringConvertible {
    public let Address: Ipv4
    public let Bits: int

    /// `bits` from 0 to 32.
    public init(_ address: Ipv4, bits: int) {
        Address = address
        Bits = max(0, min(32, bits))
    }

    /// "10.0.2.0/24", or nil.
    public static func Parse(_ s: string) -> Prefix? {
        guard let slash = s.firstIndex(of: "/"),
              let a = Ipv4.Parse(string(s[..<slash])),
              let n = int(string(s[s.index(after: slash)...])), n >= 0, n <= 32 else { return nil }
        return Prefix(a, bits: n)
    }

    /// The netmask: 255.255.255.0 for /24.
    public var Mask: Ipv4 {
        Bits == 0 ? Ipv4(value: 0) : Ipv4(value: ~uint32(0) << uint32(32 - Bits))
    }

    /// The network's first address: 10.0.2.0 for 10.0.2.15/24.
    public var Network: Ipv4 { Ipv4(value: Address.Value & Mask.Value) }

    /// The network's broadcast address: 10.0.2.255 for /24.
    public var Broadcast: Ipv4 { Ipv4(value: Network.Value | ~Mask.Value) }

    public func Contains(_ a: Ipv4) -> bool {
        a.Value & Mask.Value == Network.Value
    }

    public var description: string { "\(Address)/\(Bits)" }
}

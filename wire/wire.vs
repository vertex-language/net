// Package wire reads and writes the headers of the packets a VM's
// network carries: ARP, IPv4, ICMP, UDP and TCP, and the Internet
// checksum. Values in, bytes out, and back: no sockets, no state, so
// every codec is testable on its own. Ethernet framing is net/ether's;
// addresses are net/netip's.
//
//     let seg = wire.Udp(source: 53, destination: 4242, payload: answer)
//     let ip = wire.Ipv4Packet(source: dns, destination: guest, protocol: wire.IpProtocol.udp,
//                              payload: seg.Encode(source: dns, destination: guest))
//     let frame = ether.Frame(destination: guestMac, source: myMac,
//                             etherType: ether.EtherType.ipv4, payload: ip.Encode())
package wire

import (
    "encoding/binary"
    "net/ether"
    "net/netip"
)

/// IP protocol numbers.
public enum IpProtocol {
    public static let icmp: uint8 = 1
    public static let tcp: uint8 = 6
    public static let udp: uint8 = 17
}

/// The 16-bit one's-complement sum of RFC 1071, folded and inverted,
/// over `data` after `initial` (a pseudo-header's sum).
public func Checksum(_ data: [uint8], initial: uint32 = 0) -> uint16 {
    var sum = initial
    var i = 0
    while i + 1 < data.count {
        sum &+= uint32(data[i]) << 8 | uint32(data[i + 1])
        i += 2
    }
    if i < data.count { sum &+= uint32(data[i]) << 8 }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
    return uint16(~sum & 0xffff)
}

/// The sum of the IPv4 pseudo-header UDP and TCP checksums cover.
public func PseudoHeader(source: netip.Ipv4, destination: netip.Ipv4, protocol proto: uint8, length: int) -> uint32 {
    (source.Value >> 16) &+ (source.Value & 0xffff) &+ (destination.Value >> 16) &+ (destination.Value & 0xffff)
        &+ uint32(proto) &+ uint32(length)
}

// MARK: ARP

/// An ARP packet for IPv4 over Ethernet (RFC 826).
public struct Arp {
    public static let request: uint16 = 1
    public static let reply: uint16 = 2

    public var Operation: uint16
    public var SenderMac: ether.Mac
    public var SenderIp: netip.Ipv4
    public var TargetMac: ether.Mac
    public var TargetIp: netip.Ipv4

    public init(operation: uint16, senderMac: ether.Mac, senderIp: netip.Ipv4, targetMac: ether.Mac, targetIp: netip.Ipv4) {
        Operation = operation
        SenderMac = senderMac
        SenderIp = senderIp
        TargetMac = targetMac
        TargetIp = targetIp
    }

    /// nil unless Ethernet/IPv4 and long enough.
    public static func Parse(_ b: [uint8]) -> Arp? {
        if b.count < 28 || binary.BigEndian.Uint16(b, from: 0) != 1 || binary.BigEndian.Uint16(b, from: 2) != 0x0800
            || b[4] != 6 || b[5] != 4 { return nil }
        return Arp(operation: binary.BigEndian.Uint16(b, from: 6), senderMac: ether.Mac(b, at: 8),
                   senderIp: netip.Ipv4(b, at: 14), targetMac: ether.Mac(b, at: 18), targetIp: netip.Ipv4(b, at: 24))
    }

    public func Encode() -> [uint8] {
        var b: [uint8] = [0, 1, 0x08, 0x00, 6, 4]
        binary.BigEndian.AppendUint16(&b, Operation)
        b += SenderMac.Bytes + SenderIp.Bytes + TargetMac.Bytes + TargetIp.Bytes
        return b
    }

    /// The reply saying `mac` has the address this request asks for.
    public func Answer(_ mac: ether.Mac) -> Arp {
        Arp(operation: Arp.reply, senderMac: mac, senderIp: TargetIp, targetMac: SenderMac, targetIp: SenderIp)
    }
}

// MARK: IPv4

/// An IPv4 packet (RFC 791). Options are kept as read but never written;
/// fragments are recognised (`IsFragment`) but not reassembled.
public struct Ipv4Packet {
    public var Source: netip.Ipv4
    public var Destination: netip.Ipv4
    public var Protocol: uint8
    public var Ttl: uint8 = 64
    public var Tos: uint8 = 0
    public var Id: uint16 = 0
    public var DontFragment: bool = true
    public var MoreFragments: bool = false
    /// In bytes.
    public var FragmentOffset: int = 0
    public var Payload: [uint8]

    public init(source: netip.Ipv4, destination: netip.Ipv4, protocol proto: uint8, payload: [uint8]) {
        Source = source
        Destination = destination
        Protocol = proto
        Payload = payload
    }

    public var IsFragment: bool { MoreFragments || FragmentOffset != 0 }

    /// nil unless version 4 with a sane header and length; a frame's
    /// padding past the total length is dropped. The header checksum is
    /// not checked (a virtual card doesn't corrupt).
    public static func Parse(_ b: [uint8]) -> Ipv4Packet? {
        if b.count < 20 || b[0] >> 4 != 4 { return nil }
        let ihl = int(b[0] & 0x0f) * 4
        let total = int(binary.BigEndian.Uint16(b, from: 2))
        if ihl < 20 || total < ihl || total > b.count { return nil }
        var p = Ipv4Packet(source: netip.Ipv4(b, at: 12), destination: netip.Ipv4(b, at: 16),
                           protocol: b[9], payload: Array(b[ihl..<total]))
        p.Tos = b[1]
        p.Id = binary.BigEndian.Uint16(b, from: 4)
        let frag = binary.BigEndian.Uint16(b, from: 6)
        p.DontFragment = frag & 0x4000 != 0
        p.MoreFragments = frag & 0x2000 != 0
        p.FragmentOffset = int(frag & 0x1fff) * 8
        p.Ttl = b[8]
        return p
    }

    /// A 20-byte header, its checksum filled in, then the payload.
    public func Encode() -> [uint8] {
        var h = [uint8](repeating: 0, count: 20)
        h[0] = 0x45
        h[1] = Tos
        binary.BigEndian.PutUint16(&h, uint16(20 + Payload.count), at: 2)
        binary.BigEndian.PutUint16(&h, Id, at: 4)
        var frag = uint16(FragmentOffset / 8) & 0x1fff
        if DontFragment { frag |= 0x4000 }
        if MoreFragments { frag |= 0x2000 }
        binary.BigEndian.PutUint16(&h, frag, at: 6)
        h[8] = Ttl
        h[9] = Protocol
        h.replaceSubrange(12..<16, with: Source.Bytes)
        h.replaceSubrange(16..<20, with: Destination.Bytes)
        binary.BigEndian.PutUint16(&h, Checksum(h), at: 10)
        return h + Payload
    }
}

// MARK: ICMP

/// An ICMPv4 message (RFC 792): type, code, the four bytes after the
/// checksum (an echo's identifier and sequence), and the rest.
public struct Icmp {
    public static let echoReply: uint8 = 0
    public static let unreachable: uint8 = 3
    public static let echoRequest: uint8 = 8

    public var Kind: uint8
    public var Code: uint8
    public var Rest: [uint8]
    public var Data: [uint8]

    public init(kind: uint8, code: uint8 = 0, rest: [uint8] = [0, 0, 0, 0], data: [uint8] = []) {
        Kind = kind
        Code = code
        Rest = rest.count == 4 ? rest : [0, 0, 0, 0]
        Data = data
    }

    public static func Parse(_ b: [uint8]) -> Icmp? {
        if b.count < 8 { return nil }
        return Icmp(kind: b[0], code: b[1], rest: Array(b[4..<8]), data: Array(b[8...]))
    }

    public func Encode() -> [uint8] {
        var b: [uint8] = [Kind, Code, 0, 0] + Rest + Data
        binary.BigEndian.PutUint16(&b, Checksum(b), at: 2)
        return b
    }

    /// The echo reply to this echo request: the same identifier, sequence and data.
    public func EchoReply() -> Icmp {
        Icmp(kind: Icmp.echoReply, code: 0, rest: Rest, data: Data)
    }
}

// MARK: UDP

/// A UDP datagram (RFC 768).
public struct Udp {
    public var SourcePort: uint16
    public var DestinationPort: uint16
    public var Payload: [uint8]

    public init(source: uint16, destination: uint16, payload: [uint8]) {
        SourcePort = source
        DestinationPort = destination
        Payload = payload
    }

    /// nil if the length field doesn't fit; the checksum is not checked.
    public static func Parse(_ b: [uint8]) -> Udp? {
        if b.count < 8 { return nil }
        let len = int(binary.BigEndian.Uint16(b, from: 4))
        if len < 8 || len > b.count { return nil }
        return Udp(source: binary.BigEndian.Uint16(b, from: 0), destination: binary.BigEndian.Uint16(b, from: 2),
                   payload: Array(b[8..<len]))
    }

    /// The datagram with its checksum, which covers the IPv4 addresses it travels between.
    public func Encode(source: netip.Ipv4, destination: netip.Ipv4) -> [uint8] {
        var b = [uint8](repeating: 0, count: 8)
        binary.BigEndian.PutUint16(&b, SourcePort, at: 0)
        binary.BigEndian.PutUint16(&b, DestinationPort, at: 2)
        binary.BigEndian.PutUint16(&b, uint16(8 + Payload.count), at: 4)
        b += Payload
        var sum = Checksum(b, initial: PseudoHeader(source: source, destination: destination, protocol: IpProtocol.udp, length: b.count))
        if sum == 0 { sum = 0xffff }
        binary.BigEndian.PutUint16(&b, sum, at: 6)
        return b
    }
}

// MARK: TCP

/// TCP header flags.
public enum TcpFlags {
    public static let fin: uint8 = 0x01
    public static let syn: uint8 = 0x02
    public static let rst: uint8 = 0x04
    public static let psh: uint8 = 0x08
    public static let ack: uint8 = 0x10
}

/// A TCP segment (RFC 9293). Of the options, MSS is read and written;
/// the others (window scale, SACK, timestamps) are skipped, so a peer
/// that offered them sees them declined.
public struct Tcp {
    public var SourcePort: uint16
    public var DestinationPort: uint16
    public var Seq: uint32
    public var Ack: uint32
    public var Flags: uint8
    public var Window: uint16
    /// The maximum segment size option (a SYN's), if any.
    public var Mss: uint16? = nil
    public var Payload: [uint8]

    public init(source: uint16, destination: uint16, seq: uint32, ack: uint32, flags: uint8,
                window: uint16 = 65535, mss: uint16? = nil, payload: [uint8] = []) {
        SourcePort = source
        DestinationPort = destination
        Seq = seq
        Ack = ack
        Flags = flags
        Window = window
        Mss = mss
        Payload = payload
    }

    public func Has(_ flag: uint8) -> bool { Flags & flag != 0 }

    /// The sequence space this segment takes: its data, plus one each for SYN and FIN.
    public var Length: uint32 {
        uint32(Payload.count) + (Has(TcpFlags.syn) ? 1 : 0) + (Has(TcpFlags.fin) ? 1 : 0)
    }

    /// nil if the header doesn't fit; the checksum is not checked.
    public static func Parse(_ b: [uint8]) -> Tcp? {
        if b.count < 20 { return nil }
        let off = int(b[12] >> 4) * 4
        if off < 20 || off > b.count { return nil }
        var t = Tcp(source: binary.BigEndian.Uint16(b, from: 0), destination: binary.BigEndian.Uint16(b, from: 2),
                    seq: binary.BigEndian.Uint32(b, from: 4), ack: binary.BigEndian.Uint32(b, from: 8),
                    flags: b[13], window: binary.BigEndian.Uint16(b, from: 14), payload: Array(b[off...]))
        var i = 20
        while i < off {
            let kind = b[i]
            if kind == 0 { break }
            if kind == 1 {
                i += 1
                continue
            }
            if i + 1 >= off { break }
            let len = int(b[i + 1])
            if len < 2 || i + len > off { break }
            if kind == 2 && len == 4 { t.Mss = binary.BigEndian.Uint16(b, from: i + 2) }
            i += len
        }
        return t
    }

    /// The segment with its checksum, which covers the IPv4 addresses it travels between.
    public func Encode(source: netip.Ipv4, destination: netip.Ipv4) -> [uint8] {
        let hdr = Mss == nil ? 20 : 24
        var b = [uint8](repeating: 0, count: hdr)
        binary.BigEndian.PutUint16(&b, SourcePort, at: 0)
        binary.BigEndian.PutUint16(&b, DestinationPort, at: 2)
        binary.BigEndian.PutUint32(&b, Seq, at: 4)
        binary.BigEndian.PutUint32(&b, Ack, at: 8)
        b[12] = uint8(hdr / 4) << 4
        b[13] = Flags
        binary.BigEndian.PutUint16(&b, Window, at: 14)
        if let m = Mss {
            b[20] = 2
            b[21] = 4
            binary.BigEndian.PutUint16(&b, m, at: 22)
        }
        b += Payload
        let sum = Checksum(b, initial: PseudoHeader(source: source, destination: destination, protocol: IpProtocol.tcp, length: b.count))
        binary.BigEndian.PutUint16(&b, sum, at: 16)
        return b
    }
}

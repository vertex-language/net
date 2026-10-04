// Package dns is DNS messages (RFC 1035) and a Forwarder: what a
// virtual network's gateway needs to answer its machines' lookups. The
// Forwarder sends each query on to the host's own nameservers (the
// ones /etc/resolv.conf names, so a VPN's or a captive network's
// resolver works for the guest as it does for the host), and answers
// names it is told about itself.
package dns

import (
    "encoding/binary"
    "fs"
    "net/netip"
    "net/udp"
)

/// Record types.
public enum RecordType {
    public static let a: uint16 = 1
    public static let ns: uint16 = 2
    public static let cname: uint16 = 5
    public static let soa: uint16 = 6
    public static let ptr: uint16 = 12
    public static let mx: uint16 = 15
    public static let txt: uint16 = 16
    public static let aaaa: uint16 = 28
    public static let srv: uint16 = 33
    public static let https: uint16 = 65
}

/// Response codes.
public enum Rcode {
    public static let ok: uint8 = 0
    public static let formatError: uint8 = 1
    public static let serverFailure: uint8 = 2
    public static let nameError: uint8 = 3
    public static let notImplemented: uint8 = 4
    public static let refused: uint8 = 5
}

public struct Question: Equatable {
    /// Lower case, no trailing dot: "example.com".
    public var Name: string
    public var Kind: uint16
    public var Class: uint16 = 1

    public init(name: string, kind: uint16, class: uint16 = 1) {
        Name = name
        Kind = kind
        Class = `class`
    }
}

public struct Record {
    public var Name: string
    public var Kind: uint16
    public var Class: uint16 = 1
    public var Ttl: uint32
    /// The record's data as on the wire (names inside it are not expanded).
    public var Data: [uint8]

    public init(name: string, kind: uint16, ttl: uint32, data: [uint8]) {
        Name = name
        Kind = kind
        Ttl = ttl
        Data = data
    }

    /// An A record.
    public static func A(_ name: string, _ ip: netip.Ipv4, ttl: uint32 = 60) -> Record {
        Record(name: name, kind: RecordType.a, ttl: ttl, data: ip.Bytes)
    }

    /// The address of an A record.
    public var Ipv4: netip.Ipv4? {
        Kind == RecordType.a && Data.count == 4 ? netip.Ipv4(Data) : nil
    }
}

/// A DNS message: header, questions, and the three record sections.
public struct Message {
    public var Id: uint16
    public var Response: bool = false
    public var Opcode: uint8 = 0
    public var Authoritative: bool = false
    public var Truncated: bool = false
    public var RecursionDesired: bool = true
    public var RecursionAvailable: bool = false
    public var Rcode: uint8 = 0
    public var Questions: [Question] = []
    public var Answers: [Record] = []
    public var Authority: [Record] = []
    public var Additional: [Record] = []

    public init(id: uint16) {
        Id = id
    }

    /// A query for one name.
    public static func Query(id: uint16, name: string, kind: uint16) -> Message {
        var m = Message(id: id)
        m.Questions = [Question(name: name, kind: kind)]
        return m
    }

    /// The response to this query: same id and questions, no records yet.
    public func Reply(rcode: uint8 = 0) -> Message {
        var m = Message(id: Id)
        m.Response = true
        m.Opcode = Opcode
        m.RecursionDesired = RecursionDesired
        m.RecursionAvailable = true
        m.Rcode = rcode
        m.Questions = Questions
        return m
    }

    /// nil when malformed.
    public static func Parse(_ b: [uint8]) -> Message? {
        if b.count < 12 { return nil }
        var m = Message(id: binary.BigEndian.Uint16(b, from: 0))
        let f = binary.BigEndian.Uint16(b, from: 2)
        m.Response = f & 0x8000 != 0
        m.Opcode = uint8((f >> 11) & 0xf)
        m.Authoritative = f & 0x0400 != 0
        m.Truncated = f & 0x0200 != 0
        m.RecursionDesired = f & 0x0100 != 0
        m.RecursionAvailable = f & 0x0080 != 0
        m.Rcode = uint8(f & 0xf)
        let counts = (0..<4).map { int(binary.BigEndian.Uint16(b, from: 4 + 2 * $0)) }
        var at = 12
        for _ in 0..<counts[0] {
            guard let rn = readName(b, at) else { return nil }
            let name = rn.0
            let next = rn.1
            if next + 4 > b.count { return nil }
            m.Questions.append(Question(name: name, kind: binary.BigEndian.Uint16(b, from: next),
                                        class: binary.BigEndian.Uint16(b, from: next + 2)))
            at = next + 4
        }
        for section in 1...3 {
            for _ in 0..<counts[section] {
                guard let rn = readName(b, at) else { return nil }
                let name = rn.0
                let next = rn.1
                if next + 10 > b.count { return nil }
                let len = int(binary.BigEndian.Uint16(b, from: next + 8))
                if next + 10 + len > b.count { return nil }
                var r = Record(name: name, kind: binary.BigEndian.Uint16(b, from: next),
                               ttl: binary.BigEndian.Uint32(b, from: next + 4),
                               data: Array(b[(next + 10)..<(next + 10 + len)]))
                r.Class = binary.BigEndian.Uint16(b, from: next + 2)
                switch section {
                case 1: m.Answers.append(r)
                case 2: m.Authority.append(r)
                default: m.Additional.append(r)
                }
                at = next + 10 + len
            }
        }
        return m
    }

    /// The message, names written in full (no compression).
    public func Encode() -> [uint8] {
        var b = [uint8](repeating: 0, count: 12)
        binary.BigEndian.PutUint16(&b, Id, at: 0)
        var f = uint16(Opcode & 0xf) << 11 | uint16(Rcode & 0xf)
        if Response { f |= 0x8000 }
        if Authoritative { f |= 0x0400 }
        if Truncated { f |= 0x0200 }
        if RecursionDesired { f |= 0x0100 }
        if RecursionAvailable { f |= 0x0080 }
        binary.BigEndian.PutUint16(&b, f, at: 2)
        binary.BigEndian.PutUint16(&b, uint16(Questions.count), at: 4)
        binary.BigEndian.PutUint16(&b, uint16(Answers.count), at: 6)
        binary.BigEndian.PutUint16(&b, uint16(Authority.count), at: 8)
        binary.BigEndian.PutUint16(&b, uint16(Additional.count), at: 10)
        for q in Questions {
            b += writeName(q.Name)
            binary.BigEndian.AppendUint16(&b, q.Kind)
            binary.BigEndian.AppendUint16(&b, q.Class)
        }
        for r in Answers + Authority + Additional {
            b += writeName(r.Name)
            binary.BigEndian.AppendUint16(&b, r.Kind)
            binary.BigEndian.AppendUint16(&b, r.Class)
            binary.BigEndian.AppendUint32(&b, r.Ttl)
            binary.BigEndian.AppendUint16(&b, uint16(r.Data.count))
            b += r.Data
        }
        return b
    }
}

/// A name at `at`, following compression pointers; the offset after it.
func readName(_ b: [uint8], _ start: int) -> (string, int)? {
    var labels: [string] = []
    var at = start
    var end = -1
    var jumps = 0
    while true {
        if at >= b.count { return nil }
        let len = int(b[at])
        if len == 0 {
            at += 1
            break
        }
        if len & 0xc0 == 0xc0 {
            if at + 1 >= b.count || jumps > 32 { return nil }
            if end < 0 { end = at + 2 }
            at = (len & 0x3f) << 8 | int(b[at + 1])
            jumps += 1
            continue
        }
        if len & 0xc0 != 0 || at + 1 + len > b.count { return nil }
        labels.append(string(decoding: Array(b[(at + 1)..<(at + 1 + len)]), as: UTF8.self).lowercased())
        at += 1 + len
    }
    return (labels.joined(separator: "."), end < 0 ? at : end)
}

func writeName(_ name: string) -> [uint8] {
    var b: [uint8] = []
    for label in name.split(separator: ".") where !label.isEmpty {
        let l = [uint8](string(label).utf8).prefix(63)
        b.append(uint8(l.count))
        b += l
    }
    b.append(0)
    return b
}

/// The nameservers the host uses: /etc/resolv.conf's, else 1.1.1.1 and 8.8.8.8.
public func HostNameservers() -> [netip.Ipv4] {
    var out: [netip.Ipv4] = []
    if let text = try? fs.ReadText(fs.Path("/etc/resolv.conf")) {
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true).map { string($0) }
            if parts.count >= 2 && parts[0] == "nameserver", let a = netip.Ipv4.Parse(parts[1]) {
                out.append(a)
            }
        }
    }
    return out.isEmpty ? [netip.Ipv4(1, 1, 1, 1), netip.Ipv4(8, 8, 8, 8)] : out
}

/// Answers DNS queries for a virtual network: names in `Hosts` itself,
/// everything else by asking the upstream nameservers in turn.
public final class Forwarder {
    public let Upstreams: [netip.Ipv4]
    /// Names answered here, lower case: "host.vm.internal" → the gateway.
    public var Hosts: [string: netip.Ipv4]
    /// How long one upstream gets to answer.
    public var TimeoutMs: int32 = 2000

    public init(upstreams: [netip.Ipv4] = HostNameservers(), hosts: [string: netip.Ipv4] = [:]) {
        Upstreams = upstreams
        Hosts = hosts
    }

    /// The response to `query` (a message's bytes): local, forwarded, or
    /// SERVFAIL when no upstream answers.
    public func Answer(_ query: [uint8]) async -> [uint8]? {
        guard let q = Message.Parse(query), !q.Response else { return nil }
        if let question = q.Questions.first, q.Questions.count == 1, let ip = Hosts[question.Name] {
            var r = q.Reply()
            r.Authoritative = true
            if question.Kind == RecordType.a {
                r.Answers = [Record.A(question.Name, ip)]
            }
            return r.Encode()
        }
        for server in Upstreams {
            if let answer = await ask(server, query), let m = Message.Parse(answer), m.Id == q.Id {
                return answer
            }
        }
        return q.Reply(rcode: Rcode.serverFailure).Encode()
    }

    func ask(_ server: netip.Ipv4, _ query: [uint8]) async -> [uint8]? {
        guard var sock = try? udp.Bind(port: 0) else { return nil }
        sock.ReadTimeoutMs = TimeoutMs
        defer { sock.Close() }
        let b = server.Bytes
        guard (try? await sock.SendTo(query, to: udp.SocketAddress.IPv4(b[0], b[1], b[2], b[3], port: 53))) != nil else {
            return nil
        }
        var buf = [uint8](repeating: 0, count: 4096)
        guard let got = try? await sock.ReceiveFrom(into: &buf) else { return nil }
        let n = got.0
        if n <= 0 { return nil }
        return Array(buf[0..<n])
    }
}

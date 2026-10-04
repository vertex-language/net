// What a VM's network needs, checked: net/netip, net/ether, net/wire,
// net/dhcp, net/dns, and net/nat's Gateway end to end, a guest's frames
// in, a host TCP server answering through it.
package main

import (
    "net/dhcp"
    "net/dns"
    "net/ether"
    "net/nat"
    "net/netip"
    "net/tcp"
    "net/wire"
    "sync"
)

var failures = 0

func check(_ ok: bool, _ what: string) {
    if ok {
        print("ok    \(what)")
    } else {
        print("FAIL  \(what)")
        failures += 1
    }
}

func netipTests() {
    let a = netip.Ipv4.Parse("10.0.2.15")
    check(a == netip.Ipv4(10, 0, 2, 15) && a?.description == "10.0.2.15", "netip: parse and print an address")
    check(netip.Ipv4.Parse("10.0.2") == nil && netip.Ipv4.Parse("10.0.2.256") == nil && netip.Ipv4.Parse("01.2.3.4") == nil,
          "netip: refuse malformed addresses")
    if let p = netip.Prefix.Parse("10.0.2.15/24") {
        check(p.Mask == netip.Ipv4(255, 255, 255, 0) && p.Network == netip.Ipv4(10, 0, 2, 0) && p.Broadcast == netip.Ipv4(10, 0, 2, 255),
              "netip: a /24's mask, network and broadcast")
        check(p.Contains(netip.Ipv4(10, 0, 2, 2)) && !p.Contains(netip.Ipv4(10, 0, 3, 2)), "netip: prefix membership")
    } else {
        check(false, "netip: parse a prefix")
    }
}

func etherTests() {
    let m = ether.Mac.Random()
    check(m.Bytes[0] & 0x03 == 0x02, "ether: a random MAC is local and unicast (\(m))")
    check(ether.Mac.Random() != m, "ether: random MACs differ")
    check(ether.Mac.Parse("52:54:00:12:34:56")?.description == "52:54:00:12:34:56", "ether: parse and print a MAC")
    let f = ether.Frame(destination: .broadcast, source: m, etherType: ether.EtherType.arp, payload: [1, 2, 3])
    if let g = ether.Frame.Parse(f.Encode()) {
        check(g.Destination.IsBroadcast && g.Source == m && g.EtherType == 0x0806 && g.Payload == [1, 2, 3], "ether: frame round trip")
    } else {
        check(false, "ether: frame round trip")
    }
}

func wireTests() {
    // RFC 1071's example words sum to 0xddf2; the checksum is its complement.
    check(wire.Checksum([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]) == ~uint16(0xddf2), "wire: RFC 1071 checksum")
    let src = netip.Ipv4(10, 0, 2, 15)
    let dst = netip.Ipv4(93, 184, 216, 34)
    let arp = wire.Arp(operation: wire.Arp.request, senderMac: ether.Mac.Parse("02:00:00:00:00:01")!, senderIp: src,
                       targetMac: .zero, targetIp: netip.Ipv4(10, 0, 2, 2))
    if let a = wire.Arp.Parse(arp.Encode()) {
        check(a.Operation == 1 && a.TargetIp == netip.Ipv4(10, 0, 2, 2) && a.SenderIp == src, "wire: ARP round trip")
    } else {
        check(false, "wire: ARP round trip")
    }
    let u = wire.Udp(source: 4000, destination: 53, payload: [9, 9, 9])
    let ip = wire.Ipv4Packet(source: src, destination: dst, protocol: wire.IpProtocol.udp, payload: u.Encode(source: src, destination: dst))
    let bytes = ip.Encode()
    check(wire.Checksum(Array(bytes[0..<20])) == 0, "wire: an IPv4 header's checksum verifies")
    if let p = wire.Ipv4Packet.Parse(bytes + [0, 0, 0, 0]), let v = wire.Udp.Parse(p.Payload) {
        check(p.Source == src && p.Destination == dst && v.DestinationPort == 53 && v.Payload == [9, 9, 9],
              "wire: IPv4 + UDP round trip, frame padding dropped")
        check(wire.Checksum(p.Payload, initial: wire.PseudoHeader(source: src, destination: dst, protocol: 17, length: p.Payload.count)) == 0,
              "wire: a UDP checksum verifies over the pseudo-header")
    } else {
        check(false, "wire: IPv4 + UDP round trip")
    }
    let t = wire.Tcp(source: 5555, destination: 80, seq: 7, ack: 0, flags: wire.TcpFlags.syn, window: 29200, mss: 1400)
    let tb = t.Encode(source: src, destination: dst)
    if let s = wire.Tcp.Parse(tb) {
        check(s.Has(wire.TcpFlags.syn) && s.Mss == 1400 && s.Seq == 7 && s.Length == 1, "wire: TCP SYN with MSS round trip")
        check(wire.Checksum(tb, initial: wire.PseudoHeader(source: src, destination: dst, protocol: 6, length: tb.count)) == 0,
              "wire: a TCP checksum verifies")
    } else {
        check(false, "wire: TCP round trip")
    }
    let echo = wire.Icmp(kind: wire.Icmp.echoRequest, rest: [0, 1, 0, 2], data: [7])
    if let e = wire.Icmp.Parse(echo.Encode()) {
        let r = e.EchoReply()
        check(r.Kind == 0 && r.Rest == [0, 1, 0, 2] && r.Data == [7] && wire.Checksum(r.Encode()) == 0, "wire: ICMP echo reply")
    } else {
        check(false, "wire: ICMP parse")
    }
}

func dhcpTests() {
    var cfg = dhcp.ServerConfig(serverIp: netip.Ipv4(10, 0, 2, 2), network: netip.Prefix(netip.Ipv4(10, 0, 2, 0), bits: 24),
                                poolStart: netip.Ipv4(10, 0, 2, 15), poolEnd: netip.Ipv4(10, 0, 2, 16), dns: [netip.Ipv4(10, 0, 2, 3)])
    cfg.Reserved = [netip.Ipv4(10, 0, 2, 16)]
    let server = dhcp.Server(cfg)
    let mac = ether.Mac.Parse("02:00:00:00:00:01")!
    var d = dhcp.Message(op: 1, xid: 42, clientMac: mac)
    d.Set(dhcp.Option.messageType, [dhcp.Kind.discover])
    guard let offerMsg = server.Handle(dhcp.Message.Parse(d.Encode())!), let offer = dhcp.Message.Parse(offerMsg.Encode()) else {
        check(false, "dhcp: a DISCOVER is offered an address")
        return
    }
    check(offer.MessageType == dhcp.Kind.offer && offer.YourIp == netip.Ipv4(10, 0, 2, 15) && offer.Xid == 42, "dhcp: DISCOVER → OFFER of the pool's first address")
    let router: [uint8] = [10, 0, 2, 2]
    let nameserver: [uint8] = [10, 0, 2, 3]
    let mask: [uint8] = [255, 255, 255, 0]
    check(offer.Get(dhcp.Option.router) == router && offer.Get(dhcp.Option.dns) == nameserver && offer.Get(dhcp.Option.subnetMask) == mask,
          "dhcp: the offer names router, DNS and mask")
    var r = dhcp.Message(op: 1, xid: 43, clientMac: mac)
    r.Set(dhcp.Option.messageType, [dhcp.Kind.request])
    r.Set(dhcp.Option.requestedIp, offer.YourIp.Bytes)
    r.Set(dhcp.Option.serverId, [10, 0, 2, 2])
    check(server.Handle(r)?.MessageType == dhcp.Kind.ack, "dhcp: REQUEST → ACK")
    r.Set(dhcp.Option.requestedIp, [10, 0, 2, 99])
    check(server.Handle(r)?.MessageType == dhcp.Kind.nak, "dhcp: a REQUEST for another address → NAK")
    var other = dhcp.Message(op: 1, xid: 44, clientMac: ether.Mac.Parse("02:00:00:00:00:02")!)
    other.Set(dhcp.Option.messageType, [dhcp.Kind.discover])
    check(server.Handle(other) == nil, "dhcp: an exhausted pool (the rest reserved) offers nothing")
}

func dnsTests() async {
    var q = dns.Message.Query(id: 0x1234, name: "Example.COM", kind: dns.RecordType.a)
    q.RecursionDesired = true
    if let p = dns.Message.Parse(q.Encode()) {
        check(p.Id == 0x1234 && p.Questions == [dns.Question(name: "example.com", kind: 1)] && !p.Response, "dns: query round trip, names lower-cased")
    } else {
        check(false, "dns: query round trip")
    }
    // A compressed answer: the name is a pointer to the question's.
    var resp: [uint8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]
    resp += [7] + [uint8]("example".utf8) + [3] + [uint8]("com".utf8) + [0, 0, 1, 0, 1]
    resp += [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]
    if let m = dns.Message.Parse(resp) {
        check(m.Response && m.Answers.count == 1 && m.Answers[0].Name == "example.com" && m.Answers[0].Ipv4 == netip.Ipv4(93, 184, 216, 34),
              "dns: an answer with a compressed name")
    } else {
        check(false, "dns: parse a compressed answer")
    }
    let fwd = dns.Forwarder(upstreams: [], hosts: ["host.vm.internal": netip.Ipv4(10, 0, 2, 2)])
    let local = await fwd.Answer(dns.Message.Query(id: 7, name: "host.vm.internal", kind: dns.RecordType.a).Encode())
    if let l = local, let m = dns.Message.Parse(l) {
        check(m.Id == 7 && m.Answers.first?.Ipv4 == netip.Ipv4(10, 0, 2, 2), "dns: a local name answered by the forwarder")
    } else {
        check(false, "dns: local name")
    }
    let none = await fwd.Answer(dns.Message.Query(id: 8, name: "example.com", kind: dns.RecordType.a).Encode())
    check(none.flatMap { dns.Message.Parse($0) }?.Rcode == dns.Rcode.serverFailure, "dns: no upstream answers SERVFAIL")
    // Live: a real name, through the host's nameservers.
    let live = await dns.Forwarder().Answer(dns.Message.Query(id: 9, name: "google.com", kind: dns.RecordType.a).Encode())
    let ans = live.flatMap { dns.Message.Parse($0) }
    check(ans?.Id == 9 && ans?.Rcode == dns.Rcode.ok && (ans?.Answers.contains { $0.Ipv4 != nil } ?? false),
          "dns: google.com resolved through the host's nameservers (live)")
    check(!dns.HostNameservers().isEmpty, "dns: the host's nameservers (\(dns.HostNameservers().map { $0.description }.joined(separator: ", ")))")
}

/// A guest on the far side of a Gateway, speaking in frames. One task
/// reads everything the gateway gives into `inbox`.
final class Guest {
    let gw: nat.Gateway
    let mac = ether.Mac.Parse("02:00:00:00:00:0f")!
    var ip = netip.Ipv4.any
    let inbox = Inbox()

    init(_ gw: nat.Gateway) {
        self.gw = gw
        let box = inbox
        Task {
            while let f = try? await gw.Receive() { box.Push(f) }
        }
    }

    func send(_ p: wire.Ipv4Packet) async {
        try? await gw.Send(ether.Frame(destination: gw.Config.Mac, source: mac, etherType: ether.EtherType.ipv4, payload: p.Encode()).Encode())
    }

    /// The next frame, or nil after `ms`.
    func frame(_ ms: int = 3000) async -> ether.Frame? {
        var waited = 0
        while waited < ms {
            if let f = inbox.Pop() { return ether.Frame.Parse(f) }
            try? await Task.sleep(nanoseconds: 5_000_000)
            waited += 5
        }
        return nil
    }

    /// The next IPv4 packet for this guest, or nil after `ms`.
    func next(_ ms: int = 3000) async -> wire.Ipv4Packet? {
        while let fr = await frame(ms) {
            if fr.EtherType == ether.EtherType.ipv4 { return wire.Ipv4Packet.Parse(fr.Payload) }
        }
        return nil
    }
}

final class Inbox {
    var frames: [[uint8]] = []
    let lock = sync.Mutex()
    func Push(_ f: [uint8]) { lock.withLock { frames.append(f) } }
    func Pop() -> [uint8]? { lock.withLock { frames.isEmpty ? nil : frames.removeFirst() } }
}

final class Box { var v: [uint8]? = nil }

func gatewayTests() async {
    let gw = nat.Gateway(nat.Config.slirp)
    let g = Guest(gw)

    // ARP for the gateway is answered; for the guest's own address it is not.
    let ask = wire.Arp(operation: wire.Arp.request, senderMac: g.mac, senderIp: .any, targetMac: .zero, targetIp: netip.Ipv4(10, 0, 2, 2))
    try? await gw.Send(ether.Frame(destination: .broadcast, source: g.mac, etherType: ether.EtherType.arp, payload: ask.Encode()).Encode())
    let probe = wire.Arp(operation: wire.Arp.request, senderMac: g.mac, senderIp: .any, targetMac: .zero, targetIp: netip.Ipv4(10, 0, 2, 15))
    try? await gw.Send(ether.Frame(destination: .broadcast, source: g.mac, etherType: ether.EtherType.arp, payload: probe.Encode()).Encode())
    let first = await g.frame()
    let second = await g.frame(300)
    check(second == nil, "nat: no ARP answer for the address the guest probes")
    if let fr = first, let a = wire.Arp.Parse(fr.Payload) {
        check(a.Operation == wire.Arp.reply && a.SenderIp == netip.Ipv4(10, 0, 2, 2) && a.SenderMac == gw.Config.Mac, "nat: ARP for the gateway answered")
    } else {
        check(false, "nat: ARP for the gateway answered")
    }

    // DHCP through the gateway.
    var d = dhcp.Message(op: 1, xid: 9, clientMac: g.mac)
    d.Set(dhcp.Option.messageType, [dhcp.Kind.discover])
    let du = wire.Udp(source: 68, destination: 67, payload: d.Encode())
    await g.send(wire.Ipv4Packet(source: .any, destination: .broadcast, protocol: wire.IpProtocol.udp,
                                 payload: du.Encode(source: .any, destination: .broadcast)))
    if let p = await g.next(), let u = wire.Udp.Parse(p.Payload), let m = dhcp.Message.Parse(u.Payload) {
        check(m.MessageType == dhcp.Kind.offer && m.YourIp == netip.Ipv4(10, 0, 2, 15) && u.DestinationPort == 68,
              "nat: DHCP DISCOVER answered with 10.0.2.15 (the ARP probe for it was not)")
        g.ip = m.YourIp
    } else {
        check(false, "nat: DHCP offer")
        g.ip = netip.Ipv4(10, 0, 2, 15)
    }

    // A ping to anywhere.
    let ping = wire.Icmp(kind: wire.Icmp.echoRequest, rest: [0, 7, 0, 1], data: [1, 2, 3])
    await g.send(wire.Ipv4Packet(source: g.ip, destination: netip.Ipv4(1, 1, 1, 1), protocol: wire.IpProtocol.icmp, payload: ping.Encode()))
    if let p = await g.next(), let m = wire.Icmp.Parse(p.Payload) {
        check(m.Kind == wire.Icmp.echoReply && p.Source == netip.Ipv4(1, 1, 1, 1) && m.Data == [1, 2, 3], "nat: ping answered")
    } else {
        check(false, "nat: ping answered")
    }

    // The host's name, from the gateway's DNS.
    let q = dns.Message.Query(id: 77, name: "host.vm.internal", kind: dns.RecordType.a).Encode()
    let qu = wire.Udp(source: 3333, destination: 53, payload: q)
    let dnsIp = netip.Ipv4(10, 0, 2, 3)
    await g.send(wire.Ipv4Packet(source: g.ip, destination: dnsIp, protocol: wire.IpProtocol.udp, payload: qu.Encode(source: g.ip, destination: dnsIp)))
    if let p = await g.next(), let u = wire.Udp.Parse(p.Payload), let m = dns.Message.Parse(u.Payload) {
        check(p.Source == dnsIp && u.SourcePort == 53 && u.DestinationPort == 3333 && m.Answers.first?.Ipv4 == netip.Ipv4(10, 0, 2, 2),
              "nat: DNS at 10.0.2.3 answers host.vm.internal")
    } else {
        check(false, "nat: DNS answered")
    }

    // TCP: the guest connects to the gateway's address, which is the
    // host's loopback, where a server says hello and reads a reply.
    guard let listener = try? tcp.Listen(host: "127.0.0.1", port: 0) else {
        check(false, "nat: listen on loopback")
        return
    }
    let port = listener.LocalAddress.Port()
    let got = Box()
    Task {
        if let conn = try? await listener.Accept() {
            try? await conn.Write([uint8]("hello guest".utf8))
            var buf = [uint8](repeating: 0, count: 64)
            if let n = try? await conn.Read(into: &buf), n > 0 { got.v = Array(buf[0..<n]) }
        }
    }
    let gwIp = netip.Ipv4(10, 0, 2, 2)
    func seg(_ t: wire.Tcp) async {
        await g.send(wire.Ipv4Packet(source: g.ip, destination: gwIp, protocol: wire.IpProtocol.tcp, payload: t.Encode(source: g.ip, destination: gwIp)))
    }
    await seg(wire.Tcp(source: 40000, destination: port, seq: 100, ack: 0, flags: wire.TcpFlags.syn, mss: 1400))
    guard let sa = await g.next(), let synack = wire.Tcp.Parse(sa.Payload) else {
        check(false, "nat: SYN answered")
        return
    }
    check(synack.Has(wire.TcpFlags.syn) && synack.Has(wire.TcpFlags.ack) && synack.Ack == 101 && synack.Mss == 1460,
          "nat: SYN to the gateway connects to the host's loopback (SYN-ACK)")
    var theirs = synack.Seq &+ 1
    await seg(wire.Tcp(source: 40000, destination: port, seq: 101, ack: theirs, flags: wire.TcpFlags.ack))
    var text: [uint8] = []
    for _ in 0..<5 {
        guard let p = await g.next(), let t = wire.Tcp.Parse(p.Payload) else { break }
        if !t.Payload.isEmpty {
            text += t.Payload
            theirs = t.Seq &+ uint32(t.Payload.count)
            await seg(wire.Tcp(source: 40000, destination: port, seq: 101, ack: theirs, flags: wire.TcpFlags.ack))
            break
        }
    }
    check(string(decoding: text, as: UTF8.self) == "hello guest", "nat: the host's data reaches the guest")
    await seg(wire.Tcp(source: 40000, destination: port, seq: 101, ack: theirs, flags: wire.TcpFlags.ack | wire.TcpFlags.psh,
                       payload: [uint8]("hi host".utf8)))
    for _ in 0..<100 where got.v == nil { try? await Task.sleep(nanoseconds: 10_000_000) }
    check(got.v.map { string(decoding: $0, as: UTF8.self) } == "hi host", "nat: the guest's data reaches the host")
    listener.Close()
}

public func main() async -> int32 {
    netipTests()
    etherTests()
    wireTests()
    dhcpTests()
    await dnsTests()
    await gatewayTests()
    print(failures == 0 ? "ALL NAT CHECKS PASSED" : "\(failures) FAILED")
    return int32(failures)
}

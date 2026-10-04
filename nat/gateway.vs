// Package nat is a virtual machine's way to the internet without root,
// TUN/TAP or a bridge: a Gateway, the ether.Port the VM's network card
// plugs into, plays the router of a small private network. It answers
// ARP for itself, hands out addresses (net/dhcp), answers lookups
// (net/dns, forwarded to the host's nameservers), and carries the
// guest's UDP and TCP through ordinary host sockets, so a connection
// from the guest is a connection from the host. The gateway's own
// address reaches the host's loopback, as QEMU's slirp does.
//
//     let gw = nat.Gateway(.default)               // 192.168.127.0/24
//     let card = virtio.Net(port: gw)
package nat

import (
    "net/dhcp"
    "net/dns"
    "net/ether"
    "net/netip"
    "net/wire"
    "sync"
)

/// The private network a Gateway runs.
public struct Config {
    public var Network: netip.Prefix
    /// The router: DHCP server, default route, and the host's loopback.
    public var Gateway: netip.Ipv4
    /// Where DNS is answered (the gateway, or an address of its own).
    public var Dns: netip.Ipv4
    /// The first address DHCP hands out; the next machine gets the next.
    public var Guest: netip.Ipv4
    public var Mac: ether.Mac = ether.Mac([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02])
    /// Nameservers lookups go to; nil for the host's own.
    public var Upstreams: [netip.Ipv4]? = nil
    /// Connections to the gateway's address go to the host's 127.0.0.1.
    public var HostLoopback: bool = true
    /// A name for the host, answered with the gateway's address.
    public var HostName: string = "host.vm.internal"

    public init(network: netip.Prefix, gateway: netip.Ipv4, guest: netip.Ipv4, dns: netip.Ipv4? = nil) {
        Network = network
        Gateway = gateway
        Guest = guest
        Dns = dns ?? gateway
    }

    /// 192.168.127.0/24: gateway .1, guests from .2.
    public static let `default` = Config(network: netip.Prefix(netip.Ipv4(192, 168, 127, 0), bits: 24),
                                        gateway: netip.Ipv4(192, 168, 127, 1), guest: netip.Ipv4(192, 168, 127, 2))

    /// QEMU's user-mode network, which the Android emulator's images
    /// configure statically: 10.0.2.0/24, gateway .2 (the host), DNS .3,
    /// the guest .15.
    public static let slirp = Config(network: netip.Prefix(netip.Ipv4(10, 0, 2, 0), bits: 24),
                                     gateway: netip.Ipv4(10, 0, 2, 2), guest: netip.Ipv4(10, 0, 2, 15),
                                     dns: netip.Ipv4(10, 0, 2, 3))
}

/// The router of a VM's private network, as an ether.Port.
public final class Gateway: ether.Port {
    public let Config: Config
    public let Dhcp: dhcp.Server
    public let Dns: dns.Forwarder
    let out = ether.Queue()
    let tcp = TcpRelay()
    let udp = UdpRelay()

    public init(_ config: Config = .default) {
        Config = config
        let last = config.Network.Broadcast.Adding(~uint32(0))
        Dhcp = dhcp.Server(dhcp.ServerConfig(serverIp: config.Gateway, network: config.Network,
                                             poolStart: config.Guest, poolEnd: last, dns: [config.Dns]))
        Dhcp.Config.Reserved = [config.Gateway, config.Dns]
        var hosts: [string: netip.Ipv4] = [:]
        if !config.HostName.isEmpty { hosts[config.HostName] = config.Gateway }
        Dns = dns.Forwarder(upstreams: config.Upstreams ?? dns.HostNameservers(), hosts: hosts)
    }

    public func Receive() async throws -> [uint8] {
        await out.Pop()
    }

    public func Send(_ bytes: [uint8]) async throws {
        guard let frame = ether.Frame.Parse(bytes) else { return }
        switch frame.EtherType {
        case ether.EtherType.arp:
            if let a = wire.Arp.Parse(frame.Payload) { arp(a) }
        case ether.EtherType.ipv4:
            if let p = wire.Ipv4Packet.Parse(frame.Payload), !p.IsFragment { ipv4(p, from: frame.Source) }
        default:
            break   // IPv6 and the rest: not routed
        }
    }

    /// Whether this address is the gateway's own (it answers ARP for it).
    func ours(_ a: netip.Ipv4) -> bool {
        a == Config.Gateway || a == Config.Dns
    }

    /// Where a guest's connection to `a` really goes on the host.
    func hostAddress(_ a: netip.Ipv4) -> netip.Ipv4 {
        Config.HostLoopback && ours(a) ? netip.Ipv4.loopback : a
    }

    /// Hands the guest at `mac` an IPv4 packet.
    func deliver(_ p: wire.Ipv4Packet, to mac: ether.Mac) {
        out.Push(ether.Frame(destination: mac, source: Config.Mac, etherType: ether.EtherType.ipv4, payload: p.Encode()).Encode())
    }

    /// A UDP datagram to the guest, from `source`.
    func deliverUdp(from source: netip.Ipv4, _ sport: uint16, to dest: netip.Ipv4, _ dport: uint16, mac: ether.Mac, _ payload: [uint8]) {
        let seg = wire.Udp(source: sport, destination: dport, payload: payload)
        deliver(wire.Ipv4Packet(source: source, destination: dest, protocol: wire.IpProtocol.udp,
                                payload: seg.Encode(source: source, destination: dest)), to: mac)
    }

    func arp(_ a: wire.Arp) {
        // Only for the gateway's own addresses: answering for others
        // (the address a guest probes before taking it) would look like
        // a conflict.
        if a.Operation != wire.Arp.request || !ours(a.TargetIp) || a.SenderIp == a.TargetIp { return }
        let reply = a.Answer(Config.Mac)
        out.Push(ether.Frame(destination: a.SenderMac, source: Config.Mac, etherType: ether.EtherType.arp,
                             payload: reply.Encode()).Encode())
    }

    func ipv4(_ p: wire.Ipv4Packet, from mac: ether.Mac) {
        switch p.Protocol {
        case wire.IpProtocol.icmp:
            // Echo requests are answered here, for any address: there are
            // no unprivileged raw sockets to send them on with.
            if let m = wire.Icmp.Parse(p.Payload), m.Kind == wire.Icmp.echoRequest {
                deliver(wire.Ipv4Packet(source: p.Destination, destination: p.Source, protocol: wire.IpProtocol.icmp,
                                        payload: m.EchoReply().Encode()), to: mac)
            }
        case wire.IpProtocol.udp:
            guard let u = wire.Udp.Parse(p.Payload) else { return }
            if u.DestinationPort == 67 {
                dhcpRequest(u, from: mac)
            } else if u.DestinationPort == 53 {
                // Any nameserver the guest names is answered here.
                let src = p.Destination
                let guest = p.Source
                let q = u.Payload
                Task {
                    if let answer = await self.Dns.Answer(q) {
                        self.deliverUdp(from: src, 53, to: guest, u.SourcePort, mac: mac, answer)
                    }
                }
            } else {
                udp.Relay(self, p, u, from: mac)
            }
        case wire.IpProtocol.tcp:
            if let t = wire.Tcp.Parse(p.Payload) { tcp.Segment(self, p, t, from: mac) }
        default:
            break
        }
    }

    func dhcpRequest(_ u: wire.Udp, from mac: ether.Mac) {
        guard let req = dhcp.Message.Parse(u.Payload), let reply = Dhcp.Handle(req) else { return }
        // Before it has an address the client hears broadcast.
        let toBroadcast = reply.YourIp.IsUnspecified || req.ClientIp.IsUnspecified
        let dest = toBroadcast ? netip.Ipv4.broadcast : reply.YourIp
        deliverUdp(from: Config.Gateway, 67, to: dest, 68, mac: mac, reply.Encode())
    }
}

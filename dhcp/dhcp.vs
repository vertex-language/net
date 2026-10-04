// Package dhcp is DHCPv4 (RFC 2131, 2132): its messages, and a Server
// that hands addresses from a pool to the machines on a virtual network.
// The Server only decides what to answer; carrying messages over UDP
// (ports 67 and 68) is the caller's, as net/nat's Gateway does.
package dhcp

import (
    "encoding/binary"
    "net/ether"
    "net/netip"
    "sync"
)

/// What a message is (option 53).
public enum Kind {
    public static let discover: uint8 = 1
    public static let offer: uint8 = 2
    public static let request: uint8 = 3
    public static let decline: uint8 = 4
    public static let ack: uint8 = 5
    public static let nak: uint8 = 6
    public static let release: uint8 = 7
    public static let inform: uint8 = 8
}

/// Option codes this package reads or writes.
public enum Option {
    public static let pad: uint8 = 0
    public static let subnetMask: uint8 = 1
    public static let router: uint8 = 3
    public static let dns: uint8 = 6
    public static let hostname: uint8 = 12
    public static let domainName: uint8 = 15
    public static let broadcast: uint8 = 28
    public static let requestedIp: uint8 = 50
    public static let leaseTime: uint8 = 51
    public static let messageType: uint8 = 53
    public static let serverId: uint8 = 54
    public static let renewalTime: uint8 = 58
    public static let rebindingTime: uint8 = 59
    public static let end: uint8 = 255
}

let magic: [uint8] = [99, 130, 83, 99]

/// A DHCP message: the BOOTP header and its options.
public struct Message {
    /// 1 from a client, 2 from a server.
    public var Op: uint8
    public var Xid: uint32
    public var Secs: uint16 = 0
    /// Bit 15: the client wants the reply broadcast.
    public var Flags: uint16 = 0
    public var ClientIp: netip.Ipv4 = .any
    /// "your" address: what the server gives.
    public var YourIp: netip.Ipv4 = .any
    public var ServerIp: netip.Ipv4 = .any
    public var RelayIp: netip.Ipv4 = .any
    public var ClientMac: ether.Mac
    /// Every option but pad and end, in order, by code.
    public var Options: [(uint8, [uint8])] = []

    public init(op: uint8, xid: uint32, clientMac: ether.Mac) {
        Op = op
        Xid = xid
        ClientMac = clientMac
    }

    public func Get(_ code: uint8) -> [uint8]? {
        for (c, v) in Options where c == code { return v }
        return nil
    }

    public mutating func Set(_ code: uint8, _ value: [uint8]) {
        Options = Options.filter { $0.0 != code }
        Options.append((code, value))
    }

    /// Option 53, or 0 (plain BOOTP).
    public var MessageType: uint8 { Get(Option.messageType)?.first ?? 0 }

    public var RequestedIp: netip.Ipv4? {
        guard let v = Get(Option.requestedIp), v.count == 4 else { return nil }
        return netip.Ipv4(v)
    }

    public var ServerId: netip.Ipv4? {
        guard let v = Get(Option.serverId), v.count == 4 else { return nil }
        return netip.Ipv4(v)
    }

    public var WantsBroadcast: bool { Flags & 0x8000 != 0 }

    /// nil unless a BOOTP message with the DHCP magic cookie.
    public static func Parse(_ b: [uint8]) -> Message? {
        if b.count < 240 || Array(b[236..<240]) != magic { return nil }
        var m = Message(op: b[0], xid: binary.BigEndian.Uint32(b, from: 4), clientMac: ether.Mac(b, at: 28))
        m.Secs = binary.BigEndian.Uint16(b, from: 8)
        m.Flags = binary.BigEndian.Uint16(b, from: 10)
        m.ClientIp = netip.Ipv4(b, at: 12)
        m.YourIp = netip.Ipv4(b, at: 16)
        m.ServerIp = netip.Ipv4(b, at: 20)
        m.RelayIp = netip.Ipv4(b, at: 24)
        var i = 240
        while i < b.count {
            let code = b[i]
            if code == Option.end { break }
            if code == Option.pad {
                i += 1
                continue
            }
            if i + 1 >= b.count { break }
            let len = int(b[i + 1])
            if i + 2 + len > b.count { break }
            m.Options.append((code, Array(b[(i + 2)..<(i + 2 + len)])))
            i += 2 + len
        }
        return m
    }

    /// The message, padded to BOOTP's 300-byte minimum.
    public func Encode() -> [uint8] {
        var b = [uint8](repeating: 0, count: 236)
        b[0] = Op
        b[1] = 1    // Ethernet
        b[2] = 6
        binary.BigEndian.PutUint32(&b, Xid, at: 4)
        binary.BigEndian.PutUint16(&b, Secs, at: 8)
        binary.BigEndian.PutUint16(&b, Flags, at: 10)
        b.replaceSubrange(12..<16, with: ClientIp.Bytes)
        b.replaceSubrange(16..<20, with: YourIp.Bytes)
        b.replaceSubrange(20..<24, with: ServerIp.Bytes)
        b.replaceSubrange(24..<28, with: RelayIp.Bytes)
        b.replaceSubrange(28..<34, with: ClientMac.Bytes)
        b += magic
        for (c, v) in Options {
            b.append(c)
            b.append(uint8(min(v.count, 255)))
            b += v.prefix(255)
        }
        b.append(Option.end)
        while b.count < 300 { b.append(0) }
        return b
    }
}

/// How a Server's network looks.
public struct ServerConfig {
    /// The server's address: its identifier, and the router it names.
    public var ServerIp: netip.Ipv4
    public var Network: netip.Prefix
    /// The addresses it hands out, first to last; one machine, one address.
    public var PoolStart: netip.Ipv4
    public var PoolEnd: netip.Ipv4
    /// Nameservers the clients are told to use.
    public var Dns: [netip.Ipv4]
    /// The default route (option 3); nil for none.
    public var Router: netip.Ipv4?
    public var DomainName: string = ""
    /// Addresses in the pool never handed out (the server's own).
    public var Reserved: [netip.Ipv4] = []
    public var LeaseSeconds: uint32 = 86_400

    public init(serverIp: netip.Ipv4, network: netip.Prefix, poolStart: netip.Ipv4, poolEnd: netip.Ipv4,
                dns: [netip.Ipv4], router: netip.Ipv4? = nil) {
        ServerIp = serverIp
        Network = network
        PoolStart = poolStart
        PoolEnd = poolEnd
        Dns = dns
        Router = router ?? serverIp
    }
}

/// A DHCP server's decisions: which address each machine (by MAC) has,
/// and the reply to each message. Safe from any task.
public final class Server {
    public var Config: ServerConfig
    var leases: [ether.Mac: netip.Ipv4] = [:]
    let lock = sync.Mutex()

    public init(_ config: ServerConfig) {
        Config = config
    }

    /// The address `mac` holds or would be offered: the one it had, else
    /// the first free one in the pool.
    public func AddressFor(_ mac: ether.Mac) -> netip.Ipv4? {
        lock.withLock { () -> netip.Ipv4? in
            if let a = leases[mac] { return a }
            var taken = Set(leases.values)
            for r in Config.Reserved { taken.insert(r) }
            var a = Config.PoolStart
            while a <= Config.PoolEnd {
                if !taken.contains(a) {
                    leases[mac] = a
                    return a
                }
                a = a.Adding(1)
            }
            return nil
        }
    }

    /// Who holds `ip`, if anyone.
    public func Holder(_ ip: netip.Ipv4) -> ether.Mac? {
        lock.withLock { () -> ether.Mac? in
            for (m, a) in leases where a == ip { return m }
            return nil
        }
    }

    /// The reply to `request`, or nil when none is due (a release, a
    /// decline, a request meant for another server).
    public func Handle(_ request: Message) -> Message? {
        if request.Op != 1 { return nil }
        switch request.MessageType {
        case Kind.discover:
            guard let a = AddressFor(request.ClientMac) else { return nil }
            return reply(request, Kind.offer, a)
        case Kind.request:
            if let s = request.ServerId, s != Config.ServerIp { return nil }
            guard let a = AddressFor(request.ClientMac) else { return nil }
            let asked = request.RequestedIp ?? request.ClientIp
            if !asked.IsUnspecified && asked != a {
                return reply(request, Kind.nak, .any)
            }
            return reply(request, Kind.ack, a)
        case Kind.inform:
            var r = reply(request, Kind.ack, .any)
            r.ClientIp = request.ClientIp
            r.Options = r.Options.filter { $0.0 != Option.leaseTime && $0.0 != Option.renewalTime && $0.0 != Option.rebindingTime }
            return r
        case Kind.release, Kind.decline:
            lock.withLock { _ = leases.removeValue(forKey: request.ClientMac) }
            return nil
        default:
            return nil
        }
    }

    func reply(_ req: Message, _ kind: uint8, _ yours: netip.Ipv4) -> Message {
        var m = Message(op: 2, xid: req.Xid, clientMac: req.ClientMac)
        m.Flags = req.Flags
        m.YourIp = yours
        m.ServerIp = Config.ServerIp
        m.RelayIp = req.RelayIp
        m.Set(Option.messageType, [kind])
        m.Set(Option.serverId, Config.ServerIp.Bytes)
        if kind == Kind.nak { return m }
        var lease: [uint8] = []
        binary.BigEndian.AppendUint32(&lease, Config.LeaseSeconds)
        m.Set(Option.leaseTime, lease)
        var t1: [uint8] = []
        binary.BigEndian.AppendUint32(&t1, Config.LeaseSeconds / 2)
        m.Set(Option.renewalTime, t1)
        var t2: [uint8] = []
        binary.BigEndian.AppendUint32(&t2, Config.LeaseSeconds / 8 * 7)
        m.Set(Option.rebindingTime, t2)
        m.Set(Option.subnetMask, Config.Network.Mask.Bytes)
        m.Set(Option.broadcast, Config.Network.Broadcast.Bytes)
        if let r = Config.Router { m.Set(Option.router, r.Bytes) }
        if !Config.Dns.isEmpty { m.Set(Option.dns, Config.Dns.flatMap { $0.Bytes }) }
        if !Config.DomainName.isEmpty { m.Set(Option.domainName, [uint8](Config.DomainName.utf8)) }
        return m
    }
}

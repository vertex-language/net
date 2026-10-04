package nat

import (
    "net/ether"
    "net/netip"
    "net/udp"
    "net/wire"
    "sync"
    "time"
)

/// A guest's UDP flow, by its two ends.
struct UdpFlow: Hashable {
    var Guest: netip.Ipv4
    var GuestPort: uint16
    var Remote: netip.Ipv4
    var RemotePort: uint16
}

/// One host socket per flow; its replies go back to the guest as from
/// the address it wrote to. A flow quiet for two minutes is closed.
final class UdpSession {
    let flow: UdpFlow
    let mac: ether.Mac
    var sock: udp.UdpSocket
    var last = time.Instant.Now()
    var closed = false

    init(flow: UdpFlow, mac: ether.Mac, sock: udp.UdpSocket) {
        self.flow = flow
        self.mac = mac
        self.sock = sock
    }
}

final class UdpRelay {
    var sessions: [UdpFlow: UdpSession]
    let lock = sync.Mutex()

    init() {
        sessions = [:]
    }
    static let idleMs: int64 = 120_000

    func Relay(_ gw: Gateway, _ p: wire.Ipv4Packet, _ u: wire.Udp, from mac: ether.Mac) {
        let flow = UdpFlow(Guest: p.Source, GuestPort: u.SourcePort, Remote: p.Destination, RemotePort: u.DestinationPort)
        var created: UdpSession? = nil
        let s = lock.withLock { () -> UdpSession? in
            if let s = sessions[flow] { return s }
            guard var sock = try? udp.Bind(port: 0) else { return nil }
            sock.ReadTimeoutMs = 30_000
            let s = UdpSession(flow: flow, mac: mac, sock: sock)
            sessions[flow] = s
            created = s
            return s
        }
        guard let session = s else { return }
        session.last = time.Instant.Now()
        let target = gw.hostAddress(p.Destination).Bytes
        let to = udp.SocketAddress.IPv4(target[0], target[1], target[2], target[3], port: u.DestinationPort)
        let payload = u.Payload
        let sock = session.sock
        Task { _ = try? await sock.SendTo(payload, to: to) }
        if let c = created {
            Task { await self.receive(gw, c) }
        }
    }

    /// Replies to the guest until the flow has been idle long enough.
    func receive(_ gw: Gateway, _ s: UdpSession) async {
        var buf = [uint8](repeating: 0, count: 65536)
        while true {
            do {
                let (n, _) = try await s.sock.ReceiveFrom(into: &buf)
                s.last = time.Instant.Now()
                gw.deliverUdp(from: s.flow.Remote, s.flow.RemotePort, to: s.flow.Guest, s.flow.GuestPort,
                              mac: s.mac, Array(buf[0..<n]))
            } catch {
                // A timeout: close if the guest has also gone quiet.
                if s.last.Elapsed().AsMilliseconds() < UdpRelay.idleMs { continue }
                break
            }
        }
        lock.withLock { _ = sessions.removeValue(forKey: s.flow) }
        s.sock.Close()
    }
}

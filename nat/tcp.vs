package nat

import (
    "crypto/rand"
    "encoding/binary"
    "net/ether"
    "net/netip"
    "net/tcp"
    "net/wire"
    "sync"
)

// The guest's TCP connections, each carried on a host socket.
//
// Toward the guest this is the sending half of a TCP: what the host
// socket gives is cut into segments of the guest's MSS, sent only as far
// as the guest's window allows, kept until the guest acknowledges it, and
// sent again when an acknowledgement is slow to come (a frame the guest's
// card had no room for is lost, as on any wire). Toward the host, the
// guest's segments are taken in order and written to the socket in that
// order; anything else is answered with the ACK the guest needs. A FIN
// either way is a half-close passed on.

struct TcpFlow: Hashable {
    var Guest: netip.Ipv4
    var GuestPort: uint16
    var Remote: netip.Ipv4
    var RemotePort: uint16
}

final class TcpSession {
    let flow: TcpFlow
    let mac: ether.Mac
    let lock = sync.Mutex()
    var stream: tcp.TcpStream? = nil
    /// The next sequence number expected from the guest.
    var guestSeq: uint32
    /// The next sequence number sent to the guest.
    var seq: uint32
    /// The first byte the guest hasn't acknowledged.
    var acked: uint32
    /// The largest segment the guest takes, and its window (unscaled: no
    /// window scaling is agreed).
    var mss = 1460
    var window = 65535
    /// Sent and not yet acknowledged: the bytes from `acked` on.
    var unacked: [uint8] = []
    /// From the guest, in order, waiting for the host socket.
    var outbox: [[uint8]] = []
    var writing = false
    var guestFin = false
    var finSent = false
    var closed = false

    init(flow: TcpFlow, mac: ether.Mac, guestIsn: uint32) {
        self.flow = flow
        self.mac = mac
        guestSeq = guestIsn &+ 1
        let r = (try? rand.Bytes(4)) ?? [0, 0, 0x10, 0]
        seq = binary.BigEndian.Uint32(r, from: 0)
        acked = seq
    }

    var inFlight: int { int(seq &- acked) }
}

final class TcpRelay {
    var sessions: [TcpFlow: TcpSession]
    let lock = sync.Mutex()

    init() {
        sessions = [:]
    }

    func session(_ f: TcpFlow) -> TcpSession? { lock.withLock { sessions[f] } }
    func remove(_ f: TcpFlow) { lock.withLock { _ = sessions.removeValue(forKey: f) } }

    /// One segment to the guest. Call with the session locked (or before it is shared).
    func send(_ gw: Gateway, _ s: TcpSession, _ flags: uint8, _ payload: [uint8] = [], seq: uint32? = nil, mss: uint16? = nil) {
        let t = wire.Tcp(source: s.flow.RemotePort, destination: s.flow.GuestPort, seq: seq ?? s.seq, ack: s.guestSeq,
                         flags: flags, window: 65535, mss: mss, payload: payload)
        gw.deliver(wire.Ipv4Packet(source: s.flow.Remote, destination: s.flow.Guest, protocol: wire.IpProtocol.tcp,
                                   payload: t.Encode(source: s.flow.Remote, destination: s.flow.Guest)), to: s.mac)
    }

    /// Sends what the guest's window has room for. Session locked.
    func pump(_ gw: Gateway, _ s: TcpSession) {
        while s.inFlight < s.unacked.count {
            let room = s.window - s.inFlight
            if room <= 0 { return }
            let start = s.inFlight
            let n = min(s.mss, min(room, s.unacked.count - start))
            if n <= 0 { return }
            send(gw, s, wire.TcpFlags.ack | wire.TcpFlags.psh, Array(s.unacked[start..<(start + n)]))
            s.seq &+= uint32(n)
        }
    }

    /// Sends the first unacknowledged segment again. Session locked.
    func retransmit(_ gw: Gateway, _ s: TcpSession) {
        if s.unacked.isEmpty { return }
        let n = min(s.mss, s.unacked.count)
        send(gw, s, wire.TcpFlags.ack | wire.TcpFlags.psh, Array(s.unacked[0..<n]), seq: s.acked)
    }

    /// A reset for a segment that belongs to no connection.
    func reset(_ gw: Gateway, _ p: wire.Ipv4Packet, _ t: wire.Tcp, mac: ether.Mac) {
        let ack = t.Has(wire.TcpFlags.ack)
        let r = wire.Tcp(source: t.DestinationPort, destination: t.SourcePort, seq: ack ? t.Ack : 0,
                         ack: t.Seq &+ t.Length, flags: ack ? wire.TcpFlags.rst : wire.TcpFlags.rst | wire.TcpFlags.ack, window: 0)
        gw.deliver(wire.Ipv4Packet(source: p.Destination, destination: p.Source, protocol: wire.IpProtocol.tcp,
                                   payload: r.Encode(source: p.Destination, destination: p.Source)), to: mac)
    }

    func Segment(_ gw: Gateway, _ p: wire.Ipv4Packet, _ t: wire.Tcp, from mac: ether.Mac) {
        let flow = TcpFlow(Guest: p.Source, GuestPort: t.SourcePort, Remote: p.Destination, RemotePort: t.DestinationPort)

        // A new connection: open the host's, then answer the SYN.
        if t.Has(wire.TcpFlags.syn) && !t.Has(wire.TcpFlags.ack) {
            let s = lock.withLock { () -> TcpSession? in
                if sessions[flow] != nil { return nil }   // the SYN again, while connecting
                let s = TcpSession(flow: flow, mac: mac, guestIsn: t.Seq)
                if let m = t.Mss, m > 0 { s.mss = min(int(m), 1460) }
                s.window = int(t.Window)
                sessions[flow] = s
                return s
            }
            if let s = s { connect(gw, s, gw.hostAddress(p.Destination)) }
            return
        }

        guard let s = session(flow) else {
            if !t.Has(wire.TcpFlags.rst) { reset(gw, p, t, mac: mac) }
            return
        }
        if t.Has(wire.TcpFlags.rst) {
            close(s)
            return
        }

        var finished = false
        s.lock.withLock {
            // What the guest acknowledges leaves the send buffer.
            if t.Has(wire.TcpFlags.ack) {
                let advanced = int(t.Ack &- s.acked)
                if advanced > 0 && advanced <= s.inFlight + 1 {
                    s.unacked.removeFirst(min(advanced, s.unacked.count))
                    s.acked = t.Ack
                }
                s.window = int(t.Window)
                pump(gw, s)
                if s.finSent && s.guestFin && s.acked == s.seq { finished = true }
            }
            // Data and FIN only in order; anything else gets the ACK of what is expected.
            if t.Payload.isEmpty && !t.Has(wire.TcpFlags.fin) { return }
            if t.Seq != s.guestSeq {
                send(gw, s, wire.TcpFlags.ack)
                return
            }
            if !t.Payload.isEmpty {
                s.guestSeq &+= uint32(t.Payload.count)
                s.outbox.append(t.Payload)
            }
            if t.Has(wire.TcpFlags.fin) && !s.guestFin {
                s.guestFin = true
                s.guestSeq &+= 1
                if s.finSent && s.acked == s.seq { finished = true }
            }
            send(gw, s, wire.TcpFlags.ack)
        }
        drain(s)
        if finished { close(s) }
    }

    func connect(_ gw: Gateway, _ s: TcpSession, _ host: netip.Ipv4) {
        Task {
            guard let stream = try? await tcp.Connect(host: host.description, port: s.flow.RemotePort) else {
                // Refused or unreachable: the guest's SYN is reset.
                s.lock.withLock { self.send(gw, s, wire.TcpFlags.rst | wire.TcpFlags.ack) }
                self.remove(s.flow)
                return
            }
            s.lock.withLock {
                s.stream = stream
                // SYN-ACK, with the MSS a 1500-byte MTU holds.
                self.send(gw, s, wire.TcpFlags.syn | wire.TcpFlags.ack, mss: 1460)
                s.seq &+= 1
                s.acked = s.seq
            }
            Task { await self.watch(gw, s) }
            await self.read(gw, s, stream)
        }
    }

    /// Retransmits what the guest is slow to acknowledge; gives up on a
    /// guest that has acknowledged nothing for a minute.
    func watch(_ gw: Gateway, _ s: TcpSession) async {
        var lastAcked: uint32 = 0
        var idle = 0
        while true {
            try? await Task.sleep(nanoseconds: 100_000_000)
            let stop = s.lock.withLock { () -> bool in
                if s.closed { return true }
                if s.unacked.isEmpty || s.acked != lastAcked {
                    lastAcked = s.acked
                    idle = 0
                    return false
                }
                idle += 1
                // 300 ms without progress, then back off.
                if idle == 3 || idle == 8 || (idle > 8 && idle % 10 == 0) { retransmit(gw, s) }
                return idle > 600
            }
            if stop { break }
        }
        let abandoned = s.lock.withLock { !s.closed }
        if abandoned { close(s) }
    }

    /// The host's data to the guest, then its FIN.
    func read(_ gw: Gateway, _ s: TcpSession, _ stream: tcp.TcpStream) async {
        var buf = [uint8](repeating: 0, count: 16384)
        while true {
            // Hold off while the guest has plenty still to take.
            while s.lock.withLock({ !s.closed && s.unacked.count >= 4 * 65535 }) {
                try? await Task.sleep(nanoseconds: 5_000_000)
            }
            guard let n = try? await stream.Read(into: &buf), n > 0 else { break }
            let chunk = Array(buf[0..<n])
            s.lock.withLock {
                s.unacked += chunk
                pump(gw, s)
            }
        }
        // The host closed its side: FIN once the data is through.
        while s.lock.withLock({ !s.closed && !s.unacked.isEmpty }) {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        var finished = false
        s.lock.withLock {
            if !s.closed && !s.finSent {
                s.finSent = true
                send(gw, s, wire.TcpFlags.fin | wire.TcpFlags.ack)
                s.seq &+= 1
                if s.guestFin { finished = true }
            }
        }
        // Both sides done: keep the session a moment for the guest's last ACK.
        if finished {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            close(s)
        }
    }

    /// Writes what the guest sent to the host socket, in order, one write
    /// at a time; the guest's FIN, after its data, half-closes the socket.
    func drain(_ s: TcpSession) {
        let start = s.lock.withLock { () -> bool in
            if s.writing || s.outbox.isEmpty { return false }
            s.writing = true
            return true
        }
        if !start {
            let fin = s.lock.withLock { s.guestFin && !s.writing && s.outbox.isEmpty }
            if fin, let st = s.lock.withLock({ s.stream }) { try? st.Shutdown(.write) }
            return
        }
        Task {
            while true {
                let next = s.lock.withLock { () -> [uint8]? in
                    if s.outbox.isEmpty {
                        s.writing = false
                        return nil
                    }
                    return s.outbox.removeFirst()
                }
                guard let data = next else { break }
                if let st = s.lock.withLock({ s.stream }) { try? await st.Write(data) }
            }
            let fin = s.lock.withLock { s.guestFin && s.outbox.isEmpty }
            if fin, let st = s.lock.withLock({ s.stream }) { try? st.Shutdown(.write) }
        }
    }

    func close(_ s: TcpSession) {
        let st = s.lock.withLock { () -> tcp.TcpStream? in
            if s.closed { return nil }
            s.closed = true
            s.unacked = []
            let st = s.stream
            s.stream = nil
            return st
        }
        st?.Close()
        remove(s.flow)
    }
}

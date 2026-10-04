// Package ether is the link layer a virtual machine's network card sits
// on: MAC addresses, Ethernet frames, and Port, what a NIC plugs into.
// A Port is a network: net/nat's Gateway (the internet, through the
// host), a Pipe's other end, or anything else that takes and gives frames.
package ether

import (
    "crypto/rand"
    "encoding/binary"
    "os/sys"
    "sync"
)

/// A 48-bit MAC address.
public struct Mac: Equatable, Hashable, CustomStringConvertible {
    public let Bytes: [uint8]

    /// Six bytes; anything else is the zero address.
    public init(_ bytes: [uint8]) {
        Bytes = bytes.count == 6 ? bytes : [0, 0, 0, 0, 0, 0]
    }

    /// The six bytes at `at` in `b`.
    public init(_ b: [uint8], at: int) {
        Bytes = at >= 0 && at + 6 <= b.count ? Array(b[at..<(at + 6)]) : [0, 0, 0, 0, 0, 0]
    }

    /// A random, locally administered, unicast address: what a VM's card
    /// gets unless it is given one.
    public static func Random() -> Mac {
        var b = (try? rand.Bytes(6)) ?? [0x02, 0x56, 0x54, 0x58, 0x00, 0x01]
        b[0] = (b[0] & 0xfe) | 0x02
        return Mac(b)
    }

    /// "52:54:00:12:34:56", or nil.
    public static func Parse(_ s: string) -> Mac? {
        let parts = s.split(separator: ":")
        if parts.count != 6 { return nil }
        var b: [uint8] = []
        for p in parts {
            guard p.count == 2, let v = uint8(string(p), radix: 16) else { return nil }
            b.append(v)
        }
        return Mac(b)
    }

    public var IsBroadcast: bool { Bytes.allSatisfy { $0 == 0xff } }
    public var IsMulticast: bool { Bytes[0] & 1 != 0 }

    public static let broadcast = Mac([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    public static let zero = Mac([0, 0, 0, 0, 0, 0])

    public var description: string {
        var s = ""
        for i in 0..<6 {
            if i > 0 { s += ":" }
            let hex = string(Bytes[i], radix: 16)
            if hex.count == 1 { s += "0" }
            s += hex
        }
        return s
    }
}

/// What an Ethernet frame carries.
public enum EtherType {
    public static let ipv4: uint16 = 0x0800
    public static let arp: uint16 = 0x0806
    public static let ipv6: uint16 = 0x86dd
}

/// An Ethernet II frame: no preamble, no FCS (a virtual card has neither).
public struct Frame {
    public var Destination: Mac
    public var Source: Mac
    public var EtherType: uint16
    public var Payload: [uint8]

    public init(destination: Mac, source: Mac, etherType: uint16, payload: [uint8]) {
        Destination = destination
        Source = source
        EtherType = etherType
        Payload = payload
    }

    /// nil if shorter than a header.
    public static func Parse(_ b: [uint8]) -> Frame? {
        if b.count < 14 { return nil }
        return Frame(destination: Mac(b, at: 0), source: Mac(b, at: 6),
                     etherType: binary.BigEndian.Uint16(b, from: 12), payload: Array(b[14...]))
    }

    public func Encode() -> [uint8] {
        var out = Destination.Bytes + Source.Bytes
        binary.BigEndian.AppendUint16(&out, EtherType)
        out.append(contentsOf: Payload)
        return out
    }
}

/// A network a card plugs into: Send gives it a frame from the card,
/// Receive waits for the next frame for the card.
public protocol Port: AnyObject {
    func Receive() async throws -> [uint8]
    func Send(_ frame: [uint8]) async throws
}

/// Frames waiting for a card, pushed from any thread or task and taken
/// by one task that waits without polling (on a pipe the pusher writes
/// a byte to). What a Port implementation keeps its output in.
public final class Queue {
    var frames: [[uint8]] = []
    var head = 0
    let lock = sync.Mutex()
    let wake: (read: int32, write: int32)?

    public init() {
        wake = sys.WakePipe()
    }

    deinit {
        if let w = wake {
            _ = sys.Close(w.read)
            _ = sys.Close(w.write)
        }
    }

    /// Adds a frame and wakes the task in Pop.
    public func Push(_ frame: [uint8]) {
        lock.withLock { frames.append(frame) }
        if let w = wake {
            var b: uint8 = 1
            _ = withUnsafePointer(to: &b) { sys.Write(w.write, UnsafeRawPointer($0), 1) }
        }
    }

    /// The next frame, waiting for one.
    public func Pop() async -> [uint8] {
        while true {
            let next = lock.withLock { () -> [uint8]? in
                if head >= frames.count { return nil }
                let f = frames[head]
                head += 1
                if head > 64 && head * 2 > frames.count {
                    frames.removeFirst(head)
                    head = 0
                }
                return f
            }
            if let f = next { return f }
            if let w = wake {
                _ = await sys.vertex_task_wait_fd(w.read, 1, -1)
                var buf = [uint8](repeating: 0, count: 64)
                while buf.withUnsafeMutableBytes({ sys.Read(w.read, $0.baseAddress!, 64) }) > 0 {}
            } else {
                try? await Task.sleep(nanoseconds: 1_000_000)
            }
        }
    }

    /// Frames waiting.
    public var Count: int { lock.withLock { frames.count - head } }
}

/// Two ports joined back to back: what one is sent, the other receives.
/// For two VMs on one wire, or a test standing in for a network.
public func Pipe() -> (PipeEnd, PipeEnd) {
    let a = Queue()
    let b = Queue()
    return (PipeEnd(inbox: a, peer: b), PipeEnd(inbox: b, peer: a))
}

/// One end of a Pipe.
public final class PipeEnd: Port {
    let inbox: Queue
    let peer: Queue

    init(inbox: Queue, peer: Queue) {
        self.inbox = inbox
        self.peer = peer
    }

    public func Receive() async throws -> [uint8] { await inbox.Pop() }
    public func Send(_ frame: [uint8]) async throws { peer.Push(frame) }
}

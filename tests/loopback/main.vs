// Unified loopback test suite for 'net': verifies TCP and UDP over loopback sockets.
package main

import tcp
import udp

var failures = 0

func check(_ ok: bool, _ what: string) {
    if ok {
        print("ok    \(what)")
    } else {
        print("FAIL  \(what)")
        failures += 1
    }
}

func same(_ buf: [uint8], _ count: int, _ text: string) -> bool {
    var i = 0
    for b in text.utf8 {
        if i >= count || buf[i] != b {
            return false
        }
        i += 1
    }
    return i == count
}

func sameExact(_ buf: [uint8], _ text: string) -> bool {
    return same(buf, buf.count, text)
}

// === TCP CHECKS ===

func testTcpAddresses() {
    let a = try? tcp.SocketAddress.Parse("127.0.0.1:8080")
    check(a != nil && a!.Port() == 8080, "tcp: parse an IPv4 address")

    let b = try? tcp.SocketAddress.Parse("[::1]:9090")
    check(b != nil && b!.ToString() == "[::1]:9090", "tcp: parse and print an IPv6 address")

    let c = try? tcp.SocketAddress.Parse(":3000")
    check(c != nil && c!.Host() == "0.0.0.0", "tcp: an empty host is every interface")

    let d = try? tcp.SocketAddress.Parse("::1:9090")
    check(d == nil, "tcp: an unbracketed IPv6 address is rejected")
}

func testTcpEcho() async {
    do {
        let listener = try tcp.Listen("127.0.0.1:0")
        let port = listener.LocalAddress.Port()
        let server = Task { () async -> int in
            do {
                let s = try await listener.Accept()
                var buf = [uint8](repeating: 0, count: 64)
                let n = try await s.Read(into: &buf)
                try await s.Write(buf[0..<n])
                s.Close()
                return n
            } catch {
                return -1
            }
        }
        let c = try await tcp.Connect(host: "127.0.0.1", port: port)
        check(c.PeerAddress.Port() == port, "tcp: connect reports the peer's port")
        try await c.WriteText("hello")
        var buf = [uint8](repeating: 0, count: 5)
        try await c.ReadFull(into: &buf)
        check(sameExact(buf, "hello"), "tcp: echo round trip")
        c.Close()
        check((await server.value) == 5, "tcp: server read what the client wrote")
        listener.Close()
    } catch {
        check(false, "tcp: echo round trip")
    }
}

func testTcpRefused() async {
    do {
        let l = try tcp.Listen("127.0.0.1:0")
        let port = l.LocalAddress.Port()
        l.Close()

        var wasRefused = false
        do {
            let c = try await tcp.Connect(host: "127.0.0.1", port: port, timeoutMs: 1000)
            c.Close()
        } catch tcp.TcpError.connectionRefused(_) {
            wasRefused = true
        } catch {
            wasRefused = false
        }
        check(wasRefused, "tcp: connecting to a closed port is refused")
    } catch {
        check(false, "tcp: connecting to a closed port is refused")
    }
}

// === UDP CHECKS ===

func testUdpAddresses() {
    let a = try? udp.SocketAddress.Parse("127.0.0.1:9000")
    check(a != nil && a!.Host() == "127.0.0.1", "udp: parse IPv4 host")
    check(a != nil && a!.Port() == 9000, "udp: parse IPv4 port")
    check(a != nil && a!.ToString() == "127.0.0.1:9000", "udp: format IPv4 address")

    let b = try? udp.SocketAddress.Parse("[::1]:9001")
    check(b != nil && b!.Host() == "::1", "udp: parse IPv6 host")
    check(b != nil && b!.Port() == 9001, "udp: parse IPv6 port")
    check(b != nil && b!.ToString() == "[::1]:9001", "udp: format IPv6 address")

    let c = try? udp.SocketAddress.Parse("::1:9002")
    check(c == nil, "udp: unbracketed IPv6 address rejected")

    let d = try? udp.SocketAddress.Parse(":9003")
    check(d != nil && d!.Host() == "0.0.0.0", "udp: empty host binds all interfaces")
}

func testUdpEcho() async {
    do {
        let server = try udp.Bind("127.0.0.1:0")
        defer { server.Close() }
        let client = try udp.Bind("127.0.0.1:0")
        defer { client.Close() }

        let sPort = server.LocalAddress.Port()
        let cPort = client.LocalAddress.Port()
        check(sPort > 0, "udp: server allocated ephemeral port")
        check(cPort > 0, "udp: client allocated ephemeral port")

        let serverTask = Task { () async -> int in
            do {
                var sbuf = [uint8](repeating: 0, count: 256)
                let (sn, sender) = try await server.ReceiveFrom(into: &sbuf)
                _ = try await server.SendTo(sbuf[0..<sn], to: sender)
                return sn
            } catch {
                return -1
            }
        }

        let sent = try await client.SendText("hello udp", to: "127.0.0.1:\(sPort)")
        check(sent == 9, "udp: client sent 9 bytes")

        var cbuf = [uint8](repeating: 0, count: 256)
        let (rcvd, sender) = try await client.ReceiveFrom(into: &cbuf)
        check(rcvd == 9, "udp: client received 9 bytes")
        check(sender.Port() == sPort, "udp: reply sender matches server port")
        check(same(cbuf, rcvd, "hello udp"), "udp: payload matches sent text")

        let serverReceived = await serverTask.value
        check(serverReceived == 9, "udp: server received complete datagram")
    } catch {
        check(false, "udp: echo communication failed")
    }
}

func main() async -> int32 {
    print("Running TCP checks...")
    testTcpAddresses()
    await testTcpEcho()
    await testTcpRefused()

    print("Running UDP checks...")
    testUdpAddresses()
    await testUdpEcho()

    if failures == 0 {
        print("all net checks passed")
        return 0
    }
    print("\(failures) checks failed")
    return int32(failures)
}

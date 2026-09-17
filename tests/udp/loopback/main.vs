// net/udp checked against itself over loopback sockets.
package main

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

func addressTests() {
    do {
        let a = try udp.SocketAddress.Parse("127.0.0.1:8080")
        check(a.Host() == "127.0.0.1", "parse IPv4 host")
        check(a.Port() == 8080, "parse IPv4 port")
        check(a.ToString() == "127.0.0.1:8080", "format IPv4 address")
    } catch {
        check(false, "parse IPv4 address")
    }

    do {
        let b = try udp.SocketAddress.Parse("[::1]:9000")
        check(b.Host() == "::1", "parse IPv6 host")
        check(b.Port() == 9000, "parse IPv6 port")
        check(b.ToString() == "[::1]:9000", "format IPv6 address")
    } catch {
        check(false, "parse IPv6 address")
    }

    do {
        _ = try udp.SocketAddress.Parse("::1:9000")
        check(false, "unbracketed IPv6 address rejected")
    } catch {
        check(true, "unbracketed IPv6 address rejected")
    }

    do {
        let c = try udp.SocketAddress.Parse(":5000")
        check(c.Host() == "0.0.0.0", "empty host binds all interfaces")
        check(c.Port() == 5000, "empty host port")
    } catch {
        check(false, "empty host address")
    }
}

func roundTripTest() async {
    do {
        let server = try udp.Bind("127.0.0.1:0")
        let serverPort = server.LocalAddress.Port()
        check(serverPort > 0, "server allocated ephemeral port")

        var client = try udp.Bind("127.0.0.1:0")
        let clientPort = client.LocalAddress.Port()
        check(clientPort > 0, "client allocated ephemeral port")

        let serverTask = Task { () async -> int in
            do {
                var sbuf = [uint8](repeating: 0, count: 256)
                let (n, sender) = try await server.ReceiveFrom(into: &sbuf)
                _ = try await server.SendTo(sbuf[0..<n], to: sender)
                return n
            } catch {
                return -1
            }
        }

        let sent = try await client.SendText("hello udp", to: "127.0.0.1:\(serverPort)")
        check(sent == 9, "client sent 9 bytes")

        var cbuf = [uint8](repeating: 0, count: 256)
        let (rcvd, sender) = try await client.ReceiveFrom(into: &cbuf)
        check(rcvd == 9, "client received 9 bytes")
        check(sender.Port() == serverPort, "sender port matches server port")
        check(same(cbuf, rcvd, "hello udp"), "payload matches sent text")

        let serverReceived = await serverTask.value
        check(serverReceived == 9, "server received complete datagram")

        server.Close()
        client.Close()
    } catch let e as udp.UdpError {
        check(false, "round trip failed: \(e.Message)")
    } catch {
        check(false, "round trip failed")
    }
}

func connectedModeTest() async {
    do {
        let server = try udp.Bind("127.0.0.1:0")
        let serverPort = server.LocalAddress.Port()

        var client = try udp.Bind("127.0.0.1:0")
        try client.Connect("127.0.0.1:\(serverPort)")

        if let peer = client.PeerAddress() {
            check(peer.Port() == serverPort, "connected peer port matches")
        } else {
            check(false, "peer address available after connect")
        }

        let serverTask = Task { () async -> int in
            do {
                var sbuf = [uint8](repeating: 0, count: 128)
                let (n, sender) = try await server.ReceiveFrom(into: &sbuf)
                _ = try await server.SendTo(sbuf[0..<n], to: sender)
                return n
            } catch {
                return -1
            }
        }

        let sent = try await client.SendText("connected ping")
        check(sent == 14, "connected client send bytes")

        var cbuf = [uint8](repeating: 0, count: 128)
        let rcvd = try await client.Receive(into: &cbuf)
        check(rcvd == 14, "connected client receive bytes")
        check(same(cbuf, rcvd, "connected ping"), "connected mode payload echo")

        _ = await serverTask.value

        try client.Disconnect()
        check(client.PeerAddress() == nil, "peer cleared after disconnect")

        server.Close()
        client.Close()
    } catch let e as udp.UdpError {
        check(false, "connected mode failed: \(e.Message)")
    } catch {
        check(false, "connected mode failed")
    }
}

func timeoutTest() async {
    do {
        var socket = try udp.Bind("127.0.0.1:0")
        socket.SetReadTimeout(ms: 50)
        var buf = [uint8](repeating: 0, count: 64)
        _ = try await socket.ReceiveFrom(into: &buf)
        check(false, "receive should time out")
        socket.Close()
    } catch udp.UdpError.timedOut(_) {
        check(true, "receive timed out as expected")
    } catch {
        check(false, "unexpected error on timeout")
    }
}

func optionsTest() {
    do {
        var socket = try udp.Bind("127.0.0.1:0")
        try socket.SetBroadcast(true)
        check(true, "set broadcast")
        try socket.SetTTL(64)
        check(true, "set TTL")
        try socket.SetBufferSizes(receive: 32768, send: 32768)
        check(true, "set buffer sizes")
        socket.Close()
    } catch let e as udp.UdpError {
        check(false, "options test failed: \(e.Message)")
    } catch {
        check(false, "options test failed")
    }
}

func main() async -> int32 {
    addressTests()
    optionsTest()
    await roundTripTest()
    await connectedModeTest()
    await timeoutTest()

    if failures == 0 {
        print("all passed")
        return 0
    } else {
        print("\(failures) failed")
        return 1
    }
}

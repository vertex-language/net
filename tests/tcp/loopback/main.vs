// net/tcp checked against itself over real loopback sockets.
//
// Each check runs a server and a client as two tasks on one thread, and
// fails loudly: the program exits with the number of checks that did not
// pass, so 0 is the only good answer. Run it with
//
//     vsc run loopback
package main

import "net/tcp"

var failures = 0

func check(_ ok: bool, _ what: string) {
    if ok {
        print("ok    \(what)")
    } else {
        print("FAIL  \(what)")
        failures += 1
    }
}

// same reports whether a buffer holds exactly the UTF-8 of text.
func same(_ buf: [uint8], _ text: string) -> bool {
    var i = 0
    for b in text.utf8 {
        if i >= buf.count || buf[i] != b {
            return false
        }
        i += 1
    }
    return i == buf.count
}

// An echo round trip: what is written comes back, a byte count at a time.
func roundTrip() async {
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
        check(c.PeerAddress.Port() == port, "connect reports the peer's port")
        try await c.WriteText("hello")
        var buf = [uint8](repeating: 0, count: 5)
        try await c.ReadFull(into: &buf)
        check(same(buf, "hello"), "echo round trip")
        c.Close()
        check((await server.value) == 5, "server read what the client wrote")
        listener.Close()
    } catch let e as tcp.TcpError {
        check(false, "round trip: \(e.Message)")
    } catch {
        check(false, "round trip")
    }
}

// ReadToEnd stops at the peer's shutdown, and a write larger than any one
// kernel buffer arrives whole.
func readToEnd() async {
    do {
        let listener = try tcp.Listen("127.0.0.1:0")
        let port = listener.LocalAddress.Port()
        let size = 1024 * 1024
        let sender = Task { () async -> bool in
            do {
                let s = try await listener.Accept()
                var big = [uint8](repeating: 0, count: size)
                var i = 0
                while i < size {
                    big[i] = uint8(i % 251)
                    i += 1
                }
                try await s.Write(big)
                try s.Shutdown(.write)
                s.Close()
                return true
            } catch {
                return false
            }
        }
        let c = try await tcp.Connect(host: "127.0.0.1", port: port)
        let got = try await c.ReadToEnd()
        check(got.count == size, "ReadToEnd reads a megabyte to the shutdown")
        var inOrder = got.count == size
        var i = 0
        while inOrder && i < got.count {
            inOrder = got[i] == uint8(i % 251)
            i += 1
        }
        check(inOrder, "the megabyte arrives in order")
        c.Close()
        check(await sender.value, "the sender finished")
        listener.Close()
    } catch let e as tcp.TcpError {
        check(false, "read to end: \(e.Message)")
    } catch {
        check(false, "read to end")
    }
}

// ReadFull throws unexpectedEnd when the stream closes short.
func shortRead() async {
    do {
        let listener = try tcp.Listen("127.0.0.1:0")
        let port = listener.LocalAddress.Port()
        let server = Task { () async -> bool in
            do {
                let s = try await listener.Accept()
                try await s.WriteText("abc")
                s.Close()
                return true
            } catch {
                return false
            }
        }
        let c = try await tcp.Connect(host: "127.0.0.1", port: port)
        var buf = [uint8](repeating: 0, count: 10)
        var ended = false
        do {
            try await c.ReadFull(into: &buf)
        } catch tcp.TcpError.unexpectedEnd(_) {
            ended = true
        }
        check(ended, "ReadFull throws unexpectedEnd on a short stream")
        c.Close()
        _ = await server.value
        listener.Close()
    } catch {
        check(false, "short read")
    }
}

// A read with a deadline, from a peer that says nothing.
func readTimeout() async {
    do {
        let listener = try tcp.Listen("127.0.0.1:0")
        let port = listener.LocalAddress.Port()
        let server = Task { () async -> bool in
            do {
                let s = try await listener.Accept()
                try? await Task.sleep(nanoseconds: 300_000_000)
                s.Close()
                return true
            } catch {
                return false
            }
        }
        var c = try await tcp.Connect(host: "127.0.0.1", port: port)
        c.SetReadTimeout(ms: 50)
        var buf = [uint8](repeating: 0, count: 4)
        var timedOut = false
        do {
            _ = try await c.Read(into: &buf)
        } catch tcp.TcpError.timedOut(_) {
            timedOut = true
        }
        check(timedOut, "a read times out when nothing arrives")
        c.Close()
        _ = await server.value
        listener.Close()
    } catch {
        check(false, "read timeout")
    }
}

// Nothing listening.
func refused() async {
    do {
        // Bind a port and close it again, so that nothing is on it.
        let l = try tcp.Listen("127.0.0.1:0")
        let port = l.LocalAddress.Port()
        l.Close()
        var wasRefused = false
        do {
            let c = try await tcp.Connect(host: "127.0.0.1", port: port, timeoutMs: 1000)
            c.Close()
        } catch tcp.TcpError.connectionRefused(_) {
            wasRefused = true
        }
        check(wasRefused, "connecting to a closed port is refused")
    } catch {
        check(false, "refused")
    }
}

// Addresses.
func addresses() {
    do {
        let a = try tcp.SocketAddress.Parse("127.0.0.1:8080")
        check(a.Host() == "127.0.0.1" && a.Port() == 8080, "parse an IPv4 address")
        let b = try tcp.SocketAddress.Parse("[::1]:9000")
        check(b.ToString() == "[::1]:9000", "parse and print an IPv6 address")
        let c = try tcp.SocketAddress.Parse(":80")
        check(c.Host() == "0.0.0.0", "an empty host is every interface")
    } catch {
        check(false, "parse a valid address")
    }
    var rejected = false
    do {
        _ = try tcp.SocketAddress.Parse("::1:80")
    } catch {
        rejected = true
    }
    check(rejected, "an unbracketed IPv6 address is rejected")
}

func main() async -> int32 {
    addresses()
    await roundTrip()
    await readToEnd()
    await shortRead()
    await readTimeout()
    await refused()
    print(failures == 0 ? "all passed" : "\(failures) failed")
    return int32(failures)
}

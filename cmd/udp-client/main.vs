// A client for the UDP echo server: sends a message and waits for the echo.
package main

import "net/udp"

func main() async -> int32 {
    do {
        var socket = try udp.Bind("127.0.0.1:0")
        defer { socket.Close() }

        socket.SetReadTimeout(ms: 3000)
        let target = "127.0.0.1:9000"

        var i = 1
        var buffer = [uint8](repeating: 0, count: 256)
        while i <= 3 {
            let msg = "hello udp \(i)"
            _ = try await socket.SendText(msg, to: target)
            let (n, peer) = try await socket.ReceiveFrom(into: &buffer)
            print("Sent '\(msg)', got \(n) bytes back from \(peer.ToString())")
            i += 1
        }
    } catch let e as udp.UdpError {
        print("Client failed: \(e.Message)")
        return 1
    } catch {
        return 1
    }
    return 0
}

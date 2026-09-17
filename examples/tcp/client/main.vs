// A client for the echo server: connects, sends a few lines, and prints
// what comes back.
package main

import tcp

func main() async -> int32 {
    do {
        var stream = try await tcp.Connect("127.0.0.1:9000", timeoutMs: 2000)
        defer { stream.Close() }
        try stream.SetNoDelay(true)
        stream.SetReadTimeout(ms: 2000)
        print("connected to \(stream.PeerAddress.ToString()) from \(stream.LocalAddress.ToString())")

        var buffer = [uint8](repeating: 0, count: 256)
        var i = 1
        while i <= 3 {
            let line = "hello \(i)"
            try await stream.WriteText(line)
            let n = try await stream.Read(into: &buffer)
            print("sent \(line), got \(n) bytes back")
            i += 1
        }
    } catch let e as tcp.TcpError {
        print("failed: \(e.Message)")
        return 1
    } catch {
        return 1
    }
    return 0
}

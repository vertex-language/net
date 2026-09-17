// An echo server: receives datagrams and echoes them back to the sender.
package main

import udp

func main() async -> int32 {
    do {
        let socket = try udp.Bind(":9000")
        defer { socket.Close() }
        print("UDP echo server listening on \(socket.LocalAddress.ToString())")

        var buffer = [uint8](repeating: 0, count: 2048)
        while true {
            let (n, sender) = try await socket.ReceiveFrom(into: &buffer)
            print("Received \(n) bytes from \(sender.ToString())")
            _ = try await socket.SendTo(buffer[0..<n], to: sender)
        }
    } catch let e as udp.UdpError {
        print("Server error: \(e.Message)")
        return 1
    } catch {
        return 1
    }
    return 0
}

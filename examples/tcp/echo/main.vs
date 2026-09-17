// An echo server: everything a connection sends comes back.
//
// One task per connection, and they all run on one thread. While a
// handler waits for its client to say something, the others run and the
// accept loop keeps taking new connections.
//
// Nothing here is written differently from the blocking version of the
// same program except for the `await`s -- which are exactly the points
// where another connection gets a turn.
package main

import "net/tcp"

func handle(_ stream: consuming tcp.TcpStream) async {
    let who = stream.PeerAddress.ToString()
    print("open  \(who)")
    defer {
        print("close \(who)")
        stream.Close()
    }
    var buffer = [uint8](repeating: 0, count: 4096)
    while true {
        do {
            let n = try await stream.Read(into: &buffer)
            if n == 0 {
                return
            }
            try await stream.Write(buffer[0..<n])
        } catch let e as tcp.TcpError {
            print("error \(who): \(e.Message)")
            return
        } catch {
            return
        }
    }
}

func main() async -> int32 {
    do {
        let listener = try tcp.Listen(":9000")
        print("echo server on \(listener.LocalAddress.ToString())")
        try await listener.Serve { stream in await handle(stream) }
    } catch let e as tcp.TcpError {
        print("stopped: \(e.Message)")
        return 1
    } catch {
        return 1
    }
    return 0
}

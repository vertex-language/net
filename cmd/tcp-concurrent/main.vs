// A server and its clients in one program, to show what an `await` on a
// socket actually does.
//
// Everything here runs on a single thread. The three clients are started
// one after another and each waits on its own socket; the server handles
// them all. The interleaved output is the executor picking up whichever
// task the kernel made ready -- and every one of those hand-overs is at
// an `await` below and nowhere else.
package main

import "net/tcp"

func serve(_ listener: borrowing tcp.TcpListener, _ connections: int) async {
    var left = connections
    while left > 0 {
        do {
            let stream = try await listener.Accept()
            _ = Task { await echo(stream) }
        } catch {
            return
        }
        left -= 1
    }
}

func echo(_ stream: consuming tcp.TcpStream) async {
    var buffer = [uint8](repeating: 0, count: 256)
    while true {
        do {
            let n = try await stream.Read(into: &buffer)
            if n == 0 {
                stream.Close()
                return
            }
            try await stream.Write(buffer[0..<n])
        } catch {
            stream.Close()
            return
        }
    }
}

func talk(_ name: string, _ port: uint16, _ rounds: int) async {
    do {
        let stream = try await tcp.Connect(host: "127.0.0.1", port: port)
        var buffer = [uint8](repeating: 0, count: 256)
        var i = 1
        while i <= rounds {
            try await stream.WriteText("\(name)-\(i)")
            let n = try await stream.Read(into: &buffer)
            print("\(name) round \(i): \(n) bytes back")
            i += 1
        }
        stream.Close()
    } catch let e as tcp.TcpError {
        print("\(name) failed: \(e.Message)")
    } catch {
        print("\(name) failed")
    }
}

func main() async -> int32 {
    do {
        // Port 0 asks the kernel for a free one, so the example never
        // collides with whatever else is listening.
        let listener = try tcp.Listen("127.0.0.1:0")
        let port = listener.LocalAddress.Port()
        print("listening on \(listener.LocalAddress.ToString())")

        let server = Task { await serve(listener, 3) }
        let a = Task { await talk("alice", port, 3) }
        let b = Task { await talk("bob", port, 3) }
        let c = Task { await talk("carol", port, 3) }

        await a.value
        await b.value
        await c.value
        await server.value
        print("done")
    } catch let e as tcp.TcpError {
        print("failed: \(e.Message)")
        return 1
    } catch {
        return 1
    }
    return 0
}

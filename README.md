# net

[![package: stdlib](https://img.shields.io/badge/package-stdlib-f4f4f5?style=flat-square&labelColor=e4e4e7&color=18181b)](https://github.com/vertex-language)
[![networking: tcp | udp](https://img.shields.io/badge/networking-tcp%20%7C%20udp-f4f4f5?style=flat-square&labelColor=e4e4e7&color=18181b)](https://github.com/vertex-language/net)
[![runtime: async](https://img.shields.io/badge/runtime-async-f4f4f5?style=flat-square&labelColor=e4e4e7&color=18181b)](https://github.com/vertex-language)

Standard networking library for the Vertex programming language, providing asynchronous TCP streams and UDP datagram sockets over non-blocking platform I/O.

---

## Packages

- **`net/tcp`**: Asynchronous stream connections and listeners (`tcp.Listen`, `tcp.Connect`, `tcp.TcpStream`, `tcp.TcpListener`).
- **`net/udp`**: Asynchronous datagram communication and peer binding (`udp.Bind`, `udp.UdpSocket`).
- **`net/http`**: HTTP/1.1 client and server over asynchronous TCP (`http.Get`, `http.Post`, `http.Client`, `http.ServeConn`, `http.Request`, `http.Response`).

---

## Quick Start

### TCP Echo Server & Client

```swift
package main

import tcp

func main() async -> int32 {
    let listener = try tcp.Listen(":8080")
    print("TCP server listening on \(listener.LocalAddress.ToString())")

    while true {
        let client = try await listener.Accept()
        Task {
            defer { client.Close() }
            var buffer = [uint8](repeating: 0, count: 1024)
            while true {
                let n = try await client.Read(into: &buffer)
                if n == 0 { break }
                try await client.Write(buffer[0..<n])
            }
        }
    }
    return 0
}
```

```swift
package main

import tcp

func main() async -> int32 {
    let client = try await tcp.Connect(host: "127.0.0.1", port: 8080)
    defer { client.Close() }

    try await client.WriteText("hello vertex tcp")
    let response = try await client.ReadText(maxBytes: 1024)
    print("Received: \(response)")
    return 0
}
```

### UDP Echo Server & Client

```swift
package main

import udp

func main() async -> int32 {
    let socket = try udp.Bind(":9000")
    defer { socket.Close() }
    print("UDP server listening on \(socket.LocalAddress.ToString())")

    var buffer = [uint8](repeating: 0, count: 2048)
    while true {
        let (n, sender) = try await socket.ReceiveFrom(into: &buffer)
        _ = try await socket.SendTo(buffer[0..<n], to: sender)
    }
    return 0
}
```

```swift
package main

import udp

func main() async -> int32 {
    let client = try udp.Bind("127.0.0.1:0")
    defer { client.Close() }

    _ = try await client.SendText("hello vertex udp", to: "127.0.0.1:9000")
    var buffer = [uint8](repeating: 0, count: 2048)
    let (n, sender) = try await client.ReceiveFrom(into: &buffer)
    print("Received \(n) bytes from \(sender.ToString())")
    return 0
}
```

### HTTP Server & Client

```swift
package main

import tcp
import http

func main() async -> int32 {
    let listener = try tcp.Listen(":8080")
    print("HTTP server listening on :8080")

    while true {
        let client = try await listener.Accept()
        Task {
            await http.ServeConn(stream: client) { req in
                var w = http.ResponseWriter()
                w.SetStatus(http.Status.OK)
                w.SetHeader("Content-Type", "text/plain")
                w.WriteText("Hello from Vertex HTTP Server!")
                return w
            }
        }
    }
    return 0
}
```

```swift
package main

import http

func main() async -> int32 {
    let res = try await http.Get("http://127.0.0.1:8080/hello")
    print("Status: \(res.StatusCode) body: \(res.BodyText())")
    return 0
}
```

---

## Running

Execute examples or the test suite directly with `vsc`:

```bash
# Run comprehensive loopback checks (TCP + UDP)
vsc run loopback

# Run individual test suites
vsc run tcp-loopback
vsc run udp-loopback
vsc run http-test

# Run example servers and clients
vsc run tcp-echo
vsc run tcp-client
vsc run udp-echo
vsc run udp-client
```

---

## License

[MIT](LICENSE)

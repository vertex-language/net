# net

[![package: stdlib](https://img.shields.io/badge/package-stdlib-f4f4f5?style=flat-square&labelColor=e4e4e7&color=18181b)](https://github.com/vertex-language)
[![networking: tcp | udp | quic](https://img.shields.io/badge/networking-tcp%20%7C%20udp%20%7C%20quic-f4f4f5?style=flat-square&labelColor=e4e4e7&color=18181b)](https://github.com/vertex-language/net)
[![protocols: http1.1 | http2 | http3 | webrtc](https://img.shields.io/badge/protocols-http1.1%20%7C%20http2%20%7C%20http3%20%7C%20webrtc-f4f4f5?style=flat-square&labelColor=e4e4e7&color=18181b)](https://github.com/vertex-language/net)
[![runtime: async](https://img.shields.io/badge/runtime-async-f4f4f5?style=flat-square&labelColor=e4e4e7&color=18181b)](https://github.com/vertex-language)

Standard networking library for the Vertex programming language, providing asynchronous TCP and UDP platform primitives, pure-Vertex multi-protocol HTTP (HTTP/1.1, HTTP/2, HTTP/3), QUIC transport, and a full WebRTC real-time communication stack.

---

## Packages

- **`net/tcp`**: Asynchronous stream connections and listeners over platform POSIX sockets (`tcp.Listen`, `tcp.Connect`, `tcp.TcpStream`, `tcp.TcpListener`).
- **`net/udp`**: Asynchronous datagram communication and peer binding (`udp.Bind`, `udp.UdpSocket`).
- **`net/http`**: Unified multi-protocol HTTP client and server supporting:
  - **HTTP/1.1**: Plain TCP keep-alive and TLS 1.3 fallback.
  - **HTTP/2**: RFC 9113 binary framing, stream multiplexing, and RFC 7541 HPACK compression negotiated via TLS 1.3 ALPN (`"h2"`).
  - **HTTP/3**: RFC 9114 binary framing and RFC 9204 QPACK compression over pure-Vertex QUIC, discovered via RFC 7838 `Alt-Svc`.
  - Public APIs: `http.Get`, `http.Post`, `http.Client`, `http.Server`, `http.ServeConn`, `http.ServeConnTls`.
- **`net/quic`**: RFC 9000, 9001, 9002, and 9221 QUIC transport protocol with bidirectional/unidirectional streams, ChaCha20-Poly1305 packet protection, NewReno congestion control, and unreliable datagrams (`quic.Connect`, `quic.Listen`, `QuicConnection`, `QuicStream`).
- **`net/webrtc`**: RFC 9429 WebRTC PeerConnection, JSEP Offer/Answer state machine, and RFC 8866 SDP negotiation (`RTCPeerConnection`).
- **`net/datachannel`**: RFC 8831 / RFC 8832 WebRTC Data Channels and DCEP channel establishment (`RTCDataChannel`).
- **`net/sctp`**: RFC 4960 / RFC 8261 SCTP stream transport with Castagnoli CRC-32c checksumming (`SctpAssociation`, `SctpPacket`).
- **`net/ice`**: RFC 8445 / RFC 8838 Interactive Connectivity Establishment with candidate gathering and connectivity checks (`IceAgent`, `CandidateGatherer`).
- **`net/turn`**: RFC 8656 Traversal Using Relays around NAT client and relay server (`TurnClient`, `TurnServer`).
- **`net/stun`**: RFC 8489 STUN NAT traversal discovery and message binding (`stun.Discover`, `stun.Client`, `stun.Message`).

---

## Quick Start

### 1. Unified HTTP & HTTPS Client (HTTP/1.1, HTTP/2, HTTP/3)

`net/http` transparently negotiates the highest supported protocol (HTTP/2 via TLS ALPN, HTTP/3 via Alt-Svc cache, or HTTP/1.1):

```swift
package main

import "net/http"

func main() async -> int32 {
    do {
        // Plain HTTP or HTTPS with automatic ALPN negotiation (HTTP/2 / HTTP/1.1)
        let res = try await http.Get("https://cloudflare.com/cdn-cgi/trace")
        print("Status: \(res.StatusCode)")
        print("Protocol: \(res.Version.Name)")
        print("Body:\n\(res.BodyText())")
        return 0
    } catch {
        print("Request failed")
        return 1
    }
}
```

### 2. Multi-Protocol HTTP Server

```swift
package main

import "net/http"

func main() async -> int32 {
    var server = http.Server { req in
        var w = http.ResponseWriter()
        w.SetStatus(200)
        w.SetHeader("Content-Type", "application/json")
        w.WriteText("{\"message\":\"Hello from Vertex HTTP!\"}")
        return w
    }

    // Serve HTTP/1.1 and HTTP/2 with TLS termination
    try await server.ListenTLS(on: ":8443", cert: "server.crt", key: "server.key")
    return 0
}
```

### 3. QUIC Transport (RFC 9000 & RFC 9221)

```swift
package main

import "net/quic"
import "net/udp"

func main() async -> int32 {
    let serverAddr = SocketAddress.v4(ip: "127.0.0.1", port: 4433)
    var conn = try await quic.Connect(to: serverAddr)
    defer { conn.Close(errorCode: 0) }

    // Open a bidirectional stream
    var stream = try await conn.OpenStream(bidirectional: true)
    try await stream.WriteText("Hello from QUIC!")

    let reply = try await stream.ReadText(maxBytes: 1024)
    print("Received: \(reply)")
    return 0
}
```

### 4. TCP Echo Server & Client

```swift
package main

import "net/tcp"

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

### 5. UDP Echo Server & Client

```swift
package main

import "net/udp"

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

### 6. WebRTC DataChannel (RFC 9429)

```swift
package main

import "net/webrtc"

func main() async -> int32 {
    var config = webrtc.RTCConfiguration()
    config.IceServers = ["stun:stun.cloudflare.com:3478"]

    var pc = try await webrtc.CreatePeerConnection(config: config)
    defer { pc.Close() }

    var dc = try pc.CreateDataChannel("chat")
    dc.OnMessage { msg in
        print("Received DataChannel message: \(msg.Data)")
    }

    let offer = try await pc.CreateOffer()
    try await pc.SetLocalDescription(offer)
    return 0
}
```

### 7. STUN NAT Traversal (RFC 8489)

```swift
package main

import "net/stun"

func main() async -> int32 {
    do {
        let reflexiveAddr = try await stun.Discover(server: "stun.cloudflare.com:3478")
        print("Discovered Public Reflexive Address: \(reflexiveAddr.ToString())")
        return 0
    } catch {
        print("STUN query failed")
        return 1
    }
}
```

---

## Testing & Verification

Run the test suites directly with `vsc run <target>`:

```bash
# Web & Transport Protocols
vsc run http-test          # Multi-protocol HTTP (HTTP/1.1, HTTP/2 HPACK, HTTP/3 QPACK, Alt-Svc)
vsc run quic-test          # QUIC RFC 9000, 9001, 9002, 9221 datagrams

# Real-time Communication & WebRTC Stack
vsc run webrtc-test        # WebRTC PeerConnection, JSEP, SDP
vsc run datachannel-test   # WebRTC DataChannel & DCEP
vsc run sctp-test          # SCTP chunks, associations & CRC-32c
vsc run ice-test           # ICE RFC 8445 connectivity checks
vsc run turn-test          # TURN RFC 8656 relay allocations
vsc run stun-test          # STUN RFC 8489 discovery & binding

# Core Socket Primitives & Loopback
vsc run loopback           # TCP and UDP loopback checks
vsc run tcp-loopback
vsc run udp-loopback
```

---

## License

[MIT](LICENSE)

package http

import (
    "crypto/tls"
    "net/quic"
    "net/tcp"
    "net/udp"
)

/// ResponseWriter provides an interface for constructing and sending an HTTP response.
public struct ResponseWriter {
    public var StatusCode: int32 = 200
    public var Headers: Header = Header()
    public var Body: [uint8] = []

    public init() {}

    public mutating func SetStatus(_ code: int32) {
        self.StatusCode = code
    }

    public mutating func SetHeader(_ key: string, _ value: string) {
        Headers.Set(key, value)
    }

    public mutating func Write(_ data: [uint8]) {
        Body.append(contentsOf: data)
    }

    public mutating func WriteText(_ s: string) {
        Body.append(contentsOf: s.utf8)
    }
}

/// ServerConfig defines protocol configuration and TLS termination settings.
public struct ServerConfig {
    public var Protocols: [HttpVersion]
    public var CertFile: string
    public var KeyFile: string
    public var AltSvcEnabled: bool
    public var ReadTimeoutMs: int32
    public var WriteTimeoutMs: int32

    public init(certFile: string = "",
                keyFile: string = "",
                altSvcEnabled: bool = true,
                readTimeoutMs: int32 = 15000,
                writeTimeoutMs: int32 = 15000) {
        self.Protocols = [HttpVersion.http1_1, HttpVersion.http2, HttpVersion.http3]
        self.CertFile = certFile
        self.KeyFile = keyFile
        self.AltSvcEnabled = altSvcEnabled
        self.ReadTimeoutMs = readTimeoutMs
        self.WriteTimeoutMs = writeTimeoutMs
    }

    public init(protocols: [HttpVersion],
                certFile: string = "",
                keyFile: string = "",
                altSvcEnabled: bool = true,
                readTimeoutMs: int32 = 15000,
                writeTimeoutMs: int32 = 15000) {
        self.Protocols = protocols
        self.CertFile = certFile
        self.KeyFile = keyFile
        self.AltSvcEnabled = altSvcEnabled
        self.ReadTimeoutMs = readTimeoutMs
        self.WriteTimeoutMs = writeTimeoutMs
    }
}

@_silgen_name("memcpy")
func c_memcpy(_ dest: UnsafeMutableRawPointer, _ src: UnsafeRawPointer, _ n: int) -> UnsafeMutableRawPointer

func sliceBytes(_ src: [uint8], from: int, count: int) -> [uint8] {
    if count <= 0 { return [] }
    var dst = [uint8](repeating: 0, count: count)
    dst.withUnsafeMutableBytes { dp in
        src.withUnsafeBytes { sp in
            _ = c_memcpy(dp.baseAddress!, sp.baseAddress! + from, count)
        }
    }
    return dst
}

func appendBytes(_ dst: inout [uint8], _ src: [uint8], from: int, count: int) {
    if count <= 0 { return }
    let orig = dst.count
    dst.append(contentsOf: [uint8](repeating: 0, count: count))
    dst.withUnsafeMutableBytes { dp in
        src.withUnsafeBytes { sp in
            _ = c_memcpy(dp.baseAddress! + orig, sp.baseAddress! + from, count)
        }
    }
}

// The buffers a connection is served through. Both are made once, when
// the connection is, and reused for every request on it: the read
// buffer holds what has arrived and not yet been consumed, between
// `head` and `tail`, and a request is parsed where it lies; the write
// buffer is filled with a response and sent in one write. This is the
// shape of Go's bufio pair and hyper's Buffered, and it is why neither
// allocates per request.
let initialReadBuffer = 8192
// A request whose headers do not fit in this many bytes is refused, as
// Go's DefaultMaxHeaderBytes refuses it.
let maxHeaderBytes = 1 << 20

// The fixed bytes of a response, built once and appended as they are:
// no String is made, and no per-request literal is turned into bytes.
let bytesStatus200: [uint8] = [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10] // "HTTP/1.1 200 OK\r\n"
let bytesColonSpace: [uint8] = [58, 32]         // ": "
let bytesCRLF: [uint8] = [13, 10]               // "\r\n"
let bytesContentLength: [uint8] = [67, 111, 110, 116, 101, 110, 116, 45, 76, 101, 110, 103, 116, 104, 58, 32] // "Content-Length: "
let bytesConnKeepAlive: [uint8] = [67, 111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 107, 101, 101, 112, 45, 97, 108, 105, 118, 101, 13, 10] // "Connection: keep-alive\r\n"
let bytesConnClose: [uint8] = [67, 111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 99, 108, 111, 115, 101, 13, 10] // "Connection: close\r\n"

// appendDecimal writes n in ASCII onto the end of out: the digits of a
// Content-Length, without a String on the way.
func appendDecimal(_ out: inout [uint8], _ n: int) {
    if n < 10 {
        out.append(uint8(48 + n))
        return
    }
    var digits: [uint8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var v = n
    var i = digits.count
    while v > 0 {
        i -= 1
        digits[i] = uint8(48 + v % 10)
        v /= 10
    }
    while i < digits.count {
        out.append(digits[i])
        i += 1
    }
}

// encodeResponse writes the response's status line, headers, blank line
// and body onto out, as the bytes that go on the wire. keepAlive is what
// the connection decided, unless a Connection header of the handler's
// says otherwise, in which case it is updated.
func encodeResponse(_ out: inout [uint8], _ writer: borrowing ResponseWriter, keepAlive: inout bool) {
    if writer.StatusCode == 200 {
        out.append(contentsOf: bytesStatus200)
    } else {
        out.append(contentsOf: "HTTP/1.1 \(writer.StatusCode) \(StatusText(writer.StatusCode))\r\n".utf8)
    }
    var hasContentLength = false
    var hasConnection = false
    var i = 0
    while i < writer.Headers.entries.count {
        let e = writer.Headers.entries[i]
        if equalFold(e.Key, "Content-Length") {
            hasContentLength = true
        } else if equalFold(e.Key, "Connection") {
            hasConnection = true
            if equalFold(e.Value, "close") {
                keepAlive = false
            }
        }
        out.append(contentsOf: e.Key.utf8)
        out.append(contentsOf: bytesColonSpace)
        out.append(contentsOf: e.Value.utf8)
        out.append(contentsOf: bytesCRLF)
        i += 1
    }
    if !hasContentLength {
        out.append(contentsOf: bytesContentLength)
        appendDecimal(&out, writer.Body.count)
        out.append(contentsOf: bytesCRLF)
    }
    if !hasConnection {
        if keepAlive {
            out.append(contentsOf: bytesConnKeepAlive)
        } else {
            out.append(contentsOf: bytesConnClose)
        }
    }
    out.append(contentsOf: bytesCRLF)
    if !writer.Body.isEmpty {
        out.append(contentsOf: writer.Body)
    }
}

// wantsKeepAlive is whether the connection stays open after this
// request: HTTP/1.1 unless the client says close, HTTP/1.0 only if it
// asks.
func wantsKeepAlive(_ req: borrowing Request) -> bool {
    // A request the parser read says which span is Connection; one built
    // some other way is looked up.
    if req.connectionSpan >= 0 {
        if req.minor == 0 {
            return req.Headers.spanValueIs(req.connectionSpan, "keep-alive")
        }
        return !req.Headers.spanValueIs(req.connectionSpan, "close")
    }
    if req.minor == 0 {
        return req.Headers.valueIs("Connection", "keep-alive") ?? false
    }
    return !(req.Headers.valueIs("Connection", "close") ?? false)
}

/// ServeConn handles incoming HTTP client connections over plain TCP with keep-alive support.
///
/// Every request on the connection is read into the one buffer, parsed
/// in place, answered from the one write buffer, and sent with one
/// write. A request that arrived behind the last one (pipelining) is
/// found where it already is, without reading again.
public func ServeConn(stream: tcp.TcpStream, handle: (Request) async throws -> ResponseWriter) async {
    defer { stream.Close() }
    var readBuf = [uint8](repeating: 0, count: initialReadBuffer)
    var head = 0   // the first byte not yet consumed
    var tail = 0   // one past the last byte read
    var writeBuf: [uint8] = []
    // One Request per connection, parsed into afresh each time.
    var req = Request()

    while true {
        // The request's headers: whatever is buffered, then more until
        // the blank line is there.
        var headerEnd = Request.FindHeaderEnd(readBuf, from: head, to: tail)
        while headerEnd < 0 {
            if tail == readBuf.count {
                if head > 0 {
                    // Room at the front: slide what is left down to it.
                    let kept = tail - head
                    var k = 0
                    while k < kept {
                        readBuf[k] = readBuf[head + k]
                        k += 1
                    }
                    head = 0
                    tail = kept
                } else if readBuf.count >= maxHeaderBytes {
                    // 431 Request Header Fields Too Large
                    return
                } else {
                    readBuf.append(contentsOf: [uint8](repeating: 0, count: readBuf.count))
                }
            }
            do {
                let n = try await stream.Read(into: &readBuf, at: tail)
                if n <= 0 {
                    return
                }
                let scanFrom = tail - 3 > head ? tail - 3 : head
                tail += n
                headerEnd = Request.FindHeaderEnd(readBuf, from: scanFrom, to: tail)
            } catch {
                return
            }
        }

        do {
            try Request.parse(into: &req, readBuf, from: head, headerEnd: headerEnd)
        } catch {
            return
        }

        // The body, where there is one: Content-Length bytes after the
        // blank line, read into the same buffer.
        var bodyStart = headerEnd + 4
        // The parser read Content-Length on its way past.
        let expectedLen = req.contentLength
        while tail - bodyStart < expectedLen {
            if tail == readBuf.count {
                if head > 0 {
                    let kept = tail - head
                    var k = 0
                    while k < kept {
                        readBuf[k] = readBuf[head + k]
                        k += 1
                    }
                    bodyStart -= head
                    head = 0
                    tail = kept
                }
                let need = bodyStart + expectedLen
                if readBuf.count < need {
                    var grow = readBuf.count
                    while readBuf.count + grow < need {
                        grow *= 2
                    }
                    readBuf.append(contentsOf: [uint8](repeating: 0, count: grow))
                }
            }
            do {
                let n = try await stream.Read(into: &readBuf, at: tail)
                if n <= 0 {
                    return
                }
                tail += n
            } catch {
                return
            }
        }
        if expectedLen > 0 {
            req.Body = sliceBytes(readBuf, from: bodyStart, count: expectedLen)
        }

        // Consumed. What follows, if anything, is the next request.
        head = bodyStart + expectedLen
        if head == tail {
            head = 0
            tail = 0
        }

        var keepAlive = wantsKeepAlive(req)

        var writer: ResponseWriter
        do {
            writer = try await handle(req)
        } catch {
            return
        }

        writeBuf.removeAll(keepingCapacity: true)
        encodeResponse(&writeBuf, writer, keepAlive: &keepAlive)
        do {
            try await stream.Write(writeBuf)
        } catch {
            return
        }

        if !keepAlive {
            return
        }
    }
}

/// ServeConnTls handles a single incoming HTTPS client connection over an established TLS session.
public func ServeConnTls(conn: inout tls.Conn, handle: (Request) async throws -> ResponseWriter, altSvcPort: uint16 = 0) async {
    defer { conn.Close() }
    do {
        let negotiated = conn.state.NegotiatedProtocol

        if negotiated == "h2" {
            // Serve HTTP/2 over TLS
            var session = H2ClientSession()
            var buf = [uint8](repeating: 0, count: 4096)
            var frameBuf: [uint8] = []

            while true {
                let n = try await conn.Read(into: &buf)
                if n <= 0 { break }
                var bi = 0
                while bi < n { frameBuf.append(buf[bi]); bi += 1 }

                // Check for client connection preface (24 bytes)
                if frameBuf.count >= 24 && frameBuf[0] == 0x50 && frameBuf[1] == 0x52 && frameBuf[2] == 0x49 {
                    var rem: [uint8] = []
                    var ri = 24
                    while ri < frameBuf.count { rem.append(frameBuf[ri]); ri += 1 }
                    frameBuf = rem

                    // Send server SETTINGS
                    let serverSettings = BuildH2SettingsFrame(settings: [
                        H2Setting(identifier: H2SettingId.MaxConcurrentStreams, value: 100),
                        H2Setting(identifier: H2SettingId.InitialWindowSize, value: 65535)
                    ])
                    try await conn.Write(serverSettings)
                }

                while frameBuf.count >= 9 {
                    let fh = try ParseH2FrameHeader(data: frameBuf, offset: 0)
                    let totalFrameLen = 9 + fh.Length
                    if frameBuf.count < totalFrameLen { break }

                    var payload: [uint8] = []
                    var pi = 0
                    while pi < fh.Length {
                        payload.append(frameBuf[9 + pi])
                        pi += 1
                    }

                    var rem: [uint8] = []
                    var ri = totalFrameLen
                    while ri < frameBuf.count { rem.append(frameBuf[ri]); ri += 1 }
                    frameBuf = rem

                    let frame = H2Frame(header: fh, payload: payload)

                    if fh.Type == H2FrameType.Settings {
                        if (fh.Flags & H2Flag.Ack) == 0 {
                            let ack = BuildH2SettingsFrame(settings: [], ack: true)
                            try await conn.Write(ack)
                        }
                    } else if fh.Type == H2FrameType.Ping {
                        if (fh.Flags & H2Flag.Ack) == 0 {
                            let pong = BuildH2Ping(opaqueData: payload, ack: true)
                            try await conn.Write(pong)
                        }
                    } else if fh.Type == H2FrameType.Headers {
                        let decoded = try session.Decoder.DecodeHeaders(data: payload)
                        var req = Request(method: "GET", url: "/", version: HttpVersion.http2)
                        var hi = 0
                        while hi < decoded.count {
                            if decoded[hi].Key == ":method" { req.Method = decoded[hi].Value }
                            else if decoded[hi].Key == ":path" { req.URL = decoded[hi].Value }
                            else if !decoded[hi].Key.hasPrefix(":") { req.Headers.Add(decoded[hi].Key, decoded[hi].Value) }
                            hi += 1
                        }

                        var writer = try await handle(req)
                        var respHeaders: [HeaderEntry] = [
                            HeaderEntry(key: ":status", value: "\(writer.StatusCode)")
                        ]
                        var rhi = 0
                        while rhi < writer.Headers.entries.count {
                            respHeaders.append(writer.Headers.entries[rhi])
                            rhi += 1
                        }
                        if altSvcPort > 0 {
                            respHeaders.append(HeaderEntry(key: "alt-svc", value: "h3=\":\(altSvcPort)\"; ma=86400"))
                        }

                        let encHeaders = session.Encoder.EncodeHeaders(respHeaders)
                        var flags = H2Flag.EndHeaders
                        if writer.Body.isEmpty { flags = flags | H2Flag.EndStream }
                        let respHf = BuildH2Frame(type: H2FrameType.Headers, flags: flags, streamId: fh.StreamId, payload: encHeaders)
                        try await conn.Write(respHf)

                        if !writer.Body.isEmpty {
                            let respDf = BuildH2Frame(type: H2FrameType.Data, flags: H2Flag.EndStream, streamId: fh.StreamId, payload: writer.Body)
                            try await conn.Write(respDf)
                        }
                    }
                }
            }
        } else {
            // Serve HTTP/1.1 over TLS
            let req = try await ReadRequestTls(from: &conn)
            var writer = try await handle(req)

            var res = Response(statusCode: writer.StatusCode, version: HttpVersion.http1_1)
            res.Headers = writer.Headers
            if res.Headers.Get("Content-Length") == nil {
                res.Headers.Set("Content-Length", "\(writer.Body.count)")
            }
            if res.Headers.Get("Connection") == nil {
                res.Headers.Set("Connection", "close")
            }
            if altSvcPort > 0 && res.Headers.Get("Alt-Svc") == nil {
                res.Headers.Set("Alt-Svc", "h3=\":\(altSvcPort)\"; ma=86400")
            }
            res.Body = writer.Body
            try await WriteResponseTls(res, to: &conn)
        }
    } catch {
        // Connection closed or error
    }
}

/// Reads an incoming HTTP/1.1 request over TLS.
public func ReadRequestTls(from conn: inout tls.Conn) async throws -> Request {
    var raw: [uint8] = []
    var buf = [uint8](repeating: 0, count: 1024)
    var headerEnd = -1

    while headerEnd < 0 {
        let n = try await conn.Read(into: &buf)
        if n == 0 {
            throw HttpError.connectionClosed
        }
        var i = 0
        while i < n {
            raw.append(buf[i])
            i += 1
        }
        headerEnd = Request.FindHeaderEnd(raw, from: raw.count - n - 3)
    }

    var req = try Request.ParseHeaders(raw, headerEnd: headerEnd)

    if let clVal = req.Headers.Get("Content-Length") {
        let exp = parseContentLength(clVal)
        while req.Body.count < exp {
            let n = try await conn.Read(into: &buf)
            if n == 0 { break }
            var bi = 0
            while bi < n {
                req.Body.append(buf[bi])
                bi += 1
            }
        }
    }

    return req
}

/// Writes an HTTP response to an active TLS connection.
public func WriteResponseTls(_ res: Response, to conn: inout tls.Conn) async throws {
    try await conn.WriteText(res.HeaderText())
    if !res.Body.isEmpty {
        try await conn.Write(res.Body)
    }
}

/// HttpListener wraps an active TCP listener and serves HTTP connections.
public struct HttpListener {
    public var Listener: tcp.TcpListener
    public var Config: ServerConfig

    public init(listener: tcp.TcpListener, config: ServerConfig = ServerConfig()) {
        self.Listener = listener
        self.Config = config
    }

    /// Bound local port number.
    public var Port: uint16 {
        return self.Listener.LocalAddress.Port()
    }

    /// Bound local address formatted as "ip:port".
    public var Address: string {
        return self.Listener.LocalAddress.ToString()
    }

    /// Closes the listener socket.
    public func Close() {
        self.Listener.Close()
    }

    /// Accepts an incoming raw TCP stream.
    public func Accept() async throws -> tcp.TcpStream {
        return try await self.Listener.Accept()
    }

    /// Serves a single incoming connection and returns.
    public func ServeOne(handler: @escaping (Request) async throws -> ResponseWriter) async throws {
        let stream = try await self.Listener.Accept()
        await ServeConn(stream: stream, handle: handler)
    }

    /// Accepts and handles incoming HTTP connections concurrently using the provided handler.
    /// Multi-worker accept loops across the runtime pool are automatically leveraged via TcpListener.Serve.
    public func Serve(handler: @escaping (Request) async throws -> ResponseWriter) async throws {
        let h = handler
        try await self.Listener.Serve { stream in
            await ServeConn(stream: stream, handle: h)
        }
    }
}

/// Starts listening on the specified address and returns an HttpListener immediately.
public func Listen(_ address: string) throws -> HttpListener {
    var opts = tcp.ListenerOptions()
    opts.Backlog = 1024
    let listener = try tcp.Listen(address, options: opts)
    return HttpListener(listener: listener)
}

/// Starts listening on the specified address with server configuration and returns an HttpListener immediately.
public func Listen(_ address: string, config: ServerConfig) throws -> HttpListener {
    var opts = tcp.ListenerOptions()
    opts.Backlog = 1024
    let listener = try tcp.Listen(address, options: opts)
    return HttpListener(listener: listener, config: config)
}

/// Starts listening on the specified address and serves HTTP requests using the provided handler.
public func Listen(_ address: string, handler: @escaping (Request) async throws -> ResponseWriter) async throws {
    let hl = try Listen(address)
    defer { hl.Close() }
    try await hl.Serve(handler: handler)
}

/// Server provides multi-protocol HTTP serving over TCP and UDP.
public struct Server {
    public var Config: ServerConfig
    public var Handler: (Request) async throws -> ResponseWriter

    public init(config: ServerConfig = ServerConfig(), handler: @escaping (Request) async throws -> ResponseWriter) {
        self.Config = config
        self.Handler = handler
    }

    /// Listens on the specified address and serves requests.
    public func Listen(on address: string) async throws {
        var opts = tcp.ListenerOptions()
        opts.Backlog = 1024
        let l = try tcp.Listen(address, options: opts)
        let hl = HttpListener(listener: l, config: self.Config)
        defer { hl.Close() }
        try await hl.Serve(handler: self.Handler)
    }

    /// Listens on the specified address with TLS termination.
    public func ListenTLS(on address: string, cert: string, key: string) async throws {
        let listener = try await tcp.Listen(address)
        defer { listener.Close() }

        var tlsCfg = tls.Config()
        tlsCfg.NextProtos = ["h2", "http/1.1"]

        while true {
            let stream = try await listener.Accept()
            var conn = tls.Conn(stream: stream, config: tlsCfg)
            let h = self.Handler
            Task {
                do {
                    try await conn.Handshake()
                    await ServeConnTls(conn: &conn, handle: h)
                } catch {
                    conn.Close()
                }
            }
        }
    }
}


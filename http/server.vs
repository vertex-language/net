package http

import "net/tcp"
import "net/udp"
import "net/quic"
import "crypto/tls"

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
        var i = 0
        while i < data.count {
            Body.append(data[i])
            i += 1
        }
    }

    public mutating func WriteText(_ s: string) {
        for b in s.utf8 {
            Body.append(b)
        }
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

/// ServeConn handles a single incoming HTTP client connection over plain TCP.
public func ServeConn(stream: tcp.TcpStream, handle: (Request) async throws -> ResponseWriter) async {
    defer { stream.Close() }
    do {
        let req = try await ReadRequest(from: stream)
        var writer = try await handle(req)

        var res = Response(statusCode: writer.StatusCode)
        res.Headers = writer.Headers
        if res.Headers.Get("Content-Length") == nil {
            res.Headers.Set("Content-Length", "\(writer.Body.count)")
        }
        if res.Headers.Get("Connection") == nil {
            res.Headers.Set("Connection", "close")
        }
        res.Body = writer.Body
        try await res.Write(to: stream)
    } catch {
        // Connection closed or error
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
    public func Serve(handler: @escaping (Request) async throws -> ResponseWriter) async throws {
        while true {
            let stream = try await self.Listener.Accept()
            let h = handler
            Task {
                await ServeConn(stream: stream, handle: h)
            }
        }
    }
}

/// Starts listening on the specified address and returns an HttpListener immediately.
public func Listen(_ address: string) throws -> HttpListener {
    let listener = try tcp.Listen(address)
    return HttpListener(listener: listener)
}

/// Starts listening on the specified address with server configuration and returns an HttpListener immediately.
public func Listen(_ address: string, config: ServerConfig) throws -> HttpListener {
    let listener = try tcp.Listen(address)
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
        let l = try tcp.Listen(address)
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


package http

import (
    "crypto/tls"
    "net/quic"
    "net/tcp"
    "net/udp"
    "net/url"
)

/// The Host header for a host and port: the port only where it isn't the
/// scheme's, and an IPv6 address in brackets.
func hostHeader(_ host: string, _ port: uint16, secure: bool) -> string {
    let name = host.contains(":") ? "[" + host + "]" : host
    return port == (secure ? 443 : 80) ? name : "\(name):\(port)"
}

/// ClientConfig specifies protocol preferences, timeouts, and TLS options for Client.
public struct ClientConfig {
    public var EnabledVersions: [HttpVersion]
    public var TimeoutMs: int32
    public var EnableAltSvc: bool
    public var TLSConfig: tls.Config

    public init(timeoutMs: int32 = 10000,
                enableAltSvc: bool = true,
                tlsConfig: tls.Config = tls.Config()) {
        self.EnabledVersions = [HttpVersion.http1_1, HttpVersion.http2, HttpVersion.http3]
        self.TimeoutMs = timeoutMs
        self.EnableAltSvc = enableAltSvc
        self.TLSConfig = tlsConfig
    }

    public init(enabledVersions: [HttpVersion],
                timeoutMs: int32 = 10000,
                enableAltSvc: bool = true,
                tlsConfig: tls.Config = tls.Config()) {
        self.EnabledVersions = enabledVersions
        self.TimeoutMs = timeoutMs
        self.EnableAltSvc = enableAltSvc
        self.TLSConfig = tlsConfig
    }
}

/// Client is a unified multi-protocol HTTP client supporting HTTP/1.1, HTTP/2, and HTTP/3.
public struct Client {
    public static let Default: Client = Client()

    public var Config: ClientConfig
    public var AltSvc: AltSvcCache

    public var TimeoutMs: int32 {
        get { return self.Config.TimeoutMs }
        set { self.Config.TimeoutMs = newValue }
    }

    public var TLSConfig: tls.Config {
        get { return self.Config.TLSConfig }
        set { self.Config.TLSConfig = newValue }
    }

    public init(config: ClientConfig = ClientConfig()) {
        self.Config = config
        self.AltSvc = AltSvcCache()
    }

    public init(tlsConfig: tls.Config, timeoutMs: int32 = 5000) {
        var cfg = ClientConfig(timeoutMs: timeoutMs, tlsConfig: tlsConfig)
        self.Config = cfg
        self.AltSvc = AltSvcCache()
    }

    public init(timeoutMs: int32) {
        var cfg = ClientConfig(timeoutMs: timeoutMs)
        self.Config = cfg
        self.AltSvc = AltSvcCache()
    }

    /// Do sends an HTTP request and returns an HTTP response.
    public mutating func Do(_ req: Request, host: string, port: uint16 = 80, config: tls.Config = tls.Config()) async throws -> Response {
        let scheme = (port == 443) ? "https" : "http"
        let u = url.URL(Scheme: scheme, Host: host, Port: "\(port)", Path: req.URL)
        return try await self.DoUrl(req, url: u)
    }

    /// DoUrl executes an HTTP request targeted at a parsed URL.
    public mutating func DoUrl(_ req: Request, url target: url.URL) async throws -> Response {
        let host = target.Host
        let port = target.EffectivePort
        let origin = "\(host):\(port)"

        // 1. If HTTPS, check AltSvc cache for HTTP/3 over QUIC
        if target.Scheme == "https" && self.Config.EnableAltSvc {
            var h3Allowed = false
            var vi = 0
            while vi < self.Config.EnabledVersions.count {
                if self.Config.EnabledVersions[vi] == HttpVersion.http3 {
                    h3Allowed = true
                    break
                }
                vi += 1
            }

            if h3Allowed {
                if let alt = self.AltSvc.Get(origin: origin, protocolName: "h3") {
                    do {
                        return try await self.executeH3(req: req, host: alt.Host.isEmpty ? host : alt.Host, port: alt.Port)
                    } catch {
                        // Fallback to TLS/TCP
                    }
                }
            }
        }

        // 2. HTTPS over TLS 1.3
        if target.Scheme == "https" {
            return try await self.executeTls(req: req, url: target)
        }

        // 3. Plain HTTP/1.1 over TCP
        return try await self.executeHttp1(req: req, host: host, port: port)
    }

    /// Executes HTTP/1.1 over plain TCP.
    func executeHttp1(req: Request, host: string, port: uint16) async throws -> Response {
        let stream = try await tcp.Connect(host: host, port: port)
        defer { stream.Close() }

        var finalReq = req
        if finalReq.Headers.Get("Host") == nil {
            finalReq.Headers.Set("Host", hostHeader(host, port, secure: false))
        }
        if finalReq.Headers.Get("User-Agent") == nil {
            finalReq.Headers.Set("User-Agent", "Vertex-HTTP/1.1")
        }
        if !finalReq.Body.isEmpty && finalReq.Headers.Get("Content-Length") == nil {
            finalReq.Headers.Set("Content-Length", "\(finalReq.Body.count)")
        }
        if finalReq.Headers.Get("Connection") == nil {
            finalReq.Headers.Set("Connection", "close")
        }

        try await finalReq.Write(to: stream)
        return try await ReadResponse(from: stream)
    }

    /// Executes HTTPS over TLS 1.3 with ALPN negotiation (HTTP/2 or HTTP/1.1).
    mutating func executeTls(req: Request, url target: url.URL) async throws -> Response {
        let host = target.Host
        let port = target.EffectivePort
        let origin = "\(host):\(port)"

        var cfg = self.Config.TLSConfig
        if cfg.ServerName.isEmpty {
            cfg.ServerName = host
        }

        // Prepare ALPN protocol list from EnabledVersions
        var alpn: [string] = []
        var hasH2 = false
        var hasH1 = false
        var vi = 0
        while vi < self.Config.EnabledVersions.count {
            if self.Config.EnabledVersions[vi] == HttpVersion.http2 { hasH2 = true }
            if self.Config.EnabledVersions[vi] == HttpVersion.http1_1 { hasH1 = true }
            vi += 1
        }
        if hasH2 { alpn.append("h2") }
        if hasH1 { alpn.append("http/1.1") }
        cfg.NextProtos = alpn

        var conn = try await tls.Connect(host: host, port: port, config: cfg)
        defer { conn.Close() }

        let negotiated = conn.state.NegotiatedProtocol
        var res: Response = Response(statusCode: 200)

        if negotiated == "h2" {
            // Execute HTTP/2
            var session = H2ClientSession()
            let initBytes = session.StartHandshake()
            try await conn.Write(initBytes)

            let authority = (port == 443) ? host : "\(host):\(port)"
            let reqBytes = session.CreateRequestFrames(req: req, scheme: "https", authority: authority)
            try await conn.Write(reqBytes)

            var buf = [uint8](repeating: 0, count: 4096)
            var frameBuf: [uint8] = []

            while true {
                let n = try await conn.Read(into: &buf)
                if n <= 0 { break }
                var bi = 0
                while bi < n { frameBuf.append(buf[bi]); bi += 1 }

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
                    while ri < frameBuf.count {
                        rem.append(frameBuf[ri])
                        ri += 1
                    }
                    frameBuf = rem

                    let frame = H2Frame(header: fh, payload: payload)
                    if let completedRes = try session.ProcessFrame(frame) {
                        res = completedRes
                        break
                    }

                    let outbound = session.DrainOutbound()
                    if !outbound.isEmpty {
                        try await conn.Write(outbound)
                    }
                }

                if res.StatusCode != 0 && res.Version == HttpVersion.http2 {
                    break
                }
            }
        } else {
            // Execute HTTP/1.1
            var finalReq = req
            if finalReq.Headers.Get("Host") == nil {
                finalReq.Headers.Set("Host", hostHeader(host, port, secure: true))
            }
            if finalReq.Headers.Get("User-Agent") == nil {
                finalReq.Headers.Set("User-Agent", "Vertex-HTTP/1.1")
            }
            if !finalReq.Body.isEmpty && finalReq.Headers.Get("Content-Length") == nil {
                finalReq.Headers.Set("Content-Length", "\(finalReq.Body.count)")
            }
            if finalReq.Headers.Get("Connection") == nil {
                finalReq.Headers.Set("Connection", "close")
            }

            try await WriteRequestTls(finalReq, to: &conn)
            res = try await ReadResponseTls(from: &conn)
        }

        // Cache Alt-Svc header if present
        if self.Config.EnableAltSvc {
            if let altHeader = res.Headers.Get("alt-svc") {
                let services = ParseAltSvcHeader(altHeader, defaultHost: host)
                var si = 0
                while si < services.count {
                    self.AltSvc.Set(origin: origin, service: services[si])
                    si += 1
                }
            }
        }

        return res
    }

    /// Executes HTTP/3 over QUIC.
    public func executeH3(req: Request, host: string, port: uint16) async throws -> Response {
        var addr: udp.SocketAddress = udp.SocketAddress.v4(ip: host, port: port)
        do {
            let resolved = try udp.Resolve(host: host, port: port)
            if !resolved.isEmpty {
                addr = resolved[0]
            }
        } catch {
        }

        var qConfig = quic.QuicConfig()
        qConfig.MaxIdleTimeoutMs = uint64(self.Config.TimeoutMs)
        var qConn = try await quic.Connect(to: addr, config: qConfig)

        var session = H3ClientSession(connection: qConn)
        try await session.StartSession()

        let authority = (port == 443) ? host : "\(host):\(port)"
        var stream = try await session.SendRequest(req: req, scheme: "https", authority: authority)

        let respBytes = try await stream.Read(maxBytes: 65536)
        let res = try session.ParseResponseStream(data: respBytes)
        try await qConn.Close(errorCode: 0)
        return res
    }

    /// GetH3 sends an HTTP/3 GET request directly over QUIC.
    public func GetH3(_ address: string) async throws -> Response {
        let u = try url.Parse(address)
        let req = Request(method: "GET", url: u.RequestURI, version: HttpVersion.http3)
        return try await self.executeH3(req: req, host: u.Host, port: u.EffectivePort)
    }

    /// Get sends an HTTP or HTTPS GET request to the specified URL.
    public mutating func Get(_ address: string) async throws -> Response {
        let u = try url.Parse(address)
        let req = Request(method: "GET", url: u.RequestURI)
        return try await self.DoUrl(req, url: u)
    }

    /// Post sends an HTTP or HTTPS POST request with the specified body to the URL.
    public mutating func Post(_ address: string, contentType: string, body: [uint8]) async throws -> Response {
        let u = try url.Parse(address)
        var req = Request(method: "POST", url: u.RequestURI)
        req.Headers.Set("Content-Type", contentType)
        req.Body = body
        return try await self.DoUrl(req, url: u)
    }
}

/// Writes an HTTP request to an active TLS connection.
public func WriteRequestTls(_ req: Request, to conn: inout tls.Conn) async throws {
    try await conn.WriteText(req.HeaderText())
    if !req.Body.isEmpty {
        try await conn.Write(req.Body)
    }
}

/// Reads an HTTP/1.1 response from a connected TLS session.
public func ReadResponseTls(from conn: inout tls.Conn) async throws -> Response {
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
        headerEnd = Response.FindHeaderEnd(raw, from: raw.count - n - 3)
    }

    var res = try Response.ParseHeaders(raw, headerEnd: headerEnd)

    if let clVal = res.Headers.Get("Content-Length") {
        let exp = parseContentLength(clVal)
        while res.Body.count < exp {
            let n = try await conn.Read(into: &buf)
            if n == 0 { break }
            var bi = 0
            while bi < n {
                res.Body.append(buf[bi])
                bi += 1
            }
        }
    } else if res.Headers.Get("Transfer-Encoding") == nil && (res.StatusCode < 100 || res.StatusCode >= 200) && res.StatusCode != 204 && res.StatusCode != 304 {
        while true {
            let n = try await conn.Read(into: &buf)
            if n == 0 { break }
            var bi = 0
            while bi < n {
                res.Body.append(buf[bi])
                bi += 1
            }
        }
    }

    return res
}

public var DefaultClient = Client()

/// Get sends an HTTP GET request to url using DefaultClient.
public func Get(_ address: string) async throws -> Response {
    var c = Client()
    return try await c.Get(address)
}

/// Post sends an HTTP POST request to url using DefaultClient.
public func Post(_ address: string, contentType: string, body: [uint8]) async throws -> Response {
    var c = Client()
    return try await c.Post(address, contentType: contentType, body: body)
}

/// GetH3 sends an HTTP/3 GET request to url directly over QUIC.
public func GetH3(_ address: string) async throws -> Response {
    var c = Client()
    return try await c.GetH3(address)
}


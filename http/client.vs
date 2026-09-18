package http

import "net/tcp"
import "net/udp"
import "net/quic"
import "crypto/tls"

/// URL represents a parsed HTTP or HTTPS URL.
public struct URL {
    public var Scheme: string
    public var Host: string
    public var Port: uint16
    public var Path: string

    public init(scheme: string, host: string, port: uint16, path: string) {
        self.Scheme = scheme
        self.Host = host
        self.Port = port
        self.Path = path
    }

    public init(host: string, port: uint16, path: string) {
        self.Scheme = "http"
        self.Host = host
        self.Port = port
        self.Path = path
    }

    public static func Parse(_ url: string) throws -> URL {
        let httpsPrefix = "https://"
        let httpPrefix = "http://"
        var urlBytes: [uint8] = []
        for b in url.utf8 { urlBytes.append(b) }

        var scheme = "http"
        var offset = 0
        var defaultPort: uint16 = 80
        if url.hasPrefix(httpsPrefix) {
            scheme = "https"
            offset = 8
            defaultPort = 443
        } else if url.hasPrefix(httpPrefix) {
            scheme = "http"
            offset = 7
            defaultPort = 80
        }

        // Find host[:port] and path
        var pathStart = -1
        var i = offset
        while i < urlBytes.count {
            if urlBytes[i] == 47 { // '/'
                pathStart = i
                break
            }
            i += 1
        }

        let hostPortStr = (pathStart < 0) ? asciiString(urlBytes, from: offset, to: urlBytes.count)
                                          : asciiString(urlBytes, from: offset, to: pathStart)
        let path = (pathStart < 0) ? "/" : asciiString(urlBytes, from: pathStart, to: urlBytes.count)

        var colon = -1
        var hpBytes: [uint8] = []
        for b in hostPortStr.utf8 { hpBytes.append(b) }
        var j = 0
        while j < hpBytes.count {
            if hpBytes[j] == 58 { // ':'
                colon = j
                break
            }
            j += 1
        }

        var host = hostPortStr
        var port = defaultPort
        if colon >= 0 {
            host = asciiString(hpBytes, from: 0, to: colon)
            let portStr = asciiString(hpBytes, from: colon + 1, to: hpBytes.count)
            port = uint16(parseContentLength(portStr))
        }

        if host.isEmpty {
            throw HttpError.invalidUrl
        }
        return URL(scheme: scheme, host: host, port: port, path: path)
    }
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
        let u = URL(scheme: scheme, host: host, port: port, path: req.URL)
        return try await self.DoUrl(req, url: u)
    }

    /// DoUrl executes an HTTP request targeted at a parsed URL.
    public mutating func DoUrl(_ req: Request, url: URL) async throws -> Response {
        let host = url.Host
        let port = url.Port
        let origin = "\(host):\(port)"

        // 1. If HTTPS, check AltSvc cache for HTTP/3 over QUIC
        if url.Scheme == "https" && self.Config.EnableAltSvc {
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
        if url.Scheme == "https" {
            return try await self.executeTls(req: req, url: url)
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
            if port == 80 {
                finalReq.Headers.Set("Host", host)
            } else {
                finalReq.Headers.Set("Host", "\(host):\(port)")
            }
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
    mutating func executeTls(req: Request, url: URL) async throws -> Response {
        let host = url.Host
        let port = url.Port
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
                if port == 443 {
                    finalReq.Headers.Set("Host", host)
                } else {
                    finalReq.Headers.Set("Host", "\(host):\(port)")
                }
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
        var addr: SocketAddress = SocketAddress.v4(ip: host, port: port)
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
    public func GetH3(_ url: string) async throws -> Response {
        let u = try URL.Parse(url)
        let req = Request(method: "GET", url: u.Path, version: HttpVersion.http3)
        return try await self.executeH3(req: req, host: u.Host, port: u.Port)
    }

    /// Get sends an HTTP or HTTPS GET request to the specified URL.
    public mutating func Get(_ url: string) async throws -> Response {
        let u = try URL.Parse(url)
        let req = Request(method: "GET", url: u.Path)
        return try await self.DoUrl(req, url: u)
    }

    /// Post sends an HTTP or HTTPS POST request with the specified body to the URL.
    public mutating func Post(_ url: string, contentType: string, body: [uint8]) async throws -> Response {
        let u = try URL.Parse(url)
        var req = Request(method: "POST", url: u.Path)
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
    } else if res.Headers.Get("Transfer-Encoding") == nil && res.StatusCode != 204 && res.StatusCode != 304 {
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
public func Get(_ url: string) async throws -> Response {
    var c = Client()
    return try await c.Get(url)
}

/// Post sends an HTTP POST request to url using DefaultClient.
public func Post(_ url: string, contentType: string, body: [uint8]) async throws -> Response {
    var c = Client()
    return try await c.Post(url, contentType: contentType, body: body)
}

/// GetH3 sends an HTTP/3 GET request to url directly over QUIC.
public func GetH3(_ url: string) async throws -> Response {
    var c = Client()
    return try await c.GetH3(url)
}


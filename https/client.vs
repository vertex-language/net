package https

import "net/http"
import "net/tcp"
import "crypto/tls"

/// Client is an HTTPS client for executing requests over TLS 1.3.
public struct Client {
    public static let Default: Client = Client()

    public var TLSConfig: tls.Config
    public var TimeoutMs: int32

    public init(tlsConfig: tls.Config = tls.Config(), timeoutMs: int32 = 5000) {
        self.TLSConfig = tlsConfig
        self.TimeoutMs = timeoutMs
    }

    /// Do sends an HTTP request over a TLS connection and returns an HTTP response.
    public func Do(_ req: http.Request, host: string, port: uint16 = 443, config: tls.Config = tls.Config()) async throws -> http.Response {
        var cfg = config
        if cfg.ServerName.isEmpty {
            if !self.TLSConfig.ServerName.isEmpty {
                cfg.ServerName = self.TLSConfig.ServerName
            } else {
                cfg.ServerName = host
            }
        }

        var conn = try await tls.Dial(host: host, port: port, config: cfg)
        defer { conn.Close() }

        var finalReq = req
        if finalReq.Headers.Get("Host") == nil {
            if port == 443 {
                finalReq.Headers.Set("Host", host)
            } else {
                finalReq.Headers.Set("Host", "\(host):\(port)")
            }
        }
        if finalReq.Headers.Get("User-Agent") == nil {
            finalReq.Headers.Set("User-Agent", "Vertex-HTTPS/1.1")
        }
        if !finalReq.Body.isEmpty && finalReq.Headers.Get("Content-Length") == nil {
            finalReq.Headers.Set("Content-Length", "\(finalReq.Body.count)")
        }
        if finalReq.Headers.Get("Connection") == nil {
            finalReq.Headers.Set("Connection", "close")
        }

        try await finalReq.Write(to: &conn)
        return try await ReadResponse(from: &conn)
    }

    /// Get sends an HTTPS GET request to the specified URL.
    public func Get(_ url: string) async throws -> http.Response {
        let u = try http.URL.Parse(url)
        let req = http.Request(method: "GET", url: u.Path)
        return try await Do(req, host: u.Host, port: u.Port)
    }

    /// Post sends an HTTPS POST request with the specified body to the URL.
    public func Post(_ url: string, contentType: string, body: [uint8]) async throws -> http.Response {
        let u = try http.URL.Parse(url)
        var req = http.Request(method: "POST", url: u.Path)
        req.Headers.Set("Content-Type", contentType)
        req.Body = body
        return try await Do(req, host: u.Host, port: u.Port)
    }
}

public let DefaultClient = Client()

/// Get sends an HTTPS GET request to url using the DefaultClient.
public func Get(_ url: string) async throws -> http.Response {
    return try await DefaultClient.Get(url)
}

/// Post sends an HTTPS POST request to url using the DefaultClient.
public func Post(_ url: string, contentType: string, body: [uint8]) async throws -> http.Response {
    return try await DefaultClient.Post(url, contentType: contentType, body: body)
}

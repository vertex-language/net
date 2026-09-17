package http

import "net/tcp"

/// URL represents a parsed HTTP URL.
public struct URL {
    public var Host: string
    public var Port: uint16
    public var Path: string

    public init(host: string, port: uint16, path: string) {
        self.Host = host
        self.Port = port
        self.Path = path
    }

    public static func Parse(_ url: string) throws -> URL {
        let httpPrefix = "http://"
        var urlBytes: [uint8] = []
        for b in url.utf8 { urlBytes.append(b) }

        var offset = 0
        if url.hasPrefix(httpPrefix) {
            offset = 7
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
        var port: uint16 = 80
        if colon >= 0 {
            host = asciiString(hpBytes, from: 0, to: colon)
            let portStr = asciiString(hpBytes, from: colon + 1, to: hpBytes.count)
            port = uint16(parseContentLength(portStr))
        }

        if host.isEmpty {
            throw HttpError.invalidUrl
        }
        return URL(host: host, port: port, path: path)
    }
}

/// Client is an HTTP client for executing HTTP requests over TCP.
public struct Client {
    public var TimeoutMs: int32 = 5000

    public init(timeoutMs: int32 = 5000) {
        self.TimeoutMs = timeoutMs
    }

    /// Do sends an HTTP request and returns an HTTP response.
    public func Do(_ req: Request, host: string, port: uint16) async throws -> Response {
        let stream = try await tcp.Connect(host: host, port: port)
        defer { stream.Close() }

        var finalReq = req
        if finalReq.Headers.Get("Host") == nil {
            finalReq.Headers.Set("Host", "\(host):\(port)")
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

    /// Get sends an HTTP GET request to the specified URL.
    public func Get(_ url: string) async throws -> Response {
        let u = try URL.Parse(url)
        let req = Request(method: "GET", url: u.Path)
        return try await Do(req, host: u.Host, port: u.Port)
    }

    /// Post sends an HTTP POST request with the specified body to the URL.
    public func Post(_ url: string, contentType: string, body: [uint8]) async throws -> Response {
        let u = try URL.Parse(url)
        var req = Request(method: "POST", url: u.Path)
        req.Headers.Set("Content-Type", contentType)
        req.Body = body
        return try await Do(req, host: u.Host, port: u.Port)
    }
}

public let DefaultClient = Client()

/// Get sends an HTTP GET request to url using the DefaultClient.
public func Get(_ url: string) async throws -> Response {
    return try await DefaultClient.Get(url)
}

/// Post sends an HTTP POST request to url using the DefaultClient.
public func Post(_ url: string, contentType: string, body: [uint8]) async throws -> Response {
    return try await DefaultClient.Post(url, contentType: contentType, body: body)
}

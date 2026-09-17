package https

import "net/http"
import "crypto/tls"

/// WriteRequest writes an HTTP request to an active TLS connection.
public func WriteRequest(_ req: http.Request, to conn: inout tls.Conn) async throws {
    try await conn.WriteText(req.HeaderText())
    if !req.Body.isEmpty {
        try await conn.Write(req.Body)
    }
}

/// ReadResponse parses an HTTP/1.1 response from a connected TLS session.
public func ReadResponse(from conn: inout tls.Conn) async throws -> http.Response {
    var raw: [uint8] = []
    var buf = [uint8](repeating: 0, count: 1024)
    var headerEnd = -1

    while headerEnd < 0 {
        let n = try await conn.Read(into: &buf)
        if n == 0 {
            throw http.HttpError.connectionClosed
        }
        var i = 0
        while i < n {
            raw.append(buf[i])
            i += 1
        }
        headerEnd = http.Response.FindHeaderEnd(raw, from: raw.count - n - 3)
    }

    var res = try http.Response.ParseHeaders(raw, headerEnd: headerEnd)

    if let clVal = res.Headers.Get("Content-Length") {
        var exp = 0
        for b in clVal.utf8 {
            if b >= 48 && b <= 57 { exp = exp * 10 + int(b - 48) }
        }
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

/// WriteResponse writes an HTTP response to an active TLS connection.
public func WriteResponse(_ res: http.Response, to conn: inout tls.Conn) async throws {
    try await conn.WriteText(res.HeaderText())
    if !res.Body.isEmpty {
        try await conn.Write(res.Body)
    }
}

/// ReadRequest parses an HTTP/1.1 request from an incoming TLS connection.
public func ReadRequest(from conn: inout tls.Conn) async throws -> http.Request {
    var raw: [uint8] = []
    var buf = [uint8](repeating: 0, count: 1024)
    var headerEnd = -1

    while headerEnd < 0 {
        let n = try await conn.Read(into: &buf)
        if n == 0 {
            throw http.HttpError.connectionClosed
        }
        var i = 0
        while i < n {
            raw.append(buf[i])
            i += 1
        }
        headerEnd = http.Request.FindHeaderEnd(raw, from: raw.count - n - 3)
    }

    var req = try http.Request.ParseHeaders(raw, headerEnd: headerEnd)

    if let clVal = req.Headers.Get("Content-Length") {
        var exp = 0
        for b in clVal.utf8 {
            if b >= 48 && b <= 57 { exp = exp * 10 + int(b - 48) }
        }
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

extension http.Request {
    /// Write writes this request to an established TLS connection.
    public func Write(to conn: inout tls.Conn) async throws {
        try await conn.WriteText(self.HeaderText())
        if !self.Body.isEmpty {
            try await conn.Write(self.Body)
        }
    }
}

extension http.Response {
    /// Write writes this response to an established TLS connection.
    public func Write(to conn: inout tls.Conn) async throws {
        try await conn.WriteText(self.HeaderText())
        if !self.Body.isEmpty {
            try await conn.Write(self.Body)
        }
    }
}


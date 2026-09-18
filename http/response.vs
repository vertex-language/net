package http

import "net/tcp"

/// Response represents an HTTP response received by a client or sent by a server.
public struct Response {
    public var StatusCode: int32 = 200
    public var Status: string = "200 OK"
    public var Version: HttpVersion = HttpVersion.http1_1
    public var Proto: string = "HTTP/1.1"
    public var Headers: Header = Header()
    public var Body: [uint8] = []

    public init(statusCode: int32 = 200, proto: string = "HTTP/1.1") {
        self.StatusCode = statusCode
        self.Status = "\(statusCode) \(StatusText(statusCode))"
        self.Version = HttpVersion.http1_1
        self.Proto = proto
    }

    public init(statusCode: int32, version: HttpVersion) {
        self.StatusCode = statusCode
        self.Status = "\(statusCode) \(StatusText(statusCode))"
        self.Version = version
        self.Proto = version.Name
    }

    /// Convenience getter decoding body bytes as UTF-8 string.
    public var Text: string {
        return string(decoding: self.Body, as: UTF8.self)
    }

    public func BodyText() -> string {
        return self.Text
    }

    /// Sets the response body to the UTF-8 bytes of text.
    public mutating func SetBodyText(_ text: string) {
        var bytes: [uint8] = []
        for b in text.utf8 { bytes.append(b) }
        self.Body = bytes
    }

    /// StatusLine returns the HTTP status line including trailing CRLF.
    public func StatusLine() -> string {
        return "\(Proto) \(StatusCode) \(StatusText(StatusCode))\r\n"
    }

    /// HeaderText serializes the status line and headers in HTTP/1.1 format with trailing CRLF CRLF.
    public func HeaderText() -> string {
        var text = StatusLine()
        var i = 0
        while i < Headers.entries.count {
            let e = Headers.entries[i]
            text += "\(e.Key): \(e.Value)\r\n"
            i += 1
        }
        text += "\r\n"
        return text
    }

    /// Bytes serializes the entire HTTP response (status line, headers, and body) to wire bytes.
    public func Bytes() -> [uint8] {
        var out: [uint8] = []
        let text = HeaderText()
        for b in text.utf8 {
            out.append(b)
        }
        var i = 0
        while i < Body.count {
            out.append(Body[i])
            i += 1
        }
        return out
    }

    /// Write writes the status line, headers, and body to a stream.
    public func Write(to stream: tcp.TcpStream) async throws {
        try await stream.WriteText(HeaderText())
        if !Body.isEmpty {
            try await stream.Write(Body)
        }
    }

    /// FindHeaderEnd finds the start index of \r\n\r\n in raw bytes, or -1 if not found.
    public static func FindHeaderEnd(_ raw: [uint8], from: int = 0) -> int {
        return Request.FindHeaderEnd(raw, from: from)
    }

    /// ParseHeaders parses a Response's status line, headers, and any initial body bytes up to headerEnd.
    public static func ParseHeaders(_ raw: [uint8], headerEnd: int) throws -> Response {
        var lines: [string] = []
        var lineStart = 0
        var k = 0
        while k < headerEnd {
            if raw[k] == 13 && raw[k+1] == 10 {
                lines.append(asciiString(raw, from: lineStart, to: k))
                k += 2
                lineStart = k
            } else {
                k += 1
            }
        }
        if lineStart < headerEnd {
            lines.append(asciiString(raw, from: lineStart, to: headerEnd))
        }

        if lines.isEmpty {
            throw HttpError.malformedResponse
        }

        // First line: PROTO STATUS_CODE REASON
        let firstLine = lines[0]
        var parts: [string] = []
        var pStart = 0
        var pIdx = 0
        var flBytes: [uint8] = []
        for b in firstLine.utf8 { flBytes.append(b) }
        while pIdx < flBytes.count {
            if flBytes[pIdx] == 32 {
                parts.append(asciiString(flBytes, from: pStart, to: pIdx))
                pIdx += 1
                pStart = pIdx
            } else {
                pIdx += 1
            }
        }
        if pStart < flBytes.count {
            parts.append(asciiString(flBytes, from: pStart, to: flBytes.count))
        }

        if parts.count < 2 {
            throw HttpError.malformedResponse
        }

        let code = int32(parseContentLength(parts[1]))
        var res = Response(statusCode: code, proto: parts[0])

        var lineIdx = 1
        while lineIdx < lines.count {
            let line = lines[lineIdx]
            var colon = -1
            var cIdx = 0
            for b in line.utf8 {
                if b == 58 {
                    colon = cIdx
                    break
                }
                cIdx += 1
            }
            if colon > 0 {
                var lBytes: [uint8] = []
                for b in line.utf8 { lBytes.append(b) }
                let key = trimSpaces(asciiString(lBytes, from: 0, to: colon))
                let val = trimSpaces(asciiString(lBytes, from: colon + 1, to: lBytes.count))
                res.Headers.Add(key, val)
            }
            lineIdx += 1
        }

        let bodyStart = headerEnd + 4
        var bodyBytes: [uint8] = []
        var bIdx = bodyStart
        while bIdx < raw.count {
            bodyBytes.append(raw[bIdx])
            bIdx += 1
        }
        res.Body = bodyBytes
        return res
    }
}

/// ReadResponse parses an HTTP/1.1 response from a connected TCP stream.
public func ReadResponse(from stream: tcp.TcpStream) async throws -> Response {
    var raw: [uint8] = []
    var buf = [uint8](repeating: 0, count: 1024)
    var headerEnd = -1

    while headerEnd < 0 {
        let n = try await stream.Read(into: &buf)
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
        let expectedLen = parseContentLength(clVal)
        while res.Body.count < expectedLen {
            let n = try await stream.Read(into: &buf)
            if n == 0 { break }
            var bi = 0
            while bi < n {
                res.Body.append(buf[bi])
                bi += 1
            }
        }
    } else if res.Headers.Get("Transfer-Encoding") == nil && res.StatusCode != 204 && res.StatusCode != 304 {
        while true {
            let n = try await stream.Read(into: &buf)
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

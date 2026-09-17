package http

import tcp

/// Response represents an HTTP response received by a client or sent by a server.
public struct Response {
    public var StatusCode: int32 = 200
    public var Status: string = "200 OK"
    public var Proto: string = "HTTP/1.1"
    public var Headers: Header = Header()
    public var Body: [uint8] = []

    public init(statusCode: int32 = 200, proto: string = "HTTP/1.1") {
        self.StatusCode = statusCode
        self.Status = "\(statusCode) \(StatusText(statusCode))"
        self.Proto = proto
    }

    public func BodyText() -> string {
        var chars: [CChar] = []
        for b in Body { chars.append(CChar(truncatingIfNeeded: b)) }
        chars.append(0)
        return string(cString: chars)
    }

    /// Write writes the status line, headers, and body to a stream.
    public func Write(to stream: tcp.TcpStream) async throws {
        var text = "\(Proto) \(StatusCode) \(StatusText(StatusCode))\r\n"
        var i = 0
        while i < Headers.entries.count {
            let e = Headers.entries[i]
            text += "\(e.Key): \(e.Value)\r\n"
            i += 1
        }
        text += "\r\n"
        try await stream.WriteText(text)
        if !Body.isEmpty {
            try await stream.Write(Body)
        }
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
        if raw.count >= 4 {
            var j = raw.count - n - 3
            if j < 0 { j = 0 }
            while j + 3 < raw.count {
                if raw[j] == 13 && raw[j+1] == 10 && raw[j+2] == 13 && raw[j+3] == 10 {
                    headerEnd = j
                    break
                }
                j += 1
            }
        }
    }

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

    if let clVal = res.Headers.Get("Content-Length") {
        let expectedLen = parseContentLength(clVal)
        while bodyBytes.count < expectedLen {
            let n = try await stream.Read(into: &buf)
            if n == 0 { break }
            var bi = 0
            while bi < n {
                bodyBytes.append(buf[bi])
                bi += 1
            }
        }
    }

    res.Body = bodyBytes
    return res
}

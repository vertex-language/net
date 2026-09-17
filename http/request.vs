package http

import tcp

public enum HttpError: Error {
    case malformedRequest
    case malformedResponse
    case connectionClosed
    case invalidUrl
}

func asciiString(_ bytes: [uint8], from: int, to: int) -> string {
    var chars: [CChar] = []
    var i = from
    while i < to {
        chars.append(CChar(truncatingIfNeeded: bytes[i]))
        i += 1
    }
    chars.append(0)
    return string(cString: chars)
}

func trimSpaces(_ s: string) -> string {
    var bytes: [uint8] = []
    for b in s.utf8 { bytes.append(b) }
    var start = 0
    while start < bytes.count && (bytes[start] == 32 || bytes[start] == 9 || bytes[start] == 13 || bytes[start] == 10) {
        start += 1
    }
    var end = bytes.count
    while end > start && (bytes[end - 1] == 32 || bytes[end - 1] == 9 || bytes[end - 1] == 13 || bytes[end - 1] == 10) {
        end -= 1
    }
    return asciiString(bytes, from: start, to: end)
}

func parseContentLength(_ val: string) -> int {
    var n = 0
    for b in val.utf8 {
        if b >= 48 && b <= 57 {
            n = n * 10 + int(b - 48)
        }
    }
    return n
}

/// Request represents an HTTP request received by a server or to be sent by a client.
public struct Request {
    public var Method: string
    public var URL: string
    public var Proto: string = "HTTP/1.1"
    public var Headers: Header = Header()
    public var Body: [uint8] = []

    public init(method: string = "GET", url: string = "/", proto: string = "HTTP/1.1") {
        self.Method = method
        self.URL = url
        self.Proto = proto
    }

    public func BodyText() -> string {
        var chars: [CChar] = []
        for b in Body { chars.append(CChar(truncatingIfNeeded: b)) }
        chars.append(0)
        return string(cString: chars)
    }

    /// Write writes the HTTP request line, headers, and body to a stream.
    public func Write(to stream: tcp.TcpStream) async throws {
        var text = "\(Method) \(URL) \(Proto)\r\n"
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

/// ReadRequest parses an HTTP/1.1 request from an incoming TCP stream.
public func ReadRequest(from stream: tcp.TcpStream) async throws -> Request {
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
        // Check for \r\n\r\n
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

    // Parse header lines
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
        throw HttpError.malformedRequest
    }

    // First line: METHOD URL PROTO
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

    if parts.count < 3 {
        throw HttpError.malformedRequest
    }

    var req = Request(method: parts[0], url: parts[1], proto: parts[2])

    // Headers
    var lineIdx = 1
    while lineIdx < lines.count {
        let line = lines[lineIdx]
        var colon = -1
        var cIdx = 0
        for b in line.utf8 {
            if b == 58 { // ':'
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
            req.Headers.Add(key, val)
        }
        lineIdx += 1
    }

    // Body
    let bodyStart = headerEnd + 4
    var bodyBytes: [uint8] = []
    var bIdx = bodyStart
    while bIdx < raw.count {
        bodyBytes.append(raw[bIdx])
        bIdx += 1
    }

    if let clVal = req.Headers.Get("Content-Length") {
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

    req.Body = bodyBytes
    return req
}

package http

import "net/tcp"

@_silgen_name("vertex_string_from_utf8")
func stringFromUtf8(_ ptr: UnsafeRawPointer, _ count: int64) -> string

func asciiString(_ bytes: [uint8], from: int, to: int) -> string {
    if from >= to || from >= bytes.count {
        return ""
    }
    let count = to - from
    return bytes.withUnsafeBytes { raw in
        stringFromUtf8(raw.baseAddress! + from, int64(count))
    }
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

// headerNameIs reports whether the count bytes at raw[at...] spell name,
// ignoring case, compared where they lie. (`name.utf8` would make an array
// of name's bytes first: vsc does not use the view in place yet.)
func headerNameIs(_ raw: [uint8], _ at: int, _ count: int, _ name: string) -> bool {
    if at + count > raw.count {
        return false
    }
    let same: bool = raw.withUnsafeBytes { rp in
        equalFoldBytes(rp.baseAddress! + at, int64(count), name)
    }
    return same
}

/// Request represents an HTTP request received by a server or to be sent by a client.
public struct Request {
    public var Method: string
    public var URL: string
    public var Version: HttpVersion = HttpVersion.http1_1
    public var Proto: string = "HTTP/1.1"
    // minor is the HTTP/1.x minor version the parser read: 0 for
    // HTTP/1.0, which decides keep-alive, and 1 otherwise.
    var minor: int = 1
    // What the parser noticed on its way past, so that the server need
    // not look headers up afterwards: Content-Length's value (0 when
    // absent), and which span is Connection (-1 when absent).
    var contentLength: int = 0
    var connectionSpan: int = -1
    public var Headers: Header = Header()
    public var Body: [uint8] = []

    public init(method: string = "GET", url: string = "/", proto: string = "HTTP/1.1") {
        self.Method = method
        self.URL = url
        self.Version = HttpVersion.http1_1
        self.Proto = proto
    }

    public init(method: string, url: string, version: HttpVersion) {
        self.Method = method
        self.URL = url
        self.Version = version
        self.Proto = version.Name
    }

    public func BodyText() -> string {
        var chars: [CChar] = []
        for b in Body { chars.append(CChar(truncatingIfNeeded: b)) }
        chars.append(0)
        return string(cString: chars)
    }

    /// HeaderText serializes the request line and headers in HTTP/1.1 format with trailing CRLF CRLF.
    public func HeaderText() -> string {
        var text = "\(Method) \(URL) \(Proto)\r\n"
        let all = Headers.Materialized()
        var i = 0
        while i < all.count {
            let e = all[i]
            text += "\(e.Key): \(e.Value)\r\n"
            i += 1
        }
        text += "\r\n"
        return text
    }

    /// Bytes serializes the entire HTTP request (request line, headers, and body) to wire bytes.
    public func Bytes() -> [uint8] {
        var out: [uint8] = HeaderText().utf8
        out.append(contentsOf: Body)
        return out
    }

    /// Write writes the HTTP request line, headers, and body to a stream.
    public func Write(to stream: tcp.TcpStream) async throws {
        try await stream.WriteText(HeaderText())
        if !Body.isEmpty {
            try await stream.Write(Body)
        }
    }

    /// FindHeaderEnd finds the start index of \r\n\r\n in raw bytes, or -1 if not found.
    public static func FindHeaderEnd(_ raw: [uint8], from: int = 0) -> int {
        return FindHeaderEnd(raw, from: from, to: raw.count)
    }

    /// FindHeaderEnd finds the start index of \r\n\r\n in raw[from..<to], or -1 if not found.
    public static func FindHeaderEnd(_ raw: [uint8], from: int, to: int) -> int {
        var j = from
        if j < 0 { j = 0 }
        let end = to < raw.count ? to : raw.count
        while j + 3 < end {
            // Every request's blank line begins with \r; the three bytes
            // after it are looked at only when one is found.
            if raw[j] == 13 && raw[j+1] == 10 && raw[j+2] == 13 && raw[j+3] == 10 {
                return j
            }
            j += 1
        }
        return -1
    }

    /// ParseHeaders parses a Request's method, URL, proto, headers, and any initial body bytes up to headerEnd.
    public static func ParseHeaders(_ raw: [uint8], headerEnd: int) throws -> Request {
        var req = try ParseHeaders(raw, from: 0, headerEnd: headerEnd)
        let bodyStart = headerEnd + 4
        if bodyStart < raw.count {
            req.Body = sliceBytes(raw, from: bodyStart, count: raw.count - bodyStart)
        }
        return req
    }

    /// ParseHeaders parses the request line and headers that begin at
    /// `from` and end at `headerEnd`, the start of the blank line, and is
    /// the Request they describe. The bytes after the blank line are not
    /// looked at: a server that reads into one buffer per connection
    /// keeps the body, and the next request, where they are.
    public static func ParseHeaders(_ raw: [uint8], from: int, headerEnd: int) throws -> Request {
        var req = Request()
        try parse(into: &req, raw, from: from, headerEnd: headerEnd)
        return req
    }

    /// parse is ParseHeaders into a Request that already exists: a server
    /// keeps one per connection and parses each request into it, so the
    /// arrays that hold the header block and its spans are allocated once
    /// per connection rather than once per request. Every field the parse
    /// sets is reset first; a handler that kept the previous request has
    /// its own copy, since the arrays are copy-on-write.
    static func parse(into req: inout Request, _ raw: [uint8], from: int, headerEnd: int) throws {
        var i = from
        while i < headerEnd && (raw[i] == 32 || raw[i] == 13 || raw[i] == 10) { i += 1 }
        let mStart = i
        while i < headerEnd && raw[i] != 32 && raw[i] != 13 && raw[i] != 10 { i += 1 }
        if i >= headerEnd { throw HttpError.malformedRequest }
        let mLen = i - mStart
        var method = ""
        if mLen == 3 && raw[mStart] == 71 && raw[mStart+1] == 69 && raw[mStart+2] == 84 {
            method = "GET"
        } else if mLen == 4 && raw[mStart] == 80 && raw[mStart+1] == 79 && raw[mStart+2] == 83 && raw[mStart+3] == 84 {
            method = "POST"
        } else if mLen == 4 && raw[mStart] == 72 && raw[mStart+1] == 69 && raw[mStart+2] == 65 && raw[mStart+3] == 68 {
            method = "HEAD"
        } else if mLen == 3 && raw[mStart] == 80 && raw[mStart+1] == 85 && raw[mStart+2] == 84 {
            method = "PUT"
        } else if mLen == 6 && raw[mStart] == 68 && raw[mStart+1] == 69 && raw[mStart+2] == 76 && raw[mStart+3] == 69 && raw[mStart+4] == 84 && raw[mStart+5] == 69 {
            method = "DELETE"
        } else {
            method = asciiString(raw, from: mStart, to: i)
        }

        while i < headerEnd && raw[i] == 32 { i += 1 }
        let uStart = i
        while i < headerEnd && raw[i] != 32 && raw[i] != 13 && raw[i] != 10 { i += 1 }
        if i >= headerEnd { throw HttpError.malformedRequest }
        let uLen = i - uStart
        var url = ""
        if uLen == 1 && raw[uStart] == 47 {
            url = "/"
        } else {
            url = asciiString(raw, from: uStart, to: i)
        }

        while i < headerEnd && raw[i] == 32 { i += 1 }
        let pStart = i
        while i < headerEnd && raw[i] != 13 && raw[i] != 10 { i += 1 }
        let pLen = i - pStart
        // HTTP/1.1 and HTTP/1.0 are literals, which cost nothing to make;
        // anything else is read out of the buffer.
        var proto = "HTTP/1.1"
        var minor = 1
        if pLen == 8 && raw[pStart] == 72 && raw[pStart+1] == 84 && raw[pStart+2] == 84 && raw[pStart+3] == 80 && raw[pStart+4] == 47 && raw[pStart+5] == 49 && raw[pStart+6] == 46 && (raw[pStart+7] == 49 || raw[pStart+7] == 48) {
            if raw[pStart+7] == 48 {
                proto = "HTTP/1.0"
                minor = 0
            }
        } else {
            proto = asciiString(raw, from: pStart, to: i)
        }
        while i < headerEnd && (raw[i] == 13 || raw[i] == 10) { i += 1 }

        req.Method = method
        req.URL = url
        req.Proto = proto
        req.Version = HttpVersion.http1_1
        req.minor = minor
        req.contentLength = 0
        req.connectionSpan = -1
        if !req.Body.isEmpty { req.Body = [] }
        if !req.Headers.entries.isEmpty { req.Headers.entries = [] }
        req.Headers.spans.removeAll(keepingCapacity: true)

        // The header block is copied into the request once, and each
        // header recorded as spans into that copy: no string is made for
        // a name or value until something reads it. `from` is where the
        // request began in raw, so spans are relative to the copy.
        let blockStart = from
        req.Headers.setRaw(raw, from: blockStart, count: headerEnd - blockStart)
        while i < headerEnd {
            let lineStart = i
            var colon = -1
            // Each byte is read once: the line's end and its first colon
            // are found in the one pass.
            while i < headerEnd {
                let c = raw[i]
                if c == 13 || c == 10 { break }
                if c == 58 && colon < 0 {
                    colon = i
                }
                i += 1
            }
            if colon > lineStart {
                var kStart = lineStart
                while kStart < colon && (raw[kStart] == 32 || raw[kStart] == 9) { kStart += 1 }
                var kEnd = colon
                while kEnd > kStart && (raw[kEnd - 1] == 32 || raw[kEnd - 1] == 9) { kEnd -= 1 }

                var vStart = colon + 1
                while vStart < i && (raw[vStart] == 32 || raw[vStart] == 9) { vStart += 1 }
                var vEnd = i
                while vEnd > vStart && (raw[vEnd - 1] == 32 || raw[vEnd - 1] == 9) { vEnd -= 1 }

                if kEnd > kStart {
                    let kLen = kEnd - kStart
                    // The two headers the server acts on, told apart by
                    // length and first letter before any comparison.
                    let first = raw[kStart] | 32
                    if first == 99 && kLen == 14 && headerNameIs(raw, kStart, kLen, "content-length") {
                        var n = 0
                        var d = vStart
                        while d < vEnd {
                            let b = raw[d]
                            if b >= 48 && b <= 57 {
                                n = n * 10 + int(b - 48)
                            }
                            d += 1
                        }
                        req.contentLength = n
                    } else if first == 99 && kLen == 10 && headerNameIs(raw, kStart, kLen, "connection") {
                        req.connectionSpan = req.Headers.spans.count
                    }
                    req.Headers.addSpan(kStart: kStart - blockStart, kLen: kLen,
                                        vStart: vStart - blockStart, vLen: vEnd - vStart)
                }
            }
            while i < headerEnd && (raw[i] == 13 || raw[i] == 10) { i += 1 }
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
        headerEnd = Request.FindHeaderEnd(raw, from: raw.count - n - 3)
    }

    var req = try Request.ParseHeaders(raw, headerEnd: headerEnd)

    if let clVal = req.Headers.Get("Content-Length") {
        let expectedLen = parseContentLength(clVal)
        while req.Body.count < expectedLen {
            let n = try await stream.Read(into: &buf)
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

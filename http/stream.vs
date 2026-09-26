package http

import (
    "crypto/tls"
    "io"
    "net/tcp"
)

/// ResponseStream is a response whose body is read as it arrives, for a
/// body too big to hold: a model's weights, a dataset shard. Response
/// holds the status and headers (its Body is empty); Read gives the
/// body, with its framing -- Content-Length, chunked, or to the close --
/// taken off. HTTP/1.1, one request per connection.
public struct ResponseStream: io.AsyncReader {
    public var Response: Response
    var conn: tls.Conn
    let secure: bool
    var buf: [uint8]
    var start: int = 0
    var end: int = 0
    var eof: bool = false
    var framing: bodyFraming
    // Chunked: what is left of the current chunk, and whether its CRLF
    // is still to be read.
    var chunkLeft: int64 = 0
    var chunkCRLF: bool = false
    var finished: bool = false

    init(conn: tls.Conn, secure: bool) {
        self.Response = http.Response(statusCode: 0)
        self.conn = conn
        self.secure = secure
        self.buf = [uint8](repeating: 0, count: 65536)
        self.framing = bodyFraming.toClose
    }

    /// The body's length from Content-Length, when the response gave one.
    public var ContentLength: int64? {
        if case .length(let n) = self.framing {
            return n
        }
        return nil
    }

    /// Reads the next bytes of the body into the start of buffer; 0 at
    /// its end. A body cut short -- the connection closed before the
    /// length or the last chunk -- throws `HttpError.connectionClosed`.
    public mutating func Read(into buffer: inout [uint8]) async throws -> int {
        if self.finished || buffer.isEmpty {
            return 0
        }
        switch self.framing {
        case .none:
            self.finished = true
            return 0
        case .toClose:
            let n = try await self.take(into: &buffer, max: int64(buffer.count))
            if n == 0 {
                self.finished = true
            }
            return n
        case .length(let total):
            let left = total - self.consumed
            if left <= 0 {
                self.finished = true
                return 0
            }
            let n = try await self.take(into: &buffer, max: left)
            if n == 0 {
                throw HttpError.connectionClosed
            }
            self.consumed += int64(n)
            return n
        case .chunked:
            if self.chunkLeft == 0 {
                if self.chunkCRLF {
                    _ = try await self.line()
                    self.chunkCRLF = false
                }
                let size = try await self.line()
                guard let n = chunkSize(size) else {
                    throw HttpError.malformedResponse
                }
                if n == 0 {
                    // The trailers, up to the empty line, are dropped.
                    while !(try await self.line()).isEmpty {}
                    self.finished = true
                    return 0
                }
                self.chunkLeft = n
            }
            let n = try await self.take(into: &buffer, max: self.chunkLeft)
            if n == 0 {
                throw HttpError.connectionClosed
            }
            self.chunkLeft -= int64(n)
            if self.chunkLeft == 0 {
                self.chunkCRLF = true
            }
            return n
        }
    }

    var consumed: int64 = 0

    /// Closes the connection. Reading after it returns 0.
    public mutating func Close() {
        self.finished = true
        self.conn.Close()
    }

    // take copies up to max buffered bytes into buffer, reading more
    // when none are buffered; 0 at the connection's end.
    mutating func take(into buffer: inout [uint8], max: int64) async throws -> int {
        if self.start == self.end {
            try await self.fill()
            if self.start == self.end {
                return 0
            }
        }
        var n = self.end - self.start
        if n > buffer.count { n = buffer.count }
        if int64(n) > max { n = int(max) }
        buffer.withUnsafeMutableBytes { dst in
            self.buf.withUnsafeBytes { src in
                _ = c_memcpy(dst.baseAddress!, src.baseAddress! + self.start, n)
            }
        }
        self.start += n
        return n
    }

    // fill reads what the connection has into the buffer, after moving
    // what is left of it to the front.
    mutating func fill() async throws {
        if self.eof {
            return
        }
        if self.start > 0 {
            let left = self.end - self.start
            if left > 0 {
                self.buf.withUnsafeMutableBytes { b in
                    _ = c_memmove(b.baseAddress!, UnsafeRawPointer(b.baseAddress! + self.start), left)
                }
            }
            self.start = 0
            self.end = left
        }
        if self.end == self.buf.count {
            self.buf.append(contentsOf: [uint8](repeating: 0, count: self.buf.count))
        }
        var chunk = [uint8](repeating: 0, count: self.buf.count - self.end)
        let n = self.secure ? try await self.conn.Read(into: &chunk) : try await self.conn.stream.Read(into: &chunk)
        if n == 0 {
            self.eof = true
            return
        }
        let at = self.end
        self.buf.withUnsafeMutableBytes { dst in
            chunk.withUnsafeBytes { src in
                _ = c_memcpy(dst.baseAddress! + at, src.baseAddress!, n)
            }
        }
        self.end += n
    }

    // line reads up to the next LF and returns the line without its CRLF.
    mutating func line() async throws -> string {
        var scanned = self.start
        while true {
            while scanned < self.end {
                if self.buf[scanned] == 10 {
                    var stop = scanned
                    if stop > self.start && self.buf[stop - 1] == 13 {
                        stop -= 1
                    }
                    let text = asciiString(self.buf, from: self.start, to: stop)
                    self.start = scanned + 1
                    return text
                }
                scanned += 1
            }
            if scanned - self.start > 65536 {
                throw HttpError.malformedResponse
            }
            let before = self.start
            try await self.fill()
            if self.eof && scanned - before >= self.end - self.start {
                throw HttpError.connectionClosed
            }
            scanned = self.start + (scanned - before)
        }
    }

    // head reads the status line and headers, and works out how the body
    // is framed (RFC 9112 section 6.3).
    mutating func head(method: string) async throws {
        var lines: [string] = []
        while true {
            let l = try await self.line()
            if l.isEmpty {
                if lines.isEmpty {
                    continue
                }
                break
            }
            lines.append(l)
            if lines.count > 1000 {
                throw HttpError.malformedResponse
            }
        }
        let status = lines[0]
        let parts = status.split(separator: " ", maxSplits: 2)
        if parts.count < 2 || !status.hasPrefix("HTTP/") {
            throw HttpError.malformedResponse
        }
        guard let code = int32(String(parts[1])) else {
            throw HttpError.malformedResponse
        }
        var res = http.Response(statusCode: code, proto: String(parts[0]))
        res.Status = parts.count > 2 ? "\(code) \(parts[2])" : "\(code)"
        var i = 1
        while i < lines.count {
            let l = lines[i]
            if let colon = l.firstIndex(of: ":") {
                let key = trimSpaces(String(l[l.startIndex..<colon]))
                let val = trimSpaces(String(l[l.index(after: colon)..<l.endIndex]))
                res.Headers.Add(key, val)
            }
            i += 1
        }
        self.Response = res
        // HEAD, 1xx, 204 and 304 have no body, whatever they say.
        if method == "HEAD" || (code >= 100 && code < 200) || code == 204 || code == 304 {
            self.framing = .none
        } else if let te = res.Headers.Get("Transfer-Encoding"), te.lowercased().contains("chunked") {
            self.framing = .chunked
        } else if let cl = res.Headers.Get("Content-Length") {
            guard let n = int64(trimSpaces(cl)) else {
                throw HttpError.malformedResponse
            }
            self.framing = .length(n)
        } else {
            self.framing = .toClose
        }
    }
}

// The buffer's unread tail moves to its front, over itself.
@_silgen_name("memmove")
func c_memmove(_ dest: UnsafeMutableRawPointer, _ src: UnsafeRawPointer, _ n: int) -> UnsafeMutableRawPointer

enum bodyFraming {
    case none
    case length(int64)
    case chunked
    case toClose
}

// chunkSize reads a chunk-size line: hex digits, then extensions after a
// ';', which are ignored.
func chunkSize(_ line: string) -> int64? {
    var n: int64 = 0
    var digits = 0
    for b in line.utf8 {
        var d: int64 = 0
        if b >= 48 && b <= 57 {
            d = int64(b - 48)
        } else if b >= 97 && b <= 102 {
            d = int64(b - 87)
        } else if b >= 65 && b <= 70 {
            d = int64(b - 55)
        } else if b == 59 || b == 32 || b == 9 {
            break
        } else {
            return nil
        }
        if digits >= 15 {
            return nil
        }
        n = n * 16 + d
        digits += 1
    }
    return digits == 0 ? nil : n
}

extension Client {
    /// Open sends req to url and returns once the response's headers are
    /// in, with its body still to be read from the stream -- which the
    /// caller closes. It speaks HTTP/1.1, over TLS for https (ALPN
    /// offers only http/1.1), and does not follow redirects: a 3xx is
    /// returned as it is, its Location in the headers.
    public func Open(_ req: Request, url: URL) async throws -> ResponseStream {
        let host = url.Host
        let port = url.Port
        let secure = url.Scheme == "https"
        var r = req
        let defaultPort: uint16 = secure ? 443 : 80
        if r.Headers.Get("Host") == nil {
            r.Headers.Set("Host", port == defaultPort ? host : "\(host):\(port)")
        }
        if r.Headers.Get("User-Agent") == nil {
            r.Headers.Set("User-Agent", "Vertex-HTTP/1.1")
        }
        if !r.Body.isEmpty && r.Headers.Get("Content-Length") == nil {
            r.Headers.Set("Content-Length", "\(r.Body.count)")
        }
        r.Headers.Set("Connection", "close")

        let tcpStream = try await tcp.Connect(host: host, port: port, timeoutMs: self.Config.TimeoutMs)
        var conn: tls.Conn
        if secure {
            var cfg = self.Config.TLSConfig
            if cfg.ServerName.isEmpty {
                cfg.ServerName = host
            }
            cfg.NextProtos = ["http/1.1"]
            conn = tls.Client(tcpStream, config: cfg)
            try await conn.Handshake()
            try await WriteRequestTls(r, to: &conn)
        } else {
            conn = tls.Conn(stream: tcpStream)
            try await r.Write(to: tcpStream)
        }
        var s = ResponseStream(conn: conn, secure: secure)
        do {
            try await s.head(method: r.Method)
        } catch {
            s.Close()
            throw error
        }
        return s
    }
}

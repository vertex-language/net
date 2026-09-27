package http

import (
    "compress/flate"
    "compress/gzip"
    "compress/zlib"
)

// Bodies as they come over the wire, made into what was sent: chunked
// transfer coding taken apart, and gzip or deflate content coding
// undone.

/// Whether a chunked body in d is whole: its last, empty chunk and
/// the trailers after it are in. `from` is where the next chunk's size
/// line starts; it moves past each complete chunk, so calling again
/// as more arrives scans only what's new.
func chunkedComplete(_ d: [uint8], _ from: inout int) -> bool {
    while true {
        guard let lineEnd = crlf(d, from) else { return false }
        let size = chunkSizeAt(d, from, lineEnd)
        if size < 0 { return true } // Malformed: take what there is.
        if size == 0 {
            // Trailer lines, then an empty one.
            var p = lineEnd + 2
            while true {
                guard let e = crlf(d, p) else { return false }
                if e == p { return true }
                p = e + 2
            }
        }
        let next = lineEnd + 2 + size + 2
        if next > d.count { return false }
        from = next
    }
}

/// A chunked body's data, its chunks joined; as much as there is when
/// it was cut short.
public func DecodeChunked(_ d: [uint8]) -> [uint8] {
    var out: [uint8] = []
    var p = 0
    while let lineEnd = crlf(d, p) {
        let size = chunkSizeAt(d, p, lineEnd)
        if size <= 0 { break }
        let start = lineEnd + 2
        var end = start + size
        if end > d.count { end = d.count }
        var i = start
        while i < end {
            out.append(d[i])
            i += 1
        }
        p = start + size + 2
        if p >= d.count { break }
    }
    return out
}

/// The index of the next CRLF at or after i.
func crlf(_ d: [uint8], _ i: int) -> int? {
    var k = i
    while k + 1 < d.count {
        if d[k] == 13 && d[k + 1] == 10 { return k }
        k += 1
    }
    return nil
}

/// A chunk-size line's hexadecimal size, before any extensions; -1
/// when there are no digits.
func chunkSizeAt(_ d: [uint8], _ start: int, _ end: int) -> int {
    var n = 0
    var digits = 0
    var k = start
    while k < end {
        let c = d[k]
        var v = -1
        if c >= 48 && c <= 57 { v = int(c) - 48 }
        else if c >= 97 && c <= 102 { v = int(c) - 87 }
        else if c >= 65 && c <= 70 { v = int(c) - 55 }
        if v < 0 { break }
        n = n * 16 + v
        digits += 1
        if n > 1 << 40 { return -1 }
        k += 1
    }
    return digits > 0 ? n : -1
}

/// Undoes a response's gzip or deflate content coding, so its body is
/// what the server's resource holds; it then has no Content-Encoding,
/// and its Content-Length is the decoded body's. A coding it can't
/// undo is left as it is.
func decodeContent(_ res: inout Response) {
    guard let coding = res.Headers.Get("Content-Encoding") else { return }
    let name = res.Headers.lower(coding)
    var decoded: [uint8]? = nil
    if name == "gzip" || name == "x-gzip" {
        decoded = try? gzip.Decompress(res.Body)
    } else if name == "deflate" {
        // zlib-wrapped as the RFC says, or raw deflate as some servers send.
        decoded = (try? zlib.Decompress(res.Body)) ?? (try? flate.Decompress(res.Body))
    }
    guard let body = decoded else { return }
    res.Body = body
    res.Headers.Del("Content-Encoding")
    res.Headers.Set("Content-Length", "\(body.count)")
}

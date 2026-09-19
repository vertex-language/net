package http

public struct HeaderEntry {
    public var Key: string
    public var Value: string
    public init(key: string, value: string) {
        self.Key = key
        self.Value = value
    }
}

// A header parsed in place: where its name and value are in the bytes the
// Header holds, rather than two strings made for it. The server reads a
// request's headers this way, and turns a span into a string only for a
// header something actually asks for. See Header.
struct HeaderSpan {
    var kStart: int
    var kLen: int
    var vStart: int
    var vLen: int
}

// Header names are case-insensitive (RFC 9110 5.1), and so are the
// tokens in Connection. The runtime compares two strings that way without
// making anything.
@_silgen_name("vertex_string_equal_fold")
func equalFold(_ a: string, _ b: string) -> bool

@_silgen_name("vertex_string_from_utf8")
func headerStringFromUtf8(_ ptr: UnsafeRawPointer, _ count: int64) -> string

// The same comparison between bytes that are not yet a string -- a header
// name where it lies in the parsed block -- and one that is, so that
// looking a header up makes nothing.
@_silgen_name("vertex_string_equal_fold_bytes")
func equalFoldBytes(_ ptr: UnsafeRawPointer, _ count: int64, _ s: string) -> bool

public struct Header {
    public var entries: [HeaderEntry] = []
    // A request parsed by the server keeps its headers as spans over the
    // bytes it copied out of the read buffer, so that parsing allocates
    // one block and no strings, and a header becomes a string only when
    // it is read. `entries` is what a header built from strings uses --
    // a response, a client request -- and what materializing a span
    // moves it to.
    var raw: [uint8] = []
    var spans: [HeaderSpan] = []

    public init() {}

    func equalFold(_ a: string, _ b: string) -> bool {
        return http.equalFold(a, b)
    }

    // spanString is the string a span's bytes denote.
    func spanString(_ start: int, _ len: int) -> string {
        if len <= 0 { return "" }
        return raw.withUnsafeBytes { rp in
            headerStringFromUtf8(rp.baseAddress! + start, int64(len))
        }
    }

    // spanKeyEquals compares a span's name to key, case-insensitively,
    // without making the name into a string.
    func spanKeyEquals(_ span: HeaderSpan, _ key: string) -> bool {
        return raw.withUnsafeBytes { rp in
            equalFoldBytes(rp.baseAddress! + span.kStart, int64(span.kLen), key)
        }
    }

    // setRaw makes raw hold src[from..<from+count], reusing its storage:
    // it grows only when too short, and bytes past count are left as they
    // were, since every span says where it ends.
    mutating func setRaw(_ src: [uint8], from: int, count: int) {
        if count <= 0 { return }
        if raw.count < count {
            raw.append(contentsOf: [uint8](repeating: 0, count: count - raw.count))
        }
        raw.withUnsafeMutableBytes { dp in
            src.withUnsafeBytes { sp in
                _ = c_memcpy(dp.baseAddress!, sp.baseAddress! + from, count)
            }
        }
    }

    // addSpan records a header parsed in place. The bytes it points into
    // are the Header's own `raw`, set once for the whole block.
    mutating func addSpan(kStart: int, kLen: int, vStart: int, vLen: int) {
        spans.append(HeaderSpan(kStart: kStart, kLen: kLen, vStart: vStart, vLen: vLen))
    }

    // materialize turns every span into an entry, so that code which
    // walks `entries` sees them. The server's fast path never calls it;
    // client and HTTP/2/3 paths do, before they iterate.
    public mutating func materialize() {
        if spans.isEmpty { return }
        var i = 0
        while i < spans.count {
            let sp = spans[i]
            entries.append(HeaderEntry(key: spanString(sp.kStart, sp.kLen),
                                       value: spanString(sp.vStart, sp.vLen)))
            i += 1
        }
        spans = []
        raw = []
    }

    // Materialized returns the header as an array of entries, turning any
    // spans into strings first.
    public func Materialized() -> [HeaderEntry] {
        if spans.isEmpty { return entries }
        var out = entries
        var i = 0
        while i < spans.count {
            let sp = spans[i]
            out.append(HeaderEntry(key: spanString(sp.kStart, sp.kLen),
                                   value: spanString(sp.vStart, sp.vLen)))
            i += 1
        }
        return out
    }

    public func lower(_ s: string) -> string {
        var chars: [CChar] = []
        for b in s.utf8 {
            if b >= 65 && b <= 90 {
                chars.append(CChar(truncatingIfNeeded: b + 32))
            } else {
                chars.append(CChar(truncatingIfNeeded: b))
            }
        }
        chars.append(0)
        return string(cString: chars)
    }

    public mutating func Set(_ key: string, _ value: string) {
        var i = 0
        while i < entries.count {
            if equalFold(entries[i].Key, key) {
                entries[i] = HeaderEntry(key: key, value: value)
                return
            }
            i += 1
        }
        entries.append(HeaderEntry(key: key, value: value))
    }

    public mutating func Add(_ key: string, _ value: string) {
        entries.append(HeaderEntry(key: key, value: value))
    }

    public func Get(_ key: string) -> string? {
        var i = 0
        while i < spans.count {
            if spanKeyEquals(spans[i], key) {
                return spanString(spans[i].vStart, spans[i].vLen)
            }
            i += 1
        }
        i = 0
        while i < entries.count {
            if equalFold(entries[i].Key, key) {
                return entries[i].Value
            }
            i += 1
        }
        return nil
    }

    // spanValueIs reports whether span i's value equals value, ignoring
    // case, comparing the bytes where they lie.
    func spanValueIs(_ i: int, _ value: string) -> bool {
        let sp = spans[i]
        let same: bool = raw.withUnsafeBytes { rp in
            equalFoldBytes(rp.baseAddress! + sp.vStart, int64(sp.vLen), value)
        }
        return same
    }

    // valueIs reports whether the header key is present with a value equal
    // to value, ignoring case -- nil when it is absent. A parsed header is
    // compared where its bytes lie, so asking makes no string.
    func valueIs(_ key: string, _ value: string) -> bool? {
        var i = 0
        while i < spans.count {
            if spanKeyEquals(spans[i], key) {
                let sp = spans[i]
                let same: bool = raw.withUnsafeBytes { rp in
                    equalFoldBytes(rp.baseAddress! + sp.vStart, int64(sp.vLen), value)
                }
                return same
            }
            i += 1
        }
        i = 0
        while i < entries.count {
            if equalFold(entries[i].Key, key) {
                return equalFold(entries[i].Value, value)
            }
            i += 1
        }
        return nil
    }

    public mutating func Del(_ key: string) {
        var filtered: [HeaderEntry] = []
        var i = 0
        while i < entries.count {
            if !equalFold(entries[i].Key, key) {
                filtered.append(entries[i])
            }
            i += 1
        }
        entries = filtered
    }
}

public typealias Headers = Header


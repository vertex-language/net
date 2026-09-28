// Package url parses URLs and resolves references against them, as RFC
// 3986 describes, with the leniency the web's URLs need (WHATWG URL): a
// backslash is a slash in http(s), ws(s), ftp and file URLs, tabs and
// newlines are dropped, and the host of those schemes is lowercase.
//
//     let u = try url.Parse("https://github.com/login?return_to=%2F")
//     u.Host                        // "github.com"
//     u.EffectivePort               // 443
//     u.RequestURI                  // "/login?return_to=%2F"
//     try u.Resolve("../x.css")     // https://github.com/x.css
//     u.String()                    // the URL written out again
//
// A URL can be relative ("../x.css", "/login", "?q=1"): it has no
// scheme, and resolving it against an absolute one makes it absolute.
// A path with no scheme -- "docs/index.html" -- is a relative URL too,
// and resolves as a file path would.
package url

import "unicode/utf8"

/// A parsed URL. Components are kept as written, percent-encoding and
/// all; Scheme and a special scheme's Host are lowercased.
public struct URL: Equatable {
    /// "https", lowercase; "" for a relative URL.
    public var Scheme: string
    /// The userinfo before '@' ("user:pass"), or nil for none.
    public var User: string?
    /// The host name or address. An IPv6 address is kept without its
    /// brackets. "" where there is no authority, or an empty one.
    public var Host: string
    /// The port as written, "" for none.
    public var Port: string
    /// Whether the URL has an authority ("//..."), even an empty one
    /// (file:///x).
    public var HasAuthority: bool
    /// The path, percent-encoded as written.
    public var Path: string
    /// The query without its '?', or nil for none ("?" alone is "").
    public var Query: string?
    /// The fragment without its '#', or nil for none.
    public var Fragment: string?

    public init(Scheme: string = "", User: string? = nil, Host: string = "", Port: string = "", HasAuthority: bool = false, Path: string = "", Query: string? = nil, Fragment: string? = nil) {
        self.Scheme = Scheme
        self.User = User
        self.Host = Host
        self.Port = Port
        self.HasAuthority = HasAuthority || !Host.isEmpty
        self.Path = Path
        self.Query = Query
        self.Fragment = Fragment
    }

    /// Whether the URL has a scheme.
    public var IsAbsolute: bool { return !Scheme.isEmpty }

    /// The port to connect to: the one written, or the scheme's default
    /// (80 for http and ws, 443 for https and wss, 21 for ftp), or 0.
    public var EffectivePort: uint16 {
        if let p = parsePort(Port) { return p }
        return DefaultPort(Scheme)
    }

    /// The host and port as an authority is written: "[::1]:8080".
    public var HostPort: string {
        var out = Host.contains(":") ? "[" + Host + "]" : Host
        if !Port.isEmpty { out += ":" + Port }
        return out
    }

    /// The origin, "https://github.com", for comparing where things came
    /// from; "null" for a URL without a host.
    public var Origin: string {
        if Scheme.isEmpty || Host.isEmpty { return "null" }
        var out = Scheme + "://" + (Host.contains(":") ? "[" + Host + "]" : Host)
        if let p = parsePort(Port), p != DefaultPort(Scheme) { out += ":\(p)" }
        return out
    }

    /// What an HTTP request line names: the path, "/" where it is empty,
    /// and the query.
    public var RequestURI: string {
        var out = Path.isEmpty ? "/" : Path
        if let q = Query { out += "?" + q }
        return out
    }

    /// The URL written out again.
    public func String() -> string {
        var out = ""
        if !Scheme.isEmpty { out += Scheme + ":" }
        if HasAuthority {
            out += "//"
            if let u = User { out += u + "@" }
            out += HostPort
        }
        out += Path
        if let q = Query { out += "?" + q }
        if let f = Fragment { out += "#" + f }
        return out
    }

    /// The URL without its fragment.
    public var WithoutFragment: URL {
        var u = self
        u.Fragment = nil
        return u
    }

    /// The query's parameters, decoded.
    public var QueryValues: Values { return ParseQuery(Query ?? "") }

    /// A reference resolved against this URL (RFC 3986 Section 5.2).
    public func Resolve(_ reference: string) throws -> URL {
        return ResolveReference(try Parse(reference))
    }

    /// A parsed reference resolved against this URL (RFC 3986 Section
    /// 5.2): `/x` is rooted at the host, `//host/x` takes the scheme,
    /// `../x` climbs, `?q` keeps the path, "" is this URL without its
    /// fragment.
    public func ResolveReference(_ r: URL) -> URL {
        if !r.Scheme.isEmpty {
            var out = r
            out.Path = removeDotSegments(r.Path)
            return out
        }
        var out = URL(Scheme: Scheme)
        if r.HasAuthority {
            out.User = r.User
            out.Host = r.Host
            out.Port = r.Port
            out.HasAuthority = true
            out.Path = removeDotSegments(r.Path)
            out.Query = r.Query
        } else {
            out.User = User
            out.Host = Host
            out.Port = Port
            out.HasAuthority = HasAuthority
            if r.Path.isEmpty {
                out.Path = Path
                out.Query = r.Query ?? Query
            } else if r.Path.hasPrefix("/") {
                out.Path = removeDotSegments(r.Path)
                out.Query = r.Query
            } else {
                out.Path = removeDotSegments(merge(r.Path))
                out.Query = r.Query
            }
        }
        out.Fragment = r.Fragment
        if isSpecial(out.Scheme) && out.HasAuthority && out.Path.isEmpty { out.Path = "/" }
        return out
    }

    /// This URL's path up to its last slash, then a relative path.
    func merge(_ path: string) -> string {
        if HasAuthority && Path.isEmpty { return "/" + path }
        let b = [uint8](Path.utf8)
        var i = b.count - 1
        while i >= 0 && b[i] != 47 { i -= 1 }
        if i < 0 { return path }
        return stringOf(b, 0, i + 1) + path
    }
}

/// Why a URL doesn't parse.
public enum URLError: Error, Equatable {
    /// A port that isn't a number from 0 to 65535.
    case invalidPort(string)
    /// A host with characters no host has, or an unclosed '['.
    case invalidHost(string)
    /// An http(s), ws(s) or ftp URL without a host.
    case missingHost(string)
}

/// The port a scheme uses when a URL names none, or 0.
public func DefaultPort(_ scheme: string) -> uint16 {
    switch scheme {
    case "http", "ws": return 80
    case "https", "wss": return 443
    case "ftp": return 21
    default: return 0
    }
}

/// The schemes whose URLs are hierarchical and host-based on the web.
func isSpecial(_ scheme: string) -> bool {
    switch scheme {
    case "http", "https", "ws", "wss", "ftp", "file": return true
    default: return false
    }
}

/// Parses an absolute URL or a relative reference.
public func Parse(_ text: string) throws -> URL {
    // Leading and trailing spaces and controls go, and tabs and newlines
    // anywhere, as browsers do.
    var b: [uint8] = []
    for c in text.utf8 where c != 9 && c != 10 && c != 13 { b.append(c) }
    var start = 0
    var end = b.count
    while start < end && b[start] <= 32 { start += 1 }
    while end > start && b[end - 1] <= 32 { end -= 1 }

    var u = URL()
    var i = start
    // The scheme: a letter, then letters, digits, + - ., then ':'. A
    // Windows drive letter (C:/ or C:\) is a path, not a scheme.
    var j = i
    while j < end && (isAlpha(b[j]) || (j > i && (isDigit(b[j]) || b[j] == 43 || b[j] == 45 || b[j] == 46))) { j += 1 }
    let drive = j == i + 1 && j + 1 < end && (b[j + 1] == 47 || b[j + 1] == 92)
    if j > i && !drive && j < end && b[j] == 58 {
        u.Scheme = lowerASCII(stringOf(b, i, j))
        i = j + 1
    }
    let special = isSpecial(u.Scheme)
    // A special URL's backslashes are slashes, up to its query.
    if special {
        var k = i
        while k < end && b[k] != 63 && b[k] != 35 {
            if b[k] == 92 { b[k] = 47 }
            k += 1
        }
    }

    if i + 1 < end && b[i] == 47 && b[i + 1] == 47 {
        u.HasAuthority = true
        let aStart = i + 2
        var k = aStart
        while k < end && b[k] != 47 && b[k] != 63 && b[k] != 35 { k += 1 }
        try parseAuthority(b, aStart, k, &u, lowercase: special || u.Scheme.isEmpty)
        i = k
    }

    var k = i
    while k < end && b[k] != 63 && b[k] != 35 { k += 1 }
    u.Path = stringOf(b, i, k)
    if k < end && b[k] == 63 {
        let qs = k + 1
        var e = qs
        while e < end && b[e] != 35 { e += 1 }
        u.Query = stringOf(b, qs, e)
        k = e
    }
    if k < end && b[k] == 35 {
        u.Fragment = stringOf(b, k + 1, end)
    }

    if special && u.Scheme != "file" && u.Host.isEmpty {
        throw URLError.missingHost(text)
    }
    if special && u.HasAuthority {
        u.Path = removeDotSegments(u.Path)
        if u.Path.isEmpty { u.Path = "/" }
    }
    return u
}

/// Reads userinfo, host and port from b[start..<end].
func parseAuthority(_ b: [uint8], _ start: int, _ end: int, _ u: inout URL, lowercase: bool) throws {
    var hostStart = start
    // The userinfo ends at the last '@'.
    var k = end - 1
    while k >= start && b[k] != 64 { k -= 1 }
    if k >= start {
        u.User = stringOf(b, start, k)
        hostStart = k + 1
    }
    var hostEnd = end
    var portStart = -1
    if hostStart < end && b[hostStart] == 91 {
        // [IPv6]
        var close = hostStart + 1
        while close < end && b[close] != 93 { close += 1 }
        if close >= end { throw URLError.invalidHost(stringOf(b, start, end)) }
        u.Host = lowerASCII(stringOf(b, hostStart + 1, close))
        if close + 1 < end {
            if b[close + 1] != 58 { throw URLError.invalidHost(stringOf(b, start, end)) }
            portStart = close + 2
        }
    } else {
        var c = end - 1
        while c >= hostStart && b[c] != 58 { c -= 1 }
        if c >= hostStart {
            hostEnd = c
            portStart = c + 1
        }
        let host = stringOf(b, hostStart, hostEnd)
        for ch in host.utf8 {
            if ch == 32 || ch == 60 || ch == 62 || ch == 94 || ch == 124 || ch == 91 || ch == 93 {
                throw URLError.invalidHost(host)
            }
        }
        u.Host = lowercase ? lowerASCII(host) : host
    }
    if portStart >= 0 {
        let port = stringOf(b, portStart, end)
        if !port.isEmpty && parsePort(port) == nil { throw URLError.invalidPort(port) }
        u.Port = port
    }
}

func parsePort(_ s: string) -> uint16? {
    if s.isEmpty { return nil }
    var n = 0
    for c in s.utf8 {
        if !isDigit(c) { return nil }
        n = n * 10 + int(c - 48)
        if n > 65535 { return nil }
    }
    return uint16(n)
}

/// A path with its `.` and `..` segments applied (RFC 3986 Section
/// 5.2.4). A relative path keeps the `..` it can't climb.
func removeDotSegments(_ path: string) -> string {
    if !path.contains(".") { return path }
    let rooted = path.hasPrefix("/")
    var out: [string] = []
    let segments = path.split(separator: "/", omittingEmptySubsequences: false).map { string($0) }
    var i = rooted ? 1 : 0
    while i < segments.count {
        let s = segments[i]
        let last = i == segments.count - 1
        if s == "." || s == "%2e" || s == "%2E" {
            if last { out.append("") }
        } else if s == ".." || s == ".%2e" || s == "%2e." || s == "%2e%2e" || s == ".%2E" || s == "%2E." || s == "%2E%2E" {
            if !out.isEmpty && out[out.count - 1] != ".." {
                out.removeLast()
            } else if !rooted {
                out.append("..")
            }
            if last { out.append("") }
        } else {
            out.append(s)
        }
        i += 1
    }
    var joined = rooted ? "/" : ""
    var k = 0
    while k < out.count {
        if k > 0 { joined += "/" }
        joined += out[k]
        k += 1
    }
    return joined
}

func isAlpha(_ c: uint8) -> bool { return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) }
func isDigit(_ c: uint8) -> bool { return c >= 48 && c <= 57 }

func lowerASCII(_ s: string) -> string {
    var b = [uint8](s.utf8)
    var changed = false
    var i = 0
    while i < b.count {
        if b[i] >= 65 && b[i] <= 90 {
            b[i] += 32
            changed = true
        }
        i += 1
    }
    return changed ? stringOf(b, 0, b.count) : s
}

func stringOf(_ bytes: [uint8], _ start: int, _ end: int) -> string {
    if start >= end { return "" }
    return utf8.Decode(bytes, start, end)
}

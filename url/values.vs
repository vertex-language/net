package url

/// A query's parameters, in order, a key allowed more than once.
public struct Values: Equatable {
    public var Pairs: [(key: string, value: string)]

    public init() {
        Pairs = []
    }

    public static func == (a: Values, b: Values) -> bool {
        if a.Pairs.count != b.Pairs.count { return false }
        var i = 0
        while i < a.Pairs.count {
            if a.Pairs[i].key != b.Pairs[i].key || a.Pairs[i].value != b.Pairs[i].value { return false }
            i += 1
        }
        return true
    }

    /// The first value for a key, or nil.
    public func Get(_ key: string) -> string? {
        for p in Pairs where p.key == key { return p.value }
        return nil
    }

    /// Every value for a key, in order.
    public func All(_ key: string) -> [string] {
        var out: [string] = []
        for p in Pairs where p.key == key { out.append(p.value) }
        return out
    }

    public func Has(_ key: string) -> bool { return Get(key) != nil }

    /// Adds a value after any the key has.
    public mutating func Add(_ key: string, _ value: string) {
        Pairs.append((key: key, value: value))
    }

    /// Replaces every value for a key with one.
    public mutating func Set(_ key: string, _ value: string) {
        Delete(key)
        Add(key, value)
    }

    public mutating func Delete(_ key: string) {
        var kept: [(key: string, value: string)] = []
        for p in Pairs where p.key != key { kept.append(p) }
        Pairs = kept
    }

    /// The query string, "a=1&b=two+words", in order.
    public func Encode() -> string {
        var out = ""
        for p in Pairs {
            if !out.isEmpty { out += "&" }
            out += QueryEscape(p.key) + "=" + QueryEscape(p.value)
        }
        return out
    }
}

/// A query string's parameters: "a=1&b=two+words" (without its '?').
/// A pair without '=' has an empty value; empty pairs are skipped.
public func ParseQuery(_ query: string) -> Values {
    var v = Values()
    for part in query.split(separator: "&", omittingEmptySubsequences: true) {
        let pair = string(part)
        let b = [uint8](pair.utf8)
        var eq = 0
        while eq < b.count && b[eq] != 61 { eq += 1 }
        let key = stringOf(b, 0, eq)
        let value = eq < b.count ? stringOf(b, eq + 1, b.count) : ""
        v.Add(QueryUnescape(key), QueryUnescape(value))
    }
    return v
}

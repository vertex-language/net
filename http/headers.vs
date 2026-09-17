package http

public struct HeaderEntry {
    public var Key: string
    public var Value: string
    public init(key: string, value: string) {
        self.Key = key
        self.Value = value
    }
}

public struct Header {
    public var entries: [HeaderEntry] = []

    public init() {}

    func lower(_ s: string) -> string {
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
        let lkey = lower(key)
        var i = 0
        while i < entries.count {
            if lower(entries[i].Key) == lkey {
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
        let lkey = lower(key)
        var i = 0
        while i < entries.count {
            if lower(entries[i].Key) == lkey {
                return entries[i].Value
            }
            i += 1
        }
        return nil
    }

    public mutating func Del(_ key: string) {
        let lkey = lower(key)
        var filtered: [HeaderEntry] = []
        var i = 0
        while i < entries.count {
            if lower(entries[i].Key) != lkey {
                filtered.append(entries[i])
            }
            i += 1
        }
        entries = filtered
    }
}

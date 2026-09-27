package url

// Percent-encoding (RFC 3986 Section 2.1): what may appear as itself in
// a path segment or a query, and everything else as %XX.

/// Whether a byte stands for itself in a path segment: unreserved, and
/// the sub-delimiters, ':' and '@'.
func pathSafe(_ c: uint8) -> bool {
    if unreserved(c) { return true }
    switch c {
    case 33, 36, 38, 39, 40, 41, 42, 43, 44, 59, 61, 58, 64: return true   // ! $ & ' ( ) * + , ; = : @
    default: return false
    }
}

/// Letters, digits, - . _ ~
func unreserved(_ c: uint8) -> bool {
    return isAlpha(c) || isDigit(c) || c == 45 || c == 46 || c == 95 || c == 126
}

let hexDigits: [uint8] = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70]

func escape(_ s: string, _ safe: (uint8) -> bool, spaceAsPlus: bool) -> string {
    var out: [uint8] = []
    var changed = false
    for c in s.utf8 {
        if safe(c) {
            out.append(c)
        } else if spaceAsPlus && c == 32 {
            out.append(43)
            changed = true
        } else {
            out.append(37)
            out.append(hexDigits[int(c >> 4)])
            out.append(hexDigits[int(c & 15)])
            changed = true
        }
    }
    return changed ? stringOf(out, 0, out.count) : s
}

/// A string escaped to be one path segment: '/' is escaped too.
public func PathEscape(_ s: string) -> string {
    return escape(s, { c in pathSafe(c) && c != 47 }, spaceAsPlus: false)
}

/// A string escaped to be a query key or value, as forms send it:
/// spaces become '+'.
public func QueryEscape(_ s: string) -> string {
    return escape(s, unreserved, spaceAsPlus: true)
}

func hexValue(_ c: uint8) -> int {
    if c >= 48 && c <= 57 { return int(c) - 48 }
    if c >= 65 && c <= 70 { return int(c) - 55 }
    if c >= 97 && c <= 102 { return int(c) - 87 }
    return -1
}

func unescape(_ s: string, plusAsSpace: bool) -> string {
    let b = [uint8](s.utf8)
    var out: [uint8] = []
    var i = 0
    var changed = false
    while i < b.count {
        let c = b[i]
        if c == 37 && i + 2 < b.count {
            let hi = hexValue(b[i + 1])
            let lo = hexValue(b[i + 2])
            if hi >= 0 && lo >= 0 {
                out.append(uint8(hi * 16 + lo))
                i += 3
                changed = true
                continue
            }
        }
        if plusAsSpace && c == 43 {
            out.append(32)
            changed = true
        } else {
            out.append(c)
        }
        i += 1
    }
    return changed ? stringOf(out, 0, out.count) : s
}

/// A path's %XX sequences decoded. A '%' not followed by two hex digits
/// is kept, as browsers keep it.
public func PathUnescape(_ s: string) -> string {
    return unescape(s, plusAsSpace: false)
}

/// A query key or value decoded: %XX, and '+' as a space.
public func QueryUnescape(_ s: string) -> string {
    return unescape(s, plusAsSpace: true)
}

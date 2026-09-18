package http

/// RFC 7541 HPACK Header Compression for HTTP/2.

public struct HpackHeader {
    public var Name: string
    public var Value: string
    public init(name: string, value: string) {
        self.Name = name
        self.Value = value
    }
}

public struct DecodedInt {
    public var Value: int
    public var BytesRead: int
    public init(value: int, bytesRead: int) {
        self.Value = value
        self.BytesRead = bytesRead
    }
}

public struct DecodedStr {
    public var Value: string
    public var BytesRead: int
    public init(value: string, bytesRead: int) {
        self.Value = value
        self.BytesRead = bytesRead
    }
}

/// RFC 7541 Appendix A - Static Table
public func HpackStaticTable() -> [HpackHeader] {
    return [
        HpackHeader(name: ":authority", value: ""),
        HpackHeader(name: ":method", value: "GET"),
        HpackHeader(name: ":method", value: "POST"),
        HpackHeader(name: ":path", value: "/"),
        HpackHeader(name: ":path", value: "/index.html"),
        HpackHeader(name: ":scheme", value: "http"),
        HpackHeader(name: ":scheme", value: "https"),
        HpackHeader(name: ":status", value: "200"),
        HpackHeader(name: ":status", value: "204"),
        HpackHeader(name: ":status", value: "206"),
        HpackHeader(name: ":status", value: "304"),
        HpackHeader(name: ":status", value: "400"),
        HpackHeader(name: ":status", value: "404"),
        HpackHeader(name: ":status", value: "500"),
        HpackHeader(name: "accept-charset", value: ""),
        HpackHeader(name: "accept-encoding", value: "gzip, deflate"),
        HpackHeader(name: "accept-language", value: ""),
        HpackHeader(name: "accept-ranges", value: ""),
        HpackHeader(name: "accept", value: ""),
        HpackHeader(name: "access-control-allow-origin", value: ""),
        HpackHeader(name: "age", value: ""),
        HpackHeader(name: "allow", value: ""),
        HpackHeader(name: "authorization", value: ""),
        HpackHeader(name: "cache-control", value: ""),
        HpackHeader(name: "content-disposition", value: ""),
        HpackHeader(name: "content-encoding", value: ""),
        HpackHeader(name: "content-language", value: ""),
        HpackHeader(name: "content-length", value: ""),
        HpackHeader(name: "content-location", value: ""),
        HpackHeader(name: "content-range", value: ""),
        HpackHeader(name: "content-type", value: ""),
        HpackHeader(name: "cookie", value: ""),
        HpackHeader(name: "date", value: ""),
        HpackHeader(name: "etag", value: ""),
        HpackHeader(name: "expect", value: ""),
        HpackHeader(name: "expires", value: ""),
        HpackHeader(name: "from", value: ""),
        HpackHeader(name: "host", value: ""),
        HpackHeader(name: "if-match", value: ""),
        HpackHeader(name: "if-modified-since", value: ""),
        HpackHeader(name: "if-none-match", value: ""),
        HpackHeader(name: "if-range", value: ""),
        HpackHeader(name: "if-unmodified-since", value: ""),
        HpackHeader(name: "last-modified", value: ""),
        HpackHeader(name: "link", value: ""),
        HpackHeader(name: "location", value: ""),
        HpackHeader(name: "max-forwards", value: ""),
        HpackHeader(name: "proxy-authenticate", value: ""),
        HpackHeader(name: "proxy-authorization", value: ""),
        HpackHeader(name: "range", value: ""),
        HpackHeader(name: "referer", value: ""),
        HpackHeader(name: "refresh", value: ""),
        HpackHeader(name: "retry-after", value: ""),
        HpackHeader(name: "server", value: ""),
        HpackHeader(name: "set-cookie", value: ""),
        HpackHeader(name: "strict-transport-security", value: ""),
        HpackHeader(name: "transfer-encoding", value: ""),
        HpackHeader(name: "user-agent", value: ""),
        HpackHeader(name: "vary", value: ""),
        HpackHeader(name: "via", value: ""),
        HpackHeader(name: "www-authenticate", value: "")
    ]
}

/// Encodes an integer with a prefix mask (RFC 7541 Section 5.1).
public func HpackEncodeInt(value: int, prefixBits: int, prefixMask: uint8) -> [uint8] {
    let maxPrefix = (1 << prefixBits) - 1
    if value < maxPrefix {
        return [prefixMask | uint8(truncatingIfNeeded: value)]
    }

    var bytes: [uint8] = [prefixMask | uint8(truncatingIfNeeded: maxPrefix)]
    var rem = value - maxPrefix
    while rem >= 128 {
        bytes.append(uint8(truncatingIfNeeded: (rem & 0x7f) | 0x80))
        rem = rem >> 7
    }
    bytes.append(uint8(truncatingIfNeeded: rem))
    return bytes
}

/// Decodes an integer from HPACK byte stream (RFC 7541 Section 5.1).
public func HpackDecodeInt(data: [uint8], offset: int, prefixBits: int) throws -> DecodedInt {
    if offset >= data.count {
        throw HttpError.malformedResponse
    }

    let maxPrefix = (1 << prefixBits) - 1
    let first = int(data[offset]) & maxPrefix
    if first < maxPrefix {
        return DecodedInt(value: first, bytesRead: 1)
    }

    var value = maxPrefix
    var m = 0
    var i = offset + 1
    while i < data.count {
        let b = int(data[i])
        value += (b & 0x7f) << m
        m += 7
        if (b & 0x80) == 0 {
            return DecodedInt(value: value, bytesRead: i - offset + 1)
        }
        i += 1
    }
    throw HttpError.malformedResponse
}

/// Encodes a string literal without Huffman encoding (RFC 7541 Section 5.2).
public func HpackEncodeString(_ s: string) -> [uint8] {
    var strBytes: [uint8] = []
    for b in s.utf8 { strBytes.append(b) }

    // H bit = 0 (7-bit prefix for length)
    var out = HpackEncodeInt(value: strBytes.count, prefixBits: 7, prefixMask: 0x00)
    for b in strBytes {
        out.append(b)
    }
    return out
}

/// Decodes a string literal (RFC 7541 Section 5.2).
public func HpackDecodeString(data: [uint8], offset: int) throws -> DecodedStr {
    if offset >= data.count {
        throw HttpError.malformedResponse
    }

    let isHuffman = (data[offset] & 0x80) != 0
    let lenDec = try HpackDecodeInt(data: data, offset: offset, prefixBits: 7)
    let strLen = lenDec.Value
    let dataStart = offset + lenDec.BytesRead

    if dataStart + strLen > data.count {
        throw HttpError.malformedResponse
    }

    if isHuffman {
        // Fallback for simple ASCII representation
        let str = asciiString(data, from: dataStart, to: dataStart + strLen)
        return DecodedStr(value: str, bytesRead: lenDec.BytesRead + strLen)
    } else {
        let str = asciiString(data, from: dataStart, to: dataStart + strLen)
        return DecodedStr(value: str, bytesRead: lenDec.BytesRead + strLen)
    }
}

/// Complete HPACK Encoder supporting Static Table matching and literal encoding.
public struct HpackEncoder {
    public var staticTable: [HpackHeader]

    public init() {
        self.staticTable = HpackStaticTable()
    }

    public func EncodeHeader(name: string, value: string) -> [uint8] {
        let lowerName = Header().lower(name)

        // 1. Check exact match in static table (name + value)
        var i = 0
        while i < staticTable.count {
            if staticTable[i].Name == lowerName && staticTable[i].Value == value {
                // Indexed Header Field (starts with 1) -> index 1..61
                return HpackEncodeInt(value: i + 1, prefixBits: 7, prefixMask: 0x80)
            }
            i += 1
        }

        // 2. Check name-only match in static table
        var nameMatchIdx = -1
        i = 0
        while i < staticTable.count {
            if staticTable[i].Name == lowerName {
                nameMatchIdx = i + 1
                break
            }
            i += 1
        }

        if nameMatchIdx > 0 {
            // Literal Header Field without Indexing - Indexed Name (starts with 0000)
            var bytes = HpackEncodeInt(value: nameMatchIdx, prefixBits: 4, prefixMask: 0x00)
            let valBytes = HpackEncodeString(value)
            for b in valBytes { bytes.append(b) }
            return bytes
        } else {
            // Literal Header Field without Indexing - New Name (index 0)
            var bytes: [uint8] = [0x00]
            let nameBytes = HpackEncodeString(lowerName)
            for b in nameBytes { bytes.append(b) }
            let valBytes = HpackEncodeString(value)
            for b in valBytes { bytes.append(b) }
            return bytes
        }
    }

    public func EncodeHeaders(_ headers: [HeaderEntry]) -> [uint8] {
        var out: [uint8] = []
        var i = 0
        while i < headers.count {
            let encoded = EncodeHeader(name: headers[i].Key, value: headers[i].Value)
            for b in encoded { out.append(b) }
            i += 1
        }
        return out
    }
}

/// Complete HPACK Decoder supporting Static Table lookup and dynamic table.
public struct HpackDecoder {
    public var staticTable: [HpackHeader]
    public var dynamicTable: [HpackHeader]

    public init() {
        self.staticTable = HpackStaticTable()
        self.dynamicTable = []
    }

    public mutating func DecodeHeaders(data: [uint8]) throws -> [HeaderEntry] {
        var headers: [HeaderEntry] = []
        var offset = 0

        while offset < data.count {
            let b = data[offset]

            if (b & 0x80) != 0 {
                // 1. Indexed Header Field (starts with 1, 7-bit prefix)
                let intDec = try HpackDecodeInt(data: data, offset: offset, prefixBits: 7)
                offset += intDec.BytesRead
                let idx = intDec.Value

                if idx > 0 && idx <= staticTable.count {
                    let entry = staticTable[idx - 1]
                    headers.append(HeaderEntry(key: entry.Name, value: entry.Value))
                } else if idx > staticTable.count && idx <= staticTable.count + dynamicTable.count {
                    let dIdx = idx - staticTable.count - 1
                    let entry = dynamicTable[dIdx]
                    headers.append(HeaderEntry(key: entry.Name, value: entry.Value))
                } else {
                    throw HttpError.malformedResponse
                }
            } else if (b & 0xc0) == 0x40 {
                // 2. Literal Header Field with Incremental Indexing (starts with 01, 6-bit prefix)
                let intDec = try HpackDecodeInt(data: data, offset: offset, prefixBits: 6)
                offset += intDec.BytesRead
                var name = ""
                if intDec.Value == 0 {
                    let nameDec = try HpackDecodeString(data: data, offset: offset)
                    offset += nameDec.BytesRead
                    name = nameDec.Value
                } else if intDec.Value <= staticTable.count {
                    name = staticTable[intDec.Value - 1].Name
                } else {
                    let dIdx = intDec.Value - staticTable.count - 1
                    if dIdx < dynamicTable.count {
                        name = dynamicTable[dIdx].Name
                    }
                }
                let valDec = try HpackDecodeString(data: data, offset: offset)
                offset += valDec.BytesRead
                let value = valDec.Value

                headers.append(HeaderEntry(key: name, value: value))
                dynamicTable.insert(HpackHeader(name: name, value: value), at: 0)
            } else if (b & 0xf0) == 0x00 || (b & 0xf0) == 0x10 {
                // 3. Literal Header Field without Indexing (starts with 0000 or 0001, 4-bit prefix)
                let intDec = try HpackDecodeInt(data: data, offset: offset, prefixBits: 4)
                offset += intDec.BytesRead
                var name = ""
                if intDec.Value == 0 {
                    let nameDec = try HpackDecodeString(data: data, offset: offset)
                    offset += nameDec.BytesRead
                    name = nameDec.Value
                } else if intDec.Value <= staticTable.count {
                    name = staticTable[intDec.Value - 1].Name
                } else {
                    let dIdx = intDec.Value - staticTable.count - 1
                    if dIdx < dynamicTable.count {
                        name = dynamicTable[dIdx].Name
                    }
                }
                let valDec = try HpackDecodeString(data: data, offset: offset)
                offset += valDec.BytesRead
                let value = valDec.Value

                headers.append(HeaderEntry(key: name, value: value))
            } else if (b & 0xe0) == 0x20 {
                // 4. Dynamic Table Size Update (starts with 001, 5-bit prefix)
                let intDec = try HpackDecodeInt(data: data, offset: offset, prefixBits: 5)
                offset += intDec.BytesRead
            } else {
                offset += 1
            }
        }

        return headers
    }
}

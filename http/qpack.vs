package http

/// RFC 9204 QPACK Header Compression for HTTP/3.

public struct QpackHeader {
    public var Name: string
    public var Value: string
    public init(name: string, value: string) {
        self.Name = name
        self.Value = value
    }
}

/// RFC 9204 Appendix A - Static Table (Common 99 entries)
public func QpackStaticTable() -> [QpackHeader] {
    return [
        QpackHeader(name: ":authority", value: ""),
        QpackHeader(name: ":path", value: "/"),
        QpackHeader(name: "age", value: "0"),
        QpackHeader(name: "content-disposition", value: ""),
        QpackHeader(name: "content-length", value: "0"),
        QpackHeader(name: "cookie", value: ""),
        QpackHeader(name: "date", value: ""),
        QpackHeader(name: "etag", value: ""),
        QpackHeader(name: "if-modified-since", value: ""),
        QpackHeader(name: "if-none-match", value: ""),
        QpackHeader(name: "last-modified", value: ""),
        QpackHeader(name: "link", value: ""),
        QpackHeader(name: "location", value: ""),
        QpackHeader(name: "referer", value: ""),
        QpackHeader(name: "set-cookie", value: ""),
        QpackHeader(name: ":method", value: "CONNECT"),
        QpackHeader(name: ":method", value: "DELETE"),
        QpackHeader(name: ":method", value: "GET"),
        QpackHeader(name: ":method", value: "HEAD"),
        QpackHeader(name: ":method", value: "OPTIONS"),
        QpackHeader(name: ":method", value: "POST"),
        QpackHeader(name: ":method", value: "PUT"),
        QpackHeader(name: ":scheme", value: "http"),
        QpackHeader(name: ":scheme", value: "https"),
        QpackHeader(name: ":status", value: "103"),
        QpackHeader(name: ":status", value: "200"),
        QpackHeader(name: ":status", value: "304"),
        QpackHeader(name: ":status", value: "404"),
        QpackHeader(name: ":status", value: "503"),
        QpackHeader(name: "accept", value: "*/*"),
        QpackHeader(name: "accept", value: "application/dns-message"),
        QpackHeader(name: "accept-encoding", value: "gzip, deflate, br"),
        QpackHeader(name: "accept-ranges", value: "bytes"),
        QpackHeader(name: "access-control-allow-headers", value: "cache-control"),
        QpackHeader(name: "access-control-allow-headers", value: "content-type"),
        QpackHeader(name: "access-control-allow-origin", value: "*"),
        QpackHeader(name: "cache-control", value: "max-age=0"),
        QpackHeader(name: "cache-control", value: "max-age=2592000"),
        QpackHeader(name: "cache-control", value: "max-age=604800"),
        QpackHeader(name: "cache-control", value: "no-cache"),
        QpackHeader(name: "cache-control", value: "no-store"),
        QpackHeader(name: "cache-control", value: "public, max-age=31536000"),
        QpackHeader(name: "content-encoding", value: "br"),
        QpackHeader(name: "content-encoding", value: "gzip"),
        QpackHeader(name: "content-type", value: "application/dns-message"),
        QpackHeader(name: "content-type", value: "application/javascript"),
        QpackHeader(name: "content-type", value: "application/json"),
        QpackHeader(name: "content-type", value: "application/x-www-form-urlencoded"),
        QpackHeader(name: "content-type", value: "image/gif"),
        QpackHeader(name: "content-type", value: "image/jpeg"),
        QpackHeader(name: "content-type", value: "image/png"),
        QpackHeader(name: "content-type", value: "text/css"),
        QpackHeader(name: "content-type", value: "text/html; charset=utf-8"),
        QpackHeader(name: "content-type", value: "text/plain"),
        QpackHeader(name: "content-type", value: "text/plain;charset=utf-8"),
        QpackHeader(name: "range", value: "bytes=0-"),
        QpackHeader(name: "strict-transport-security", value: "max-age=31536000"),
        QpackHeader(name: "strict-transport-security", value: "max-age=31536000; includesubdomains"),
        QpackHeader(name: "strict-transport-security", value: "max-age=31536000; includesubdomains; preload"),
        QpackHeader(name: "vary", value: "accept-encoding"),
        QpackHeader(name: "vary", value: "origin"),
        QpackHeader(name: "x-content-type-options", value: "nosniff"),
        QpackHeader(name: "x-xss-protection", value: "1; mode=block"),
        QpackHeader(name: ":status", value: "100"),
        QpackHeader(name: ":status", value: "204"),
        QpackHeader(name: ":status", value: "206"),
        QpackHeader(name: ":status", value: "302"),
        QpackHeader(name: ":status", value: "400"),
        QpackHeader(name: ":status", value: "403"),
        QpackHeader(name: ":status", value: "421"),
        QpackHeader(name: ":status", value: "425"),
        QpackHeader(name: ":status", value: "500"),
        QpackHeader(name: "accept-language", value: ""),
        QpackHeader(name: "access-control-allow-credentials", value: "FALSE"),
        QpackHeader(name: "access-control-allow-credentials", value: "TRUE"),
        QpackHeader(name: "access-control-allow-headers", value: "*"),
        QpackHeader(name: "access-control-allow-methods", value: "get"),
        QpackHeader(name: "access-control-allow-methods", value: "get, post, options"),
        QpackHeader(name: "access-control-allow-methods", value: "options"),
        QpackHeader(name: "access-control-expose-headers", value: "content-length"),
        QpackHeader(name: "actual-location", value: ""),
        QpackHeader(name: "alt-svc", value: "clear"),
        QpackHeader(name: "authorization", value: ""),
        QpackHeader(name: "content-security-policy", value: "script-src 'none'; object-src 'none'; base-uri 'none'"),
        QpackHeader(name: "early-data", value: "1"),
        QpackHeader(name: "expect-ct", value: ""),
        QpackHeader(name: "forwarded", value: ""),
        QpackHeader(name: "if-range", value: ""),
        QpackHeader(name: "origin", value: ""),
        QpackHeader(name: "purpose", value: "prefetch"),
        QpackHeader(name: "server", value: ""),
        QpackHeader(name: "timing-allow-origin", value: "*"),
        QpackHeader(name: "upgrade-insecure-requests", value: "1"),
        QpackHeader(name: "user-agent", value: ""),
        QpackHeader(name: "x-forwarded-for", value: ""),
        QpackHeader(name: "x-frame-options", value: "deny"),
        QpackHeader(name: "x-frame-options", value: "sameorigin")
    ]
}

/// QPACK Encoder for HTTP/3 header blocks.
public struct QpackEncoder {
    public var staticTable: [QpackHeader]

    public init() {
        self.staticTable = QpackStaticTable()
    }

    public func EncodeHeader(name: string, value: string) -> [uint8] {
        let lowerName = Header().lower(name)

        // 1. Check exact match in static table (T=1, starts with 11, 6-bit index)
        var i = 0
        while i < staticTable.count {
            if staticTable[i].Name == lowerName && staticTable[i].Value == value {
                return HpackEncodeInt(value: i, prefixBits: 6, prefixMask: 0xc0)
            }
            i += 1
        }

        // 2. Check name match in static table (T=1, starts with 0101, 4-bit index)
        var nameMatchIdx = -1
        i = 0
        while i < staticTable.count {
            if staticTable[i].Name == lowerName {
                nameMatchIdx = i
                break
            }
            i += 1
        }

        if nameMatchIdx >= 0 && nameMatchIdx < 16 {
            var bytes = HpackEncodeInt(value: nameMatchIdx, prefixBits: 4, prefixMask: 0x50)
            let valBytes = HpackEncodeString(value)
            for b in valBytes { bytes.append(b) }
            return bytes
        } else {
            // Literal field with literal name (starts with 0010, 3-bit prefix)
            var bytes: [uint8] = [0x20]
            let nameBytes = HpackEncodeString(lowerName)
            for b in nameBytes { bytes.append(b) }
            let valBytes = HpackEncodeString(value)
            for b in valBytes { bytes.append(b) }
            return bytes
        }
    }

    /// Encodes a list of headers into a QPACK Field Section prefix + field lines.
    public func EncodeHeaders(_ headers: [HeaderEntry]) -> [uint8] {
        // Section Prefix: Required Insert Count (0) and Delta Base (0) -> [0x00, 0x00]
        var out: [uint8] = [0x00, 0x00]
        var i = 0
        while i < headers.count {
            let encoded = EncodeHeader(name: headers[i].Key, value: headers[i].Value)
            for b in encoded { out.append(b) }
            i += 1
        }
        return out
    }
}

/// QPACK Decoder for HTTP/3 header blocks.
public struct QpackDecoder {
    public var staticTable: [QpackHeader]

    public init() {
        self.staticTable = QpackStaticTable()
    }

    public func DecodeHeaders(data: [uint8]) throws -> [HeaderEntry] {
        if data.count < 2 {
            return []
        }

        var headers: [HeaderEntry] = []
        // Skip 2-byte QPACK section prefix (Required Insert Count & Base)
        var offset = 2

        while offset < data.count {
            let b = data[offset]

            if (b & 0xc0) == 0xc0 {
                // 1. Indexed Field Line from Static Table (starts with 11, 6-bit prefix)
                let intDec = try HpackDecodeInt(data: data, offset: offset, prefixBits: 6)
                offset += intDec.BytesRead
                let idx = intDec.Value
                if idx < staticTable.count {
                    let entry = staticTable[idx]
                    headers.append(HeaderEntry(key: entry.Name, value: entry.Value))
                }
            } else if (b & 0xf0) == 0x50 {
                // 2. Literal Field with Name Reference in Static Table (starts with 0101, 4-bit prefix)
                let intDec = try HpackDecodeInt(data: data, offset: offset, prefixBits: 4)
                offset += intDec.BytesRead
                var name = ""
                if intDec.Value < staticTable.count {
                    name = staticTable[intDec.Value].Name
                }
                let valDec = try HpackDecodeString(data: data, offset: offset)
                offset += valDec.BytesRead
                headers.append(HeaderEntry(key: name, value: valDec.Value))
            } else if (b & 0xe0) == 0x20 {
                // 3. Literal Field with Literal Name (starts with 0010, 3-bit prefix)
                offset += 1
                let nameDec = try HpackDecodeString(data: data, offset: offset)
                offset += nameDec.BytesRead
                let valDec = try HpackDecodeString(data: data, offset: offset)
                offset += valDec.BytesRead
                headers.append(HeaderEntry(key: nameDec.Value, value: valDec.Value))
            } else {
                offset += 1
            }
        }

        return headers
    }
}

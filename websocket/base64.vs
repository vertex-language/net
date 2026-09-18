package websocket

func base64Char(at index: int) -> uint8 {
    let stdBase64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    var i = 0
    for b in stdBase64Chars.utf8 {
        if i == index { return b }
        i += 1
    }
    return 61 // '='
}

func base64DecodeVal(_ b: uint8) -> int32 {
    if b >= 65 && b <= 90 { return int32(b - 65) }
    if b >= 97 && b <= 122 { return int32(b - 97 + 26) }
    if b >= 48 && b <= 57 { return int32(b - 48 + 52) }
    if b == 43 { return 62 }
    if b == 47 { return 63 }
    return -1
}

/// Encodes binary bytes to standard Base64 string.
public func Base64Encode(_ src: [uint8]) -> string {
    var out: [uint8] = []
    let pad: uint8 = 61 // '='
    var i = 0
    while i < src.count {
        let remain = src.count - i
        let b0 = src[i]
        out.append(base64Char(at: int(b0 >> 2)))

        if remain == 1 {
            out.append(base64Char(at: int((b0 & 0x03) << 4)))
            out.append(pad)
            out.append(pad)
            break
        }

        let b1 = src[i + 1]
        out.append(base64Char(at: int(((b0 & 0x03) << 4) | (b1 >> 4))))

        if remain == 2 {
            out.append(base64Char(at: int((b1 & 0x0f) << 2)))
            out.append(pad)
            break
        }

        let b2 = src[i + 2]
        out.append(base64Char(at: int(((b1 & 0x0f) << 2) | (b2 >> 6))))
        out.append(base64Char(at: int(b2 & 0x3f)))
        i += 3
    }
    return string(decoding: out, as: UTF8.self)
}

/// Decodes standard Base64 string to bytes.
public func Base64Decode(_ s: string) throws -> [uint8] {
    var raw: [uint8] = []
    for b in s.utf8 {
        if b != 32 && b != 10 && b != 13 && b != 9 {
            raw.append(b)
        }
    }
    if raw.isEmpty { return [] }
    if raw.count % 4 != 0 {
        throw WebSocketError.protocolError("Invalid Base64 length")
    }

    var out: [uint8] = []
    var i = 0
    while i < raw.count {
        let c0 = raw[i]
        let c1 = raw[i + 1]
        let c2 = raw[i + 2]
        let c3 = raw[i + 3]

        let v0 = base64DecodeVal(c0)
        let v1 = base64DecodeVal(c1)
        if v0 < 0 || v1 < 0 { throw WebSocketError.protocolError("Invalid Base64 byte") }

        let b0 = uint8(truncatingIfNeeded: (v0 << 2) | (v1 >> 4))
        out.append(b0)

        if c2 != 61 {
            let v2 = base64DecodeVal(c2)
            if v2 < 0 { throw WebSocketError.protocolError("Invalid Base64 byte") }
            let b1 = uint8(truncatingIfNeeded: ((v1 & 0x0f) << 4) | (v2 >> 2))
            out.append(b1)

            if c3 != 61 {
                let v3 = base64DecodeVal(c3)
                if v3 < 0 { throw WebSocketError.protocolError("Invalid Base64 byte") }
                let b2 = uint8(truncatingIfNeeded: ((v2 & 0x03) << 6) | v3)
                out.append(b2)
            }
        }
        i += 4
    }
    return out
}

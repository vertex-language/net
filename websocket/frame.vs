package websocket

import "crypto/rand"

/// Frame represents a single RFC 6455 binary frame.
public struct Frame {
    public var Fin: bool
    public var Rsv1: bool
    public var Rsv2: bool
    public var Rsv3: bool
    public var Opcode: uint8
    public var Masked: bool
    public var MaskingKey: [uint8]
    public var Payload: [uint8]

    public init(fin: bool, opcode: uint8) {
        self.Fin = fin
        self.Rsv1 = false
        self.Rsv2 = false
        self.Rsv3 = false
        self.Opcode = opcode
        self.Masked = false
        self.MaskingKey = []
        self.Payload = []
    }

    public init(fin: bool,
                opcode: uint8,
                masked: bool,
                maskingKey: [uint8],
                payload: [uint8]) {
        self.Fin = fin
        self.Rsv1 = false
        self.Rsv2 = false
        self.Rsv3 = false
        self.Opcode = opcode
        self.Masked = masked
        self.MaskingKey = maskingKey
        self.Payload = payload
    }
}

public struct ParsedFrame {
    public var Frame: Frame
    public var BytesRead: int
    public init(frame: Frame, bytesRead: int) {
        self.Frame = frame
        self.BytesRead = bytesRead
    }
}

/// Applies RFC 6455 4-byte XOR masking in place.
public func MaskPayload(payload: inout [uint8], maskingKey: [uint8]) {
    if maskingKey.count < 4 { return }
    var i = 0
    while i < payload.count {
        payload[i] = payload[i] ^ maskingKey[i % 4]
        i += 1
    }
}

/// Generates a random 4-byte masking key for client frames.
public func GenerateMaskingKey() -> [uint8] {
    if let k = try? rand.Bytes(4) {
        return k
    }
    return [0x12, 0x34, 0x56, 0x78]
}

/// Builds an RFC 6455 serialized frame without payload.
public func BuildFrame(fin: bool,
                       opcode: uint8,
                       masked: bool) -> [uint8] {
    let emptyKey: [uint8] = []
    let emptyPayload: [uint8] = []
    return BuildFrame(fin: fin, opcode: opcode, masked: masked, maskingKey: emptyKey, payload: emptyPayload)
}

/// Builds an RFC 6455 serialized frame with automatic masking key generation if masked.
public func BuildFrame(fin: bool,
                       opcode: uint8,
                       masked: bool,
                       payload: [uint8]) -> [uint8] {
    var key: [uint8] = []
    if masked {
        key = GenerateMaskingKey()
    }
    return BuildFrame(fin: fin, opcode: opcode, masked: masked, maskingKey: key, payload: payload)
}

/// Builds an RFC 6455 serialized frame.
public func BuildFrame(fin: bool,
                       opcode: uint8,
                       masked: bool,
                       maskingKey: [uint8],
                       payload: [uint8]) -> [uint8] {
    var out: [uint8] = []

    // Byte 0: FIN, RSV1..3, Opcode
    var b0: uint8 = opcode & 0x0f
    if fin { b0 = b0 | 0x80 }
    out.append(b0)

    // Byte 1: Mask bit + Length indicator
    let len = payload.count
    var b1: uint8 = masked ? 0x80 : 0x00

    if len <= 125 {
        b1 = b1 | uint8(truncatingIfNeeded: len)
        out.append(b1)
    } else if len <= 65535 {
        b1 = b1 | 126
        out.append(b1)
        out.append(uint8(truncatingIfNeeded: (len >> 8) & 0xff))
        out.append(uint8(truncatingIfNeeded: len & 0xff))
    } else {
        b1 = b1 | 127
        out.append(b1)
        var s: int = 56
        while s >= 0 {
            out.append(uint8(truncatingIfNeeded: (len >> s) & 0xff))
            s -= 8
        }
    }

    // Masking Key & Payload
    if masked {
        var key = maskingKey
        if key.count < 4 {
            key = GenerateMaskingKey()
        }
        var ki = 0
        while ki < 4 {
            out.append(key[ki])
            ki += 1
        }

        var maskedPayload = payload
        MaskPayload(payload: &maskedPayload, maskingKey: key)
        var pi = 0
        while pi < maskedPayload.count {
            out.append(maskedPayload[pi])
            pi += 1
        }
    } else {
        var pi = 0
        while pi < payload.count {
            out.append(payload[pi])
            pi += 1
        }
    }

    return out
}

/// Parses an RFC 6455 frame from raw buffer starting at offset 0.
public func ParseFrame(data: [uint8]) throws -> ParsedFrame {
    return try ParseFrame(data: data, offset: 0)
}

/// Parses an RFC 6455 frame from raw buffer at offset.
public func ParseFrame(data: [uint8], offset: int) throws -> ParsedFrame {
    if offset + 2 > data.count {
        throw WebSocketError.protocolError("Incomplete frame header")
    }

    let b0 = data[offset]
    let b1 = data[offset + 1]

    let fin = (b0 & 0x80) != 0
    let rsv1 = (b0 & 0x40) != 0
    let rsv2 = (b0 & 0x20) != 0
    let rsv3 = (b0 & 0x10) != 0
    let opcode = b0 & 0x0f
    let masked = (b1 & 0x80) != 0
    let lenIndicator = int(b1 & 0x7f)

    var curr = offset + 2
    var payloadLen: int = 0

    if lenIndicator <= 125 {
        payloadLen = lenIndicator
    } else if lenIndicator == 126 {
        if curr + 2 > data.count {
            throw WebSocketError.protocolError("Incomplete extended length 126")
        }
        payloadLen = (int(data[curr]) << 8) | int(data[curr + 1])
        curr += 2
    } else {
        // 127: 8-byte length
        if curr + 8 > data.count {
            throw WebSocketError.protocolError("Incomplete extended length 127")
        }
        if (data[curr] & 0x80) != 0 {
            throw WebSocketError.protocolError("Most significant bit of 64-bit length must be 0")
        }
        var s: int = 56
        var l: int = 0
        var i = 0
        while i < 8 {
            l = l | (int(data[curr + i]) << s)
            s -= 8
            i += 1
        }
        payloadLen = l
        curr += 8
    }

    var maskingKey: [uint8] = []
    if masked {
        if curr + 4 > data.count {
            throw WebSocketError.protocolError("Incomplete masking key")
        }
        var ki = 0
        while ki < 4 {
            maskingKey.append(data[curr + ki])
            ki += 1
        }
        curr += 4
    }

    if curr + payloadLen > data.count {
        throw WebSocketError.protocolError("Incomplete frame payload")
    }

    var payload: [uint8] = []
    var pi = 0
    while pi < payloadLen {
        payload.append(data[curr + pi])
        pi += 1
    }

    if masked {
        MaskPayload(payload: &payload, maskingKey: maskingKey)
    }

    var frame = Frame(fin: fin, opcode: opcode, masked: masked, maskingKey: maskingKey, payload: payload)
    frame.Rsv1 = rsv1
    frame.Rsv2 = rsv2
    frame.Rsv3 = rsv3

    let totalBytes = (curr + payloadLen) - offset
    return ParsedFrame(frame: frame, bytesRead: totalBytes)
}

/// Builds payload for a Close control frame (2-byte code).
public func BuildClosePayload(code: uint16) -> [uint8] {
    return BuildClosePayload(code: code, reason: "")
}

/// Builds payload for a Close control frame (2-byte code + reason).
public func BuildClosePayload(code: uint16, reason: string) -> [uint8] {
    var out: [uint8] = [
        uint8(truncatingIfNeeded: (code >> 8) & 0xff),
        uint8(truncatingIfNeeded: code & 0xff)
    ]
    for b in reason.utf8 {
        out.append(b)
    }
    return out
}

/// CloseInfo holds parsed WebSocket Close code and reason.
public struct CloseInfo {
    public var Code: uint16
    public var Reason: string
    public init(code: uint16, reason: string) {
        self.Code = code
        self.Reason = reason
    }
}

/// Parses Close control frame payload into status code and UTF-8 reason string.
public func ParseClosePayload(payload: [uint8]) -> CloseInfo {
    if payload.count < 2 {
        return CloseInfo(code: CloseCode.NoStatusReceived, reason: "")
    }
    let code = (uint16(payload[0]) << 8) | uint16(payload[1])
    var reasonBytes: [uint8] = []
    var i = 2
    while i < payload.count {
        reasonBytes.append(payload[i])
        i += 1
    }
    let reason = string(decoding: reasonBytes, as: UTF8.self)
    return CloseInfo(code: code, reason: reason)
}

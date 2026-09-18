package quic

/// Variable-Length Integer Encoding (RFC 9000 Section 16).
/// QUIC uses a 2-bit prefix encoding scheme for integers up to 62 bits:
/// - 00: 1 byte  (6 bits: 0 .. 63)
/// - 01: 2 bytes (14 bits: 0 .. 16,383)
/// - 10: 4 bytes (30 bits: 0 .. 1,073,741,823)
/// - 11: 8 bytes (62 bits: 0 .. 4,611,686,018,427,387,903)

public let MaxVarint: uint64 = 4611686018427387903 // (1 << 62) - 1

/// Represents a successfully decoded variable-length integer and its byte size.
public struct DecodedVarint {
    public var Value: uint64
    public var BytesRead: int

    public init(value: uint64, bytesRead: int) {
        self.Value = value
        self.BytesRead = bytesRead
    }
}

/// Returns the number of bytes required to encode the given variable-length integer.
public func VarintLen(_ val: uint64) -> int {
    if val <= 63 {
        return 1
    } else if val <= 16383 {
        return 2
    } else if val <= 1073741823 {
        return 4
    } else {
        return 8
    }
}

/// Encodes an integer into RFC 9000 variable-length format.
public func EncodeVarint(_ val: uint64) -> [uint8] {
    if val <= 63 {
        return [uint8(val)]
    } else if val <= 16383 {
        return [
            uint8(0x40 | ((val >> 8) & 0x3f)),
            uint8(val & 0xff)
        ]
    } else if val <= 1073741823 {
        return [
            uint8(0x80 | ((val >> 24) & 0x3f)),
            uint8((val >> 16) & 0xff),
            uint8((val >> 8) & 0xff),
            uint8(val & 0xff)
        ]
    } else {
        return [
            uint8(0xc0 | ((val >> 56) & 0x3f)),
            uint8((val >> 48) & 0xff),
            uint8((val >> 40) & 0xff),
            uint8((val >> 32) & 0xff),
            uint8((val >> 24) & 0xff),
            uint8((val >> 16) & 0xff),
            uint8((val >> 8) & 0xff),
            uint8(val & 0xff)
        ]
    }
}

/// Decodes an RFC 9000 variable-length integer from a byte buffer at the given offset.
public func DecodeVarint(_ data: [uint8], offset: int = 0) throws -> DecodedVarint {
    if offset >= data.count {
        throw QuicError.transport(code: 0x01, msg: "Unexpected EOF while reading varint")
    }

    let first = data[offset]
    let prefix = (first >> 6) & 0x03

    if prefix == 0 {
        // 1 byte
        let val = uint64(first & 0x3f)
        return DecodedVarint(value: val, bytesRead: 1)
    } else if prefix == 1 {
        // 2 bytes
        if offset + 2 > data.count {
            throw QuicError.transport(code: 0x01, msg: "Truncated 2-byte varint")
        }
        let b0 = uint64(first & 0x3f)
        let b1 = uint64(data[offset + 1])
        let val = (b0 << 8) | b1
        return DecodedVarint(value: val, bytesRead: 2)
    } else if prefix == 2 {
        // 4 bytes
        if offset + 4 > data.count {
            throw QuicError.transport(code: 0x01, msg: "Truncated 4-byte varint")
        }
        let b0 = uint64(first & 0x3f)
        let b1 = uint64(data[offset + 1])
        let b2 = uint64(data[offset + 2])
        let b3 = uint64(data[offset + 3])
        let val = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        return DecodedVarint(value: val, bytesRead: 4)
    } else {
        // 8 bytes
        if offset + 8 > data.count {
            throw QuicError.transport(code: 0x01, msg: "Truncated 8-byte varint")
        }
        let b0 = uint64(first & 0x3f)
        let b1 = uint64(data[offset + 1])
        let b2 = uint64(data[offset + 2])
        let b3 = uint64(data[offset + 3])
        let b4 = uint64(data[offset + 4])
        let b5 = uint64(data[offset + 5])
        let b6 = uint64(data[offset + 6])
        let b7 = uint64(data[offset + 7])
        let val = (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) |
                  (b4 << 24) | (b5 << 16) | (b6 << 8) | b7
        return DecodedVarint(value: val, bytesRead: 8)
    }
}

package stun

import "crypto/rand"
import "crypto/crc32"
import "crypto/hmac"
import "crypto/sha1"

/// Generates a cryptographically random 12-byte (96-bit) STUN transaction ID.
public func NewTransactionId() -> [uint8] {
    if let b = try? rand.Bytes(12) {
        return b
    }
    // Fallback pseudo-random bytes if entropy pool fails
    var fb: [uint8] = []
    var i = 0
    while i < 12 {
        fb.append(uint8((i * 37 + 101) & 0xFF))
        i += 1
    }
    return fb
}

/// Message represents an RFC 8489 STUN protocol packet.
public struct Message {
    public var Type: uint16
    public var TransactionId: [uint8]
    public var Attributes: [Attribute] = []

    public init(type: uint16, transactionId: [uint8]? = nil) {
        self.Type = type
        if let tid = transactionId, tid.count == 12 {
            self.TransactionId = tid
        } else {
            self.TransactionId = NewTransactionId()
        }
    }

    /// Adds an attribute to the message.
    public mutating func AddAttribute(_ attr: Attribute) {
        self.Attributes.append(attr)
    }

    /// Finds the first attribute of the given type.
    public func GetAttribute(_ attrType: uint16) -> Attribute? {
        var i = 0
        while i < self.Attributes.count {
            if self.Attributes[i].Type == attrType {
                return self.Attributes[i]
            }
            i += 1
        }
        return nil
    }

    /// Encodes the STUN message into a raw byte array.
    public func Encode() -> [uint8] {
        var attrBytes: [uint8] = []
        var i = 0
        while i < self.Attributes.count {
            let attr = self.Attributes[i]
            // Type (2 bytes)
            attrBytes.append(uint8(attr.Type >> 8))
            attrBytes.append(uint8(attr.Type & 0xFF))
            // Length (2 bytes)
            attrBytes.append(uint8(attr.Value.count >> 8))
            attrBytes.append(uint8(attr.Value.count & 0xFF))
            // Value
            var vi = 0
            while vi < attr.Value.count {
                attrBytes.append(attr.Value[vi])
                vi += 1
            }
            // 4-byte alignment padding (RFC 8489 Section 5)
            let pad = (4 - (attr.Value.count % 4)) % 4
            var p = 0
            while p < pad {
                attrBytes.append(0)
                p += 1
            }
            i += 1
        }

        var raw: [uint8] = []
        // 1. Type (2 bytes)
        raw.append(uint8(self.Type >> 8))
        raw.append(uint8(self.Type & 0xFF))

        // 2. Length (2 bytes, excludes 20-byte header)
        raw.append(uint8(attrBytes.count >> 8))
        raw.append(uint8(attrBytes.count & 0xFF))

        // 3. Magic Cookie (4 bytes: 0x21, 0x12, 0xA4, 0x42)
        raw.append(0x21)
        raw.append(0x12)
        raw.append(0xA4)
        raw.append(0x42)

        // 4. Transaction ID (12 bytes)
        var ti = 0
        while ti < 12 && ti < self.TransactionId.count {
            raw.append(self.TransactionId[ti])
            ti += 1
        }
        while raw.count < HeaderSize {
            raw.append(0)
        }

        // 5. Attributes payload
        var ai = 0
        while ai < attrBytes.count {
            raw.append(attrBytes[ai])
            ai += 1
        }

        return raw
    }

    /// Adds an RFC 8489 Section 14.7 FINGERPRINT attribute to the message.
    public mutating func AddFingerprint() {
        // Encode message without fingerprint first
        let currentRaw = self.Encode()
        // The length field in the header must include the 8-byte FINGERPRINT attribute
        var rawForCrc = currentRaw
        let newLen = (rawForCrc.count - HeaderSize) + 8
        rawForCrc[2] = uint8(newLen >> 8)
        rawForCrc[3] = uint8(newLen & 0xFF)

        // Calculate CRC-32 over the header and existing attributes
        let crc = crc32.Checksum(rawForCrc)
        let fpVal = crc ^ 0x5354554E

        var fpBytes: [uint8] = []
        fpBytes.append(uint8((fpVal >> 24) & 0xFF))
        fpBytes.append(uint8((fpVal >> 16) & 0xFF))
        fpBytes.append(uint8((fpVal >> 8) & 0xFF))
        fpBytes.append(uint8(fpVal & 0xFF))

        self.AddAttribute(Attribute(type: AttrFingerprint, value: fpBytes))
    }

    /// Adds an RFC 8489 Section 14.5 MESSAGE-INTEGRITY attribute using HMAC-SHA1.
    public mutating func AddMessageIntegrity(key: [uint8]) {
        let currentRaw = self.Encode()
        // Message length must include the 24-byte MESSAGE-INTEGRITY attribute
        var rawForHmac = currentRaw
        let newLen = (rawForHmac.count - HeaderSize) + 24
        rawForHmac[2] = uint8(newLen >> 8)
        rawForHmac[3] = uint8(newLen & 0xFF)

        let mac = hmac.Compute(key: key, message: rawForHmac, hash: .sha1)
        self.AddAttribute(Attribute(type: AttrMessageIntegrity, value: mac))
    }

    /// Validates the FINGERPRINT attribute in an encoded STUN packet.
    public static func ValidateFingerprint(_ raw: [uint8]) -> bool {
        if raw.count < HeaderSize + 8 { return false }
        // Verify last 8 bytes form a FINGERPRINT attribute (Type 0x0080, Len 0x0004)
        let end = raw.count
        let type = (uint16(raw[end - 8]) << 8) | uint16(raw[end - 7])
        let len = (uint16(raw[end - 6]) << 8) | uint16(raw[end - 5])
        if type != AttrFingerprint || len != 4 { return false }

        let expectedFp = (uint32(raw[end - 4]) << 24) |
                         (uint32(raw[end - 3]) << 16) |
                         (uint32(raw[end - 2]) << 8) |
                          uint32(raw[end - 1])

        var prefix: [uint8] = []
        var i = 0
        while i < end - 8 {
            prefix.append(raw[i])
            i += 1
        }

        let computedCrc = crc32.Checksum(prefix)
        return (computedCrc ^ 0x5354554E) == expectedFp
    }

    /// Decodes a STUN message from raw received network bytes.
    public static func Decode(_ raw: [uint8]) throws -> Message {
        if raw.count < HeaderSize {
            throw StunError.invalidHeader("datagram shorter than 20-byte STUN header")
        }

        // RFC 8489 Section 5: The most significant 2 bits of the first byte must be 00
        if (raw[0] & 0xC0) != 0 {
            throw StunError.invalidHeader("first two bits must be 00")
        }

        let msgType = (uint16(raw[0]) << 8) | uint16(raw[1])
        let msgLen = (int(raw[2]) << 8) | int(raw[3])

        // Verify Magic Cookie 0x2112A442
        let cookie = (uint32(raw[4]) << 24) | (uint32(raw[5]) << 16) | (uint32(raw[6]) << 8) | uint32(raw[7])
        if cookie != MagicCookie {
            throw StunError.invalidMagicCookie
        }

        var tid: [uint8] = []
        var ti = 0
        while ti < 12 {
            tid.append(raw[8 + ti])
            ti += 1
        }

        if raw.count < HeaderSize + msgLen {
            throw StunError.invalidHeader("datagram length mismatch")
        }

        var msg = Message(type: msgType, transactionId: tid)

        // Parse attributes
        var offset = HeaderSize
        let endOffset = HeaderSize + msgLen
        while offset + 4 <= endOffset {
            let aType = (uint16(raw[offset]) << 8) | uint16(raw[offset + 1])
            let aLen = (int(raw[offset + 2]) << 8) | int(raw[offset + 3])
            offset += 4

            if offset + aLen > endOffset {
                throw StunError.malformedAttribute("attribute exceeds message length")
            }

            var val: [uint8] = []
            var vi = 0
            while vi < aLen {
                val.append(raw[offset + vi])
                vi += 1
            }

            msg.AddAttribute(Attribute(type: aType, value: val))
            offset += aLen

            // 4-byte padding alignment
            let pad = (4 - (aLen % 4)) % 4
            offset += pad
        }

        return msg
    }
}

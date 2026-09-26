package quic

import (
    "crypto/chacha20"
    "crypto/chacha20poly1305"
    "crypto/hkdf"
)

/// Authoritative RFC 9001 Section 5.2 Initial Salt for QUIC Version 1.
public struct QuicSalt {
    public static let V1: [uint8] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a
    ]
}

/// RFC 8446 / RFC 9001 HKDF-Expand-Label.
public func HkdfExpandLabel(secret: [uint8], label: string, context: [uint8] = [], length: int) -> [uint8] {
    var info: [uint8] = []

    // 1. Length (uint16 big-endian)
    info.append(uint8((length >> 8) & 0xff))
    info.append(uint8(length & 0xff))

    // 2. "tls13 " + label
    let fullLabel = "tls13 " + label
    var labelBytes: [uint8] = []
    for b in fullLabel.utf8 { labelBytes.append(b) }
    info.append(uint8(labelBytes.count))
    for b in labelBytes { info.append(b) }

    // 3. Context
    info.append(uint8(context.count))
    for b in context { info.append(b) }

    return hkdf.Expand(hash: .sha256, prk: secret, info: info, length: length)
}

/// QUIC AEAD and Header Protection Keys derived for an encryption level.
public struct QuicCipherKeys {
    public var Key: [uint8]
    public var Iv: [uint8]
    public var HpKey: [uint8]

    public init(key: [uint8], iv: [uint8], hpKey: [uint8]) {
        self.Key = key
        self.Iv = iv
        self.HpKey = hpKey
    }

    /// Derives QUIC keys from an encryption secret (RFC 9001 Section 5.1).
    public static func Derive(secret: [uint8]) -> QuicCipherKeys {
        let key = HkdfExpandLabel(secret: secret, label: "quic key", context: [], length: 32)
        let iv = HkdfExpandLabel(secret: secret, label: "quic iv", context: [], length: 12)
        let hp = HkdfExpandLabel(secret: secret, label: "quic hp", context: [], length: 32)
        return QuicCipherKeys(key: key, iv: iv, hpKey: hp)
    }
}

/// Computes the 12-byte AEAD Nonce by XORing the IV with the packet number.
public func ComputeNonce(iv: [uint8], pn: uint64) -> [uint8] {
    var nonce = iv
    var i = 0
    while i < 8 {
        let shift: uint64 = uint64((7 - i) * 8)
        let pnByte = uint8((pn >> shift) & 0xff)
        nonce[12 - 8 + i] ^= pnByte
        i += 1
    }
    return nonce
}

/// Generates a 5-byte header protection mask using ChaCha20 (RFC 9001 Section 5.4.3).
public func GenerateHeaderMask(hpKey: [uint8], sample: [uint8]) throws -> [uint8] {
    if sample.count < 16 {
        throw QuicError.transport(code: TransportErrorCode.InternalError, msg: "Sample must be at least 16 bytes")
    }

    // Counter: first 4 bytes of sample (little endian)
    let c0 = uint32(sample[0])
    let c1 = uint32(sample[1])
    let c2 = uint32(sample[2])
    let c3 = uint32(sample[3])
    let counter = c0 | (c1 << 8) | (c2 << 16) | (c3 << 24)

    // Nonce: remaining 12 bytes of sample
    var nonce: [uint8] = []
    var i = 4
    while i < 16 {
        nonce.append(sample[i])
        i += 1
    }

    let zeroBytes: [uint8] = [0, 0, 0, 0, 0]
    let keystream = try chacha20.Encrypt(key: hpKey, nonce: nonce, plaintext: zeroBytes, counter: counter)
    return keystream
}

/// Applies RFC 9001 header protection in place to a serialized packet buffer.
public func ApplyHeaderProtection(packet: inout [uint8], pnOffset: int, pnLen: int, hpKey: [uint8]) throws {
    let sampleOffset = pnOffset + 4
    if sampleOffset + 16 > packet.count {
        throw QuicError.transport(code: TransportErrorCode.InternalError, msg: "Packet too small to extract header protection sample")
    }

    var sample: [uint8] = []
    var i = 0
    while i < 16 {
        sample.append(packet[sampleOffset + i])
        i += 1
    }

    let mask = try GenerateHeaderMask(hpKey: hpKey, sample: sample)

    // Mask first byte
    let isLong = (packet[0] & 0x80) != 0
    if isLong {
        packet[0] ^= (mask[0] & 0x0f)
    } else {
        packet[0] ^= (mask[0] & 0x1f)
    }

    // Mask packet number bytes
    i = 0
    while i < pnLen {
        packet[pnOffset + i] ^= mask[1 + i]
        i += 1
    }
}

/// Unprotected header info returned after removing RFC 9001 header protection.
public struct UnprotectedHeader {
    public var PacketNumber: uint64
    public var PnLength: int

    public init(packetNumber: uint64, pnLength: int) {
        self.PacketNumber = packetNumber
        self.PnLength = pnLength
    }
}

/// Decrypted packet result containing reconstructed packet number and parsed frames.
public struct DecryptedPacket {
    public var PacketNumber: uint64
    public var Frames: [QuicFrame]

    public init(packetNumber: uint64, frames: [QuicFrame]) {
        self.PacketNumber = packetNumber
        self.Frames = frames
    }
}

/// Removes RFC 9001 header protection from an inbound packet buffer, returning the decoded packet number.
public func RemoveHeaderProtection(packet: inout [uint8], pnOffset: int, hpKey: [uint8], largestAcked: uint64) throws -> UnprotectedHeader {
    let sampleOffset = pnOffset + 4
    if sampleOffset + 16 > packet.count {
        throw QuicError.transport(code: TransportErrorCode.ProtocolViolation, msg: "Inbound packet too small for header protection sample")
    }

    var sample: [uint8] = []
    var i = 0
    while i < 16 {
        sample.append(packet[sampleOffset + i])
        i += 1
    }

    let mask = try GenerateHeaderMask(hpKey: hpKey, sample: sample)

    // Unmask first byte
    let isLong = (packet[0] & 0x80) != 0
    if isLong {
        packet[0] ^= (mask[0] & 0x0f)
    } else {
        packet[0] ^= (mask[0] & 0x1f)
    }

    let pnLen = int(packet[0] & 0x03) + 1

    // Unmask packet number bytes
    var truncatedPn: uint64 = 0
    i = 0
    while i < pnLen {
        packet[pnOffset + i] ^= mask[1 + i]
        truncatedPn = (truncatedPn << 8) | uint64(packet[pnOffset + i])
        i += 1
    }

    let fullPn = DecodePacketNumber(largestPn: largestAcked, truncatedPn: truncatedPn, pnLen: pnLen)
    return UnprotectedHeader(packetNumber: fullPn, pnLength: pnLen)
}

/// Encrypts and protects a complete QUIC packet (AEAD payload + header protection).
public func SealPacket(header: [uint8],
                       payload: [uint8],
                       pn: uint64,
                       pnOffset: int,
                       pnLen: int,
                       keys: QuicCipherKeys) throws -> [uint8] {
    let nonce = ComputeNonce(iv: keys.Iv, pn: pn)
    let aead = try chacha20poly1305.AEAD.New(key: keys.Key)
    let ciphertext = try aead.Seal(nonce: nonce, plaintext: payload, additionalData: header)

    var packet: [uint8] = []
    for b in header { packet.append(b) }
    for b in ciphertext { packet.append(b) }

    try ApplyHeaderProtection(packet: &packet, pnOffset: pnOffset, pnLen: pnLen, hpKey: keys.HpKey)
    return packet
}

/// Unprotects and decrypts an inbound QUIC packet (removes header protection, decrypts AEAD payload).
public func OpenPacket(packet: [uint8],
                       pnOffset: int,
                       keys: QuicCipherKeys,
                       largestAcked: uint64) throws -> DecryptedPacket {
    var raw = packet
    let hdr = try RemoveHeaderProtection(packet: &raw, pnOffset: pnOffset, hpKey: keys.HpKey, largestAcked: largestAcked)
    let pn = hdr.PacketNumber
    let pnLen = hdr.PnLength

    let headerLen = pnOffset + pnLen
    var headerBytes: [uint8] = []
    var i = 0
    while i < headerLen {
        headerBytes.append(raw[i])
        i += 1
    }

    var ciphertext: [uint8] = []
    i = headerLen
    while i < raw.count {
        ciphertext.append(raw[i])
        i += 1
    }

    let nonce = ComputeNonce(iv: keys.Iv, pn: pn)
    let aead = try chacha20poly1305.AEAD.New(key: keys.Key)
    let plaintext = try aead.Open(nonce: nonce, ciphertextAndTag: ciphertext, additionalData: headerBytes)

    let frames = try ParseFrames(plaintext)
    return DecryptedPacket(packetNumber: pn, frames: frames)
}

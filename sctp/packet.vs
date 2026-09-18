package sctp

import "crypto/crc32"

/// Packet represents an SCTP packet consisting of a 12-byte common header and one or more chunks.
public struct Packet {
    public var SourcePort: uint16
    public var DestinationPort: uint16
    public var VerificationTag: uint32
    public var Chunks: [RawChunk]

    public init(sourcePort: uint16,
                destinationPort: uint16,
                verificationTag: uint32,
                chunks: [RawChunk] = []) {
        self.SourcePort = sourcePort
        self.DestinationPort = destinationPort
        self.VerificationTag = verificationTag
        self.Chunks = chunks
    }

    /// Serialize writes the packet into bytes and computes the RFC 3309 CRC-32c checksum.
    public func Serialize() -> [uint8] {
        var out = [uint8](repeating: 0, count: 12)

        // Source Port
        out[0] = uint8(truncatingIfNeeded: (self.SourcePort >> 8) & 0xff)
        out[1] = uint8(truncatingIfNeeded: self.SourcePort & 0xff)

        // Destination Port
        out[2] = uint8(truncatingIfNeeded: (self.DestinationPort >> 8) & 0xff)
        out[3] = uint8(truncatingIfNeeded: self.DestinationPort & 0xff)

        // Verification Tag
        out[4] = uint8(truncatingIfNeeded: (self.VerificationTag >> 24) & 0xff)
        out[5] = uint8(truncatingIfNeeded: (self.VerificationTag >> 16) & 0xff)
        out[6] = uint8(truncatingIfNeeded: (self.VerificationTag >> 8) & 0xff)
        out[7] = uint8(truncatingIfNeeded: self.VerificationTag & 0xff)

        // Checksum initially 0
        out[8] = 0
        out[9] = 0
        out[10] = 0
        out[11] = 0

        // Append all chunks
        var c = 0
        while c < self.Chunks.count {
            let chunkBytes = self.Chunks[c].Serialize()
            var b = 0
            while b < chunkBytes.count {
                out.append(chunkBytes[b])
                b += 1
            }
            c += 1
        }

        // Compute RFC 3309 / RFC 4960 CRC-32C
        let sum = crc32.ChecksumCastagnoli(out)
        out[8] = uint8(truncatingIfNeeded: (sum >> 24) & 0xff)
        out[9] = uint8(truncatingIfNeeded: (sum >> 16) & 0xff)
        out[10] = uint8(truncatingIfNeeded: (sum >> 8) & 0xff)
        out[11] = uint8(truncatingIfNeeded: sum & 0xff)

        return out
    }

    /// Parse deserializes an SCTP packet from raw bytes and verifies its CRC-32c checksum.
    public static func Parse(_ data: [uint8], verifyChecksum: bool = true) throws -> Packet {
        if data.count < 12 {
            throw SctpError.invalidPacket("Packet too short for SCTP common header")
        }

        let srcPort = (uint16(data[0]) << 8) | uint16(data[1])
        let dstPort = (uint16(data[2]) << 8) | uint16(data[3])
        let vTag = (uint32(data[4]) << 24) | (uint32(data[5]) << 16) | (uint32(data[6]) << 8) | uint32(data[7])
        let expectedCrc = (uint32(data[8]) << 24) | (uint32(data[9]) << 16) | (uint32(data[10]) << 8) | uint32(data[11])

        if verifyChecksum {
            var zeroed = [uint8](repeating: 0, count: data.count)
            var idx = 0
            while idx < data.count {
                zeroed[idx] = data[idx]
                idx += 1
            }
            zeroed[8] = 0
            zeroed[9] = 0
            zeroed[10] = 0
            zeroed[11] = 0

            let actualCrc = crc32.ChecksumCastagnoli(zeroed)
            if actualCrc != expectedCrc {
                throw SctpError.checksumMismatch("CRC-32c checksum mismatch")
            }
        }

        // Parse chunks
        var chunks: [RawChunk] = []
        var pos = 12
        while pos + 4 <= data.count {
            let cType = data[pos]
            let cFlags = data[pos + 1]
            let cLen = (int(data[pos + 2]) << 8) | int(data[pos + 3])

            if cLen < 4 || pos + cLen > data.count {
                throw SctpError.invalidPacket("Invalid chunk length in packet")
            }

            let valLen = cLen - 4
            var valBytes = [uint8](repeating: 0, count: valLen)
            var v = 0
            while v < valLen {
                valBytes[v] = data[pos + 4 + v]
                v += 1
            }

            chunks.append(RawChunk(type: cType, flags: cFlags, length: cLen, value: valBytes))

            let pad = (4 - (cLen % 4)) % 4
            pos += cLen + pad
        }

        return Packet(sourcePort: srcPort, destinationPort: dstPort, verificationTag: vTag, chunks: chunks)
    }
}

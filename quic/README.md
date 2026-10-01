# net/quic

RFC 9000, 9001, 9002, and 9221 QUIC transport protocol with bidirectional/unidirectional streams, ChaCha20-Poly1305 packet protection, NewReno congestion control, and unreliable datagrams (`quic.Connect`, `quic.Listen`, `QuicConnection`, `QuicStream`).

```vertex
import "net/quic"
```

## Types

- **`QuicConnection`** (struct): QuicConnection represents an active QUIC connection managing streams, flow control, packet numbers, encryption, and unreliable datagrams (RFC 9000 & RFC 9221).
- **`QuicSalt`** (struct): Authoritative RFC 9001 Section 5.2 Initial Salt for QUIC Version 1.
- **`QuicCipherKeys`** (struct): QUIC AEAD and Header Protection Keys derived for an encryption level.
- **`UnprotectedHeader`** (struct): Unprotected header info returned after removing RFC 9001 header protection.
- **`DecryptedPacket`** (struct): Decrypted packet result containing reconstructed packet number and parsed frames.
- **`AckRange`** (struct): ACK range gap and count pair.
- **`AckFrameData`** (struct): Payload for ACK frame (RFC 9000 Section 19.3).
- **`StreamFrameData`** (struct): Payload for STREAM frame (RFC 9000 Section 19.8).
- **`ResetStreamData`** (struct): Payload for RESET_STREAM frame (RFC 9000 Section 19.4).
- **`NewConnectionIdData`** (struct): Payload for NEW_CONNECTION_ID frame (RFC 9000 Section 19.15).
- and 19 more

## Functions

- `func CreateConnection(to remoteAddress: string, isClient: bool = true) throws -> QuicConnection`: Creates a new QuicConnection with an autonomously bound UDP socket and resolved string address.
- `func CreateLoopbackPair() throws -> (client: QuicConnection, server: QuicConnection)`: Creates a client and server connection pair bound to localhost on ephemeral ports.
- `func HkdfExpandLabel(secret: [uint8], label: string, context: [uint8] = [], length: int) -> [uint8]`: RFC 8446 / RFC 9001 HKDF-Expand-Label.
- `func ComputeNonce(iv: [uint8], pn: uint64) -> [uint8]`: Computes the 12-byte AEAD Nonce by XORing the IV with the packet number.
- `func GenerateHeaderMask(hpKey: [uint8], sample: [uint8]) throws -> [uint8]`: Generates a 5-byte header protection mask using ChaCha20 (RFC 9001 Section 5.4.3).
- `func ApplyHeaderProtection(packet: inout [uint8], pnOffset: int, pnLen: int, hpKey: [uint8]) throws`: Applies RFC 9001 header protection in place to a serialized packet buffer.
- `func RemoveHeaderProtection(packet: inout [uint8], pnOffset: int, hpKey: [uint8], largestAcked: uint64) throws -> UnprotectedHeader`: Removes RFC 9001 header protection from an inbound packet buffer, returning the decoded packet number.
- `func SealPacket(header: [uint8], payload: [uint8], pn: uint64, pnOffset: int, pnLen: int, keys: QuicCipherKeys) throws -> [uint8]`: Encrypts and protects a complete QUIC packet (AEAD payload + header protection).
- `func OpenPacket(packet: [uint8], pnOffset: int, keys: QuicCipherKeys, largestAcked: uint64) throws -> DecryptedPacket`: Unprotects and decrypts an inbound QUIC packet (removes header protection, decrypts AEAD payload).
- `func EncodeFrame(_ frame: QuicFrame) -> [uint8]`: Serializes a single QUIC frame into wire format bytes.
- and 25 more

Part of the [`net`](https://github.com/vertex-language/net) repository.

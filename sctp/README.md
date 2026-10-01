# net/sctp

RFC 4960 / RFC 8261 SCTP stream transport with Castagnoli CRC-32c checksumming (`SctpAssociation`, `SctpPacket`).

```vertex
import "net/sctp"
```

## Types

- **`ReceivedMessage`** (struct): ReceivedMessage represents reassembled payload delivered from an SCTP stream.
- **`Association`** (struct): Association manages the state, streams, and TSN sequencing of an SCTP connection (RFC 4960 / RFC 8261).
- **`RawChunk`** (struct): RawChunk represents an SCTP chunk with a 4-byte header and raw value bytes.
- **`InitChunk`** (struct): InitChunk represents an INIT (1) or INIT ACK (2) chunk.
- **`DataChunk`** (struct): DataChunk represents an SCTP DATA (0) chunk.
- **`SackChunk`** (struct): SackChunk represents an SCTP Selective Acknowledgement (3) chunk.
- **`CookieEchoChunk`** (struct): CookieEchoChunk represents a COOKIE ECHO (10) chunk.
- **`CookieAckChunk`** (struct): CookieAckChunk represents a COOKIE ACK (11) chunk.
- **`HeartbeatChunk`** (struct): HeartbeatChunk represents a HEARTBEAT (4) or HEARTBEAT ACK (5) chunk.
- **`AbortChunk`** (struct): AbortChunk represents an ABORT (6) chunk.
- and 6 more

Part of the [`net`](https://github.com/vertex-language/net) repository.

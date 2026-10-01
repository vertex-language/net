# net/webtransport

RFC 9297 WebTransport over HTTP/3 and QUIC with multiplexed bidirectional and unidirectional reliable streams, unreliable datagrams (RFC 9221), HTTP/3 extended CONNECT session negotiation, and capsule protocol control signaling (`webtransport.Connect`, `webtransport.ParseEndpoint`

```vertex
import "net/webtransport"
```

## Types

- **`ParsedCapsule`** (struct): Parsed representation of an RFC 9297 Capsule.
- **`DecodedDatagram`** (struct): Represents a decoded WebTransport datagram.
- **`WebTransportListener`** (struct): WebTransportListener listens for incoming WebTransport sessions over QUIC.
- **`Upgrader`** (struct): Upgrader provides helpers for verifying and upgrading incoming HTTP/3 requests to WebTransport.
- **`SessionEvent`** (enum): Events dispatched by WebTransportSession.NextEvent().
- **`WebTransportSession`** (struct): WebTransportSession represents an active RFC 9297 WebTransport session over HTTP/3 / QUIC.
- **`WebTransportStream`** (struct): WebTransportStream represents a bidirectional stream multiplexed within a WebTransport session (RFC 9297 Section 4.1).
- **`WebTransportSendStream`** (struct): WebTransportSendStream represents an outgoing unidirectional stream (RFC 9297 Section 4.2).
- **`WebTransportReceiveStream`** (struct): WebTransportReceiveStream represents an incoming unidirectional stream (RFC 9297 Section 4.2).
- **`WebTransportError`** (enum): Protocol errors encountered in WebTransport sessions (RFC 9297).
- and 6 more

## Functions

- `func BuildCapsule(type: uint64, payload: [uint8]) -> [uint8]`: Serializes an RFC 9297 Capsule given its type identifier and payload.
- `func ParseCapsule(data: [uint8], offset: int = 0) throws -> ParsedCapsule`: Parses an RFC 9297 Capsule from a byte buffer starting at offset.
- `func BuildCloseSessionPayload(code: uint32, reason: string) -> [uint8]`: Serializes a CLOSE_WEBTRANSPORT_SESSION (0x2843) capsule payload.
- `func BuildCloseSessionCapsule(code: uint32, reason: string) -> [uint8]`: Builds a complete CLOSE_WEBTRANSPORT_SESSION capsule frame.
- `func ParseCloseSessionPayload(_ payload: [uint8]) throws -> SessionCloseInfo`: Parses a CLOSE_WEBTRANSPORT_SESSION capsule payload into SessionCloseInfo.
- `func BuildDrainSessionCapsule() -> [uint8]`: Builds a complete DRAIN_WEBTRANSPORT_SESSION capsule frame.
- `func ParseEndpoint(_ address: string) throws -> url.URL`: A WebTransport endpoint's URL, parsed: https://, with a host.
- `func Connect(_ address: string) async throws -> WebTransportSession`: Connects to a WebTransport endpoint over HTTP/3 via QUIC (matching webtransport_package.md).
- `func Connect(_ address: string, config: WebTransportConfig) async throws -> WebTransportSession`: Connects to a WebTransport endpoint with custom configuration.
- `func EncodeDatagram(sessionId: uint64, payload: [uint8]) -> [uint8]`: Encapsulates application data into an RFC 9297 WebTransport datagram.
- and 4 more

Part of the [`net`](https://github.com/vertex-language/net) repository.

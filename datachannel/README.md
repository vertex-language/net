# net/datachannel

RFC 8831 / RFC 8832 WebRTC Data Channels and DCEP channel establishment (`RTCDataChannel`).

```vertex
import "net/datachannel"
```

## Types

- **`InboundKind`** (struct)
- **`DataChannelInboundResult`** (struct): DataChannelInboundResult represents an event or data extracted from an incoming SCTP stream message.
- **`OutboundMessage`** (struct): OutboundMessage represents an SCTP chunk payload to transmit.
- **`RTCDataChannel`** (struct): RTCDataChannel represents a bidirectional peer-to-peer data channel (RFC 8831).
- **`DcepOpenMessage`** (struct): DcepOpenMessage holds the parameters of a received DCEP DATA_CHANNEL_OPEN message (RFC 8832).
- **`ChannelType`** (struct)
- **`DcepMessageType`** (struct)
- **`RTCDataChannelState`** (struct)
- **`RTCDataChannelInit`** (struct)
- **`DataChannelError`** (enum)

## Functions

- `func BuildDcepOpen(channelType: uint8, priority: uint16, reliabilityParam: uint32, label: string, subprotocol: string = "") -> [uint8]`: BuildDcepOpen serializes a DCEP DATA_CHANNEL_OPEN message (RFC 8832 Section 5.1).
- `func ParseDcepOpen(_ data: [uint8]) throws -> DcepOpenMessage`: ParseDcepOpen parses a DCEP DATA_CHANNEL_OPEN message from bytes.
- `func BuildDcepAck() -> [uint8]`: BuildDcepAck serializes a DCEP DATA_CHANNEL_ACK message (RFC 8832 Section 5.2).

Part of the [`net`](https://github.com/vertex-language/net) repository.

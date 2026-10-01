# net/stun

RFC 8489 STUN NAT traversal discovery and message binding (`stun.Discover`, `stun.Client`, `stun.Message`).

```vertex
import "net/stun"
```

## Types

- **`Attribute`** (struct): Attribute represents a raw Type-Length-Value (TLV) STUN attribute.
- **`Client`** (struct): Client queries STUN servers to discover NAT mappings and reflexive IP addresses.
- **`StunAddress`** (struct): StunAddress represents a discovered reflexive or mapped address from a STUN server.
- **`Message`** (struct): Message represents an RFC 8489 STUN protocol packet.
- **`Header`** (struct)
- **`MessageType`** (struct): STUN Message Types (RFC 8489 Section 18.1)
- **`AttributeType`** (struct): STUN & TURN & ICE Attribute Types (RFC 8489, RFC 8656, RFC 8445)
- **`ErrorCodeInfo`** (struct)
- **`StunError`** (enum): StunError represents STUN packet parsing, encoding, or transaction failures.

## Functions

- `func MakeXorMappedAddress(address: udp.SocketAddress, transactionId: [uint8]) -> Attribute`: MakeXorMappedAddress creates an XOR-MAPPED-ADDRESS attribute (RFC 8489 Section 14.2).
- `func ParseXorMappedAddress(_ attr: Attribute, transactionId: [uint8]) throws -> udp.SocketAddress`: ParseXorMappedAddress decodes an XOR-MAPPED-ADDRESS attribute.
- `func MakeXorRelayedAddress(address: udp.SocketAddress, transactionId: [uint8]) -> Attribute`: MakeXorRelayedAddress creates an XOR-RELAYED-ADDRESS attribute (RFC 8656 Section 14.5).
- `func ParseXorRelayedAddress(_ attr: Attribute, transactionId: [uint8]) throws -> udp.SocketAddress`: ParseXorRelayedAddress decodes an XOR-RELAYED-ADDRESS attribute.
- `func MakeXorPeerAddress(address: udp.SocketAddress, transactionId: [uint8]) -> Attribute`: MakeXorPeerAddress creates an XOR-PEER-ADDRESS attribute (RFC 8656 Section 14.3).
- `func ParseXorPeerAddress(_ attr: Attribute, transactionId: [uint8]) throws -> udp.SocketAddress`: ParseXorPeerAddress decodes an XOR-PEER-ADDRESS attribute.
- `func MakeMappedAddress(address: udp.SocketAddress) -> Attribute`: MakeMappedAddress creates a legacy MAPPED-ADDRESS attribute (RFC 8489 Section 14.1).
- `func ParseMappedAddress(_ attr: Attribute) throws -> udp.SocketAddress`: ParseMappedAddress decodes a legacy MAPPED-ADDRESS attribute.
- `func MakeSoftware(_ name: string) -> Attribute`: MakeSoftware creates a SOFTWARE attribute (RFC 8489 Section 14.8).
- `func ParseSoftware(_ attr: Attribute) -> string`: ParseSoftware extracts the software string from a SOFTWARE attribute.
- and 23 more

Part of the [`net`](https://github.com/vertex-language/net) repository.

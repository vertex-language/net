# net/turn

RFC 8656 Traversal Using Relays around NAT client and relay server (`TurnClient`, `TurnServer`).

```vertex
import "net/turn"
```

## Types

- **`Client`** (struct): Client coordinates RFC 8656 TURN relay allocation, permissions, and packet transport over UDP.
- **`ServerSession`** (struct): ServerSession tracks an active allocation on the mock/local TURN server.
- **`Server`** (struct): Server provides lightweight RFC 8656 TURN server logic for local testing and relay coordination.
- **`MessageType`** (struct): TURN Message Types (RFC 8656 Section 18.1)
- **`AttributeType`** (struct): TURN Attribute Types (RFC 8656 Section 18.2)
- **`Allocation`** (struct): Allocation represents an established TURN relay allocation on the server.
- **`TurnError`** (enum): TurnError represents protocol, authentication, or allocation errors in TURN.

## Functions

- `func GenerateKey(username: string, realm: string, password: string) -> [uint8]`: Computes the TURN Long-Term Credential Key (RFC 5389 Section 15.4 / RFC 8656 Section 9.1.1): key = MD5(username ":" realm ":" password)
- `func NewClient(socket: udp.UdpSocket, serverAddress: udp.SocketAddress, username: string, password: string) -> Client`: Creates a new unallocated TURN Client instance.
- `func ParseDataIndication(_ msg: stun.Message) throws -> (data: [uint8], peerAddress: udp.SocketAddress)`: Decodes an incoming TURN Data Indication packet (RFC 8656 Section 10).
- `func Connect(server: string, username: string, password: string) throws -> Client`: Connect initializes a TURN client by binding an ephemeral UDP socket and parsing the server address.

Part of the [`net`](https://github.com/vertex-language/net) repository.

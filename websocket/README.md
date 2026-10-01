# net/websocket

RFC 6455 WebSocket client and server over plain TCP (`ws://`) and TLS 1.3 (`wss://`) with complete frame masking/demasking, ping/pong heartbeats, close handshakes, and fragment reassembly (`websocket.Connect`, `websocket.ParseEndpoint`, `websocket.Upgrade`, `websocket.UpgradeTLS`, `websocket.Server`, `WebSocket`).

```vertex
import "net/websocket"
```

## Types

- **`ClientConfig`** (struct): Client configuration options.
- **`WebSocket`** (struct): WebSocket represents an established WebSocket connection over plain TCP or TLS 1.3.
- **`Conn`** (typealias): Backward-compatible typealias for WebSocket connection.
- **`Frame`** (struct): Frame represents a single RFC 6455 binary frame.
- **`ParsedFrame`** (struct)
- **`CloseInfo`** (struct): CloseInfo holds parsed WebSocket Close code and reason.
- **`Server`** (struct): Server provides high-level WebSocket server listeners.
- **`WebSocketListener`** (struct): WebSocketListener wraps an active TCP listener and serves WebSocket connections.
- **`Opcode`** (struct): RFC 6455 Section 5.2 Opcodes.
- **`CloseCode`** (struct): RFC 6455 Section 7.4.1 Status Codes.
- and 3 more

## Functions

- `func Base64Encode(_ src: [uint8]) -> string`: Encodes binary bytes to standard Base64 string.
- `func Base64Decode(_ s: string) throws -> [uint8]`: Decodes standard Base64 string to bytes.
- `func ParseEndpoint(_ address: string) throws -> url.URL`: A WebSocket endpoint's URL, parsed: ws:// or wss://, with a host.
- `func Connect(_ address: string) async throws -> WebSocket`: Connects to a WebSocket endpoint written as text ("ws://..." or "wss://...").
- `func Connect(_ address: string, subprotocols: [string]) async throws -> WebSocket`: Connects to a WebSocket endpoint with specified subprotocols.
- `func Connect(_ address: string, config: ClientConfig) async throws -> WebSocket`: Connects to a WebSocket endpoint with custom client configuration.
- `func MaskPayload(payload: inout [uint8], maskingKey: [uint8])`: Applies RFC 6455 4-byte XOR masking in place.
- `func GenerateMaskingKey() -> [uint8]`: Generates a random 4-byte masking key for client frames.
- `func BuildFrame(fin: bool, opcode: uint8, masked: bool) -> [uint8]`: Builds an RFC 6455 serialized frame without payload.
- `func BuildFrame(fin: bool, opcode: uint8, masked: bool, payload: [uint8]) -> [uint8]`: Builds an RFC 6455 serialized frame with automatic masking key generation if masked.
- and 21 more

Part of the [`net`](https://github.com/vertex-language/net) repository.

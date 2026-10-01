# net/webrtc

RFC 9429 WebRTC PeerConnection, JSEP Offer/Answer state machine, and RFC 8866 SDP negotiation (`RTCPeerConnection`).

```vertex
import "net/webrtc"
```

## Types

- **`RTCPeerConnection`** (struct): RTCPeerConnection represents a WebRTC peer connection coordinating ICE, DTLS, SCTP, and DataChannels (RFC 9429 / W3C).
- **`ParsedSdp`** (struct): ParsedSdp contains structured fields extracted from an SDP description.
- **`RTCSignalingState`** (struct)
- **`RTCIceConnectionState`** (struct)
- **`RTCPeerConnectionState`** (struct)
- **`RTCSdpType`** (struct)
- **`RTCSessionDescription`** (struct)
- **`RTCDataChannelState`** (struct)
- **`RTCIceServer`** (struct)
- **`RTCConfiguration`** (struct)
- and 3 more

## Functions

- `func NewPeerConnection(socket: udp.UdpSocket, configuration: RTCConfiguration) -> RTCPeerConnection`: Creates a new RTCPeerConnection configured with ICE Agent, DTLS ciphers, and SCTP association.
- `func CreatePeerConnection() async throws -> RTCPeerConnection`: Creates a new WebRTC PeerConnection with default configuration and autonomously bound socket.
- `func CreatePeerConnection(configuration: RTCConfiguration) async throws -> RTCPeerConnection`: Creates a new WebRTC PeerConnection with the specified configuration and autonomously bound socket.
- `func BuildSdp(type: string, ufrag: string, pwd: string, fingerprint: string, setup: string, sctpPort: uint16, candidates: [ice.Candidate]) -> string`: BuildSdp constructs an RFC 8866 / RFC 8839 compliant SDP description for WebRTC DataChannels.
- `func ParseSdp(_ sdp: string, type: string) throws -> ParsedSdp`: ParseSdp parses a WebRTC SDP string into structured fields.

Part of the [`net`](https://github.com/vertex-language/net) repository.

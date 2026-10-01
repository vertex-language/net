# net/ice

RFC 8445 / RFC 8838 Interactive Connectivity Establishment with candidate gathering and connectivity checks (`IceAgent`, `CandidateGatherer`).

```vertex
import "net/ice"
```

## Types

- **`IceRole`** (struct): ICE Roles (RFC 8445 Section 6.1.1)
- **`IceConnectionState`** (struct): ICE Connection States (RFC 8445 Section 6.1.2.6)
- **`IceError`** (enum)
- **`Agent`** (struct): Agent conducts Interactive Connectivity Establishment (RFC 8445 & RFC 8838 Trickle ICE).
- **`CandidateType`** (struct): Candidate Types (RFC 8445 Section 5.1.1)
- **`Candidate`** (struct): Candidate represents an ICE transport address candidate (RFC 8445 / RFC 8839).
- **`CandidateGatherer`** (struct): CandidateGatherer manages local host and server-reflexive ICE candidate discovery.
- **`PairState`** (struct): Candidate Pair States (RFC 8445 Section 6.1.2.6)
- **`CandidatePair`** (struct): CandidatePair represents a checklist entry of a local and remote candidate (RFC 8445 Section 6.1.2).

## Functions

- `func NewAgent(socket: udp.UdpSocket, role: string = IceRole.Controlling, localCandidates: [Candidate] = [], ufrag: string = "", pwd: string = "") -> Agent`: Creates a new ICE Agent initialized with local credentials and host candidates.
- `func CalculatePriority(type: string, localPref: uint16 = 65535, component: uint16 = 1) -> uint32`: Computes the candidate priority according to RFC 8445 Section 5.1.2: priority = (2^24 * type_pref) + (2^8 * local_pref) + (256 - component_id)
- `func NewHostCandidate(foundation: string, address: udp.SocketAddress, localPref: uint16 = 65535, component: uint16 = 1) -> Candidate`: Creates a new Host candidate.
- `func NewServerReflexiveCandidate(foundation: string, address: udp.SocketAddress, relatedAddress: udp.SocketAddress, localPref: uint16 = 65535, component: uint16 = 1) -> Candidate`: Creates a new Server Reflexive candidate.
- `func NewRelayCandidate(foundation: string, address: udp.SocketAddress, relatedAddress: udp.SocketAddress, localPref: uint16 = 65535, component: uint16 = 1) -> Candidate`: Creates a new Relay candidate.
- `func ParseSDPLine(_ line: string) -> Candidate?`: Parses an RFC 8839 / RFC 8445 candidate attribute line from an SDP description.
- `func CalculatePairPriority(controllingPriority: uint32, controlledPriority: uint32) -> uint64`: Calculates pair priority according to RFC 8445 Section 6.1.2.3: pair_priority = (2^32 * MIN(G, D)) + (2 * MAX(G, D)) + (G > D ?
- `func NewCandidatePair(local: Candidate, remote: Candidate, isControlling: bool) -> CandidatePair`: Creates a new CandidatePair and computes its pair priority.

Part of the [`net`](https://github.com/vertex-language/net) repository.

# net/wire

The headers a virtual machine's network carries, read and written: values in, bytes out, and back. No sockets and no state, so each codec is testable alone. Ethernet framing is `net/ether`'s; addresses are `net/netip`'s.

```vertex
import "net/wire"
```

## Types

- **`IpProtocol`** (enum): `icmp`, `tcp`, `udp`.
- **`Arp`** (struct): ARP for IPv4 over Ethernet; `Answer(mac)` is the reply to a request.
- **`Ipv4Packet`** (struct): A 20-byte header written with its checksum; a frame's padding past the total length dropped on reading; fragments recognised (`IsFragment`), not reassembled.
- **`Icmp`** (struct): Type, code, the four bytes after the checksum, data; `EchoReply()`.
- **`Udp`** (struct): `Encode(source:destination:)` fills the checksum over the pseudo-header.
- **`TcpFlags`** (enum), **`Tcp`** (struct): A segment with its MSS option read and written (others skipped); `Length` is its sequence space.

## Functions

- `func Checksum(_ data: [uint8], initial: uint32 = 0) -> uint16`: RFC 1071.
- `func PseudoHeader(source:destination:protocol:length:) -> uint32`: what UDP and TCP checksums cover besides themselves.

Part of the [`net`](https://github.com/vertex-language/net) repository.

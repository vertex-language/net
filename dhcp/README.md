# net/dhcp

DHCPv4 (RFC 2131, 2132): its messages, and a `Server` that leases addresses to the machines on a virtual network. The server only decides the answer; carrying it over UDP 67/68 is the caller's (`net/nat`'s `Gateway`).

```vertex
import "net/dhcp"
```

## Types

- **`Kind`** (enum): Message types (option 53): discover, offer, request, decline, ack, nak, release, inform.
- **`Option`** (enum): The option codes read or written here.
- **`Message`** (struct): The BOOTP header and options: `Parse`, `Encode` (padded to 300 bytes), `Get`/`Set` an option, `MessageType`, `RequestedIp`, `ServerId`, `WantsBroadcast`.
- **`ServerConfig`** (struct): The server's address, network, pool, nameservers, router, domain, lease time, and `Reserved` addresses never handed out.
- **`Server`** (class): `Handle(message)` → the reply or nil; `AddressFor(mac)`, `Holder(ip)`. One address per MAC, kept across requests.

Part of the [`net`](https://github.com/vertex-language/net) repository.

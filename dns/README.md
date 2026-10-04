# net/dns

DNS messages (RFC 1035) and a `Forwarder`: what a virtual network's gateway needs to answer its machines' lookups.

```vertex
import "net/dns"
```

## Types

- **`RecordType`** (enum), **`Rcode`** (enum)
- **`Question`** (struct), **`Record`** (struct): `Record.A(name, ip)`; a record's `Ipv4`.
- **`Message`** (struct): `Parse` (compressed names followed), `Encode` (names in full), `Query(id:name:kind:)`, `Reply(rcode:)`.
- **`Forwarder`** (class): `Answer(query)`: names in `Hosts` answered itself (a `host.vm.internal` for the host, say), the rest sent to the `Upstreams` in turn, SERVFAIL when none answers. Upstreams default to the host's own nameservers, so a VPN's or a captive network's resolver works for the guest as it does for the host.

## Functions

- `func HostNameservers() -> [netip.Ipv4]`: /etc/resolv.conf's nameservers, else 1.1.1.1 and 8.8.8.8.

Part of the [`net`](https://github.com/vertex-language/net) repository.

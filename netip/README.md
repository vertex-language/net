# net/netip

IP addresses and networks as values: no sockets, no lookups. What `net/wire`, `net/dhcp`, `net/dns` and `net/nat` speak in.

```vertex
import "net/netip"
```

## Types

- **`Ipv4`** (struct): An IPv4 address: `Ipv4(10, 0, 2, 15)`, `Parse("10.0.2.15")`, from four bytes; `Bytes`, `Value` (big-endian `uint32`), `IsLoopback`/`IsBroadcast`/`IsMulticast`/`IsUnspecified`, `Adding(n)`; `any`, `broadcast`, `loopback`.
- **`Prefix`** (struct): An IPv4 network: `Prefix(addr, bits: 24)`, `Parse("10.0.2.0/24")`; `Mask`, `Network`, `Broadcast`, `Contains`.

Part of the [`net`](https://github.com/vertex-language/net) repository.

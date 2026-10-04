# net/ether

The link layer a virtual machine's network card sits on: `Mac` addresses, Ethernet `Frame`s, and `Port`, what a card plugs into.

```vertex
import "net/ether"
```

## Types

- **`Mac`** (struct): A 48-bit MAC address; `Random()` is locally administered and unicast, `Parse("52:54:00:12:34:56")`.
- **`EtherType`** (enum): `ipv4`, `arp`, `ipv6`.
- **`Frame`** (struct): An Ethernet II frame (no preamble or FCS): `Parse`, `Encode`.
- **`Port`** (protocol): A network: `Send` gives it a frame from the card, `Receive` waits for the next frame for the card. `net/nat`'s `Gateway` is one.
- **`Queue`** (class): Frames waiting for a card: `Push` from any thread or task, `Pop` waits without polling (on a wake pipe, `os/sys.WakePipe`).
- **`PipeEnd`** (class): One end of a `Pipe()`.

## Functions

- `func Pipe() -> (PipeEnd, PipeEnd)`: Two ports back to back: what one is sent, the other receives. Two VMs on one wire, or a test standing in for a network.

Part of the [`net`](https://github.com/vertex-language/net) repository.

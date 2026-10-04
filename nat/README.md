# net/nat

A virtual machine's way to the internet without root, TUN/TAP or a bridge. A `Gateway` is the `ether.Port` the VM's network card plugs into, and plays the router of a small private network:

- ARP for its own addresses (never for one a guest is probing before taking it)
- DHCP from `net/dhcp`'s `Server`
- DNS from `net/dns`'s `Forwarder`, at whatever nameserver address the guest uses, forwarded to the host's own nameservers; `host.vm.internal` is the host
- ping, answered here (there are no unprivileged raw sockets to send it on)
- UDP, one host socket per flow, closed after two minutes idle
- TCP on host sockets: the guest's MSS and window respected, unacknowledged data retransmitted, the guest's data written to the host in order, half-closes passed on, random initial sequence numbers

Connections to the gateway's own address go to the host's 127.0.0.1, as with QEMU's slirp (`HostLoopback`).

```vertex
import "net/nat"

let card = virtio.Net(port: nat.Gateway(.default))   // 192.168.127.0/24
let android = nat.Gateway(.slirp)                     // 10.0.2.0/24: gateway .2, DNS .3, guest .15
```

## Types

- **`Config`** (struct): `Network`, `Gateway`, `Dns`, `Guest` (the first address DHCP gives), `Mac`, `Upstreams` (nil: the host's), `HostLoopback`, `HostName`; `default` and `slirp`.
- **`Gateway`** (class): The `ether.Port`; its `Dhcp` server and `Dns` forwarder are open for inspection or changes (more `Hosts`, say).

Not yet: IPv6, port forwarding from the host into the guest, real ICMP.

Part of the [`net`](https://github.com/vertex-language/net) repository.

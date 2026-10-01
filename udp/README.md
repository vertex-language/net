# net/udp

Asynchronous datagram communication and peer binding (`udp.Bind`, `udp.UdpSocket`).

```vertex
import "net/udp"
```

## Types

- **`SocketAddress`** (enum): SocketAddress is a host and a port.
- **`UdpError`** (enum): UdpError is every way an operation in this package fails.
- **`NetworkInterface`** (struct): NetworkInterface represents an active local network adapter and its IP address.
- **`SocketOptions`** (struct): Socket configuration options for binding.
- **`UdpSocket`** (struct): A UDP datagram socket for connectionless or connected packet communication.

## Functions

- `func Resolve(host: string, port: uint16) throws -> [SocketAddress]`: Resolves host to datagram addresses for port.
- `func GetNetworkInterfaces() throws -> [NetworkInterface]`: GetNetworkInterfaces enumerates all active network interfaces and IP addresses on this host.
- `func Bind(_ address: string, options: SocketOptions = .default) throws -> UdpSocket`: Binds a UDP socket on an address written as text: "127.0.0.1:8080", ":9000", or a port of 0 to request an ephemeral port from the kernel.
- `func Bind(host: string = "0.0.0.0", port: uint16, options: SocketOptions = .default) throws -> UdpSocket`: Binds a UDP socket on a specific host and port.
- `func Bind(address: SocketAddress, options: SocketOptions = .default) throws -> UdpSocket`: Binds a UDP socket on an already parsed address.
- `func SocketAddress.Host() -> string`: The host, without the port, as it was written.
- `func SocketAddress.Port() -> uint16`: The port, whichever family the address is.
- `func SocketAddress.ToString() -> string`: The address as written: "host:port", and "[host]:port" for IPv6.
- `func UdpSocket.ReceiveFrom( into buffer: inout [uint8]) async throws -> (int, SocketAddress)`: Receives a datagram into buffer. Returns the number of bytes read and the sender's remote address.
- `func UdpSocket.Receive(into buffer: inout [uint8]) async throws -> int`: Receives a datagram on a connected UDP socket.
- and 21 more

Part of the [`net`](https://github.com/vertex-language/net) repository.

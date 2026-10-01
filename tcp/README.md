# net/tcp

Asynchronous stream connections and listeners over platform POSIX sockets (`tcp.Listen`, `tcp.Connect`, `tcp.TcpStream`, `tcp.TcpListener`). A `TcpStream` is an `io.AsyncReader` and `io.AsyncWriter`, so `io.AsyncBufferedReader(stream).ReadLine()` and `io.Copy` take it.

```vertex
import "net/tcp"
```

## Types

- **`SocketAddress`** (enum): SocketAddress is a host and a port. The host is held as it was written.
- **`TcpError`** (enum): TcpError is every way an operation in this package fails.
- **`ListenerOptions`** (struct): How a listener's socket is set up, for the cases where the defaults are not what is wanted.
- **`TcpListener`** (struct): A socket accepting incoming connections. Binding is immediate, so `Listen` is an ordinary function. Waiting for a connection is not, so `Accept` is `async`.
- **`ShutdownMode`** (enum): Which half of a connection `Shutdown` closes.
- **`TcpStream`** (struct): A connected TCP socket: a reliable byte stream, readable and writable at the same time.

## Functions

- `func Resolve(host: string, port: uint16) throws -> [SocketAddress]`: Every address a host name resolves to, for this port, in the order the resolver gave them -- which is the order to try connecting in.
- `func Listen(_ address: string, options: ListenerOptions = .default) throws -> TcpListener`: Listens on an address written as text: "127.0.0.1:8080", ":8080" for every interface, "[::1]:9000", or a port of 0 to be given a free one.
- `func Listen(host: string = "0.0.0.0", port: uint16, options: ListenerOptions = .default) throws -> TcpListener`: Listens on a host and port.
- `func Listen(address: SocketAddress, options: ListenerOptions = .default) throws -> TcpListener`: Listens on an address that has already been parsed.
- `func Connect(_ address: string, timeoutMs: int32 = 5000) async throws -> TcpStream`: Connects to an address written as text: "example.com:80", "127.0.0.1:8080".
- `func Connect(host: string, port: uint16, timeoutMs: int32 = 5000) async throws -> TcpStream`: Connects to a host and port. The host may be a name, and resolving it stops the thread rather than the task; see `Resolve`.
- `func Connect(address: SocketAddress, timeoutMs: int32 = 5000) async throws -> TcpStream`: Connects to an address that has already been parsed or resolved.
- `func SocketAddress.Host() -> string`: The host, without the port, as it was written.
- `func SocketAddress.Port() -> uint16`: The port, whichever family the address is.
- `func SocketAddress.ToString() -> string`: The address as it is written: "host:port", and "[host]:port" for IPv6.
- and 19 more

Part of the [`net`](https://github.com/vertex-language/net) repository.

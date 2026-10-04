# net/unix

Stream sockets named by a path: for talking to another process on the same
machine (a daemon, a helper such as swtpm) without opening a TCP port that
any local user could reach. File permissions guard the socket.

The shape is `net/tcp`'s: every operation that can wait is `async`, and
waiting parks the task, not the thread.

```vertex
var s = try await unix.Connect("/tmp/app.sock")
defer { s.Close() }
try await s.Write(request)
try await s.ReadFull(into: &reply)

let l = try unix.Listen("/tmp/app.sock", removeStale: true)
var conn = try await l.Accept()
```

`UnixError` names what failed: `notFound` (no socket file), `connectionRefused`
(a file, nobody accepting), `pathTooLong` (over ~100 bytes), and the rest.
Windows 10 and later have AF_UNIX too (`afunix.h`).

Checks: `vsc run ./cmd/unix-loopback`.

// net/unix checked against itself over a real socket file: a server and a
// client as two tasks on one thread. The program exits with the number of
// checks that did not pass. Run it with
//
//     vsc run ./cmd/unix-loopback
package main

import (
    "net/unix"
)

var failures = 0

func check(_ ok: bool, _ what: string) {
    if ok {
        print("ok    \(what)")
    } else {
        print("FAIL  \(what)")
        failures += 1
    }
}

let path = "/tmp/vertex-unix-loopback.sock"

/// An echo round trip, a request larger than one read.
func roundTrip() async {
    do {
        let listener = try unix.Listen(path, removeStale: true)
        let server = Task { () async -> int in
            do {
                var conn = try await listener.Accept()
                var buf = [uint8](repeating: 0, count: 100_000)
                try await conn.ReadFull(into: &buf)
                try await conn.Write(buf)
                conn.Close()
                return buf.count
            } catch {
                return -1
            }
        }
        var client = try await unix.Connect(path)
        var out = [uint8](repeating: 0, count: 100_000)
        for i in 0..<out.count { out[i] = uint8(truncatingIfNeeded: i * 31) }
        try await client.Write(out)
        var back = [uint8](repeating: 0, count: out.count)
        try await client.ReadFull(into: &back)
        check(back == out, "100,000 bytes echo back unchanged")
        var more = [uint8](repeating: 0, count: 16)
        check(try await client.Read(into: &more) == 0, "a read after the server closed is the end (0)")
        client.Close()
        check(await server.value == 100_000, "the server read the whole request")
        listener.Close()
    } catch {
        check(false, "round trip threw \(error)")
    }
}

/// The errors a missing or refused socket gives.
func errors() async {
    do {
        _ = try await unix.Connect("/tmp/vertex-unix-no-such.sock")
        check(false, "connecting to a missing path fails")
    } catch let e as unix.UnixError {
        if case .notFound = e {
            check(true, "connecting to a missing path is notFound")
        } else {
            check(false, "connecting to a missing path: \(e.Message)")
        }
    } catch {
        check(false, "connecting to a missing path: \(error)")
    }
    let long = "/tmp/" + string(repeating: "x", count: 200)
    do {
        _ = try unix.Listen(long)
        check(false, "a 200-byte path is refused")
    } catch let e as unix.UnixError {
        if case .pathTooLong = e {
            check(true, "a 200-byte path is pathTooLong")
        } else {
            check(false, "a 200-byte path: \(e.Message)")
        }
    } catch {
        check(false, "a 200-byte path: \(error)")
    }
}

func main() async -> int32 {
    await roundTrip()
    await errors()
    print(failures == 0 ? "ALL UNIX CHECKS PASSED" : "\(failures) FAILED")
    return int32(failures)
}

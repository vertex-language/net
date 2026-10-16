// hcurl: a download through net/http, timed, to hold beside curl. It
// streams a body the way remote/hub does -- net/http's ResponseStream,
// redirects followed, a buffer read at a time -- and says how fast each
// part went, so the network stack is measured on its own.
//
//     hcurl https://huggingface.co/unsloth/Qwen3-0.6B-GGUF/resolve/main/Qwen3-0.6B-Q4_K_M.gguf
//     hcurl http://127.0.0.1:8000/big.bin               plain TCP: no TLS
//     hcurl --sha256 -o out.bin https://...             what hub adds: a hash, a file
//
// Beside it, with the same URL:
//
//     curl -sL -o /dev/null -w '%{speed_download}\n' https://...
package main

import (
    "crypto/sha256"
    "fs"
    "net/http"
    "net/url"
    "time"
)

func usage() -> int32 {
    print("usage: hcurl [-o FILE] [--sha256] [--buf BYTES] [--max BYTES] [-H 'Name: value']... URL")
    print("")
    print("  -o FILE      write the body to FILE (default: read and discard it)")
    print("  --sha256     hash the body as it arrives, as remote/hub checks a download")
    print("  --buf BYTES  read the body this much at a time (default 262144, hub's)")
    print("  --max BYTES  stop after this much of the body")
    print("  -H HEADER    send a header")
    return 2
}

func since(_ a: time.Instant) -> float64 {
    return (time.Instant.Now() - a).AsSeconds()
}

func size(_ n: int64) -> string {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var v = float64(n)
    var u = 0
    while v >= 1000 && u < units.count - 1 {
        v /= 1000
        u += 1
    }
    if u == 0 {
        return "\(n) B"
    }
    let tenths = int64(v * 10 + 0.5)
    return "\(tenths / 10).\(tenths % 10) \(units[u])"
}

func rate(_ bytes: int64, _ seconds: float64) -> string {
    if seconds <= 0 {
        return "-"
    }
    return size(int64(float64(bytes) / seconds)) + "/s"
}

func ms(_ seconds: float64) -> string {
    return "\(int64(seconds * 1000)) ms"
}

func main() async -> int32 {
    var address = ""
    var outPath = ""
    var hash = false
    var bufSize = 1 << 18
    var max: int64 = -1
    var headers: [(string, string)] = []
    let args = CommandLine.arguments
    var i = 1
    while i < args.count {
        let a = args[i]
        if a == "-o" && i + 1 < args.count {
            outPath = args[i + 1]
            i += 1
        } else if a == "--sha256" {
            hash = true
        } else if a == "--buf" && i + 1 < args.count {
            bufSize = int(args[i + 1]) ?? bufSize
            i += 1
        } else if a == "--max" && i + 1 < args.count {
            max = int64(args[i + 1]) ?? max
            i += 1
        } else if a == "-H" && i + 1 < args.count {
            let h = args[i + 1]
            if let colon = h.firstIndex(of: ":") {
                let name = String(h[h.startIndex..<colon])
                var value = String(h[h.index(after: colon)...])
                while value.hasPrefix(" ") {
                    value = String(value.dropFirst())
                }
                headers.append((name, value))
            }
            i += 1
        } else if a.hasPrefix("-") || !address.isEmpty {
            return usage()
        } else {
            address = a
        }
        i += 1
    }
    if address.isEmpty {
        return usage()
    }

    do {
        let start = time.Instant.Now()
        let client = http.Client(timeoutMs: 30000)
        var u = try url.Parse(address)
        var hops: [string] = []
        var stream: http.ResponseStream? = nil
        // Redirects followed by hand, as remote/hub follows them.
        while stream == nil {
            var req = http.Request(method: "GET", url: u.RequestURI)
            req.Headers.Set("User-Agent", "hcurl/0.1")
            for (k, v) in headers {
                req.Headers.Set(k, v)
            }
            let hopStart = time.Instant.Now()
            var s = try await client.Open(req, url: u)
            let code = int(s.Response.StatusCode)
            hops.append("\(code) \(u.Scheme)://\(u.Host)  \(ms(since(hopStart)))")
            if code == 301 || code == 302 || code == 303 || code == 307 || code == 308 {
                let loc = s.Response.Headers.Get("Location")
                s.Close()
                guard let l = loc, hops.count <= 10 else {
                    print("hcurl: \(code) with no Location, or too many redirects")
                    return 1
                }
                u = try u.Resolve(l)
                continue
            }
            stream = s
        }
        var s = stream!
        defer { s.Close() }
        let headed = since(start)
        let code = int(s.Response.StatusCode)

        var out: fs.File? = nil
        if !outPath.isEmpty {
            out = try fs.Open(fs.Path(outPath), fs.OpenOptions.write)
        }
        var digest = sha256.Digest()
        var buf = [uint8](repeating: 0, count: bufSize)
        var got: int64 = 0
        var reads = 0
        // Time in each part of the loop, so a slow one shows itself.
        var readTime = 0.0
        var hashTime = 0.0
        var writeTime = 0.0
        let bodyStart = time.Instant.Now()
        while max < 0 || got < max {
            var t = time.Instant.Now()
            let n = try await s.Read(into: &buf)
            readTime += since(t)
            if n == 0 {
                break
            }
            reads += 1
            got += int64(n)
            if hash || out != nil {
                let chunk = Array(buf[0..<n])
                if hash {
                    t = time.Instant.Now()
                    digest.Write(chunk)
                    hashTime += since(t)
                }
                if let f = out {
                    t = time.Instant.Now()
                    try f.Write(chunk)
                    writeTime += since(t)
                }
            }
        }
        let body = since(bodyStart)
        if let f = out {
            try f.Close()
        }

        for h in hops {
            print("hop      \(h)")
        }
        print("status   \(code), Content-Length \(s.ContentLength.map { size($0) } ?? "none")")
        print("headers  \(ms(headed)) (connect, TLS, request, every hop)")
        print("body     \(size(got)) in \(ms(body)) = \(rate(got, body)), \(reads) reads of up to \(size(int64(bufSize)))")
        print("  read   \(ms(readTime)) = \(rate(got, readTime)) (the network stack: TCP, TLS, HTTP framing)")
        if hash {
            print("  sha256 \(ms(hashTime)) = \(rate(got, hashTime))  \(sha256.ToHex(digest.Checksum()))")
        }
        if out != nil {
            print("  write  \(ms(writeTime)) = \(rate(got, writeTime))  \(outPath)")
        }
        print("total    \(ms(since(start))) = \(rate(got, since(start)))")
    } catch {
        print("hcurl: \(error)")
        return 1
    }
    return 0
}

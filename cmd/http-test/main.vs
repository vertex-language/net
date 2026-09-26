package main

import (
    "net/http"
    "net/quic"
    "net/tcp"
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

func stringContains(_ s: string, _ sub: string) -> bool {
    var sBytes: [uint8] = []
    for b in s.utf8 { sBytes.append(b) }
    var subBytes: [uint8] = []
    for b in sub.utf8 { subBytes.append(b) }
    if subBytes.isEmpty { return true }
    if sBytes.count < subBytes.count { return false }
    var i = 0
    while i <= sBytes.count - subBytes.count {
        var match = true
        var j = 0
        while j < subBytes.count {
            if sBytes[i + j] != subBytes[j] {
                match = false
                break
            }
            j += 1
        }
        if match { return true }
        i += 1
    }
    return false
}

func testURL() {
    do {
        let u1 = try http.URL.Parse("http://127.0.0.1:8080/api/v1/users")
        check(u1.Scheme == "http" && u1.Host == "127.0.0.1" && u1.Port == 8080 && u1.Path == "/api/v1/users", "URL.Parse with port and path")

        let u2 = try http.URL.Parse("http://example.com")
        check(u2.Scheme == "http" && u2.Host == "example.com" && u2.Port == 80 && u2.Path == "/", "URL.Parse default port 80 and slash")

        let u3 = try http.URL.Parse("http://localhost:3000/")
        check(u3.Scheme == "http" && u3.Host == "localhost" && u3.Port == 3000 && u3.Path == "/", "URL.Parse localhost:3000/")

        let u4 = try http.URL.Parse("https://cloudflare.com/cdn-cgi/trace")
        check(u4.Scheme == "https" && u4.Host == "cloudflare.com" && u4.Port == 443 && u4.Path == "/cdn-cgi/trace", "URL.Parse https scheme and default port 443")

        let u5 = try http.URL.Parse("https://127.0.0.1:8443/status")
        check(u5.Scheme == "https" && u5.Host == "127.0.0.1" && u5.Port == 8443 && u5.Path == "/status", "URL.Parse https with custom port 8443")
    } catch {
        check(false, "URL.Parse threw error")
    }
}

func testHeaders() {
    var h = http.Header()
    h.Set("Content-Type", "text/plain")
    check(h.Get("content-type") == "text/plain", "Header case-insensitive get")
    check(h.Get("CONTENT-TYPE") == "text/plain", "Header case-insensitive get upper")

    h.Set("x-custom", "abc")
    check(h.Get("X-Custom") == "abc", "Header set overwrite")

    h.Del("content-type")
    check(h.Get("Content-Type") == nil, "Header del")
}

func testRoundTrip() async {
    do {
        let listener = try tcp.Listen("127.0.0.1:0")
        let port = listener.LocalAddress.Port()

        // Spawn server task handling 3 consecutive connections
        let serverTask = Task { () async -> int in
            var served = 0
            while served < 3 {
                do {
                    let client = try await listener.Accept()
                    await http.ServeConn(stream: client) { req in
                        var w = http.ResponseWriter()
                        if req.Method == "GET" && req.URL == "/hello" {
                            w.SetStatus(http.Status.OK)
                            w.SetHeader("Content-Type", "text/plain")
                            w.WriteText("Hello Vertex HTTP!")
                        } else if req.Method == "POST" && req.URL == "/echo" {
                            w.SetStatus(http.Status.OK)
                            w.SetHeader("X-Echo", "true")
                            w.Write(req.Body)
                        } else {
                            w.SetStatus(http.Status.NotFound)
                            w.WriteText("Not Found")
                        }
                        return w
                    }
                    served += 1
                } catch {
                    break
                }
            }
            return served
        }

        // Client 1: GET /hello
        let res1 = try await http.Get("http://127.0.0.1:\(port)/hello")
        check(res1.StatusCode == 200, "GET /hello status 200")
        check(res1.Headers.Get("Content-Type") == "text/plain", "GET /hello header Content-Type")
        check(res1.BodyText() == "Hello Vertex HTTP!", "GET /hello body text")

        // Client 2: POST /echo
        var echoBody: [uint8] = [112, 105, 110, 103] // "ping"
        let res2 = try await http.Post("http://127.0.0.1:\(port)/echo", contentType: "text/plain", body: echoBody)
        check(res2.StatusCode == 200, "POST /echo status 200")
        check(res2.Headers.Get("X-Echo") == "true", "POST /echo header X-Echo")
        check(res2.BodyText() == "ping", "POST /echo body echo")

        // Client 3: GET /missing
        let res3 = try await http.Get("http://127.0.0.1:\(port)/missing")
        check(res3.StatusCode == 404, "GET /missing status 404")
        check(res3.BodyText() == "Not Found", "GET /missing body text")

        let count = await serverTask.value
        check(count == 3, "server handled 3 requests")
        listener.Close()
    } catch {
        check(false, "roundTrip caught unexpected exception")
    }
}

func testSerialization() {
    var req = http.Request(method: "POST", url: "/submit")
    req.Headers.Set("Content-Type", "application/json")
    let payload = [uint8](repeating: 65, count: 4) // "AAAA"
    req.Body = payload
    let rawReq = req.Bytes()
    check(rawReq.count > 0, "Request.Bytes non-empty")
    let endIdx = http.Request.FindHeaderEnd(rawReq)
    check(endIdx > 0, "Request.FindHeaderEnd found CRLF CRLF")

    do {
        let parsed = try http.Request.ParseHeaders(rawReq, headerEnd: endIdx)
        check(parsed.Method == "POST", "parsed method is POST")
        check(parsed.URL == "/submit", "parsed URL is /submit")
        check(parsed.Headers.Get("content-type") == "application/json", "parsed header matches")
        check(parsed.Body.count == 4 && parsed.Body[0] == 65, "parsed initial body matches")
    } catch {
        check(false, "Request.ParseHeaders threw error")
    }

    var res = http.Response(statusCode: 200)
    res.Headers.Set("Server", "Vertex")
    res.Body = payload
    let rawRes = res.Bytes()
    let resEndIdx = http.Response.FindHeaderEnd(rawRes)
    check(resEndIdx > 0, "Response.FindHeaderEnd found CRLF CRLF")

    do {
        let parsedRes = try http.Response.ParseHeaders(rawRes, headerEnd: resEndIdx)
        check(parsedRes.StatusCode == 200, "parsed response status 200")
        check(parsedRes.Headers.Get("server") == "Vertex", "parsed response header matches")
        check(parsedRes.Body.count == 4, "parsed response body matches")
    } catch {
        check(false, "Response.ParseHeaders threw error")
    }
}

func testHttpTypes() {
    let v1 = http.HttpVersion.http1_1
    let v2 = http.HttpVersion.http2
    let v3 = http.HttpVersion.http3
    check(v1 != v2 && v2 != v3, "HttpVersion enum distinct")

    var req = http.Request(method: "GET", url: "/status", version: http.HttpVersion.http2)
    check(req.Version == http.HttpVersion.http2, "Request version is HTTP/2")

    var res = http.Response(statusCode: 200, version: http.HttpVersion.http3)
    res.SetBodyText("Pure Vertex HTTP/3")
    check(res.Version == http.HttpVersion.http3, "Response version is HTTP/3")
    check(res.Text == "Pure Vertex HTTP/3", "Response Text property matches")

    var rw = http.ResponseWriter()
    rw.SetStatus(201)
    rw.SetHeader("X-Vertex", "MultiProtocol")
    rw.WriteText("Created")
    check(rw.StatusCode == 201, "ResponseWriter status code")
    check(rw.Headers.Get("x-vertex") == "MultiProtocol", "ResponseWriter headers")
    check(rw.Body.count == 7, "ResponseWriter body count")
}

func testAltSvc() {
    let headerVal = "h3=\":443\"; ma=2592000, h3-29=\":443\"; ma=86400"
    let services = http.ParseAltSvcHeader(headerVal, defaultHost: "example.com")
    check(services.count == 2, "ParseAltSvcHeader found 2 services")
    if services.count >= 2 {
        check(services[0].Protocol == "h3" && services[0].Port == 443 && services[0].MaxAgeSeconds == 2592000, "AltSvc service 0 parsed")
        check(services[1].Protocol == "h3-29" && services[1].Port == 443 && services[1].MaxAgeSeconds == 86400, "AltSvc service 1 parsed")
    }

    var cache = http.AltSvcCache()
    var entry = http.AltSvcService(proto: "h3", host: "example.com", port: 443, maxAgeSeconds: 86400)
    cache.Set(origin: "example.com:443", service: entry)

    if let cached = cache.Get(origin: "example.com:443", protocolName: "h3") {
        check(cached.Port == 443 && cached.Protocol == "h3", "AltSvcCache hit")
    } else {
        check(false, "AltSvcCache miss")
    }

    check(cache.Get(origin: "other.com:443", protocolName: "h3") == nil, "AltSvcCache negative lookup")
    cache.Clear()
    check(cache.Get(origin: "example.com:443", protocolName: "h3") == nil, "AltSvcCache cleared")
}

func testHpack() {
    var enc = http.HpackEncoder()
    var dec = http.HpackDecoder()

    var headers: [http.HeaderEntry] = [
        http.HeaderEntry(key: ":method", value: "GET"),
        http.HeaderEntry(key: ":path", value: "/index.html"),
        http.HeaderEntry(key: ":scheme", value: "https"),
        http.HeaderEntry(key: ":authority", value: "vertex.lang"),
        http.HeaderEntry(key: "x-custom", value: "pure-vertex")
    ]

    let encoded = enc.EncodeHeaders(headers)
    check(!encoded.isEmpty, "HPACK encoded non-empty")

    do {
        let decoded = try dec.DecodeHeaders(data: encoded)
        check(decoded.count == 5, "HPACK decoded 5 headers")

        var methodFound = false
        var pathFound = false
        var customFound = false
        var i = 0
        while i < decoded.count {
            if decoded[i].Key == ":method" && decoded[i].Value == "GET" { methodFound = true }
            if decoded[i].Key == ":path" && decoded[i].Value == "/index.html" { pathFound = true }
            if decoded[i].Key == "x-custom" && decoded[i].Value == "pure-vertex" { customFound = true }
            i += 1
        }
        check(methodFound, "HPACK decoded :method")
        check(pathFound, "HPACK decoded :path")
        check(customFound, "HPACK decoded custom header")
    } catch {
        check(false, "HPACK DecodeHeaders threw error")
    }
}

func testH2Framing() {
    let settings = [
        http.H2Setting(identifier: http.H2SettingId.MaxConcurrentStreams, value: 100),
        http.H2Setting(identifier: http.H2SettingId.InitialWindowSize, value: 65535)
    ]
    let settingsFrame = http.BuildH2SettingsFrame(settings: settings, ack: false)
    check(settingsFrame.count == 21, "H2 SETTINGS frame length matches (9-byte header + 12-byte payload)")

    do {
        let header = try http.ParseH2FrameHeader(data: settingsFrame, offset: 0)
        check(header.Length == 12, "H2 parsed header length")
        check(header.Type == http.H2FrameType.Settings, "H2 parsed header type")
        check(header.Flags == 0, "H2 parsed header flags")
        check(header.StreamId == 0, "H2 parsed header stream ID")
    } catch {
        check(false, "ParseH2FrameHeader threw error")
    }

    let pingData: [uint8] = [1, 2, 3, 4, 5, 6, 7, 8]
    let pingFrame = http.BuildH2Ping(opaqueData: pingData, ack: false)
    check(pingFrame.count == 17, "H2 PING frame length is 17")

    let wuFrame = http.BuildH2WindowUpdate(streamId: 0, increment: 1048576)
    check(wuFrame.count == 13, "H2 WINDOW_UPDATE frame length is 13")

    let rstFrame = http.BuildH2RstStream(streamId: 1, errorCode: 8)
    check(rstFrame.count == 13, "H2 RST_STREAM frame length is 13")

    var session = http.H2ClientSession()
    let handshake = session.StartHandshake()
    check(handshake.count >= 24, "H2ClientSession StartHandshake includes preface and settings")

    var req = http.Request(method: "GET", url: "/test")
    req.Headers.Set("user-agent", "vertex-test")
    let reqFrames = session.CreateRequestFrames(req: req, scheme: "https", authority: "localhost")
    check(!reqFrames.isEmpty, "H2ClientSession CreateRequestFrames non-empty")
}

func testQpackAndH3Framing() {
    var qenc = http.QpackEncoder()
    var qdec = http.QpackDecoder()

    var headers: [http.HeaderEntry] = [
        http.HeaderEntry(key: ":method", value: "GET"),
        http.HeaderEntry(key: ":path", value: "/h3"),
        http.HeaderEntry(key: ":scheme", value: "https"),
        http.HeaderEntry(key: "user-agent", value: "vertex-h3")
    ]
    let encFieldSec = qenc.EncodeHeaders(headers)
    check(!encFieldSec.isEmpty, "QPACK EncodeHeaders non-empty")

    do {
        let decHeaders = try qdec.DecodeHeaders(data: encFieldSec)
        check(decHeaders.count == 4, "QPACK decoded 4 headers")

        var foundMethod = false
        var foundPath = false
        var foundUa = false
        var i = 0
        while i < decHeaders.count {
            if decHeaders[i].Key == ":method" && decHeaders[i].Value == "GET" { foundMethod = true }
            if decHeaders[i].Key == ":path" && decHeaders[i].Value == "/h3" { foundPath = true }
            if decHeaders[i].Key == "user-agent" && decHeaders[i].Value == "vertex-h3" { foundUa = true }
            i += 1
        }
        check(foundMethod, "QPACK decoded :method")
        check(foundPath, "QPACK decoded :path")
        check(foundUa, "QPACK decoded user-agent")
    } catch {
        check(false, "QPACK DecodeHeaders threw error")
    }

    do {
        let v1 = quic.EncodeVarint(25)
        check(v1.count == 1 && v1[0] == 25, "H3 Varint 1-byte encode")
        let dec1 = try quic.DecodeVarint(v1, offset: 0)
        check(dec1.Value == 25 && dec1.BytesRead == 1, "H3 Varint 1-byte decode")

        let v2 = quic.EncodeVarint(15213)
        check(v2.count == 2, "H3 Varint 2-byte encode")
        let dec2 = try quic.DecodeVarint(v2, offset: 0)
        check(dec2.Value == 15213 && dec2.BytesRead == 2, "H3 Varint 2-byte decode")
    } catch {
        check(false, "quic.DecodeVarint threw error")
    }

    let dataPayload: [uint8] = [72, 69, 76, 76, 79]
    let h3FrameBytes = http.BuildH3Frame(type: http.H3FrameType.Data, payload: dataPayload)
    check(!h3FrameBytes.isEmpty, "H3 BuildH3Frame non-empty")

    do {
        let parsedFrame = try http.ParseH3Frame(data: h3FrameBytes, offset: 0)
        check(parsedFrame.BytesRead == h3FrameBytes.count, "H3 ParseH3Frame consumed all bytes")
        check(parsedFrame.Type == http.H3FrameType.Data, "H3 ParseH3Frame type is DATA")
        check(parsedFrame.Payload.count == 5, "H3 ParseH3Frame payload length is 5")
    } catch {
        check(false, "ParseH3Frame threw error")
    }
}

// Reads a whole ResponseStream body, or nil if it throws.
func readAll(_ s: inout http.ResponseStream) async -> string? {
    var out: [uint8] = []
    var buf = [uint8](repeating: 0, count: 7) // small, to split chunks
    do {
        while true {
            let n = try await s.Read(into: &buf)
            if n == 0 { break }
            out.append(contentsOf: buf[0..<n])
        }
    } catch {
        return nil
    }
    return String(decoding: out, as: UTF8.self)
}

// A server that answers each connection with the next canned response,
// written in pieces, and closes it.
func testStream() async {
    let answers = [
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nHello\r\nB\r\n, streamed!\r\n0\r\nX-Trailer: t\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nexactly 11!ignored after",
        "HTTP/1.1 200 OK\r\n\r\nuntil the close",
        "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n",
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 20\r\n\r\ncut short",
        "HTTP/1.1 302 Found\r\nLocation: https://cdn.example/x\r\nContent-Length: 3\r\n\r\nabc",
    ]
    do {
        let listener = try tcp.Listen("127.0.0.1:0")
        let port = listener.LocalAddress.Port()
        let serverTask = Task { () async -> int in
            var served = 0
            for a in answers {
                do {
                    let conn = try await listener.Accept()
                    var req = [uint8](repeating: 0, count: 4096)
                    _ = try await conn.Read(into: &req)
                    let bytes = [uint8](a.utf8)
                    var at = 0
                    while at < bytes.count {
                        let end = at + 9 < bytes.count ? at + 9 : bytes.count
                        try await conn.Write(Array(bytes[at..<end]))
                        at = end
                    }
                    conn.Close()
                    served += 1
                } catch {
                    break
                }
            }
            return served
        }
        let c = http.Client()
        let u = try http.URL.Parse("http://127.0.0.1:\(port)/x")

        var s = try await c.Open(http.Request(method: "GET", url: "/x"), url: u)
        check(s.Response.StatusCode == 200 && s.ContentLength == nil, "stream: chunked head")
        check(await readAll(&s) == "Hello, streamed!", "stream: chunked body, extensions and trailers dropped")
        s.Close()

        s = try await c.Open(http.Request(method: "GET", url: "/x"), url: u)
        check(s.ContentLength == 11, "stream: Content-Length")
        check(await readAll(&s) == "exactly 11!", "stream: sized body stops at its length")
        s.Close()

        s = try await c.Open(http.Request(method: "GET", url: "/x"), url: u)
        check(await readAll(&s) == "until the close", "stream: body read to the close")
        s.Close()

        s = try await c.Open(http.Request(method: "HEAD", url: "/x"), url: u)
        check(s.ContentLength == nil && await readAll(&s) == "", "stream: HEAD has no body")
        s.Close()

        s = try await c.Open(http.Request(method: "GET", url: "/x"), url: u)
        check(s.Response.StatusCode == 206 && await readAll(&s) == nil, "stream: a body cut short throws")
        s.Close()

        s = try await c.Open(http.Request(method: "GET", url: "/x"), url: u)
        check(s.Response.StatusCode == 302 && s.Response.Headers.Get("Location") == "https://cdn.example/x", "stream: a redirect is returned, not followed")
        s.Close()

        check(await serverTask.value == answers.count, "stream: server answered each")
        listener.Close()
    } catch {
        check(false, "stream: \(error)")
    }
}

func main() async -> int32 {
    print("=== net/http Test Suite ===")
    testURL()
    testHeaders()
    testSerialization()
    testHttpTypes()
    testAltSvc()
    testHpack()
    testH2Framing()
    testQpackAndH3Framing()
    await testRoundTrip()
    await testStream()
    print(failures == 0 ? "All net/http tests passed!" : "\(failures) tests failed.")
    return int32(failures)
}

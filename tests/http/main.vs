package main

import "net/tcp"
import "net/http"

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

func main() async -> int32 {
    print("=== net/http Test Suite ===")
    testURL()
    testHeaders()
    testSerialization()
    await testRoundTrip()
    print(failures == 0 ? "All net/http tests passed!" : "\(failures) tests failed.")
    return int32(failures)
}

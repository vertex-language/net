package main

import tcp
import http

var failures = 0

func check(_ ok: bool, _ what: string) {
    if ok {
        print("ok    \(what)")
    } else {
        print("FAIL  \(what)")
        failures += 1
    }
}

func testURL() {
    do {
        let u1 = try http.URL.Parse("http://127.0.0.1:8080/api/v1/users")
        check(u1.Host == "127.0.0.1" && u1.Port == 8080 && u1.Path == "/api/v1/users", "URL.Parse with port and path")

        let u2 = try http.URL.Parse("http://example.com")
        check(u2.Host == "example.com" && u2.Port == 80 && u2.Path == "/", "URL.Parse default port 80 and slash")

        let u3 = try http.URL.Parse("http://localhost:3000/")
        check(u3.Host == "localhost" && u3.Port == 3000 && u3.Path == "/", "URL.Parse localhost:3000/")
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

func main() async -> int32 {
    print("=== net/http Test Suite ===")
    testURL()
    testHeaders()
    await testRoundTrip()
    print(failures == 0 ? "All net/http tests passed!" : "\(failures) tests failed.")
    return int32(failures)
}

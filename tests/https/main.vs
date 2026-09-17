package main

import "net/http"
import "net/https"
import "crypto/tls"

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

func testClientConfig() {
    var cfg = tls.Config(serverName: "custom.host", insecureSkipVerify: true)
    var client = https.Client(tlsConfig: cfg, timeoutMs: 3000)
    check(client.TLSConfig.ServerName == "custom.host", "Client TLSConfig ServerName preserved")
    check(client.TimeoutMs == 3000, "Client TimeoutMs preserved")
}

func testLiveHttpsGet() async {
    print("Testing live HTTPS GET cloudflare.com/cdn-cgi/trace...")
    do {
        let res = try await https.Get("https://cloudflare.com/cdn-cgi/trace")
        check(res.StatusCode == 200, "HTTPS GET status 200")
        let body = res.BodyText()
        check(!body.isEmpty, "HTTPS response body not empty")
        check(stringContains(body, "visit_scheme=https"), "Response contains visit_scheme=https")
        check(stringContains(body, "tls=TLSv1.3"), "Response negotiated TLSv1.3")
    } catch {
        check(false, "HTTPS GET threw unexpected error")
    }
}

func testCustomClientGet() async {
    print("Testing custom client HTTPS GET...")
    do {
        var client = https.Client()
        let res = try await client.Get("https://cloudflare.com/cdn-cgi/trace")
        check(res.StatusCode == 200, "Custom client HTTPS GET status 200")
        let body = res.BodyText()
        check(stringContains(body, "fl="), "Response contains fl= trace field")
    } catch {
        check(false, "Custom client HTTPS GET threw unexpected error")
    }
}

func main() async -> int32 {
    print("=== net/https Test Suite ===")
    testClientConfig()
    await testLiveHttpsGet()
    await testCustomClientGet()
    print(failures == 0 ? "All net/https tests passed!" : "\(failures) tests failed.")
    return int32(failures)
}

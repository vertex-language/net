package main

import (
    "net/stun"
    "net/udp"
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

func testHeaderAndFraming() {
    print("=== stun: header and framing ===")
    let tid: [uint8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    var msg = stun.Message(type: stun.MessageType.BindingRequest, transactionId: tid)
    msg.AddAttribute(stun.MakeSoftware("Vertex-STUN-Unit"))
    msg.AddFingerprint()

    let raw = msg.Encode()
    check(raw.count >= stun.Header.Size + 8, "encoded size exceeds header + fingerprint")
    check(raw[0] == 0x00 && raw[1] == 0x01, "header type is 0x0001 (BindingRequest)")
    check(raw[4] == 0x21 && raw[5] == 0x12 && raw[6] == 0xA4 && raw[7] == 0x42, "magic cookie is 0x2112A442")

    // Validate fingerprint on encoded buffer
    check(stun.Message.ValidateFingerprint(raw), "raw buffer fingerprint validation passed")

    do {
        let decoded = try stun.Message.Decode(raw)
        check(decoded.Type == stun.MessageType.BindingRequest, "decoded type matches")
        check(decoded.TransactionId.count == 12 && decoded.TransactionId[0] == 1, "decoded transaction ID matches")
        if let swAttr = decoded.GetAttribute(stun.AttributeType.Software) {
            check(stun.ParseSoftware(swAttr) == "Vertex-STUN-Unit", "decoded software attribute matches")
        } else {
            check(false, "software attribute not found")
        }
    } catch {
        check(false, "decode threw unexpected error")
    }
}

func testXorMapping() {
    print("=== stun: XOR address mapping ===")
    let tid: [uint8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C]
    let addr = udp.SocketAddress.v4(ip: "192.0.2.1", port: 54321)

    let attr = stun.MakeXorMappedAddress(address: addr, transactionId: tid)
    check(attr.Type == stun.AttributeType.XorMappedAddress, "attribute type is XOR-MAPPED-ADDRESS")
    check(attr.Value.count == 8, "IPv4 XOR-MAPPED-ADDRESS value length is 8")

    // 54321 = 0xD431 ^ 0x2112 = 0xF523
    let expPort = 54321 ^ 0x2112
    let actualPort = (int(attr.Value[2]) << 8) | int(attr.Value[3])
    check(actualPort == expPort, "X-Port masked correctly")

    do {
        let decodedAddr = try stun.ParseXorMappedAddress(attr, transactionId: tid)
        check(decodedAddr.Host() == "192.0.2.1", "decoded IPv4 host matches original")
        check(decodedAddr.Port() == 54321, "decoded IPv4 port matches original")
    } catch {
        check(false, "ParseXorMappedAddress threw error")
    }
}

func testLoopbackServer() async {
    print("=== stun: local loopback roundtrip ===")
    do {
        let serverSocket = try udp.Bind("127.0.0.1:0")
        let serverPort = serverSocket.LocalAddress.Port()

        // Server task: replies to 1 STUN request
        let serverTask = Task { () async -> bool in
            var buf = [uint8](repeating: 0, count: 1024)
            do {
                let (n, clientAddr) = try await serverSocket.ReceiveFrom(into: &buf)
                var rawReq: [uint8] = []
                var i = 0
                while i < n { rawReq.append(buf[i]); i += 1 }

                if let respBytes = stun.HandleBindingRequest(rawReq, sender: clientAddr) {
                    _ = try await serverSocket.SendTo(respBytes, to: clientAddr)
                    return true
                }
            } catch {
                return false
            }
            return false
        }

        // Client queries local STUN server
        let client = stun.Client(timeoutMs: 2000)
        let reflexAddr = try await client.Query(server: "127.0.0.1:\(serverPort)")
        check(reflexAddr.Host() == "127.0.0.1", "reflexive host matches loopback")
        check(reflexAddr.Port() > 0, "reflexive port is valid ephemeral port")

        let handled = await serverTask.value
        check(handled, "server handled request successfully")
        serverSocket.Close()
    } catch {
        check(false, "loopback STUN test threw unexpected error")
    }
}

func testLiveDiscovery() async {
    print("=== stun: live public discovery (stun.cloudflare.com) ===")
    do {
        let reflexAddr = try await stun.Discover(server: "stun.cloudflare.com:3478", timeoutMs: 3000)
        print("Discovered Public Reflexive Address: \(reflexAddr.ToString())")
        check(!reflexAddr.Host().isEmpty, "live discovery returned non-empty host")
        check(reflexAddr.Port() > 0, "live discovery returned valid port")
    } catch {
        // Network might be offline or blocking UDP 3478; print warning rather than failing hard
        print("Note: live STUN query to cloudflare timed out or offline")
    }
}

func main() async -> int32 {
    print("=== net/stun Test Suite ===")
    testHeaderAndFraming()
    testXorMapping()
    await testLoopbackServer()
    await testLiveDiscovery()

    if failures == 0 {
        print("All net/stun tests passed!")
        return 0
    } else {
        print("\(failures) tests failed.")
        return int32(failures)
    }
}

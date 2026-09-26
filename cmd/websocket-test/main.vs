package main

import (
    "net/http"
    "net/tcp"
    "net/websocket"
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

func testAcceptKeyDerivation() {
    // RFC 6455 Section 1.3 official test vector:
    // Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
    // Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
    let clientKey = "dGhlIHNhbXBsZSBub25jZQ=="
    let acceptKey = websocket.ComputeAcceptKey(clientKey)
    check(acceptKey == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "RFC 6455 §1.3 Sec-WebSocket-Accept test vector")
}

func testBase64() {
    let raw: [uint8] = [72, 101, 108, 108, 111] // "Hello"
    let enc = websocket.Base64Encode(raw)
    check(enc == "SGVsbG8=", "Base64Encode 'Hello' -> 'SGVsbG8='")

    do {
        let dec = try websocket.Base64Decode(enc)
        check(dec.count == 5 && dec[0] == 72 && dec[4] == 111, "Base64Decode roundtrip matches")
    } catch {
        check(false, "Base64Decode threw error")
    }
}

func testFrameSerialization() {
    // 1. Unmasked short Text frame
    let textPayload: [uint8] = [72, 105] // "Hi"
    let unmaskedBytes = websocket.BuildFrame(
        fin: true,
        opcode: websocket.Opcode.Text,
        masked: false,
        payload: textPayload
    )
    check(unmaskedBytes.count == 4, "Unmasked frame length is 4 bytes (2-byte header + 2-byte payload)")

    do {
        let parsed = try websocket.ParseFrame(data: unmaskedBytes, offset: 0)
        check(parsed.BytesRead == 4, "ParseFrame consumed 4 bytes")
        check(parsed.Frame.Fin == true, "Parsed frame FIN is true")
        check(parsed.Frame.Opcode == websocket.Opcode.Text, "Parsed frame Opcode is Text")
        check(parsed.Frame.Masked == false, "Parsed frame Masked is false")
        check(parsed.Frame.Payload.count == 2 && parsed.Frame.Payload[0] == 72, "Parsed payload matches")
    } catch {
        check(false, "ParseFrame unmasked threw error")
    }

    // 2. Masked Text frame with explicit 4-byte key
    let maskKey: [uint8] = [0x37, 0xfa, 0x21, 0x3d]
    let maskedBytes = websocket.BuildFrame(
        fin: true,
        opcode: websocket.Opcode.Text,
        masked: true,
        maskingKey: maskKey,
        payload: textPayload
    )
    check(maskedBytes.count == 8, "Masked frame length is 8 bytes (2-byte header + 4-byte key + 2-byte payload)")

    do {
        let parsedM = try websocket.ParseFrame(data: maskedBytes, offset: 0)
        check(parsedM.BytesRead == 8, "Parsed masked frame consumed 8 bytes")
        check(parsedM.Frame.Masked == true, "Parsed frame Masked is true")
        check(parsedM.Frame.Payload.count == 2 && parsedM.Frame.Payload[0] == 72 && parsedM.Frame.Payload[1] == 105, "Unmasked payload matches original")
    } catch {
        check(false, "ParseFrame masked threw error")
    }

    // 3. Extended length 126 frame (256 bytes payload)
    let largePayload = [uint8](repeating: 65, count: 256)
    let extBytes = websocket.BuildFrame(
        fin: true,
        opcode: websocket.Opcode.Binary,
        masked: false,
        payload: largePayload
    )
    check(extBytes.count == 4 + 256, "Extended length 126 frame length is 4-byte header + 256-byte payload")

    do {
        let parsedExt = try websocket.ParseFrame(data: extBytes, offset: 0)
        check(parsedExt.BytesRead == 260, "Parsed extended frame consumed 260 bytes")
        check(parsedExt.Frame.Payload.count == 256, "Parsed extended payload count is 256")
    } catch {
        check(false, "ParseFrame extended threw error")
    }
}

func testControlFrames() {
    // Ping frame
    let pingData: [uint8] = [1, 2, 3, 4]
    let pingBytes = websocket.BuildFrame(fin: true, opcode: websocket.Opcode.Ping, masked: false, payload: pingData)
    check(pingBytes.count == 6, "Ping frame length is 6")

    do {
        let parsed = try websocket.ParseFrame(data: pingBytes, offset: 0)
        check(parsed.Frame.Opcode == websocket.Opcode.Ping, "Parsed frame is Ping")
        check(parsed.Frame.Payload.count == 4, "Ping payload length is 4")
    } catch {
        check(false, "Parse Ping frame threw error")
    }

    // Close frame with code 1000 and reason "Goodbye"
    let closePayload = websocket.BuildClosePayload(code: websocket.CloseCode.NormalClosure, reason: "Goodbye")
    let closeBytes = websocket.BuildFrame(fin: true, opcode: websocket.Opcode.Close, masked: false, payload: closePayload)

    do {
        let parsedClose = try websocket.ParseFrame(data: closeBytes, offset: 0)
        let closeInfo = websocket.ParseClosePayload(payload: parsedClose.Frame.Payload)
        check(closeInfo.Code == 1000, "Close status code is 1000 (NormalClosure)")
        check(closeInfo.Reason == "Goodbye", "Close reason is 'Goodbye'")
    } catch {
        check(false, "Parse Close frame threw error")
    }
}

func testLoopbackSession() async {
    do {
        let listener = try tcp.Listen("127.0.0.1:0")
        let port = listener.LocalAddress.Port()

        let serverTask = Task { () async -> int in
            do {
                let stream = try await listener.Accept()
                let req = try await http.ReadRequest(from: stream)
                var conn = try await websocket.Upgrade(stream: stream, req: req)

                // Server echo loop for 2 messages
                var handled = 0
                while handled < 2 {
                    let msg = try await conn.Receive()
                    if msg.Type == websocket.MessageType.text {
                        try await conn.SendText("Echo: " + msg.Text)
                        handled += 1
                    } else if msg.Type == websocket.MessageType.binary {
                        try await conn.SendBinary(msg.Data)
                        handled += 1
                    }
                }
                try await conn.Close(code: websocket.CloseCode.NormalClosure, reason: "Done")
                return handled
            } catch {
                return 0
            }
        }

        // Client connects
        var clientConn = try await websocket.Connect("ws://127.0.0.1:\(port)/ws")
        check(!clientConn.IsClosed, "Client WebSocket connection established")

        // 1. Send Text
        try await clientConn.SendText("Hello Vertex WebSocket!")
        let resp1 = try await clientConn.Receive()
        check(resp1.Type == websocket.MessageType.text, "Client received Text response")
        check(resp1.Text == "Echo: Hello Vertex WebSocket!", "Client received expected echoed text")

        // 2. Send Binary
        var binData: [uint8] = [0xde, 0xad, 0xbe, 0xef]
        try await clientConn.SendBinary(binData)
        let resp2 = try await clientConn.Receive()
        check(resp2.Type == websocket.MessageType.binary, "Client received Binary response")
        check(resp2.Data.count == 4 && resp2.Data[0] == 0xde && resp2.Data[3] == 0xef, "Client binary payload matches")

        let serverCount = await serverTask.value
        check(serverCount == 2, "Server handled 2 messages")

        try await clientConn.Close()
        listener.Close()
    } catch {
        check(false, "testLoopbackSession threw unexpected error")
    }
}

func main() async -> int32 {
    print("=== net/websocket Test Suite ===")
    testAcceptKeyDerivation()
    testBase64()
    testFrameSerialization()
    testControlFrames()
    await testLoopbackSession()
    print(failures == 0 ? "All net/websocket tests passed!" : "\(failures) tests failed.")
    return int32(failures)
}

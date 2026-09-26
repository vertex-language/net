package main

import "net/webtransport"
import "net/http"
import "net/quic"

var failures = 0

func check(_ cond: bool, _ msg: string) {
    if cond {
        print("ok    \(msg)")
    } else {
        print("FAIL  \(msg)")
        failures += 1
    }
}

func testUrlParsing() {
    print("=== WebTransport URL Parsing ===")

    do {
        let u1 = try webtransport.WebTransportURL.Parse("https://game.example.com/wt")
        check(u1.Scheme == "https", "url: scheme is https")
        check(u1.Host == "game.example.com", "url: host is game.example.com")
        check(u1.Port == 443, "url: default port is 443")
        check(u1.Path == "/wt", "url: path is /wt")
    } catch {
        check(false, "url: parse game.example.com failed")
    }

    do {
        let u2 = try webtransport.WebTransportURL.Parse("https://127.0.0.1:4433/chat/lobby")
        check(u2.Host == "127.0.0.1", "url: host is 127.0.0.1")
        check(u2.Port == 4433, "url: custom port is 4433")
        check(u2.Path == "/chat/lobby", "url: path is /chat/lobby")
    } catch {
        check(false, "url: parse 127.0.0.1:4433 failed")
    }

    var threwInvalid = false
    do {
        _ = try webtransport.WebTransportURL.Parse("http://plain.example.com/wt")
    } catch {
        threwInvalid = true
    }
    check(threwInvalid, "url: rejected non-https scheme")
}

func testCapsuleFraming() {
    print("=== RFC 9297 Capsule Protocol Framing ===")

    let dummyPayload: [uint8] = [0xde, 0xad, 0xbe, 0xef]
    let cap = webtransport.BuildCapsule(type: 0x1234, payload: dummyPayload)
    check(!cap.isEmpty, "capsule: generated non-empty bytes")

    do {
        let parsed = try webtransport.ParseCapsule(data: cap, offset: 0)
        check(parsed.Type == 0x1234, "capsule: parsed type matches 0x1234")
        check(parsed.Payload.count == 4, "capsule: payload length matches 4")
        check(parsed.Payload[0] == 0xde && parsed.Payload[3] == 0xef, "capsule: payload bytes match")
    } catch {
        check(false, "capsule: parse generic capsule failed")
    }

    // CLOSE_WEBTRANSPORT_SESSION (0x2843)
    let closeCap = webtransport.BuildCloseSessionCapsule(code: 42, reason: "Client shutdown")
    do {
        let parsedClose = try webtransport.ParseCapsule(data: closeCap, offset: 0)
        check(parsedClose.Type == webtransport.WebTransportCapsuleType.CloseWebTransportSession, "capsule: CLOSE_WEBTRANSPORT_SESSION type is 0x2843")
        let closeInfo = try webtransport.ParseCloseSessionPayload(parsedClose.Payload)
        check(closeInfo.Code == 42, "capsule: close code is 42")
        check(closeInfo.Reason == "Client shutdown", "capsule: close reason is 'Client shutdown'")
    } catch {
        check(false, "capsule: parse CLOSE_WEBTRANSPORT_SESSION failed")
    }

    // DRAIN_WEBTRANSPORT_SESSION (0x78ae)
    let drainCap = webtransport.BuildDrainSessionCapsule()
    do {
        let parsedDrain = try webtransport.ParseCapsule(data: drainCap, offset: 0)
        check(parsedDrain.Type == webtransport.WebTransportCapsuleType.DrainWebTransportSession, "capsule: DRAIN_WEBTRANSPORT_SESSION type is 0x78ae")
        check(parsedDrain.Payload.isEmpty, "capsule: drain payload is empty")
    } catch {
        check(false, "capsule: parse DRAIN_WEBTRANSPORT_SESSION failed")
    }
}

func testDatagramMultiplexing() {
    print("=== RFC 9297 Datagram Multiplexing ===")

    // SessionId = 8 -> Quarter Stream ID = 8 / 4 = 2
    let payload: [uint8] = [0x10, 0x20, 0x30, 0x40]
    let enc = webtransport.EncodeDatagram(sessionId: 8, payload: payload)
    check(enc.count == 5, "datagram: encoded 4 bytes payload + 1 byte quarter stream ID")
    check(enc[0] == 0x02, "datagram: quarter stream ID varint is 0x02")

    do {
        let dec = try webtransport.DecodeDatagram(enc)
        check(dec.SessionId == 8, "datagram: decoded Session ID matches 8")
        check(dec.Payload.count == 4, "datagram: decoded payload length is 4")
        check(dec.Payload[0] == 0x10 && dec.Payload[3] == 0x40, "datagram: decoded payload bytes match")
    } catch {
        check(false, "datagram: decode failed")
    }
}

func testUpgraderValidation() {
    print("=== WebTransport Upgrader & Extended CONNECT ===")

    let upgrader = webtransport.Upgrader()

    var validReq = http.Request(method: "CONNECT", url: "/wt", version: http.HttpVersion.http3)
    validReq.Headers.Set(":protocol", "webtransport")
    check(upgrader.IsWebTransportRequest(req: validReq), "upgrader: recognized valid WebTransport CONNECT request")

    var getReq = http.Request(method: "GET", url: "/wt", version: http.HttpVersion.http3)
    getReq.Headers.Set(":protocol", "webtransport")
    check(!upgrader.IsWebTransportRequest(req: getReq), "upgrader: rejected non-CONNECT method")

    var plainConnect = http.Request(method: "CONNECT", url: "/wt", version: http.HttpVersion.http3)
    check(!upgrader.IsWebTransportRequest(req: plainConnect), "upgrader: rejected CONNECT without webtransport protocol")
}

func testLoopbackSessionPair() async {
    print("=== WebTransport Loopback Session Pair ===")

    do {
        let pair = try webtransport.CreateLoopbackSessionPair()
        var client = pair.Client
        var server = pair.Server
        check(client.SessionId == 0, "loopback: client session ID is 0")
        check(server.SessionId == 0, "loopback: server session ID is 0")
        check(!client.IsClosed, "loopback: client is initially open")
        check(!server.IsClosed, "loopback: server is initially open")

        // 1. Datagram transmission (client -> server)
        let playerState: [uint8] = [0x7f, 0x00, 0xaa, 0xbb]
        try await client.SendDatagram(playerState)

        // Directly enqueue on server to simulate delivery
        server.EnqueueDatagram(playerState)
        let recvdDatagram = try await server.ReceiveDatagram()
        check(recvdDatagram.count == 4, "loopback: server received datagram")
        check(recvdDatagram[0] == 0x7f && recvdDatagram[2] == 0xaa, "loopback: datagram bytes match")

        // 2. Reliable Bidirectional Stream
        var clientStream = try await client.OpenStream()
        check(clientStream.SessionId == 0, "loopback: client stream belongs to session 0")
        try await clientStream.WriteText("join_channel:lobby\n")

        // Simulate server accepting stream with inbound data
        var serverQuicStream = quic.QuicStream(streamId: clientStream.StreamId)
        // Initiator writes 0x41 + SessionId prefix then text
        var serverStream = webtransport.WebTransportStream(
            streamId: clientStream.StreamId,
            sessionId: server.SessionId,
            quicStream: serverQuicStream,
            isInitiator: false
        )
        // Feed client stream bytes into server stream buffer
        let outFrames = clientStream.QuicStream.DrainOutboundFrames()
        var payloadBytes: [uint8] = []
        var fi = 0
        while fi < outFrames.count {
            switch outFrames[fi] {
            case .stream(let sf):
                for b in sf.Data { payloadBytes.append(b) }
            default:
                break
            }
            fi += 1
        }
        serverStream.QuicStream.ReceiveStreamData(offset: 0, fin: false, data: payloadBytes)

        let serverReadText = try await serverStream.ReadText(maxBytes: 1024)
        check(serverReadText == "join_channel:lobby\n", "loopback: server read stream text: 'join_channel:lobby\\n'")

        // Server sends reply back to client
        try await serverStream.WriteText("ack:welcome\n")
        let serverOutFrames = serverStream.QuicStream.DrainOutboundFrames()
        var replyBytes: [uint8] = []
        fi = 0
        while fi < serverOutFrames.count {
            switch serverOutFrames[fi] {
            case .stream(let sf):
                for b in sf.Data { replyBytes.append(b) }
            default:
                break
            }
            fi += 1
        }
        clientStream.QuicStream.ReceiveStreamData(offset: 0, fin: false, data: replyBytes)

        let clientReadReply = try await clientStream.ReadText(maxBytes: 1024)
        check(clientReadReply == "ack:welcome\n", "loopback: client received reply: 'ack:welcome\\n'")

        // 3. Unidirectional Stream (client send -> server receive)
        var clientUni = try await client.OpenUniStream()
        try await clientUni.WriteText("telemetry_tick:12345")
        let uniFrames = clientUni.QuicStream.DrainOutboundFrames()
        var uniBytes: [uint8] = []
        fi = 0
        while fi < uniFrames.count {
            switch uniFrames[fi] {
            case .stream(let sf):
                for b in sf.Data { uniBytes.append(b) }
            default:
                break
            }
            fi += 1
        }

        var serverRxQuic = quic.QuicStream(streamId: clientUni.StreamId)
        serverRxQuic.ReceiveStreamData(offset: 0, fin: false, data: uniBytes)
        var serverRx = webtransport.WebTransportReceiveStream(
            streamId: clientUni.StreamId,
            sessionId: server.SessionId,
            quicStream: serverRxQuic
        )
        let rxText = try await serverRx.ReadText(maxBytes: 1024)
        check(rxText == "telemetry_tick:12345", "loopback: server read uni stream text: 'telemetry_tick:12345'")

        // 4. Session Event Loop (NextEvent matching webtransport_package.md pattern)
        server.EnqueueDatagram([0x01, 0x02])
        if let ev = try await server.NextEvent() {
            switch ev {
            case .datagram(let d):
                check(d.count == 2 && d[0] == 0x01, "loopback: NextEvent yielded .datagram")
            default:
                check(false, "loopback: NextEvent expected .datagram")
            }
        } else {
            check(false, "loopback: NextEvent returned nil")
        }

        // 5. Session Termination via Capsule
        try await client.Close(code: 100, reason: "Client shutdown")
        check(client.IsClosed, "loopback: client session is closed after Close()")
        if let ev = try await client.NextEvent() {
            switch ev {
            case .sessionClosed(let code, let reason):
                check(code == 100, "loopback: NextEvent yielded .sessionClosed with code 100")
                check(reason == "Client shutdown", "loopback: NextEvent yielded close reason 'Client shutdown'")
            default:
                check(false, "loopback: NextEvent expected .sessionClosed")
            }
        } else {
            check(false, "loopback: NextEvent returned nil for closed session")
        }

    } catch {
        check(false, "loopback: session pair test threw error")
    }
}

func main() async -> int32 {
    print("Running net/webtransport test suite...\n")

    testUrlParsing()
    print("")
    testCapsuleFraming()
    print("")
    testDatagramMultiplexing()
    print("")
    testUpgraderValidation()
    print("")
    await testLoopbackSessionPair()
    print("")

    if failures == 0 {
        print("ALL WEBTRANSPORT CHECKS PASSED!")
        return 0
    } else {
        print("\(failures) TEST(S) FAILED!")
        return 1
    }
}

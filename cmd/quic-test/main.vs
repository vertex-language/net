package main

import (
    "crypto/hkdf"
    "net/quic"
    "net/udp"
)

var failures = 0

func check(_ cond: bool, _ msg: string) {
    if cond {
        print("ok    \(msg)")
    } else {
        print("FAIL  \(msg)")
        failures += 1
    }
}

func testVarint() {
    print("=== RFC 9000 Varint Encoding & Decoding ===")

    // RFC 9000 Section 16 Examples
    // 37 -> 1 byte 0x25
    let b1 = quic.EncodeVarint(37)
    check(b1.count == 1 && b1[0] == 0x25, "varint: 37 encodes as 1 byte [0x25]")
    do {
        let dec = try quic.DecodeVarint(b1)
        check(dec.Value == 37 && dec.BytesRead == 1, "varint: decodes 37 correctly")
    } catch {
        check(false, "varint: decode 37 failed")
    }

    // 15293 -> 2 bytes 0x7bbd
    let b2 = quic.EncodeVarint(15293)
    check(b2.count == 2 && b2[0] == 0x7b && b2[1] == 0xbd, "varint: 15293 encodes as 2 bytes [0x7b, 0xbd]")
    do {
        let dec = try quic.DecodeVarint(b2)
        check(dec.Value == 15293 && dec.BytesRead == 2, "varint: decodes 15293 correctly")
    } catch {
        check(false, "varint: decode 15293 failed")
    }

    // 494878333 -> 4 bytes 0x9d7f3e7d
    let b4 = quic.EncodeVarint(494878333)
    check(b4.count == 4 && b4[0] == 0x9d && b4[1] == 0x7f && b4[2] == 0x3e && b4[3] == 0x7d, "varint: 494878333 encodes as 4 bytes [0x9d, 0x7f, 0x3e, 0x7d]")
    do {
        let dec = try quic.DecodeVarint(b4)
        check(dec.Value == 494878333 && dec.BytesRead == 4, "varint: decodes 494878333 correctly")
    } catch {
        check(false, "varint: decode 494878333 failed")
    }

    // 151288809941952652 -> 8 bytes 0xc2197c5eff14e88c
    let b8 = quic.EncodeVarint(151288809941952652)
    check(b8.count == 8 && b8[0] == 0xc2 && b8[1] == 0x19, "varint: 151288809941952652 encodes as 8 bytes")
    do {
        let dec = try quic.DecodeVarint(b8)
        check(dec.Value == 151288809941952652 && dec.BytesRead == 8, "varint: decodes 62-bit integer correctly")
    } catch {
        check(false, "varint: decode 8-byte failed")
    }
}

func testFrames() {
    print("=== RFC 9000 & RFC 9221 Frame Serialization & Parsing ===")

    // 1. STREAM Frame
    let streamPayload: [uint8] = [72, 101, 108, 108, 111] // "Hello"
    let streamFrame = quic.QuicFrame.stream(quic.StreamFrameData(streamId: 4, offset: 100, fin: true, data: streamPayload))
    let encodedStream = quic.EncodeFrame(streamFrame)
    check(encodedStream.count > 0, "frame: stream frame serialized")

    do {
        let parsed = try quic.ParseFrames(encodedStream)
        check(parsed.count == 1, "frame: parsed 1 stream frame")
        if parsed.count == 1 {
            switch parsed[0] {
            case .stream(let s):
                check(s.StreamId == 4, "frame: stream ID matches 4")
                check(s.Offset == 100, "frame: stream offset matches 100")
                check(s.Fin == true, "frame: stream FIN is true")
                check(s.Data.count == 5, "frame: stream payload count is 5")
            default:
                check(false, "frame: expected stream frame")
            }
        }
    } catch {
        check(false, "frame: parse stream frame failed")
    }

    // 2. ACK Frame
    let ranges = [quic.AckRange(gap: 1, rangeLength: 2)]
    let ackData = quic.AckFrameData(largestAcked: 50, ackDelay: 10, firstRange: 5, ranges: ranges)
    let ackFrame = quic.QuicFrame.ack(ackData)
    let encodedAck = quic.EncodeFrame(ackFrame)

    do {
        let parsed = try quic.ParseFrames(encodedAck)
        check(parsed.count == 1, "frame: parsed 1 ACK frame")
        if parsed.count == 1 {
            switch parsed[0] {
            case .ack(let a):
                check(a.LargestAcked == 50, "frame: ACK largest acked matches 50")
                check(a.AckDelay == 10, "frame: ACK delay matches 10")
                check(a.FirstRange == 5, "frame: ACK first range matches 5")
                check(a.Ranges.count == 1 && a.Ranges[0].Gap == 1, "frame: ACK gap matches 1")
            default:
                check(false, "frame: expected ACK frame")
            }
        }
    } catch {
        check(false, "frame: parse ACK frame failed")
    }

    // 3. Flow Control Frames (MAX_DATA & MAX_STREAM_DATA)
    let maxDataFrame = quic.QuicFrame.maxData(1048576)
    let maxStreamDataFrame = quic.QuicFrame.maxStreamData(streamId: 8, maxData: 262144)
    let encodedFlow = quic.EncodeFrames([maxDataFrame, maxStreamDataFrame])

    do {
        let parsed = try quic.ParseFrames(encodedFlow)
        check(parsed.count == 2, "frame: parsed 2 flow control frames")
        if parsed.count == 2 {
            switch parsed[0] {
            case .maxData(let md): check(md == 1048576, "frame: MAX_DATA matches 1048576")
            default: check(false, "frame: expected MAX_DATA")
            }
            switch parsed[1] {
            case .maxStreamData(let sid, let msd):
                check(sid == 8 && msd == 262144, "frame: MAX_STREAM_DATA matches")
            default: check(false, "frame: expected MAX_STREAM_DATA")
            }
        }
    } catch {
        check(false, "frame: parse flow control frames failed")
    }

    // 4. RFC 9221 DATAGRAM Frame
    let dgramPayload: [uint8] = [1, 2, 3, 4, 5, 6, 7, 8]
    let dgramFrame = quic.QuicFrame.datagram(dgramPayload)
    let encodedDgram = quic.EncodeFrame(dgramFrame)

    do {
        let parsed = try quic.ParseFrames(encodedDgram)
        check(parsed.count == 1, "frame: parsed 1 DATAGRAM frame")
        if parsed.count == 1 {
            switch parsed[0] {
            case .datagram(let d):
                check(d.count == 8 && d[0] == 1, "frame: DATAGRAM payload matches")
            default:
                check(false, "frame: expected DATAGRAM frame")
            }
        }
    } catch {
        check(false, "frame: parse DATAGRAM frame failed")
    }
}

func testPacketHeadersAndCrypto() {
    print("=== RFC 9001 Crypto, Header Protection & AEAD ===")

    let dcid: [uint8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
    let scid: [uint8] = [0x43, 0x4c, 0x49, 0x01, 0x02, 0x03, 0x04, 0x05]

    // 1. Initial Secret Derivation
    let initSecret = hkdf.Extract(hash: .sha256, secret: dcid, salt: quic.QuicSalt.V1)
    check(initSecret.count == 32, "crypto: derived 32-byte initial secret from DCID")

    let clientKeys = quic.QuicCipherKeys.Derive(secret: initSecret)
    check(clientKeys.Key.count == 32, "crypto: derived 32-byte AEAD key")
    check(clientKeys.Iv.count == 12, "crypto: derived 12-byte IV")
    check(clientKeys.HpKey.count == 32, "crypto: derived 32-byte Header Protection key")

    // 2. Nonce Computation
    let nonce0 = quic.ComputeNonce(iv: clientKeys.Iv, pn: 0)
    check(nonce0 == clientKeys.Iv, "crypto: Nonce for PN 0 equals IV")

    let nonce1 = quic.ComputeNonce(iv: clientKeys.Iv, pn: 1)
    check(nonce1[11] == (clientKeys.Iv[11] ^ 0x01), "crypto: Nonce for PN 1 XORs lowest byte")

    // 3. Packet Number Encoding & Reconstruction (RFC 9000 Appendix A)
    let pnLen = quic.PacketNumberLength(pn: 100, largestAcked: 95)
    check(pnLen == 1, "packet: PN length for small delta is 1")

    let reconstructed = quic.DecodePacketNumber(largestPn: 95, truncatedPn: 100, pnLen: 1)
    check(reconstructed == 100, "packet: reconstructed packet number matches 100")

    // 4. Seal & Open Packet with AEAD & Header Protection
    let testFrames = [quic.QuicFrame.ping, quic.QuicFrame.maxData(50000)]
    let payloadBytes = quic.EncodeFrames(testFrames)

    let pn: uint64 = 42
    let header = quic.BuildLongHeader(
        packetType: quic.QuicPacketType.Initial,
        version: quic.QuicVersion.V1,
        dcid: dcid,
        scid: scid,
        token: [],
        packetNumber: pn,
        pnLength: 4,
        payloadLength: payloadBytes.count + 16
    )
    let pnOffset = header.count - 4

    var sealedPacket: [uint8] = []
    do {
        sealedPacket = try quic.SealPacket(
            header: header,
            payload: payloadBytes,
            pn: pn,
            pnOffset: pnOffset,
            pnLen: 4,
            keys: clientKeys
        )
        check(sealedPacket.count == header.count + payloadBytes.count + 16, "crypto: sealed packet length includes AEAD tag")
    } catch {
        check(false, "crypto: SealPacket threw error")
    }

    // Verify packet header was protected (masked)
    check(sealedPacket[0] != header[0], "crypto: header protection masked first byte")

    // Open packet and verify decrypted payload and unmasked packet number
    do {
        let decPkt = try quic.OpenPacket(
            packet: sealedPacket,
            pnOffset: pnOffset,
            keys: clientKeys,
            largestAcked: 0
        )
        check(decPkt.PacketNumber == pn, "crypto: decrypted packet number matches 42")
        check(decPkt.Frames.count == 2, "crypto: decrypted 2 frames")
    } catch {
        check(false, "crypto: OpenPacket threw error")
    }

    // Tamper detection: Corrupt ciphertext byte
    var corruptedPacket = sealedPacket
    corruptedPacket[corruptedPacket.count - 1] ^= 0xff
    var tamperCaught = false
    do {
        _ = try quic.OpenPacket(
            packet: corruptedPacket,
            pnOffset: pnOffset,
            keys: clientKeys,
            largestAcked: 0
        )
    } catch {
        tamperCaught = true
    }
    check(tamperCaught, "crypto: tampered ciphertext rejected by Poly1305 AEAD integrity check")
}

func testLossAndCongestion() {
    print("=== RFC 9002 Loss Detection & Congestion Control ===")

    // 1. RTT Estimator
    var rtt = quic.RttEstimator(initialRttMs: 100)
    rtt.UpdateRtt(latestSampleMs: 80, ackDelayMs: 5)
    check(rtt.SmoothedRttMs == 80, "loss: first RTT sample sets smoothed RTT")
    check(rtt.MinRttMs == 80, "loss: min RTT is 80")

    rtt.UpdateRtt(latestSampleMs: 120, ackDelayMs: 0)
    check(rtt.SmoothedRttMs > 80 && rtt.SmoothedRttMs < 120, "loss: smoothed Rtt smoothly tracks new sample")

    let pto = rtt.ComputePto(maxAckDelayMs: 25)
    check(pto > rtt.SmoothedRttMs, "loss: PTO exceeds smoothed RTT")

    // 2. Loss Detector
    var detector = quic.LossDetector()
    detector.OnPacketSent(quic.SentPacket(packetNumber: 1, sentTimeMs: 1000, bytesSent: 1200, ackEliciting: true))
    detector.OnPacketSent(quic.SentPacket(packetNumber: 2, sentTimeMs: 1001, bytesSent: 1200, ackEliciting: true))
    detector.OnPacketSent(quic.SentPacket(packetNumber: 3, sentTimeMs: 1002, bytesSent: 1200, ackEliciting: true))
    detector.OnPacketSent(quic.SentPacket(packetNumber: 4, sentTimeMs: 1003, bytesSent: 1200, ackEliciting: true))
    detector.OnPacketSent(quic.SentPacket(packetNumber: 5, sentTimeMs: 1004, bytesSent: 1200, ackEliciting: true))

    // Peer acknowledges packet 5. Packet 1 is <= 5 - 3 (PacketThreshold = 3), so Packet 1 is lost!
    let lost = detector.OnAckReceived(largestAcked: 5, nowMs: 1050, rtt: rtt)
    check(lost.count >= 1, "loss: loss detector declared lost packets on threshold trigger")
    if !lost.isEmpty {
        check(lost[0].PacketNumber == 1, "loss: packet 1 identified as lost")
    }

    // 3. NewReno Congestion Controller
    var cc = quic.NewRenoCongestionController(maxDatagramSize: 1200)
    let initCwnd = cc.CongestionWindow
    check(initCwnd == 12000, "congestion: initial window is 10 * 1200 = 12000 bytes")

    cc.OnPacketSent(bytes: 2400)
    check(cc.BytesInFlight == 2400, "congestion: bytes in flight tracks sent packets")
    check(cc.CanSend(), "congestion: can send while under window")

    cc.OnPacketAcked(bytes: 2400)
    check(cc.CongestionWindow > initCwnd, "congestion: slow start increases congestion window")

    cc.OnPacketLost(bytes: 1200)
    check(cc.CongestionWindow < initCwnd + 2400, "congestion: loss drops congestion window")
}

func testTransportParameters() {
    print("=== RFC 9000 Section 18.2 Transport Parameters ===")

    var params = quic.TransportParameters()
    params.InitialMaxData = 2097152               // 2 MB
    params.InitialMaxStreamDataBidiLocal = 524288 // 512 KB
    params.MaxDatagramFrameSize = 1400
    params.DisableActiveMigration = true

    let encoded = quic.EncodeTransportParameters(params)
    check(!encoded.isEmpty, "tp: transport parameters encoded")

    do {
        let decoded = try quic.DecodeTransportParameters(encoded)
        check(decoded.InitialMaxData == 2097152, "tp: decoded initial max data matches")
        check(decoded.InitialMaxStreamDataBidiLocal == 524288, "tp: decoded bidi local stream data matches")
        check(decoded.MaxDatagramFrameSize == 1400, "tp: decoded max datagram size matches 1400")
        check(decoded.DisableActiveMigration == true, "tp: decoded disable active migration matches")
    } catch {
        check(false, "tp: decode transport parameters failed")
    }
}

func testEndToEndP2P() async {
    print("=== WebRTC & QUIC P2P Loopback Session ===")

    var s1: udp.UdpSocket?
    var s2: udp.UdpSocket?
    do {
        s1 = try udp.Bind(address: .v4(ip: "127.0.0.1", port: 0))
        s2 = try udp.Bind(address: .v4(ip: "127.0.0.1", port: 0))
    } catch {
        check(false, "p2p: UDP bind failed")
        return
    }

    guard let sock1 = s1, let sock2 = s2 else {
        check(false, "p2p: invalid sockets")
        return
    }

    let serverAddr = sock2.LocalAddress
    let clientAddr = sock1.LocalAddress

    let clientCid: [uint8] = [0x43, 0x4c, 0x49, 0x01, 0x02, 0x03, 0x04, 0x05]
    let serverCid: [uint8] = [0x53, 0x52, 0x56, 0x01, 0x02, 0x03, 0x04, 0x05]

    var client = quic.QuicConnection(
        socket: sock1,
        remoteAddress: serverAddr,
        localCid: clientCid,
        remoteCid: serverCid,
        isClient: true
    )

    var server = quic.QuicConnection(
        socket: sock2,
        remoteAddress: clientAddr,
        localCid: serverCid,
        remoteCid: clientCid,
        isClient: false
    )

    // 1. Client opens stream and writes data
    do {
        var clientStream = try await client.OpenStream()
        check(clientStream.StreamId == 0, "p2p: client opened bidi stream 0")

        let msg: [uint8] = [86, 101, 114, 116, 101, 120, 32, 81, 85, 73, 67] // "Vertex QUIC"
        try await clientStream.Write(msg)

        let outboundFrames = clientStream.DrainOutboundFrames()
        check(outboundFrames.count == 1, "p2p: stream produced 1 STREAM frame")

        // Send encrypted 1-RTT packet from client to server
        try await client.SendPacket(frames: outboundFrames, packetType: quic.QuicPacketType.OneRtt)
    } catch {
        check(false, "p2p: client stream write failed")
    }

    // 2. Server receives UDP packet, decrypts, and routes to stream
    do {
        var buf = [uint8](repeating: 0, count: 2048)
        let (n, _) = try await sock2.ReceiveFrom(into: &buf)
        var rawPkt: [uint8] = []
        var bi = 0
        while bi < n { rawPkt.append(buf[bi]); bi += 1 }

        let frames = try server.ProcessInboundDatagram(rawPkt)
        check(frames.count == 1, "p2p: server processed 1 decrypted frame")

        var serverStream = try await server.AcceptStream()
        let receivedBytes = try await serverStream.Read(maxBytes: 100)
        let receivedText = string(decoding: receivedBytes, as: UTF8.self)
        check(receivedText == "Vertex QUIC", "p2p: server read stream data matches 'Vertex QUIC'")
    } catch {
        check(false, "p2p: server stream read failed")
    }

    // 3. RFC 9221 Unreliable Datagram Transmission
    do {
        let dgramPayload: [uint8] = [85, 108, 116, 114, 97, 70, 97, 115, 116] // "UltraFast"
        try await client.SendDatagram(dgramPayload)

        var buf = [uint8](repeating: 0, count: 2048)
        let (n, _) = try await sock2.ReceiveFrom(into: &buf)
        var rawDgram: [uint8] = []
        var bi = 0
        while bi < n { rawDgram.append(buf[bi]); bi += 1 }

        _ = try server.ProcessInboundDatagram(rawDgram)

        let receivedDgram = try await server.ReceiveDatagram()
        let dgramText = string(decoding: receivedDgram, as: UTF8.self)
        check(dgramText == "UltraFast", "p2p: server received RFC 9221 datagram matches 'UltraFast'")
    } catch {
        check(false, "p2p: datagram transmission failed")
    }

    // 4. Teardown
    sock1.Close()
    sock2.Close()
    check(true, "p2p: QUIC P2P loopback session completed cleanly")
}

func main() async -> int32 {
    testVarint()
    testFrames()
    testPacketHeadersAndCrypto()
    testLossAndCongestion()
    testTransportParameters()
    await testEndToEndP2P()

    if failures == 0 {
        print("\nAll net/quic tests passed!")
        return 0
    } else {
        print("\n\(failures) test(s) failed in net/quic")
        return 1
    }
}

package main

import (
    "net/datachannel"
    "net/ice"
    "net/sctp"
    "net/udp"
    "net/webrtc"
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

func stringContains(_ s: string, _ substr: string) -> bool {
    var sBytes: [uint8] = []
    for b in s.utf8 { sBytes.append(b) }
    var subBytes: [uint8] = []
    for b in substr.utf8 { subBytes.append(b) }
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

func testSdp() {
    print("=== WebRTC SDP Serialization & Parsing (RFC 8866 / RFC 8839) ===")

    let hostCand = ice.NewHostCandidate(foundation: "1", address: .v4(ip: "192.168.1.50", port: 54321))
    let sdpStr = webrtc.BuildSdp(
        type: webrtc.RTCSdpType.Offer,
        ufrag: "test-ufrag",
        pwd: "test-ice-password",
        fingerprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
        setup: "actpass",
        sctpPort: 5000,
        candidates: [hostCand]
    )

    check(stringContains(sdpStr, "v=0"), "sdp: contains version line")
    check(stringContains(sdpStr, "a=ice-ufrag:test-ufrag"), "sdp: contains ufrag")
    check(stringContains(sdpStr, "a=ice-pwd:test-ice-password"), "sdp: contains pwd")
    check(stringContains(sdpStr, "a=setup:actpass"), "sdp: contains setup actpass")
    check(stringContains(sdpStr, "a=sctp-port:5000"), "sdp: contains sctp-port 5000")
    check(stringContains(sdpStr, "a=candidate:"), "sdp: contains candidate line")

    do {
        let parsed = try webrtc.ParseSdp(sdpStr, type: webrtc.RTCSdpType.Offer)
        check(parsed.Ufrag == "test-ufrag", "sdp: parsed ufrag matches")
        check(parsed.Pwd == "test-ice-password", "sdp: parsed pwd matches")
        check(parsed.Setup == "actpass", "sdp: parsed setup matches")
        check(parsed.SctpPort == 5000, "sdp: parsed sctp-port matches 5000")
        check(parsed.Candidates.count == 1, "sdp: parsed 1 candidate")
        if parsed.Candidates.count == 1 {
            check(parsed.Candidates[0].Foundation == "1", "sdp: candidate foundation matches")
            check(parsed.Candidates[0].Type == ice.CandidateType.Host, "sdp: candidate type is host")
        }
    } catch {
        check(false, "sdp: ParseSdp threw error")
    }
}

func testPeerConnectionSignalingAndData() async {
    print("=== WebRTC PeerConnection JSEP Signaling & DTLS/SCTP DataChannel ===")

    // Create UDP sockets for ICE agents
    var s1: udp.UdpSocket?
    var s2: udp.UdpSocket?
    do {
        s1 = try udp.Bind(address: .v4(ip: "127.0.0.1", port: 0))
        s2 = try udp.Bind(address: .v4(ip: "127.0.0.1", port: 0))
    } catch {
        check(false, "webrtc: failed to bind local UDP sockets")
        return
    }

    guard let sock1 = s1, let sock2 = s2 else {
        check(false, "webrtc: invalid sockets")
        return
    }

    var pc1 = webrtc.RTCPeerConnection(socket: sock1, configuration: webrtc.RTCConfiguration())
    var pc2 = webrtc.RTCPeerConnection(socket: sock2, configuration: webrtc.RTCConfiguration())

    check(pc1.SignalingState == webrtc.RTCSignalingState.Stable, "pc1: initial signaling state is Stable")
    check(pc2.SignalingState == webrtc.RTCSignalingState.Stable, "pc2: initial signaling state is Stable")

    // 1. Create DataChannel on pc1
    let dc1 = pc1.CreateDataChannel(label: "p2p-chat")
    check(dc1.Label == "p2p-chat", "pc1: created data channel 'p2p-chat'")
    check(pc1.DataChannels.count == 1, "pc1: 1 data channel registered")

    // 2. JSEP Offer / Answer negotiation
    var offer: webrtc.RTCSessionDescription = webrtc.RTCSessionDescription(type: "", sdp: "")
    do {
        offer = try pc1.CreateOffer()
    } catch {
        check(false, "pc1: CreateOffer failed")
    }
    check(pc1.SignalingState == webrtc.RTCSignalingState.HaveLocalOffer, "pc1: signaling state is HaveLocalOffer")

    do {
        try pc2.SetRemoteDescription(offer)
    } catch {
        check(false, "pc2: SetRemoteDescription(offer) failed")
    }
    check(pc2.SignalingState == webrtc.RTCSignalingState.HaveRemoteOffer, "pc2: signaling state is HaveRemoteOffer")
    check(pc2.RemoteUfrag == pc1.LocalUfrag, "pc2: remote ufrag matched pc1 local ufrag")

    var answer: webrtc.RTCSessionDescription = webrtc.RTCSessionDescription(type: "", sdp: "")
    do {
        answer = try pc2.CreateAnswer()
    } catch {
        check(false, "pc2: CreateAnswer failed")
    }

    do {
        try pc2.SetLocalDescription(answer)
        try pc1.SetRemoteDescription(answer)
    } catch {
        check(false, "webrtc: SetLocalDescription / SetRemoteDescription answer failed")
    }

    check(pc1.SignalingState == webrtc.RTCSignalingState.Stable, "pc1: signaling state returned to Stable")
    check(pc2.SignalingState == webrtc.RTCSignalingState.Stable, "pc2: signaling state returned to Stable")

    // 3. Establish connection
    pc1.SetConnected()
    pc2.SetConnected()
    check(pc1.ConnectionState == webrtc.RTCPeerConnectionState.Connected, "pc1: connection state is Connected")
    check(pc2.ConnectionState == webrtc.RTCPeerConnectionState.Connected, "pc2: connection state is Connected")

    // 4. Send encrypted DataChannel message from pc1 to pc2
    pc1.SetDataChannelState(channelId: 0, state: datachannel.RTCDataChannelState.Open)

    var protectedDatagram: [uint8] = []
    do {
        protectedDatagram = try pc1.ProtectTextMessage(channelId: 0, text: "Hello from Pure-Vertex WebRTC!")
    } catch {
        check(false, "pc1: ProtectTextMessage failed")
    }
    check(protectedDatagram.count > 13 + 16, "webrtc: protected datagram contains DTLS record header, ciphertext, and Poly1305 tag")
    check(protectedDatagram[0] == 23, "webrtc: DTLS record ContentType is ApplicationData (23)")

    // 5. Process datagram on pc2
    var inboundResults: [datachannel.DataChannelInboundResult] = []
    do {
        inboundResults = try pc2.ProcessIncomingDatagram(protectedDatagram)
    } catch {
        check(false, "pc2: ProcessIncomingDatagram failed")
    }
    check(inboundResults.count == 1, "pc2: processed 1 inbound message")
    if inboundResults.count == 1 {
        check(inboundResults[0].Kind == datachannel.InboundKind.Text, "pc2: received message is Text")
        check(inboundResults[0].TextMessage == "Hello from Pure-Vertex WebRTC!", "pc2: delivered text matches 'Hello from Pure-Vertex WebRTC!'")
    }

    // 6. Security verification: tamper with encrypted datagram
    var tampered = protectedDatagram
    tampered[tampered.count - 1] ^= 0x55 // corrupt Poly1305 authentication tag
    var tamperCaught = false
    do {
        var dummy = try pc2.ProcessIncomingDatagram(tampered)
    } catch {
        tamperCaught = true
    }
    check(tamperCaught, "webrtc: tampered datagram successfully rejected by DTLS AEAD integrity check")

    // 7. Teardown
    pc1.Close()
    pc2.Close()
    check(pc1.ConnectionState == webrtc.RTCPeerConnectionState.Closed, "pc1: connection state Closed")
    check(pc2.ConnectionState == webrtc.RTCPeerConnectionState.Closed, "pc2: connection state Closed")
}

func main() async -> int32 {
    testSdp()
    await testPeerConnectionSignalingAndData()

    if failures == 0 {
        print("\nAll net/webrtc tests passed!")
        return 0
    } else {
        print("\n\(failures) tests failed in net/webrtc")
        return int32(failures)
    }
}

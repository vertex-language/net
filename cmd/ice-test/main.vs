package main

import "net/udp"
import "net/ice"

var failures = 0

func check(_ ok: bool, _ msg: string) {
    if ok {
        print("ok    \(msg)")
    } else {
        print("FAIL  \(msg)")
        failures += 1
    }
}

func main() async -> int32 {
    print("=== net/ice Test Suite ===")

    // 1. Candidate Priority Calculation (RFC 8445 Section 5.1.2)
    // Host type pref = 126, local pref = 65535, component = 1
    // (126 << 24) | (65535 << 8) | 255 = 2113929216 | 16776960 | 255 = 2130706431
    let hostPrio = ice.CalculatePriority(type: ice.CandidateType.Host, localPref: 65535, component: 1)
    check(hostPrio == 2130706431, "ice: host candidate priority matches RFC 8445 formula")

    let relayPrio = ice.CalculatePriority(type: ice.CandidateType.Relay, localPref: 65535, component: 1)
    check(relayPrio == 16777215, "ice: relay candidate priority has 0 type preference")

    // 2. SDP Formatting and Parsing (RFC 8839 / RFC 8445)
    let sampleAddr = udp.SocketAddress.v4(ip: "192.168.1.50", port: 50000)
    let cand = ice.NewHostCandidate(foundation: "1", address: sampleAddr, localPref: 65535, component: 1)
    let sdpLine = cand.ToSDP()
    check(sdpLine == "candidate:1 1 UDP 2130706431 192.168.1.50 50000 typ host", "ice: candidate ToSDP formatted correctly")

    if let parsed = ice.ParseSDPLine(sdpLine) {
        check(parsed.Foundation == "1", "ice: parsed SDP foundation matches")
        check(parsed.Component == 1, "ice: parsed SDP component matches")
        check(parsed.Protocol == "UDP", "ice: parsed SDP protocol matches")
        check(parsed.Priority == 2130706431, "ice: parsed SDP priority matches")
        check(parsed.Type == ice.CandidateType.Host, "ice: parsed SDP type matches")
        switch parsed.Address {
        case .v4(let ip, let port):
            check(ip == "192.168.1.50" && port == 50000, "ice: parsed SDP address matches")
        default:
            check(false, "ice: unexpected address family in parsed SDP")
        }
    } else {
        check(false, "ice: failed to parse SDP line")
    }

    // 3. Pair Priority Calculation (RFC 8445 Section 6.1.2.3)
    // G = 2130706431 (controlling), D = 1000000 (controlled)
    // minVal = 1000000, maxVal = 2130706431, tie = 1
    // pairPriority = (1000000 << 32) | (2130706431 << 1) | 1
    let pairPrio = ice.CalculatePairPriority(controllingPriority: 2130706431, controlledPriority: 1000000)
    let expectedPairPrio = (uint64(1000000) << 32) | (uint64(2130706431) << 1) | 1
    check(pairPrio == expectedPairPrio, "ice: pair priority matches RFC 8445 formula")

    // 4. Candidate Gathering (Host Discovery)
    do {
        let gatherer = ice.CandidateGatherer(localPort: 0, stunServers: [])
        let (sock, gatheredCands) = try await gatherer.Gather()
        check(!gatheredCands.isEmpty, "ice: gatherer found at least 1 host candidate")
        check(sock.LocalAddress.Port() > 0, "ice: gatherer bound valid socket")
        sock.Close()
    } catch {
        check(false, "ice: gatherer threw exception")
    }

    // 5. Full P2P 2-Agent Loopback Session (RFC 8445 Connectivity Checks + Data Exchange)
    do {
        // Agent A (Controlling) setup
        let sockA = try udp.Bind(address: .v4(ip: "127.0.0.1", port: 0))
        let portA = sockA.LocalAddress.Port()
        let candA = ice.NewHostCandidate(foundation: "1", address: .v4(ip: "127.0.0.1", port: portA))
        var agentA = ice.NewAgent(socket: sockA, role: ice.IceRole.Controlling, localCandidates: [candA])

        // Agent B (Controlled) setup
        let sockB = try udp.Bind(address: .v4(ip: "127.0.0.1", port: 0))
        let portB = sockB.LocalAddress.Port()
        let candB = ice.NewHostCandidate(foundation: "2", address: .v4(ip: "127.0.0.1", port: portB))
        var agentB = ice.NewAgent(socket: sockB, role: ice.IceRole.Controlled, localCandidates: [candB])

        // Signaling exchange (Credentials + Candidates)
        agentA.SetRemoteCredentials(ufrag: agentB.LocalUfrag, pwd: agentB.LocalPwd)
        agentA.AddRemoteCandidate(candB)

        agentB.SetRemoteCredentials(ufrag: agentA.LocalUfrag, pwd: agentA.LocalPwd)
        agentB.AddRemoteCandidate(candA)

        // Spawn Agent B in background task to answer checks & connect
        _ = Task {
            do {
                try await agentB.Connect()
            } catch {
                print("agent B connect exception")
            }
        }

        // Run Agent A connectivity checks
        try await agentA.Connect()

        check(agentA.State == ice.IceConnectionState.Connected, "ice loopback: Agent A reached Connected state")
        check(agentA.HasSelectedPair, "ice loopback: Agent A selected active candidate pair")

        // Test Bidirectional P2P Data Exchange over selected ICE pair
        let msgToB: [uint8] = [72, 101, 108, 108, 111, 32, 66] // "Hello B"
        try await agentA.Send(msgToB)

        let receivedAtB = try await agentB.Receive()
        check(receivedAtB.count == msgToB.count, "ice loopback: Agent B received correct byte count")
        check(receivedAtB[0] == 72 && receivedAtB[6] == 66, "ice loopback: Agent B payload content matches")

        let msgToA: [uint8] = [65, 67, 75, 32, 65] // "ACK A"
        try await agentB.Send(msgToA)

        let receivedAtA = try await agentA.Receive()
        check(receivedAtA.count == msgToA.count, "ice loopback: Agent A received correct ACK byte count")
        check(receivedAtA[0] == 65 && receivedAtA[4] == 65, "ice loopback: Agent A ACK payload content matches")

        sockA.Close()
        sockB.Close()

    } catch {
        check(false, "ice loopback: exception occurred during 2-agent session")
    }

    if failures == 0 {
        print("All net/ice tests passed!")
        return 0
    } else {
        print("\(failures) tests failed in net/ice")
        return int32(failures)
    }
}

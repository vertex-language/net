package main

import "net/udp"
import "net/stun"
import "net/turn"
import "crypto/md5"

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
    print("=== net/turn Test Suite ===")

    // 1. Key Derivation Test
    let key = turn.GenerateKey(username: "user", realm: "realm", password: "pass")
    check(md5.ToHex(key) == "8493fbc53ba582fb4c044c456bdc40eb", "turn: credential key matches RFC 5389 test vector")

    // 2. Data Indication Encode & Decode Test
    let peerAddr = udp.SocketAddress.v4(ip: "192.168.1.100", port: 54321)
    let sampleData: [uint8] = [1, 2, 3, 4, 5]
    var ind = stun.Message(type: turn.MessageType.DataIndication)
    ind.AddAttribute(stun.MakeXorPeerAddress(address: peerAddr, transactionId: ind.TransactionId))
    ind.AddAttribute(stun.MakeData(sampleData))
    ind.AddFingerprint()

    do {
        let rawInd = ind.Encode()
        let decodedInd = try stun.Message.Decode(rawInd)
        let (payload, parsedPeer) = try turn.ParseDataIndication(decodedInd)
        check(payload.count == sampleData.count, "turn: data indication payload length matches")
        check(payload[0] == 1 && payload[4] == 5, "turn: data indication payload content matches")
        switch parsedPeer {
        case .v4(let ip, let port):
            check(ip == "192.168.1.100" && port == 54321, "turn: data indication peer address matches")
        default:
            check(false, "turn: unexpected peer address family")
        }
    } catch {
        check(false, "turn: data indication encode/decode exception")
    }

    // 3. Full Local TURN Server & Client Loopback Session
    do {
        let serverSock = try udp.Bind(address: .v4(ip: "127.0.0.1", port: 0))
        let serverAddr = serverSock.LocalAddress

        let clientSock = try udp.Bind(address: .v4(ip: "127.0.0.1", port: 0))

        var server = turn.Server(realm: "vertex.turn")
        server.AddUser(username: "alice", password: "supersecret")

        // Server processing loop
        _ = Task {
            var buf = [uint8](repeating: 0, count: 1500)
            var running = true
            while running {
                do {
                    let (n, from) = try await serverSock.ReceiveFrom(into: &buf)
                    if n > 0 {
                        var packet: [uint8] = []
                        var i = 0
                        while i < n {
                            packet.append(buf[i])
                            i += 1
                        }
                        if let resp = server.HandlePacket(packet, from: from) {
                            _ = try await serverSock.SendTo(resp, to: from)
                        }
                    }
                } catch {
                    running = false
                }
            }
        }

        var client = turn.NewClient(socket: clientSock,
                                     serverAddress: serverAddr,
                                     username: "alice",
                                     password: "supersecret")

        // Test Allocate (solicits 401 challenge, calculates HMAC, completes allocation)
        let alloc = try await client.Allocate(lifetime: 600)
        check(alloc.Lifetime == 600, "turn loopback: allocation lifetime is 600s")
        check(alloc.Realm == "vertex.turn", "turn loopback: allocation realm matches server")

        switch alloc.RelayedAddress {
        case .v4(let ip, let port):
            check(ip == "127.0.0.1", "turn loopback: relayed IP is loopback")
            check(port >= 34000, "turn loopback: relayed port is valid allocated port")
        default:
            check(false, "turn loopback: relayed address not IPv4")
        }

        // Test CreatePermission
        let targetPeer = udp.SocketAddress.v4(ip: "127.0.0.1", port: 45000)
        try await client.CreatePermission(peerAddress: targetPeer)
        check(true, "turn loopback: CreatePermission succeeded")

        // Test Refresh
        let renewedLifetime = try await client.Refresh(lifetime: 1200)
        check(renewedLifetime == 1200, "turn loopback: Refresh updated lifetime to 1200s")

        // Close sockets
        clientSock.Close()
        serverSock.Close()

    } catch {
        check(false, "turn loopback: exception occurred during session")
    }

    if failures == 0 {
        print("All net/turn tests passed!")
        return 0
    } else {
        print("\(failures) tests failed in net/turn")
        return int32(failures)
    }
}

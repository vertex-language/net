package main

import "net/sctp"

var failures = 0

func check(_ cond: bool, _ msg: string) {
    if cond {
        print("ok    \(msg)")
    } else {
        print("FAIL  \(msg)")
        failures += 1
    }
}

func testPacketChecksum() {
    print("=== SCTP Packet & CRC-32c Verification ===")

    let dummyPayload: [uint8] = [0xde, 0xad, 0xbe, 0xef]
    let chunk = sctp.RawChunk(type: sctp.ChunkType.Data, flags: 0x03, value: dummyPayload)
    let pkt = sctp.Packet(sourcePort: 5000, destinationPort: 5000, verificationTag: 0x12345678, chunks: [chunk])

    let serialized = pkt.Serialize()
    check(serialized.count >= 12 + 8, "sctp: serialized packet length includes 12-byte header and padded chunk")

    do {
        let parsed = try sctp.Packet.Parse(serialized)
        check(parsed.SourcePort == 5000, "sctp: parsed source port matches 5000")
        check(parsed.DestinationPort == 5000, "sctp: parsed destination port matches 5000")
        check(parsed.VerificationTag == 0x12345678, "sctp: parsed verification tag matches")
        check(parsed.Chunks.count == 1, "sctp: parsed 1 chunk")
        check(parsed.Chunks[0].Type == sctp.ChunkType.Data, "sctp: chunk type is DATA")
    } catch {
        check(false, "sctp: parse valid packet threw error")
    }

    // Tamper with packet byte to ensure checksum catches corruption
    var corrupted = serialized
    corrupted[14] = corrupted[14] ^ 0xff
    var caught = false
    do {
        var p = try sctp.Packet.Parse(corrupted)
    } catch {
        caught = true
    }
    check(caught, "sctp: tampered packet rejected by CRC-32c checksum verification")
}

func testChunks() {
    print("=== SCTP Chunk Encoding & Decoding ===")

    // Init Chunk
    let initChunk = sctp.InitChunk(initiateTag: 0xfeedbeef, a_rwnd: 1048576, outboundStreams: 16, inboundStreams: 16, initialTSN: 500, cookie: [1, 2, 3, 4])
    let rawInit = initChunk.ToRawChunk(isAck: true)
    check(rawInit.Type == sctp.ChunkType.InitAck, "init: InitAck chunk type correct")
    let parsedInit = sctp.InitChunk.Parse(rawInit)
    check(parsedInit.InitiateTag == 0xfeedbeef, "init: parsed initiate tag matches")
    check(parsedInit.a_rwnd == 1048576, "init: parsed a_rwnd matches")
    check(parsedInit.InitialTSN == 500, "init: parsed initial TSN matches")
    check(parsedInit.Cookie.count == 4, "init: parsed cookie matches")

    // Data Chunk
    let payload: [uint8] = [65, 66, 67, 68]
    let dataChunk = sctp.DataChunk(flags: sctp.DataFlags.Complete, tsn: 1001, streamId: 1, streamSeq: 5, ppid: sctp.PPID.String, userData: payload)
    let rawData = dataChunk.ToRawChunk()
    let parsedData = sctp.DataChunk.Parse(rawData)
    check(parsedData.TSN == 1001, "data: parsed TSN matches")
    check(parsedData.StreamId == 1, "data: parsed stream ID matches")
    check(parsedData.StreamSeq == 5, "data: parsed stream seq matches")
    check(parsedData.PPID == sctp.PPID.String, "data: parsed PPID matches string")
    check(parsedData.UserData == payload, "data: parsed payload matches")

    // Sack Chunk
    let sack = sctp.SackChunk(cumulativeTSNAck: 1005, a_rwnd: 1000000, gapAckBlocks: [1, 2], duplicateTSNs: [999])
    let rawSack = sack.ToRawChunk()
    let parsedSack = sctp.SackChunk.Parse(rawSack)
    check(parsedSack.CumulativeTSNAck == 1005, "sack: parsed cumulative TSN matches")
    check(parsedSack.GapAckBlocks.count == 2, "sack: parsed gap ack blocks")
    check(parsedSack.DuplicateTSNs.count == 1, "sack: parsed duplicate TSNs")
}

func testAssociationHandshakeAndData() {
    print("=== SCTP Association Handshake & Data Transfer ===")

    var client = sctp.Association(localPort: 5000, remotePort: 5000)
    var server = sctp.Association(localPort: 5000, remotePort: 5000)

    // 1. Client sends INIT
    let initPkt = client.InitHandshake()
    check(initPkt.count > 0, "assoc: client generated INIT packet")

    // 2. Server receives INIT, generates INIT ACK
    var initAckPkt: [uint8] = []
    do {
        initAckPkt = try server.HandlePacket(initPkt)
    } catch {
        check(false, "assoc: server failed to handle INIT")
    }
    check(initAckPkt.count > 0, "assoc: server generated INIT ACK packet")

    // 3. Client receives INIT ACK, generates COOKIE ECHO
    var cookieEchoPkt: [uint8] = []
    do {
        cookieEchoPkt = try client.HandlePacket(initAckPkt)
    } catch {
        check(false, "assoc: client failed to handle INIT ACK")
    }
    check(cookieEchoPkt.count > 0, "assoc: client generated COOKIE ECHO packet")

    // 4. Server receives COOKIE ECHO, generates COOKIE ACK
    var cookieAckPkt: [uint8] = []
    do {
        cookieAckPkt = try server.HandlePacket(cookieEchoPkt)
    } catch {
        check(false, "assoc: server failed to handle COOKIE ECHO")
    }
    check(cookieAckPkt.count > 0, "assoc: server generated COOKIE ACK packet")
    check(server.IsEstablished(), "assoc: server transitioned to ESTABLISHED")

    // 5. Client receives COOKIE ACK
    var clientAckResp: [uint8] = []
    do {
        clientAckResp = try client.HandlePacket(cookieAckPkt)
    } catch {
        check(false, "assoc: client failed to handle COOKIE ACK")
    }
    check(client.IsEstablished(), "assoc: client transitioned to ESTABLISHED")

    // 6. Data Transfer: Client sends message to Server
    let msgBytes: [uint8] = [72, 101, 108, 108, 111, 32, 83, 67, 84, 80] // "Hello SCTP"
    let dataPkt = client.SendData(streamId: 0, ppid: sctp.PPID.String, payload: msgBytes)

    var sackPkt: [uint8] = []
    do {
        sackPkt = try server.HandlePacket(dataPkt)
    } catch {
        check(false, "assoc: server failed to handle DATA packet")
    }
    check(sackPkt.count > 0, "assoc: server acknowledged DATA packet with SACK")

    let received = server.ReadDelivered()
    check(received.count == 1, "assoc: server received 1 delivered message")
    if received.count == 1 {
        check(received[0].StreamId == 0, "assoc: stream ID is 0")
        check(received[0].PPID == sctp.PPID.String, "assoc: PPID matches string")
        check(received[0].Payload == msgBytes, "assoc: payload content matches 'Hello SCTP'")
    }

    // 7. Server handles SACK on Client
    do {
        var sackResp = try client.HandlePacket(sackPkt)
    } catch {
        check(false, "assoc: client failed to handle SACK")
    }
}

func main() -> int32 {
    testPacketChecksum()
    testChunks()
    testAssociationHandshakeAndData()

    if failures == 0 {
        print("\nAll net/sctp tests passed!")
        return 0
    } else {
        print("\n\(failures) tests failed in net/sctp")
        return int32(failures)
    }
}

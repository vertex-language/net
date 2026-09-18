package main

import "net/datachannel"
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

func testDcepSerialization() {
    print("=== DCEP Message Serialization & Parsing ===")

    let label = "chat"
    let proto = "json"
    let openBytes = datachannel.BuildDcepOpen(
        channelType: datachannel.ChannelType.Reliable,
        priority: 100,
        reliabilityParam: 0,
        label: label,
        subprotocol: proto
    )

    check(openBytes.count == 12 + 4 + 4, "dcep: open message length matches 12-byte header + label + proto")
    check(openBytes[0] == datachannel.DcepMessageType.Open, "dcep: message type is OPEN (3)")
    check(openBytes[1] == datachannel.ChannelType.Reliable, "dcep: channel type is Reliable (0)")

    do {
        let parsed = try datachannel.ParseDcepOpen(openBytes)
        check(parsed.ChannelType == datachannel.ChannelType.Reliable, "dcep: parsed channel type matches")
        check(parsed.Priority == 100, "dcep: parsed priority matches 100")
        check(parsed.ReliabilityParam == 0, "dcep: parsed reliability parameter matches 0")
        check(parsed.Label == "chat", "dcep: parsed label matches 'chat'")
        check(parsed.Subprotocol == "json", "dcep: parsed protocol matches 'json'")
    } catch {
        check(false, "dcep: ParseDcepOpen threw unexpected error")
    }

    let ackBytes = datachannel.BuildDcepAck()
    check(ackBytes.count == 1, "dcep: ack message length is 1")
    check(ackBytes[0] == datachannel.DcepMessageType.Ack, "dcep: ack message type is ACK (2)")
}

func testDataChannelCommunication() {
    print("=== RTCDataChannel P2P Simulation ===")

    // 1. Client creates channel
    var clientDc = datachannel.RTCDataChannel(id: 1, label: "game-data")
    check(clientDc.ReadyState == datachannel.RTCDataChannelState.Connecting, "dc: client channel starts in Connecting state")

    let openMsg = clientDc.InitOpenMessage()
    check(openMsg.StreamId == 1, "dc: open message streamId is 1")
    check(openMsg.PPID == sctp.PPID.DCEP, "dc: open message PPID is DCEP")

    // 2. Server receives DCEP Open
    var serverDc = datachannel.RTCDataChannel(id: 1, label: "")
    var serverInbound: datachannel.DataChannelInboundResult = datachannel.DataChannelInboundResult(kind: 0)
    do {
        serverInbound = try serverDc.HandleInbound(ppid: openMsg.PPID, data: openMsg.Payload)
    } catch {
        check(false, "dc: server HandleInbound threw error on DCEP Open")
    }

    check(serverDc.ReadyState == datachannel.RTCDataChannelState.Open, "dc: server channel transitioned to Open")
    check(serverDc.Label == "game-data", "dc: server adopted client label 'game-data'")
    check(serverInbound.Kind == datachannel.InboundKind.AckResponseNeeded, "dc: server responded with ACK needed")

    // 3. Client receives DCEP Ack
    var clientInbound: datachannel.DataChannelInboundResult = datachannel.DataChannelInboundResult(kind: 0)
    do {
        clientInbound = try clientDc.HandleInbound(ppid: sctp.PPID.DCEP, data: serverInbound.AckData)
    } catch {
        check(false, "dc: client HandleInbound threw error on DCEP Ack")
    }
    check(clientDc.ReadyState == datachannel.RTCDataChannelState.Open, "dc: client channel transitioned to Open")

    // 4. Client sends String message
    var textOut: datachannel.OutboundMessage = datachannel.OutboundMessage(streamId: 0, ppid: 0, payload: [], unordered: false)
    do {
        textOut = try clientDc.Send(text: "Hello WebRTC DataChannel!")
    } catch {
        check(false, "dc: client Send(string) failed")
    }
    check(textOut.PPID == sctp.PPID.String, "dc: outbound text PPID is String")

    // 5. Server handles String message
    do {
        let msgRes = try serverDc.HandleInbound(ppid: textOut.PPID, data: textOut.Payload)
        check(msgRes.Kind == datachannel.InboundKind.Text, "dc: server received Text message")
        check(msgRes.TextMessage == "Hello WebRTC DataChannel!", "dc: server received text payload matches")
    } catch {
        check(false, "dc: server failed to handle text message")
    }

    // 6. Server sends Binary message
    let binData: [uint8] = [0x01, 0x02, 0x03, 0x04, 0x05]
    var binOut: datachannel.OutboundMessage = datachannel.OutboundMessage(streamId: 0, ppid: 0, payload: [], unordered: false)
    do {
        binOut = try serverDc.Send(bytes: binData)
    } catch {
        check(false, "dc: server Send(bytes) failed")
    }
    check(binOut.PPID == sctp.PPID.Binary, "dc: outbound binary PPID is Binary")

    // 7. Client handles Binary message
    do {
        let binRes = try clientDc.HandleInbound(ppid: binOut.PPID, data: binOut.Payload)
        check(binRes.Kind == datachannel.InboundKind.Binary, "dc: client received Binary message")
        check(binRes.BinaryMessage == binData, "dc: client received binary payload matches")
    } catch {
        check(false, "dc: client failed to handle binary message")
    }

    // 8. Close channel
    clientDc.Close()
    check(clientDc.ReadyState == datachannel.RTCDataChannelState.Closed, "dc: client channel is Closed")
}

func main() -> int32 {
    testDcepSerialization()
    testDataChannelCommunication()

    if failures == 0 {
        print("\nAll net/datachannel tests passed!")
        return 0
    } else {
        print("\n\(failures) tests failed in net/datachannel")
        return int32(failures)
    }
}

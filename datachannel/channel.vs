package datachannel

import "net/sctp"

public struct InboundKind {
    public static let None: int = 0
    public static let AckResponseNeeded: int = 1
    public static let Text: int = 2
    public static let Binary: int = 3
}

/// DataChannelInboundResult represents an event or data extracted from an incoming SCTP stream message.
public struct DataChannelInboundResult {
    public var Kind: int
    public var AckData: [uint8]
    public var TextMessage: string
    public var BinaryMessage: [uint8]

    public init(kind: int,
                ackData: [uint8] = [],
                textMessage: string = "",
                binaryMessage: [uint8] = []) {
        self.Kind = kind
        self.AckData = ackData
        self.TextMessage = textMessage
        self.BinaryMessage = binaryMessage
    }
}

/// OutboundMessage represents an SCTP chunk payload to transmit.
public struct OutboundMessage {
    public var StreamId: uint16
    public var PPID: uint32
    public var Payload: [uint8]
    public var Unordered: bool

    public init(streamId: uint16, ppid: uint32, payload: [uint8], unordered: bool) {
        self.StreamId = streamId
        self.PPID = ppid
        self.Payload = payload
        self.Unordered = unordered
    }
}

/// RTCDataChannel represents a bidirectional peer-to-peer data channel (RFC 8831).
public struct RTCDataChannel {
    public var Id: uint16
    public var Label: string
    public var Subprotocol: string
    public var Ordered: bool
    public var MaxPacketLifeTime: int
    public var MaxRetransmits: int
    public var Negotiated: bool
    public var ReadyState: int

    public init(id: uint16, label: string, options: RTCDataChannelInit) {
        self.Id = id
        self.Label = label
        self.Subprotocol = options.Subprotocol
        self.Ordered = options.Ordered
        self.MaxPacketLifeTime = options.MaxPacketLifeTime
        self.MaxRetransmits = options.MaxRetransmits
        self.Negotiated = options.Negotiated
        self.ReadyState = options.Negotiated ? RTCDataChannelState.Open : RTCDataChannelState.Connecting
    }

    public init(id: uint16, label: string) {
        self.Id = id
        self.Label = label
        self.Subprotocol = ""
        self.Ordered = true
        self.MaxPacketLifeTime = 0
        self.MaxRetransmits = 0
        self.Negotiated = false
        self.ReadyState = RTCDataChannelState.Connecting
    }

    /// InitOpenMessage creates the DCEP OPEN message for un-negotiated channels.
    public func InitOpenMessage() -> OutboundMessage {
        var cType = ChannelType.Reliable
        var relParam: uint32 = 0

        if !self.Ordered {
            cType = ChannelType.ReliableUnordered
        }
        if self.MaxRetransmits > 0 {
            cType = self.Ordered ? ChannelType.PartialReliableRexmit : ChannelType.PartialReliableRexmitUnordered
            relParam = uint32(self.MaxRetransmits)
        } else if self.MaxPacketLifeTime > 0 {
            cType = self.Ordered ? ChannelType.PartialReliableTimed : ChannelType.PartialReliableTimedUnordered
            relParam = uint32(self.MaxPacketLifeTime)
        }

        let openBytes = BuildDcepOpen(
            channelType: cType,
            priority: 0,
            reliabilityParam: relParam,
            label: self.Label,
            subprotocol: self.Subprotocol
        )

        return OutboundMessage(
            streamId: self.Id,
            ppid: sctp.PPID.DCEP,
            payload: openBytes,
            unordered: false
        )
    }

    /// Send transmits a UTF-8 string over the data channel.
    public func Send(text: string) throws -> OutboundMessage {
        if self.ReadyState != RTCDataChannelState.Open {
            throw DataChannelError.channelClosed("Cannot send on closed or connecting channel")
        }

        var bytes: [uint8] = []
        for b in text.utf8 {
            bytes.append(b)
        }
        let ppid = bytes.isEmpty ? sctp.PPID.StringEmpty : sctp.PPID.String

        return OutboundMessage(
            streamId: self.Id,
            ppid: ppid,
            payload: bytes,
            unordered: !self.Ordered
        )
    }

    /// Send transmits a binary byte buffer over the data channel.
    public func Send(bytes: [uint8]) throws -> OutboundMessage {
        if self.ReadyState != RTCDataChannelState.Open {
            throw DataChannelError.channelClosed("Cannot send on closed or connecting channel")
        }

        let ppid = bytes.isEmpty ? sctp.PPID.BinaryEmpty : sctp.PPID.Binary

        return OutboundMessage(
            streamId: self.Id,
            ppid: ppid,
            payload: bytes,
            unordered: !self.Ordered
        )
    }

    /// HandleInbound processes an incoming message from the SCTP stream for this channel.
    public mutating func HandleInbound(ppid: uint32, data: [uint8]) throws -> DataChannelInboundResult {
        if ppid == sctp.PPID.DCEP {
            if data.isEmpty {
                return DataChannelInboundResult(kind: InboundKind.None)
            }
            let msgType = data[0]
            if msgType == DcepMessageType.Open {
                let openMsg = try ParseDcepOpen(data)
                self.Label = openMsg.Label
                self.Subprotocol = openMsg.Subprotocol
                self.ReadyState = RTCDataChannelState.Open
                let ackBytes = BuildDcepAck()
                return DataChannelInboundResult(kind: InboundKind.AckResponseNeeded, ackData: ackBytes)
            } else if msgType == DcepMessageType.Ack {
                self.ReadyState = RTCDataChannelState.Open
                return DataChannelInboundResult(kind: InboundKind.None)
            }
        } else if ppid == sctp.PPID.String {
            let str = string(decoding: data, as: UTF8.self)
            return DataChannelInboundResult(kind: InboundKind.Text, textMessage: str)
        } else if ppid == sctp.PPID.StringEmpty {
            return DataChannelInboundResult(kind: InboundKind.Text, textMessage: "")
        } else if ppid == sctp.PPID.Binary || ppid == sctp.PPID.BinaryEmpty {
            return DataChannelInboundResult(kind: InboundKind.Binary, binaryMessage: data)
        }

        return DataChannelInboundResult(kind: InboundKind.None)
    }

    /// Close marks the data channel as closed.
    public mutating func Close() {
        self.ReadyState = RTCDataChannelState.Closed
    }
}

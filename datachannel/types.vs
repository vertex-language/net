package datachannel

public struct ChannelType {
    public static let Reliable: uint8 = 0x00
    public static let ReliableUnordered: uint8 = 0x01
    public static let PartialReliableRexmit: uint8 = 0x02
    public static let PartialReliableRexmitUnordered: uint8 = 0x03
    public static let PartialReliableTimed: uint8 = 0x04
    public static let PartialReliableTimedUnordered: uint8 = 0x05
}

public struct DcepMessageType {
    public static let Ack: uint8 = 0x02
    public static let Open: uint8 = 0x03
}

public struct RTCDataChannelState {
    public static let Connecting: int = 0
    public static let Open: int = 1
    public static let Closing: int = 2
    public static let Closed: int = 3
}

public struct RTCDataChannelInit {
    public var Ordered: bool
    public var MaxPacketLifeTime: int
    public var MaxRetransmits: int
    public var Subprotocol: string
    public var Negotiated: bool
    public var Id: uint16

    public init() {
        self.Ordered = true
        self.MaxPacketLifeTime = 0
        self.MaxRetransmits = 0
        self.Subprotocol = ""
        self.Negotiated = false
        self.Id = 0
    }

    public init(ordered: bool,
                maxPacketLifeTime: int,
                maxRetransmits: int,
                subprotocol: string,
                negotiated: bool,
                id: uint16) {
        self.Ordered = ordered
        self.MaxPacketLifeTime = maxPacketLifeTime
        self.MaxRetransmits = maxRetransmits
        self.Subprotocol = subprotocol
        self.Negotiated = negotiated
        self.Id = id
    }
}

public enum DataChannelError: Error {
    case invalidMessage(string)
    case channelClosed(string)
}

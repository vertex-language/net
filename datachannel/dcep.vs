package datachannel

/// DcepOpenMessage holds the parameters of a received DCEP DATA_CHANNEL_OPEN message (RFC 8832).
public struct DcepOpenMessage {
    public var ChannelType: uint8
    public var Priority: uint16
    public var ReliabilityParam: uint32
    public var Label: string
    public var Subprotocol: string

    public init(channelType: uint8,
                priority: uint16,
                reliabilityParam: uint32,
                label: string,
                subprotocol: string) {
        self.ChannelType = channelType
        self.Priority = priority
        self.ReliabilityParam = reliabilityParam
        self.Label = label
        self.Subprotocol = subprotocol
    }
}

/// BuildDcepOpen serializes a DCEP DATA_CHANNEL_OPEN message (RFC 8832 Section 5.1).
public func BuildDcepOpen(channelType: uint8,
                          priority: uint16,
                          reliabilityParam: uint32,
                          label: string,
                          subprotocol: string = "") -> [uint8] {
    var labelBytes: [uint8] = []
    for b in label.utf8 {
        labelBytes.append(b)
    }
    var protoBytes: [uint8] = []
    for b in subprotocol.utf8 {
        protoBytes.append(b)
    }

    var out = [uint8](repeating: 0, count: 12 + labelBytes.count + protoBytes.count)

    // Message Type: 0x03
    out[0] = DcepMessageType.Open

    // Channel Type
    out[1] = channelType

    // Priority
    out[2] = uint8(truncatingIfNeeded: (priority >> 8) & 0xff)
    out[3] = uint8(truncatingIfNeeded: priority & 0xff)

    // Reliability Parameter
    out[4] = uint8(truncatingIfNeeded: (reliabilityParam >> 24) & 0xff)
    out[5] = uint8(truncatingIfNeeded: (reliabilityParam >> 16) & 0xff)
    out[6] = uint8(truncatingIfNeeded: (reliabilityParam >> 8) & 0xff)
    out[7] = uint8(truncatingIfNeeded: reliabilityParam & 0xff)

    // Label Length
    out[8] = uint8(truncatingIfNeeded: (labelBytes.count >> 8) & 0xff)
    out[9] = uint8(truncatingIfNeeded: labelBytes.count & 0xff)

    // Protocol Length
    out[10] = uint8(truncatingIfNeeded: (protoBytes.count >> 8) & 0xff)
    out[11] = uint8(truncatingIfNeeded: protoBytes.count & 0xff)

    // Append Label
    var i = 0
    while i < labelBytes.count {
        out[12 + i] = labelBytes[i]
        i += 1
    }

    // Append Protocol
    var j = 0
    while j < protoBytes.count {
        out[12 + labelBytes.count + j] = protoBytes[j]
        j += 1
    }

    return out
}

/// ParseDcepOpen parses a DCEP DATA_CHANNEL_OPEN message from bytes.
public func ParseDcepOpen(_ data: [uint8]) throws -> DcepOpenMessage {
    if data.count < 12 {
        throw DataChannelError.invalidMessage("DCEP OPEN message too short")
    }

    if data[0] != DcepMessageType.Open {
        throw DataChannelError.invalidMessage("Not a DCEP OPEN message")
    }

    let cType = data[1]
    let prio = (uint16(data[2]) << 8) | uint16(data[3])
    let relParam = (uint32(data[4]) << 24) | (uint32(data[5]) << 16) | (uint32(data[6]) << 8) | uint32(data[7])
    let labelLen = (int(data[8]) << 8) | int(data[9])
    let protoLen = (int(data[10]) << 8) | int(data[11])

    if data.count < 12 + labelLen + protoLen {
        throw DataChannelError.invalidMessage("DCEP OPEN message truncated")
    }

    var labelBytes = [uint8](repeating: 0, count: labelLen)
    var i = 0
    while i < labelLen {
        labelBytes[i] = data[12 + i]
        i += 1
    }
    let labelStr = string(decoding: labelBytes, as: UTF8.self)

    var protoBytes = [uint8](repeating: 0, count: protoLen)
    var j = 0
    while j < protoLen {
        protoBytes[j] = data[12 + labelLen + j]
        j += 1
    }
    let protoStr = string(decoding: protoBytes, as: UTF8.self)

    return DcepOpenMessage(channelType: cType, priority: prio, reliabilityParam: relParam, label: labelStr, subprotocol: protoStr)
}

/// BuildDcepAck serializes a DCEP DATA_CHANNEL_ACK message (RFC 8832 Section 5.2).
public func BuildDcepAck() -> [uint8] {
    return [DcepMessageType.Ack]
}

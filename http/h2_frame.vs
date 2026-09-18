package http

/// RFC 9113 HTTP/2 Binary Frame Format.

public struct H2FrameType {
    public static let Data: uint8 = 0x00
    public static let Headers: uint8 = 0x01
    public static let Priority: uint8 = 0x02
    public static let RstStream: uint8 = 0x03
    public static let Settings: uint8 = 0x04
    public static let PushPromise: uint8 = 0x05
    public static let Ping: uint8 = 0x06
    public static let GoAway: uint8 = 0x07
    public static let WindowUpdate: uint8 = 0x08
    public static let Continuation: uint8 = 0x09
}

public struct H2Flag {
    public static let EndStream: uint8 = 0x01
    public static let Ack: uint8 = 0x01
    public static let EndHeaders: uint8 = 0x04
    public static let Padded: uint8 = 0x08
    public static let Priority: uint8 = 0x20
}

public struct H2ErrorCode {
    public static let NoError: uint32 = 0x00
    public static let ProtocolError: uint32 = 0x01
    public static let InternalError: uint32 = 0x02
    public static let FlowControlError: uint32 = 0x03
    public static let SettingsTimeout: uint32 = 0x04
    public static let StreamClosed: uint32 = 0x05
    public static let FrameSizeError: uint32 = 0x06
    public static let RefusedStream: uint32 = 0x07
    public static let Cancel: uint32 = 0x08
}

public struct H2SettingId {
    public static let HeaderTableSize: uint16 = 0x01
    public static let EnablePush: uint16 = 0x02
    public static let MaxConcurrentStreams: uint16 = 0x03
    public static let InitialWindowSize: uint16 = 0x04
    public static let MaxFrameSize: uint16 = 0x05
    public static let MaxHeaderListSize: uint16 = 0x06
}

public struct H2Setting {
    public var Identifier: uint16
    public var Value: uint32
    public init(identifier: uint16, value: uint32) {
        self.Identifier = identifier
        self.Value = value
    }
}

public struct H2FrameHeader {
    public var Length: int
    public var Type: uint8
    public var Flags: uint8
    public var StreamId: uint32

    public init(length: int, type: uint8, flags: uint8, streamId: uint32) {
        self.Length = length
        self.Type = type
        self.Flags = flags
        self.StreamId = streamId
    }
}

public struct H2Frame {
    public var Header: H2FrameHeader
    public var Payload: [uint8]

    public init(header: H2FrameHeader, payload: [uint8]) {
        self.Header = header
        self.Payload = payload
    }
}

/// 24-byte client connection preface (RFC 9113 Section 3.4).
public func H2ClientPreface() -> [uint8] {
    // "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    return [
        0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32,
        0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a
    ]
}

/// Serializes an RFC 9113 9-byte frame header and payload.
public func BuildH2Frame(type: uint8, flags: uint8, streamId: uint32, payload: [uint8]) -> [uint8] {
    var out = [uint8](repeating: 0, count: 9 + payload.count)

    // Length (24-bit big endian)
    let len = payload.count
    out[0] = uint8(truncatingIfNeeded: (len >> 16) & 0xff)
    out[1] = uint8(truncatingIfNeeded: (len >> 8) & 0xff)
    out[2] = uint8(truncatingIfNeeded: len & 0xff)

    // Type & Flags
    out[3] = type
    out[4] = flags

    // R (1 bit = 0) | StreamId (31-bit big endian)
    out[5] = uint8(truncatingIfNeeded: (streamId >> 24) & 0x7f)
    out[6] = uint8(truncatingIfNeeded: (streamId >> 16) & 0xff)
    out[7] = uint8(truncatingIfNeeded: (streamId >> 8) & 0xff)
    out[8] = uint8(truncatingIfNeeded: streamId & 0xff)

    var i = 0
    while i < payload.count {
        out[9 + i] = payload[i]
        i += 1
    }

    return out
}

/// Parses an RFC 9113 9-byte frame header.
public func ParseH2FrameHeader(data: [uint8], offset: int = 0) throws -> H2FrameHeader {
    if offset + 9 > data.count {
        throw HttpError.malformedResponse
    }

    let len = (int(data[offset]) << 16) | (int(data[offset + 1]) << 8) | int(data[offset + 2])
    let fType = data[offset + 3]
    let flags = data[offset + 4]

    let s0 = uint32(data[offset + 5] & 0x7f)
    let s1 = uint32(data[offset + 6])
    let s2 = uint32(data[offset + 7])
    let s3 = uint32(data[offset + 8])
    let streamId = (s0 << 24) | (s1 << 16) | (s2 << 8) | s3

    return H2FrameHeader(length: len, type: fType, flags: flags, streamId: streamId)
}

/// Builds an HTTP/2 SETTINGS frame.
public func BuildH2SettingsFrame(settings: [H2Setting], ack: bool = false) -> [uint8] {
    let flags: uint8 = ack ? H2Flag.Ack : 0
    var payload: [uint8] = []

    if !ack {
        var i = 0
        while i < settings.count {
            let s = settings[i]
            payload.append(uint8(truncatingIfNeeded: (s.Identifier >> 8) & 0xff))
            payload.append(uint8(truncatingIfNeeded: s.Identifier & 0xff))
            payload.append(uint8(truncatingIfNeeded: (s.Value >> 24) & 0xff))
            payload.append(uint8(truncatingIfNeeded: (s.Value >> 16) & 0xff))
            payload.append(uint8(truncatingIfNeeded: (s.Value >> 8) & 0xff))
            payload.append(uint8(truncatingIfNeeded: s.Value & 0xff))
            i += 1
        }
    }

    return BuildH2Frame(type: H2FrameType.Settings, flags: flags, streamId: 0, payload: payload)
}

/// Parses payload of an HTTP/2 SETTINGS frame.
public func ParseH2Settings(payload: [uint8]) -> [H2Setting] {
    var settings: [H2Setting] = []
    var i = 0
    while i + 6 <= payload.count {
        let id = (uint16(payload[i]) << 8) | uint16(payload[i + 1])
        let v0 = uint32(payload[i + 2])
        let v1 = uint32(payload[i + 3])
        let v2 = uint32(payload[i + 4])
        let v3 = uint32(payload[i + 5])
        let val = (v0 << 24) | (v1 << 16) | (v2 << 8) | v3
        settings.append(H2Setting(identifier: id, value: val))
        i += 6
    }
    return settings
}

/// Builds an HTTP/2 WINDOW_UPDATE frame.
public func BuildH2WindowUpdate(streamId: uint32, increment: uint32) -> [uint8] {
    var payload = [uint8](repeating: 0, count: 4)
    payload[0] = uint8(truncatingIfNeeded: (increment >> 24) & 0x7f)
    payload[1] = uint8(truncatingIfNeeded: (increment >> 16) & 0xff)
    payload[2] = uint8(truncatingIfNeeded: (increment >> 8) & 0xff)
    payload[3] = uint8(truncatingIfNeeded: increment & 0xff)
    return BuildH2Frame(type: H2FrameType.WindowUpdate, flags: 0, streamId: streamId, payload: payload)
}

/// Builds an HTTP/2 PING frame.
public func BuildH2Ping(opaqueData: [uint8], ack: bool = false) -> [uint8] {
    let flags: uint8 = ack ? H2Flag.Ack : 0
    var payload = [uint8](repeating: 0, count: 8)
    var i = 0
    while i < 8 && i < opaqueData.count {
        payload[i] = opaqueData[i]
        i += 1
    }
    return BuildH2Frame(type: H2FrameType.Ping, flags: flags, streamId: 0, payload: payload)
}

/// Builds an HTTP/2 GOAWAY frame.
public func BuildH2GoAway(lastStreamId: uint32, errorCode: uint32) -> [uint8] {
    var payload = [uint8](repeating: 0, count: 8)
    payload[0] = uint8(truncatingIfNeeded: (lastStreamId >> 24) & 0x7f)
    payload[1] = uint8(truncatingIfNeeded: (lastStreamId >> 16) & 0xff)
    payload[2] = uint8(truncatingIfNeeded: (lastStreamId >> 8) & 0xff)
    payload[3] = uint8(truncatingIfNeeded: lastStreamId & 0xff)

    payload[4] = uint8(truncatingIfNeeded: (errorCode >> 24) & 0xff)
    payload[5] = uint8(truncatingIfNeeded: (errorCode >> 16) & 0xff)
    payload[6] = uint8(truncatingIfNeeded: (errorCode >> 8) & 0xff)
    payload[7] = uint8(truncatingIfNeeded: errorCode & 0xff)

    return BuildH2Frame(type: H2FrameType.GoAway, flags: 0, streamId: 0, payload: payload)
}

/// Builds an HTTP/2 RST_STREAM frame.
public func BuildH2RstStream(streamId: uint32, errorCode: uint32) -> [uint8] {
    var payload = [uint8](repeating: 0, count: 4)
    payload[0] = uint8(truncatingIfNeeded: (errorCode >> 24) & 0xff)
    payload[1] = uint8(truncatingIfNeeded: (errorCode >> 16) & 0xff)
    payload[2] = uint8(truncatingIfNeeded: (errorCode >> 8) & 0xff)
    payload[3] = uint8(truncatingIfNeeded: errorCode & 0xff)
    return BuildH2Frame(type: H2FrameType.RstStream, flags: 0, streamId: streamId, payload: payload)
}

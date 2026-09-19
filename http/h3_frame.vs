package http

import "net/quic"

/// RFC 9114 HTTP/3 Binary Frame Format.

public struct H3FrameType {
    public static let Data: uint64 = 0x00
    public static let Headers: uint64 = 0x01
    public static let CancelPush: uint64 = 0x03
    public static let Settings: uint64 = 0x04
    public static let PushPromise: uint64 = 0x07
    public static let GoAway: uint64 = 0x0c
    public static let MaxPushId: uint64 = 0x0d
    public static let WebTransportStream: uint64 = 0x41
}

public struct H3StreamType {
    public static let Control: uint64 = 0x00
    public static let Push: uint64 = 0x01
    public static let QpackEncoder: uint64 = 0x02
    public static let QpackDecoder: uint64 = 0x03
    public static let WebTransportUni: uint64 = 0x54
}

public struct H3SettingId {
    public static let QpackMaxTableCapacity: uint64 = 0x01
    public static let MaxFieldSectionSize: uint64 = 0x06
    public static let QpackBlockedStreams: uint64 = 0x07
    public static let EnableConnectProtocol: uint64 = 0x08
    public static let EnableWebTransport: uint64 = 0x2b60
    public static let WebTransportMaxSessions: uint64 = 0xc67170
}

public struct H3Setting {
    public var Identifier: uint64
    public var Value: uint64
    public init(identifier: uint64, value: uint64) {
        self.Identifier = identifier
        self.Value = value
    }
}

public struct H3ParsedFrame {
    public var Type: uint64
    public var Payload: [uint8]
    public var BytesRead: int
    public init(type: uint64, payload: [uint8], bytesRead: int) {
        self.Type = type
        self.Payload = payload
        self.BytesRead = bytesRead
    }
}

/// Serializes an RFC 9114 frame using RFC 9000 varint encoding for type and length.
public func BuildH3Frame(type: uint64, payload: [uint8]) -> [uint8] {
    let typeBytes = quic.EncodeVarint(type)
    let lenBytes = quic.EncodeVarint(uint64(payload.count))

    var out: [uint8] = []
    for b in typeBytes { out.append(b) }
    for b in lenBytes { out.append(b) }
    for b in payload { out.append(b) }
    return out
}

/// Parses an RFC 9114 frame from a byte buffer.
public func ParseH3Frame(data: [uint8], offset: int = 0) throws -> H3ParsedFrame {
    if offset >= data.count {
        throw HttpError.malformedResponse
    }

    var curr = offset
    let typeDec = try quic.DecodeVarint(data, offset: curr)
    curr += typeDec.BytesRead

    let lenDec = try quic.DecodeVarint(data, offset: curr)
    curr += lenDec.BytesRead

    let len = Int(lenDec.Value)
    if curr + len > data.count {
        throw HttpError.malformedResponse
    }

    var payload: [uint8] = []
    var i = 0
    while i < len {
        payload.append(data[curr + i])
        i += 1
    }
    curr += len

    return H3ParsedFrame(type: typeDec.Value, payload: payload, bytesRead: curr - offset)
}

/// Serializes an HTTP/3 SETTINGS frame.
public func BuildH3SettingsFrame(settings: [H3Setting]) -> [uint8] {
    var payload: [uint8] = []
    var i = 0
    while i < settings.count {
        let s = settings[i]
        let idBytes = quic.EncodeVarint(s.Identifier)
        let valBytes = quic.EncodeVarint(s.Value)
        for b in idBytes { payload.append(b) }
        for b in valBytes { payload.append(b) }
        i += 1
    }
    return BuildH3Frame(type: H3FrameType.Settings, payload: payload)
}

/// Parses payload of an HTTP/3 SETTINGS frame.
public func ParseH3Settings(payload: [uint8]) throws -> [H3Setting] {
    var settings: [H3Setting] = []
    var offset = 0
    while offset < payload.count {
        let idDec = try quic.DecodeVarint(payload, offset: offset)
        offset += idDec.BytesRead

        let valDec = try quic.DecodeVarint(payload, offset: offset)
        offset += valDec.BytesRead

        settings.append(H3Setting(identifier: idDec.Value, value: valDec.Value))
    }
    return settings
}

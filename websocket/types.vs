package websocket

/// RFC 6455 Section 5.2 Opcodes.
public struct Opcode {
    public static let Continuation: uint8 = 0x0
    public static let Text: uint8 = 0x1
    public static let Binary: uint8 = 0x2
    public static let Close: uint8 = 0x8
    public static let Ping: uint8 = 0x9
    public static let Pong: uint8 = 0xa
}

/// RFC 6455 Section 7.4.1 Status Codes.
public struct CloseCode {
    public static let NormalClosure: uint16 = 1000
    public static let GoingAway: uint16 = 1001
    public static let ProtocolError: uint16 = 1002
    public static let UnsupportedData: uint16 = 1003
    public static let NoStatusReceived: uint16 = 1005
    public static let AbnormalClosure: uint16 = 1006
    public static let InvalidFramePayloadData: uint16 = 1007
    public static let PolicyViolation: uint16 = 1008
    public static let MessageTooBig: uint16 = 1009
    public static let MandatoryExtension: uint16 = 1010
    public static let InternalServerError: uint16 = 1011
    public static let TlsHandshake: uint16 = 1015
}

/// High-level message types for WebSocket frames.
public enum MessageType {
    case text
    case binary
    case ping
    case pong
    case close
}

/// Message represents a received or sent application message.
public struct Message {
    public var Type: MessageType
    public var Data: [uint8]

    public init(type: MessageType, data: [uint8]) {
        self.Type = type
        self.Data = data
    }

    public init(text: string) {
        self.Type = MessageType.text
        var bytes: [uint8] = []
        for b in text.utf8 { bytes.append(b) }
        self.Data = bytes
    }

    public init(binary: [uint8]) {
        self.Type = MessageType.binary
        self.Data = binary
    }

    /// Convenience property decoding payload bytes as UTF-8 string.
    public var Text: string {
        return string(decoding: self.Data, as: UTF8.self)
    }

    public func BodyText() -> string {
        return self.Text
    }
}

/// Typed error enum for WebSocket operations.
public enum WebSocketError: Error {
    case invalidUrl(string)
    case handshakeFailed(string)
    case protocolError(string)
    case connectionClosed
    case unexpectedOpcode(uint8)
    case maskRequired
    case maskForbidden
    case payloadTooLarge
    case invalidCloseCode(uint16)
}

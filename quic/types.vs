package quic

/// Protocol version identifiers.
public struct QuicVersion {
    public static let V1: uint32 = 0x00000001
    public static let V2: uint32 = 0x6b3343cf
    public static let Draft29: uint32 = 0xff00001d
}

/// QUIC Packet Types (RFC 9000).
public struct QuicPacketType {
    public static let Initial: uint8 = 0x00
    public static let ZeroRtt: uint8 = 0x01
    public static let Handshake: uint8 = 0x02
    public static let Retry: uint8 = 0x03
    public static let OneRtt: uint8 = 0x04
}

/// QUIC Stream Types (RFC 9000 Section 2.1).
public struct QuicStreamType {
    public static let ClientBidi: uint8 = 0x00
    public static let ServerBidi: uint8 = 0x01
    public static let ClientUni: uint8 = 0x02
    public static let ServerUni: uint8 = 0x03
}

/// QUIC Packet Number Spaces (RFC 9002 Section 4).
public struct PacketNumberSpace {
    public static let Initial: int = 0
    public static let Handshake: int = 1
    public static let ApplicationData: int = 2
}

/// QUIC Transport and Application Errors (RFC 9000 Section 20).
public enum QuicError: Error {
    case transport(code: uint64, msg: string)
    case application(code: uint64, msg: string)
    case general(string)
}

/// Well-known QUIC transport error codes (RFC 9000 Section 20.1).
public struct TransportErrorCode {
    public static let NoError: uint64 = 0x00
    public static let InternalError: uint64 = 0x01
    public static let ConnectionRefused: uint64 = 0x02
    public static let FlowControlError: uint64 = 0x03
    public static let StreamLimitError: uint64 = 0x04
    public static let StreamStateError: uint64 = 0x05
    public static let FinalSizeError: uint64 = 0x06
    public static let FrameEncodingError: uint64 = 0x07
    public static let TransportParameterError: uint64 = 0x08
    public static let ConnectionIdLimitError: uint64 = 0x09
    public static let ProtocolViolation: uint64 = 0x0a
    public static let InvalidToken: uint64 = 0x0b
    public static let ApplicationError: uint64 = 0x0c
    public static let CryptoBufferExceeded: uint64 = 0x0d
    public static let KeyUpdateError: uint64 = 0x0e
    public static let AeadLimitReached: uint64 = 0x0f
    public static let NoViablePath: uint64 = 0x10
}

/// QUIC Configuration parameters.
public struct QuicConfig {
    public var MaxIdleTimeoutMs: uint64
    public var InitialMaxData: uint64
    public var InitialMaxStreamDataBidiLocal: uint64
    public var InitialMaxStreamDataBidiRemote: uint64
    public var InitialMaxStreamDataUni: uint64
    public var MaxConcurrentBidiStreams: uint64
    public var MaxConcurrentUniStreams: uint64
    public var EnableDatagrams: bool
    public var MaxDatagramPayloadSize: uint64

    public init() {
        self.MaxIdleTimeoutMs = 30000
        self.InitialMaxData = 1048576               // 1 MB
        self.InitialMaxStreamDataBidiLocal = 262144 // 256 KB
        self.InitialMaxStreamDataBidiRemote = 262144
        self.InitialMaxStreamDataUni = 262144
        self.MaxConcurrentBidiStreams = 100
        self.MaxConcurrentUniStreams = 100
        self.EnableDatagrams = true
        self.MaxDatagramPayloadSize = 1200
    }
}

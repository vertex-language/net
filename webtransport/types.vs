package webtransport

/// Protocol errors encountered in WebTransport sessions (RFC 9297).
public enum WebTransportError: Error {
    case invalidUrl(string)
    case handshakeFailed(string)
    case sessionClosed(code: uint32, reason: string)
    case streamClosed
    case protocolViolation(string)
    case datagramTooLarge(int)
    case connectionClosed
}

/// WebTransport session closure metadata (RFC 9297 Section 4.3).
public struct SessionCloseInfo {
    public var Code: uint32
    public var Reason: string

    public init(code: uint32 = 0, reason: string = "") {
        self.Code = code
        self.Reason = reason
    }
}

/// RFC 9297 Capsule Types used on the HTTP/3 CONNECT stream.
public struct WebTransportCapsuleType {
    public static let CloseWebTransportSession: uint64 = 0x2843
    public static let DrainWebTransportSession: uint64 = 0x78ae
}

/// RFC 9297 Stream framing identifiers.
public struct WebTransportFrameType {
    public static let Stream: uint64 = 0x41
}

public struct WebTransportStreamType {
    public static let Uni: uint64 = 0x54
}

/// Configuration options for WebTransport client and server sessions.
public struct WebTransportConfig {
    public var TimeoutMs: int32
    public var MaxDatagramSize: int
    public var EnableDatagrams: bool

    public init(timeoutMs: int32 = 10000, maxDatagramSize: int = 1200, enableDatagrams: bool = true) {
        self.TimeoutMs = timeoutMs
        self.MaxDatagramSize = maxDatagramSize
        self.EnableDatagrams = enableDatagrams
    }
}

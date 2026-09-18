package http

/// Represents supported HTTP protocol versions.
public enum HttpVersion {
    case http1_1
    case http2
    case http3

    /// Standard protocol designation (e.g. "HTTP/1.1", "HTTP/2", "HTTP/3").
    public var Name: string {
        switch self {
        case .http1_1: return "HTTP/1.1"
        case .http2:   return "HTTP/2"
        case .http3:   return "HTTP/3"
        }
    }

    /// Official IANA ALPN protocol token.
    public var Alpn: string {
        switch self {
        case .http1_1: return "http/1.1"
        case .http2:   return "h2"
        case .http3:   return "h3"
        }
    }

    /// Official Alt-Svc advertisement token.
    public var AltSvcToken: string {
        switch self {
        case .http1_1: return "http/1.1"
        case .http2:   return "h2"
        case .http3:   return "h3"
        }
    }
}

/// Typed HTTP errors across HTTP/1.1, HTTP/2, and HTTP/3.
public enum HttpError: Error {
    case malformedRequest
    case malformedResponse
    case connectionClosed
    case invalidUrl
    case connectionFailed
    case handshakeFailed
    case streamError
    case protocolError
    case timeout
    case unsupportedProtocol
    case general(string)
}

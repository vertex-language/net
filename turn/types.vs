package turn

import "net/udp"

// TURN Message Types (RFC 8656 Section 18.1)
public struct MessageType {
    public static let AllocateRequest: uint16                = 0x0003
    public static let AllocateResponse: uint16               = 0x0103
    public static let AllocateErrorResponse: uint16          = 0x0113
    public static let RefreshRequest: uint16                 = 0x0004
    public static let RefreshResponse: uint16                = 0x0104
    public static let RefreshErrorResponse: uint16           = 0x0114
    public static let SendIndication: uint16                 = 0x0016
    public static let DataIndication: uint16                 = 0x0017
    public static let CreatePermissionRequest: uint16        = 0x0008
    public static let CreatePermissionResponse: uint16       = 0x0108
    public static let CreatePermissionErrorResponse: uint16  = 0x0118
    public static let ChannelBindRequest: uint16             = 0x0009
    public static let ChannelBindResponse: uint16            = 0x0109
    public static let ChannelBindErrorResponse: uint16       = 0x0119
}

public let AllocateRequest: uint16                = 0x0003
public let AllocateResponse: uint16               = 0x0103
public let AllocateErrorResponse: uint16          = 0x0113
public let RefreshRequest: uint16                 = 0x0004
public let RefreshResponse: uint16                = 0x0104
public let RefreshErrorResponse: uint16           = 0x0114
public let SendIndication: uint16                 = 0x0016
public let DataIndication: uint16                 = 0x0017
public let CreatePermissionRequest: uint16        = 0x0008
public let CreatePermissionResponse: uint16       = 0x0108
public let CreatePermissionErrorResponse: uint16  = 0x0118
public let ChannelBindRequest: uint16             = 0x0009
public let ChannelBindResponse: uint16            = 0x0109
public let ChannelBindErrorResponse: uint16       = 0x0119

// TURN Attribute Types (RFC 8656 Section 18.2)
public struct AttributeType {
    public static let ChannelNumber: uint16         = 0x000C
    public static let Lifetime: uint16              = 0x000D
    public static let XorPeerAddress: uint16        = 0x0012
    public static let Data: uint16                  = 0x0013
    public static let XorRelayedAddress: uint16     = 0x0016
    public static let RequestedTransport: uint16    = 0x0019
    public static let DontFrag: uint16              = 0x001A
    public static let ReservationToken: uint16      = 0x0022
}

public let AttrChannelNumber: uint16         = 0x000C
public let AttrLifetime: uint16              = 0x000D
public let AttrXorPeerAddress: uint16        = 0x0012
public let AttrData: uint16                  = 0x0013
public let AttrXorRelayedAddress: uint16     = 0x0016
public let AttrRequestedTransport: uint16    = 0x0019
public let AttrDontFrag: uint16              = 0x001A
public let AttrReservationToken: uint16      = 0x0022

/// Allocation represents an established TURN relay allocation on the server.
public struct Allocation {
    public var RelayedAddress: udp.SocketAddress
    public var MappedAddress: udp.SocketAddress
    public var Lifetime: uint32
    public var Realm: string
    public var Nonce: string
}

/// TurnError represents protocol, authentication, or allocation errors in TURN.
public enum TurnError: Error {
    case allocationFailed(string)
    case unauthorized(string)
    case permissionDenied(string)
    case protocolError(string)
    case timedOut(string)
    case serverError(int, string)

    public var Message: string {
        switch self {
        case .allocationFailed(let s):
            return "TURN allocation failed: \(s)"
        case .unauthorized(let s):
            return "TURN authentication failed: \(s)"
        case .permissionDenied(let s):
            return "TURN permission denied: \(s)"
        case .protocolError(let s):
            return "TURN protocol error: \(s)"
        case .timedOut(let s):
            return "TURN timed out: \(s)"
        case .serverError(let code, let msg):
            return "TURN server error \(code): \(msg)"
        }
    }
}

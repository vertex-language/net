package stun

// Magic Cookie constant as defined in RFC 8489 Section 5.
public let MagicCookie: uint32 = 0x2112A442

// Standard STUN message header size in bytes.
public let HeaderSize: int = 20

public struct Header {
    public static let Size: int = 20
    public static let MagicCookie: uint32 = 0x2112A442
}

// STUN Message Types (RFC 8489 Section 18.1)
public struct MessageType {
    public static let BindingRequest: uint16       = 0x0001
    public static let BindingIndication: uint16     = 0x0011
    public static let BindingResponse: uint16       = 0x0101
    public static let BindingErrorResponse: uint16  = 0x0111
}
public let BindingRequest: uint16       = 0x0001
public let BindingIndication: uint16     = 0x0011
public let BindingResponse: uint16       = 0x0101
public let BindingErrorResponse: uint16  = 0x0111

// STUN Attribute Types (RFC 8489 Section 18.2)
public struct AttributeType {
    public static let MappedAddress: uint16         = 0x0001
    public static let Username: uint16              = 0x0006
    public static let MessageIntegrity: uint16      = 0x0008
    public static let ErrorCode: uint16             = 0x0009
    public static let UnknownAttributes: uint16     = 0x000A
    public static let XorMappedAddress: uint16      = 0x0020
    public static let MessageIntegritySha256: uint16 = 0x001C
    public static let Fingerprint: uint16           = 0x0080
    public static let Software: uint16              = 0x8022
    public static let AlternateServer: uint16       = 0x8023
}
public let AttrMappedAddress: uint16         = 0x0001
public let AttrUsername: uint16              = 0x0006
public let AttrMessageIntegrity: uint16      = 0x0008
public let AttrErrorCode: uint16             = 0x0009
public let AttrUnknownAttributes: uint16     = 0x000A
public let AttrXorMappedAddress: uint16      = 0x0020
public let AttrMessageIntegritySha256: uint16 = 0x001C
public let AttrFingerprint: uint16           = 0x0080
public let AttrSoftware: uint16              = 0x8022
public let AttrAlternateServer: uint16       = 0x8023

/// StunError represents STUN packet parsing, encoding, or transaction failures.
public enum StunError: Error {
    case invalidHeader(string)
    case invalidMagicCookie
    case malformedAttribute(string)
    case attributeNotFound(uint16)
    case invalidFingerprint
    case transactionMismatch
    case timedOut(string)

    public var Message: string {
        switch self {
        case .invalidHeader(let s):
            return "stun: invalid header: \(s)"
        case .invalidMagicCookie:
            return "stun: invalid magic cookie (expected 0x2112A442)"
        case .malformedAttribute(let s):
            return "stun: malformed attribute: \(s)"
        case .attributeNotFound(let t):
            return "stun: attribute 0x\(t) not found"
        case .invalidFingerprint:
            return "stun: invalid fingerprint CRC32 checksum"
        case .transactionMismatch:
            return "stun: transaction ID mismatch in response"
        case .timedOut(let s):
            return "stun: operation timed out: \(s)"
        }
    }
}

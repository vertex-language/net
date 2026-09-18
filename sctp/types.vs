package sctp

public struct ChunkType {
    public static let Data: uint8 = 0
    public static let Init: uint8 = 1
    public static let InitAck: uint8 = 2
    public static let Sack: uint8 = 3
    public static let Heartbeat: uint8 = 4
    public static let HeartbeatAck: uint8 = 5
    public static let Abort: uint8 = 6
    public static let Shutdown: uint8 = 7
    public static let ShutdownAck: uint8 = 8
    public static let Error: uint8 = 9
    public static let CookieEcho: uint8 = 10
    public static let CookieAck: uint8 = 11
    public static let ShutdownComplete: uint8 = 14
    public static let Reconfig: uint8 = 130
}

public struct DataFlags {
    public static let Ending: uint8 = 0x01
    public static let Beginning: uint8 = 0x02
    public static let Unordered: uint8 = 0x04
    public static let Complete: uint8 = 0x03
}

public struct PPID {
    public static let DCEP: uint32 = 50
    public static let String: uint32 = 51
    public static let Binary: uint32 = 52
    public static let StringEmpty: uint32 = 53
    public static let BinaryEmpty: uint32 = 54
}

public struct AssociationState {
    public static let Closed: int = 0
    public static let CookieWait: int = 1
    public static let CookieEchoed: int = 2
    public static let Established: int = 3
    public static let ShutdownPending: int = 4
    public static let ShutdownSent: int = 5
    public static let ShutdownReceived: int = 6
    public static let ShutdownAckSent: int = 7
}

public enum SctpError: Error {
    case invalidPacket(string)
    case checksumMismatch(string)
    case invalidState(string)
    case streamClosed(string)
}

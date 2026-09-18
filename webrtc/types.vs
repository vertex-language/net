package webrtc

public struct RTCSignalingState {
    public static let Stable: int = 0
    public static let HaveLocalOffer: int = 1
    public static let HaveRemoteOffer: int = 2
    public static let HaveLocalPranswer: int = 3
    public static let HaveRemotePranswer: int = 4
    public static let Closed: int = 5
}

public struct RTCIceConnectionState {
    public static let New: int = 0
    public static let Checking: int = 1
    public static let Connected: int = 2
    public static let Completed: int = 3
    public static let Failed: int = 4
    public static let Disconnected: int = 5
    public static let Closed: int = 6
}

public struct RTCPeerConnectionState {
    public static let New: int = 0
    public static let Connecting: int = 1
    public static let Connected: int = 2
    public static let Disconnected: int = 3
    public static let Failed: int = 4
    public static let Closed: int = 5
}

public struct RTCSdpType {
    public static let Offer: string = "offer"
    public static let Answer: string = "answer"
    public static let Pranswer: string = "pranswer"
    public static let Rollback: string = "rollback"
}

public struct RTCSessionDescription {
    public var Type: string
    public var Sdp: string

    public init(type: string, sdp: string) {
        self.Type = type
        self.Sdp = sdp
    }
}

public struct RTCDataChannelState {
    public static let Connecting: int = 0
    public static let Open: int = 1
    public static let Closing: int = 2
    public static let Closed: int = 3
}

public struct RTCIceServer {
    public var Urls: [string]
    public var Username: string
    public var Credential: string

    public init(urls: [string]) {
        self.Urls = urls
        self.Username = ""
        self.Credential = ""
    }

    public init(urls: [string], username: string, credential: string) {
        self.Urls = urls
        self.Username = username
        self.Credential = credential
    }
}

public struct RTCConfiguration {
    public var IceServers: [RTCIceServer]

    public init(iceServers: [RTCIceServer] = []) {
        self.IceServers = iceServers
    }
}

public enum WebRtcError: Error {
    case invalidState(string)
    case invalidSdp(string)
    case handshakeFailed(string)
}

public struct InboundKind {
    public static let None: int = 0
    public static let Text: int = 1
    public static let Binary: int = 2
    public static let AckResponseNeeded: int = 3
}

public struct RTCInboundKind {
    public static let None: int = 0
    public static let Text: int = 1
    public static let Binary: int = 2
    public static let AckResponseNeeded: int = 3
}


package ice

import "net/udp"

// Candidate Types (RFC 8445 Section 5.1.1)
public struct CandidateType {
    public static let Host: string            = "host"
    public static let ServerReflexive: string = "srflx"
    public static let PeerReflexive: string   = "prflx"
    public static let Relay: string           = "relay"
}

/// Computes the candidate priority according to RFC 8445 Section 5.1.2:
/// priority = (2^24 * type_pref) + (2^8 * local_pref) + (256 - component_id)
public func CalculatePriority(type: string, localPref: uint16 = 65535, component: uint16 = 1) -> uint32 {
    var typePref: uint32 = 0
    if type == CandidateType.Host {
        typePref = 126
    } else if type == CandidateType.PeerReflexive {
        typePref = 110
    } else if type == CandidateType.ServerReflexive {
        typePref = 100
    } else if type == CandidateType.Relay {
        typePref = 0
    }

    let pType = typePref << 24
    let pLocal = uint32(localPref) << 8
    let pComp = uint32(256 - int(component))
    return pType | pLocal | pComp
}

/// Candidate represents an ICE transport address candidate (RFC 8445 / RFC 8839).
public struct Candidate {
    public var Foundation: string
    public var Component: uint16
    public var Protocol: string
    public var Priority: uint32
    public var Address: udp.SocketAddress
    public var Type: string
    public var RelatedAddress: string
    public var RelatedPort: uint16

    /// Formats the candidate as an RFC 8839 SDP attribute line:
    /// candidate:<foundation> <component> <transport> <priority> <ip> <port> typ <type> ...
    public func ToSDP() -> string {
        var ip = ""
        var port: uint16 = 0
        switch self.Address {
        case .v4(let i, let p):
            ip = i
            port = p
        case .v6(let i, let p):
            ip = i
            port = p
        }

        var sdp = "candidate:\(self.Foundation) \(self.Component) \(self.Protocol) \(self.Priority) \(ip) \(port) typ \(self.Type)"
        if !self.RelatedAddress.isEmpty && self.RelatedPort > 0 {
            sdp = "\(sdp) raddr \(self.RelatedAddress) rport \(self.RelatedPort)"
        }
        return sdp
    }
}

/// Creates a new Host candidate.
public func NewHostCandidate(foundation: string,
                             address: udp.SocketAddress,
                             localPref: uint16 = 65535,
                             component: uint16 = 1) -> Candidate {
    let prio = CalculatePriority(type: CandidateType.Host, localPref: localPref, component: component)
    return Candidate(
        Foundation: foundation,
        Component: component,
        Protocol: "UDP",
        Priority: prio,
        Address: address,
        Type: CandidateType.Host,
        RelatedAddress: "",
        RelatedPort: 0
    )
}

/// Creates a new Server Reflexive candidate.
public func NewServerReflexiveCandidate(foundation: string,
                                       address: udp.SocketAddress,
                                       relatedAddress: udp.SocketAddress,
                                       localPref: uint16 = 65535,
                                       component: uint16 = 1) -> Candidate {
    let prio = CalculatePriority(type: CandidateType.ServerReflexive, localPref: localPref, component: component)
    var relIp = ""
    var relPort: uint16 = 0
    switch relatedAddress {
    case .v4(let i, let p):
        relIp = i
        relPort = p
    case .v6(let i, let p):
        relIp = i
        relPort = p
    }
    return Candidate(
        Foundation: foundation,
        Component: component,
        Protocol: "UDP",
        Priority: prio,
        Address: address,
        Type: CandidateType.ServerReflexive,
        RelatedAddress: relIp,
        RelatedPort: relPort
    )
}

/// Creates a new Relay candidate.
public func NewRelayCandidate(foundation: string,
                              address: udp.SocketAddress,
                              relatedAddress: udp.SocketAddress,
                              localPref: uint16 = 65535,
                              component: uint16 = 1) -> Candidate {
    let prio = CalculatePriority(type: CandidateType.Relay, localPref: localPref, component: component)
    var relIp = ""
    var relPort: uint16 = 0
    switch relatedAddress {
    case .v4(let i, let p):
        relIp = i
        relPort = p
    case .v6(let i, let p):
        relIp = i
        relPort = p
    }
    return Candidate(
        Foundation: foundation,
        Component: component,
        Protocol: "UDP",
        Priority: prio,
        Address: address,
        Type: CandidateType.Relay,
        RelatedAddress: relIp,
        RelatedPort: relPort
    )
}

/// Parses an RFC 8839 / RFC 8445 candidate attribute line from an SDP description.
public func ParseSDPLine(_ line: string) -> Candidate? {
    var raw = line
    // Strip leading "a=" and/or "candidate:" if present
    var stripped = true
    while stripped {
        stripped = false
        if raw.hasPrefix("a=") {
            var bytes: [uint8] = []
            for b in raw.utf8 { bytes.append(b) }
            var slice: [uint8] = []
            var i = 2
            while i < bytes.count { slice.append(bytes[i]); i += 1 }
            raw = string(decoding: slice, as: UTF8.self)
            stripped = true
        }
        if raw.hasPrefix("candidate:") {
            var bytes: [uint8] = []
            for b in raw.utf8 { bytes.append(b) }
            var slice: [uint8] = []
            var i = 10
            while i < bytes.count { slice.append(bytes[i]); i += 1 }
            raw = string(decoding: slice, as: UTF8.self)
            stripped = true
        }
    }

    // Tokenize by space
    var tokens: [string] = []
    var curToken: [uint8] = []
    for b in raw.utf8 {
        if b == 32 { // space
            if !curToken.isEmpty {
                tokens.append(string(decoding: curToken, as: UTF8.self))
                curToken.removeAll()
            }
        } else {
            curToken.append(b)
        }
    }
    if !curToken.isEmpty {
        tokens.append(string(decoding: curToken, as: UTF8.self))
    }

    // Expected tokens:
    // [0]: foundation
    // [1]: component (1)
    // [2]: protocol (UDP)
    // [3]: priority
    // [4]: ip
    // [5]: port
    // [6]: "typ"
    // [7]: type ("host" / "srflx" / "relay")
    if tokens.count < 8 {
        return nil
    }

    let foundation = tokens[0]
    let comp = uint16(Int(tokens[1]) ?? 1)
    let proto = tokens[2]
    let prio = uint32(Int(tokens[3]) ?? 0)
    let ip = tokens[4]
    let port = uint16(Int(tokens[5]) ?? 0)
    let cType = tokens[7]

    var raddr = ""
    var rport: uint16 = 0

    var idx = 8
    while idx + 1 < tokens.count {
        if tokens[idx] == "raddr" {
            raddr = tokens[idx + 1]
        } else if tokens[idx] == "rport" {
            rport = uint16(Int(tokens[idx + 1]) ?? 0)
        }
        idx += 2
    }

    let addr = udp.SocketAddress.v4(ip: ip, port: port)
    return Candidate(
        Foundation: foundation,
        Component: comp,
        Protocol: proto,
        Priority: prio,
        Address: addr,
        Type: cType,
        RelatedAddress: raddr,
        RelatedPort: rport
    )
}

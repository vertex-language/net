package webrtc

import "net/ice"

/// ParsedSdp contains structured fields extracted from an SDP description.
public struct ParsedSdp {
    public var Type: string
    public var Ufrag: string
    public var Pwd: string
    public var Fingerprint: string
    public var Setup: string
    public var SctpPort: uint16
    public var Candidates: [ice.Candidate]
}

/// BuildSdp constructs an RFC 8866 / RFC 8839 compliant SDP description for WebRTC DataChannels.
public func BuildSdp(type: string,
                     ufrag: string,
                     pwd: string,
                     fingerprint: string,
                     setup: string,
                     sctpPort: uint16,
                     candidates: [ice.Candidate]) -> string {
    var buf: [uint8] = []
    func appendStr(_ s: string) {
        for b in s.utf8 {
            buf.append(b)
        }
    }

    appendStr("v=0\r\n")
    appendStr("o=- 1234567890 2 IN IP4 127.0.0.1\r\n")
    appendStr("s=-\r\n")
    appendStr("t=0 0\r\n")
    appendStr("a=group:BUNDLE 0\r\n")
    appendStr("a=msid-semantic: WMS\r\n")
    appendStr("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
    appendStr("c=IN IP4 0.0.0.0\r\n")
    appendStr("a=ice-ufrag:" + ufrag + "\r\n")
    appendStr("a=ice-pwd:" + pwd + "\r\n")
    appendStr("a=ice-options:trickle\r\n")
    if !fingerprint.isEmpty {
        appendStr("a=fingerprint:sha-256 " + fingerprint + "\r\n")
    }
    appendStr("a=setup:" + setup + "\r\n")
    appendStr("a=mid:0\r\n")
    appendStr("a=sctp-port:\(sctpPort)\r\n")
    appendStr("a=max-message-size:262144\r\n")

    var i = 0
    while i < candidates.count {
        let c = candidates[i]
        appendStr("a=" + c.ToSDP() + "\r\n")
        i += 1
    }

    return string(decoding: buf, as: UTF8.self)
}

/// ParseSdp parses a WebRTC SDP string into structured fields.
public func ParseSdp(_ sdp: string, type: string) throws -> ParsedSdp {
    var ufrag = ""
    var pwd = ""
    var fp = ""
    var setup = ""
    var sctpPort: uint16 = 5000
    var candidates: [ice.Candidate] = []

    // Split lines by '\n'
    var lines: [string] = []
    var curLine: [uint8] = []
    for b in sdp.utf8 {
        if b == 13 {
            // skip '\r'
        } else if b == 10 { // '\n'
            lines.append(string(decoding: curLine, as: UTF8.self))
            curLine.removeAll()
        } else {
            curLine.append(b)
        }
    }
    if !curLine.isEmpty {
        lines.append(string(decoding: curLine, as: UTF8.self))
    }

    var i = 0
    while i < lines.count {
        let line = lines[i]

        if line.hasPrefix("a=ice-ufrag:") {
            var bytes: [uint8] = []
            for b in line.utf8 { bytes.append(b) }
            var sub: [uint8] = []
            var j = 12
            while j < bytes.count { sub.append(bytes[j]); j += 1 }
            ufrag = string(decoding: sub, as: UTF8.self)
        } else if line.hasPrefix("a=ice-pwd:") {
            var bytes: [uint8] = []
            for b in line.utf8 { bytes.append(b) }
            var sub: [uint8] = []
            var j = 10
            while j < bytes.count { sub.append(bytes[j]); j += 1 }
            pwd = string(decoding: sub, as: UTF8.self)
        } else if line.hasPrefix("a=fingerprint:sha-256 ") {
            var bytes: [uint8] = []
            for b in line.utf8 { bytes.append(b) }
            var sub: [uint8] = []
            var j = 22
            while j < bytes.count { sub.append(bytes[j]); j += 1 }
            fp = string(decoding: sub, as: UTF8.self)
        } else if line.hasPrefix("a=setup:") {
            var bytes: [uint8] = []
            for b in line.utf8 { bytes.append(b) }
            var sub: [uint8] = []
            var j = 8
            while j < bytes.count { sub.append(bytes[j]); j += 1 }
            setup = string(decoding: sub, as: UTF8.self)
        } else if line.hasPrefix("a=sctp-port:") {
            var bytes: [uint8] = []
            for b in line.utf8 { bytes.append(b) }
            var sub: [uint8] = []
            var j = 12
            while j < bytes.count { sub.append(bytes[j]); j += 1 }
            let portStr = string(decoding: sub, as: UTF8.self)
            sctpPort = uint16(Int(portStr) ?? 5000)
        } else if line.hasPrefix("a=candidate:") {
            if let cand = ice.ParseSDPLine(line) {
                candidates.append(cand)
            }
        }

        i += 1
    }

    return ParsedSdp(
        Type: type,
        Ufrag: ufrag,
        Pwd: pwd,
        Fingerprint: fp,
        Setup: setup,
        SctpPort: sctpPort,
        Candidates: candidates
    )
}

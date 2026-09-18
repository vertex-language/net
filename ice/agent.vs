package ice

import "net/udp"
import "net/stun"
import "crypto/rand"

// ICE Roles (RFC 8445 Section 6.1.1)
public struct IceRole {
    public static let Controlling: string = "controlling"
    public static let Controlled: string  = "controlled"
}

// ICE Connection States (RFC 8445 Section 6.1.2.6)
public struct IceConnectionState {
    public static let New: string         = "new"
    public static let Checking: string    = "checking"
    public static let Connected: string   = "connected"
    public static let Completed: string   = "completed"
    public static let Failed: string      = "failed"
    public static let Closed: string      = "closed"
}

public enum IceError: Error {
    case noCandidates
    case connectivityFailed
    case protocolError(string)
    case timedOut(string)

    public var Message: string {
        switch self {
        case .noCandidates:
            return "ICE error: no candidates available to form pairs"
        case .connectivityFailed:
            return "ICE error: connectivity checks failed across all candidate pairs"
        case .protocolError(let s):
            return "ICE protocol error: \(s)"
        case .timedOut(let s):
            return "ICE timed out: \(s)"
        }
    }
}

func randomAlphanumeric(length: int) -> string {
    let chars: [uint8] = [
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
        110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77,
        78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57
    ]
    var res: [uint8] = []
    if let rnd = try? rand.Bytes(length) {
        var i = 0
        while i < length {
            res.append(chars[int(rnd[i]) % chars.count])
            i += 1
        }
        return string(decoding: res, as: UTF8.self)
    }
    var i = 0
    while i < length {
        res.append(chars[(i * 17 + 7) % chars.count])
        i += 1
    }
    return string(decoding: res, as: UTF8.self)
}

/// Demultiplexes STUN packets from application media or data (RFC 7983 Section 4).
func isStunPacket(_ raw: [uint8]) -> bool {
    if raw.count < 20 { return false }
    if (raw[0] & 0xC0) != 0 { return false }
    let cookie = (uint32(raw[4]) << 24) | (uint32(raw[5]) << 16) | (uint32(raw[6]) << 8) | uint32(raw[7])
    return cookie == 0x2112A442
}

func stringToBytes(_ s: string) -> [uint8] {
    var b: [uint8] = []
    for byte in s.utf8 { b.append(byte) }
    return b
}

/// Agent conducts Interactive Connectivity Establishment (RFC 8445 & RFC 8838 Trickle ICE).
public struct Agent {
    public var Socket: udp.UdpSocket
    public var Role: string
    public var TieBreaker: uint64
    public var LocalUfrag: string
    public var LocalPwd: string
    public var RemoteUfrag: string
    public var RemotePwd: string
    public var LocalCandidates: [Candidate]
    public var RemoteCandidates: [Candidate]
    public var Pairs: [CandidatePair]
    public var SelectedPair: CandidatePair
    public var HasSelectedPair: bool
    public var State: string

    /// Adds a remote candidate received via signaling / Trickle ICE (RFC 8838).
    public mutating func AddRemoteCandidate(_ cand: Candidate) {
        self.RemoteCandidates.append(cand)
    }

    /// Sets the remote peer's ICE username fragment and password.
    public mutating func SetRemoteCredentials(ufrag: string, pwd: string) {
        self.RemoteUfrag = ufrag
        self.RemotePwd = pwd
    }

    /// Forms all valid candidate pairs and sorts them by priority descending (RFC 8445 Section 6.1.2).
    public mutating func FormPairs() {
        self.Pairs.removeAll()
        let isControlling = (self.Role == IceRole.Controlling)

        var li = 0
        while li < self.LocalCandidates.count {
            let localCand = self.LocalCandidates[li]
            var ri = 0
            while ri < self.RemoteCandidates.count {
                let remoteCand = self.RemoteCandidates[ri]
                let pair = NewCandidatePair(local: localCand, remote: remoteCand, isControlling: isControlling)
                self.Pairs.append(pair)
                ri += 1
            }
            li += 1
        }

        // Sort pairs in descending order of pair priority
        var i = 0
        while i < self.Pairs.count {
            var j = i + 1
            while j < self.Pairs.count {
                if self.Pairs[j].Priority > self.Pairs[i].Priority {
                    let tmp = self.Pairs[i]
                    self.Pairs[i] = self.Pairs[j]
                    self.Pairs[j] = tmp
                }
                j += 1
            }
            i += 1
        }
    }

    /// Runs the ICE connectivity check phase (RFC 8445 Section 7).
    public mutating func Connect(timeoutMs: int32 = 4000) async throws {
        self.State = IceConnectionState.Checking
        FormPairs()

        if self.Pairs.isEmpty {
            self.State = IceConnectionState.Failed
            throw IceError.noCandidates
        }

        let isControlling = (self.Role == IceRole.Controlling)
        let remoteKey = stringToBytes(self.RemotePwd)
        let localKey = stringToBytes(self.LocalPwd)

        // Connectivity check loop: probe top pairs
        var pIdx = 0
        while pIdx < self.Pairs.count {
            let pair = self.Pairs[pIdx]

            // Construct STUN Binding Request for this pair check
            var req = stun.Message(type: stun.MessageType.BindingRequest)
            let checkUsername = "\(self.RemoteUfrag):\(self.LocalUfrag)"
            req.AddAttribute(stun.MakeUsername(checkUsername))
            req.AddAttribute(stun.MakePriority(pair.Local.Priority))

            if isControlling {
                req.AddAttribute(stun.MakeIceControlling(self.TieBreaker))
                req.AddAttribute(stun.MakeUseCandidate()) // Nominate pair
            } else {
                req.AddAttribute(stun.MakeIceControlled(self.TieBreaker))
            }

            req.AddMessageIntegrity(key: remoteKey)
            req.AddFingerprint()

            // Send check
            _ = try await Socket.SendTo(req.Encode(), to: pair.Remote.Address)

            // Listen for STUN check responses or incoming checks from remote peer
            var buf = [uint8](repeating: 0, count: 1500)
            var attempts = 0
            while attempts < 10 {
                let (n, from) = try await Socket.ReceiveFrom(into: &buf)
                if n > 0 {
                    var raw: [uint8] = []
                    var bi = 0
                    while bi < n { raw.append(buf[bi]); bi += 1 }

                    if isStunPacket(raw) {
                        if let msg = try? stun.Message.Decode(raw) {
                            if msg.Type == stun.MessageType.BindingResponse {
                                // STUN Check Succeeded!
                                var winningPair = pair
                                winningPair.State = PairState.Succeeded
                                winningPair.Nominated = true
                                self.SelectedPair = winningPair
                                self.HasSelectedPair = true
                                winningPair.State = PairState.Succeeded
                                winningPair.Nominated = true
                                self.SelectedPair = winningPair
                                self.HasSelectedPair = true
                                self.State = IceConnectionState.Connected
                                return
                            } else if msg.Type == stun.MessageType.BindingRequest {
                                // Answer peer's connectivity check
                                var resp = stun.Message(type: stun.MessageType.BindingResponse, transactionId: msg.TransactionId)
                                resp.AddAttribute(stun.MakeXorMappedAddress(address: from, transactionId: msg.TransactionId))
                                resp.AddMessageIntegrity(key: localKey)
                                resp.AddFingerprint()
                                _ = try await Socket.SendTo(resp.Encode(), to: from)

                                if !isControlling {
                                    // Controlled agent received check with USE-CANDIDATE nomination
                                    if msg.GetAttribute(stun.AttributeType.UseCandidate) != nil {
                                        var winningPair = pair
                                        winningPair.State = PairState.Succeeded
                                        winningPair.Nominated = true
                                        self.SelectedPair = winningPair
                                        self.HasSelectedPair = true
                                        self.State = IceConnectionState.Connected
                                        return
                                    }
                                }
                            }
                        }
                    }
                }
                attempts += 1
            }
            pIdx += 1
        }

        if !self.HasSelectedPair {
            self.State = IceConnectionState.Failed
            throw IceError.connectivityFailed
        }
    }

    /// Sends application payload over the nominated ICE candidate pair.
    public func Send(_ data: [uint8]) async throws {
        if !self.HasSelectedPair {
            throw IceError.connectivityFailed
        }
        _ = try await Socket.SendTo(data, to: self.SelectedPair.Remote.Address)
    }

    /// Receives application payload, automatically responding to STUN consent checks (RFC 7675).
    public func Receive() async throws -> [uint8] {
        if !self.HasSelectedPair {
            throw IceError.connectivityFailed
        }

        var buf = [uint8](repeating: 0, count: 1500)
        let localKey = stringToBytes(self.LocalPwd)

        while true {
            let (n, from) = try await Socket.ReceiveFrom(into: &buf)
            if n > 0 {
                var raw: [uint8] = []
                var i = 0
                while i < n { raw.append(buf[i]); i += 1 }

                if isStunPacket(raw) {
                    // STUN Consent Freshness check (RFC 7675)
                    if let msg = try? stun.Message.Decode(raw) {
                        if msg.Type == stun.MessageType.BindingRequest {
                            var resp = stun.Message(type: stun.MessageType.BindingResponse, transactionId: msg.TransactionId)
                            resp.AddAttribute(stun.MakeXorMappedAddress(address: from, transactionId: msg.TransactionId))
                            resp.AddMessageIntegrity(key: localKey)
                            resp.AddFingerprint()
                            _ = try await Socket.SendTo(resp.Encode(), to: from)
                        }
                    }
                } else {
                    // Application data packet
                    return raw
                }
            }
        }
    }
}

/// Creates a new ICE Agent initialized with local credentials and host candidates.
public func NewAgent(socket: udp.UdpSocket,
                     role: string = IceRole.Controlling,
                     localCandidates: [Candidate] = [],
                     ufrag: string = "",
                     pwd: string = "") -> Agent {
    let finalUfrag = ufrag.isEmpty ? randomAlphanumeric(length: 8) : ufrag
    let finalPwd = pwd.isEmpty ? randomAlphanumeric(length: 24) : pwd

    let dummyCand = Candidate(
        Foundation: "",
        Component: 1,
        Protocol: "UDP",
        Priority: 0,
        Address: .v4(ip: "0.0.0.0", port: 0),
        Type: "host",
        RelatedAddress: "",
        RelatedPort: 0
    )

    let dummyPair = CandidatePair(
        Local: dummyCand,
        Remote: dummyCand,
        Priority: 0,
        State: PairState.Waiting,
        Nominated: false
    )

    return Agent(
        Socket: socket,
        Role: role,
        TieBreaker: 0x123456789ABCDEF0,
        LocalUfrag: finalUfrag,
        LocalPwd: finalPwd,
        RemoteUfrag: "",
        RemotePwd: "",
        LocalCandidates: localCandidates,
        RemoteCandidates: [],
        Pairs: [],
        SelectedPair: dummyPair,
        HasSelectedPair: false,
        State: IceConnectionState.New
    )
}

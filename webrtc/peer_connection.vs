package webrtc

import "net/udp"
import "net/ice"
import "net/sctp"
import "net/datachannel"
import "crypto/dtls"

/// RTCPeerConnection represents a WebRTC peer connection coordinating ICE, DTLS, SCTP, and DataChannels (RFC 9429 / W3C).
public struct RTCPeerConnection {
    public var SignalingState: int
    public var IceConnectionState: int
    public var ConnectionState: int
    public var Configuration: RTCConfiguration

    public var LocalUfrag: string
    public var LocalPwd: string
    public var RemoteUfrag: string
    public var RemotePwd: string

    public var LocalFingerprint: string
    public var RemoteFingerprint: string

    public var LocalDescription: RTCSessionDescription
    public var RemoteDescription: RTCSessionDescription
    public var HasLocalDescription: bool
    public var HasRemoteDescription: bool

    public var IceAgent: ice.Agent
    public var SctpAssoc: sctp.Association
    public var DataChannels: [datachannel.RTCDataChannel]
    public var NextChannelId: uint16

    public var DtlsCipher: dtls.RecordCipher
    public var DtlsDecipher: dtls.RecordCipher

    public init(socket: udp.UdpSocket, configuration: RTCConfiguration) {
        self.SignalingState = RTCSignalingState.Stable
        self.IceConnectionState = RTCIceConnectionState.New
        self.ConnectionState = RTCPeerConnectionState.New
        self.Configuration = configuration

        self.LocalUfrag = "vs-ufrag-42"
        self.LocalPwd = "vs-ice-pwd-9876543210"
        self.RemoteUfrag = ""
        self.RemotePwd = ""

        let certBytes = [uint8](repeating: 0x5a, count: 64)
        self.LocalFingerprint = dtls.CalculateFingerprint(certBytes)
        self.RemoteFingerprint = ""

        self.LocalDescription = RTCSessionDescription(type: "", sdp: "")
        self.RemoteDescription = RTCSessionDescription(type: "", sdp: "")
        self.HasLocalDescription = false
        self.HasRemoteDescription = false

        let hostCand = ice.NewHostCandidate(foundation: "1", address: .v4(ip: "127.0.0.1", port: 50000))
        self.IceAgent = ice.NewAgent(
            socket: socket,
            role: ice.IceRole.Controlling,
            localCandidates: [hostCand],
            ufrag: self.LocalUfrag,
            pwd: self.LocalPwd
        )

        self.SctpAssoc = sctp.Association(localPort: 5000, remotePort: 5000)
        self.DataChannels = []
        self.NextChannelId = 0

        let defaultKey = [uint8](repeating: 0x77, count: 32)
        let defaultIv = [uint8](repeating: 0x88, count: 12)
        self.DtlsCipher = dtls.RecordCipher(key: defaultKey, iv: defaultIv, epoch: 1)
        self.DtlsDecipher = dtls.RecordCipher(key: defaultKey, iv: defaultIv, epoch: 1)
    }

    /// Creates an RFC 8866 / RFC 9429 SDP offer.
    public mutating func CreateOffer() throws -> RTCSessionDescription {
        if self.SignalingState != RTCSignalingState.Stable {
            throw WebRtcError.invalidState("CreateOffer requires Stable signaling state")
        }

        let sdp = BuildSdp(
            type: RTCSdpType.Offer,
            ufrag: self.LocalUfrag,
            pwd: self.LocalPwd,
            fingerprint: self.LocalFingerprint,
            setup: "actpass",
            sctpPort: 5000,
            candidates: self.IceAgent.LocalCandidates
        )

        self.SignalingState = RTCSignalingState.HaveLocalOffer
        self.LocalDescription = RTCSessionDescription(type: RTCSdpType.Offer, sdp: sdp)
        self.HasLocalDescription = true
        return self.LocalDescription
    }

    /// Creates an RFC 8866 / RFC 9429 SDP answer in response to a remote offer.
    public mutating func CreateAnswer() throws -> RTCSessionDescription {
        if self.SignalingState != RTCSignalingState.HaveRemoteOffer {
            throw WebRtcError.invalidState("CreateAnswer requires HaveRemoteOffer signaling state")
        }

        let sdp = BuildSdp(
            type: RTCSdpType.Answer,
            ufrag: self.LocalUfrag,
            pwd: self.LocalPwd,
            fingerprint: self.LocalFingerprint,
            setup: "active",
            sctpPort: 5000,
            candidates: self.IceAgent.LocalCandidates
        )

        self.LocalDescription = RTCSessionDescription(type: RTCSdpType.Answer, sdp: sdp)
        self.HasLocalDescription = true
        return self.LocalDescription
    }

    /// Sets the local description on the peer connection.
    public mutating func SetLocalDescription(_ desc: RTCSessionDescription) throws {
        self.LocalDescription = desc
        self.HasLocalDescription = true

        if desc.Type == RTCSdpType.Offer {
            self.SignalingState = RTCSignalingState.HaveLocalOffer
        } else if desc.Type == RTCSdpType.Answer {
            self.SignalingState = RTCSignalingState.Stable
        }
    }

    /// Sets the remote description on the peer connection and parses candidates/credentials.
    public mutating func SetRemoteDescription(_ desc: RTCSessionDescription) throws {
        let parsed = try ParseSdp(desc.Sdp, type: desc.Type)
        self.RemoteUfrag = parsed.Ufrag
        self.RemotePwd = parsed.Pwd
        self.RemoteFingerprint = parsed.Fingerprint

        self.RemoteDescription = desc
        self.HasRemoteDescription = true

        var agent = self.IceAgent
        agent.SetRemoteCredentials(ufrag: parsed.Ufrag, pwd: parsed.Pwd)
        self.IceAgent = agent

        if desc.Type == RTCSdpType.Offer {
            self.SignalingState = RTCSignalingState.HaveRemoteOffer
        } else if desc.Type == RTCSdpType.Answer {
            self.SignalingState = RTCSignalingState.Stable
        }
    }

    /// Adds a remote Trickle ICE candidate.
    public mutating func AddIceCandidate(_ candidate: ice.Candidate) {
        var agent = self.IceAgent
        agent.AddRemoteCandidate(candidate)
        self.IceAgent = agent
    }

    /// Creates a new RTCDataChannel on this peer connection.
    public mutating func CreateDataChannel(label: string, options: datachannel.RTCDataChannelInit) -> datachannel.RTCDataChannel {
        let channelId = self.NextChannelId
        self.NextChannelId += 1

        var opts = options
        opts.Id = channelId
        let dc = datachannel.RTCDataChannel(id: channelId, label: label, options: opts)
        self.DataChannels.append(dc)
        return dc
    }

    /// Creates a new RTCDataChannel with default options.
    public mutating func CreateDataChannel(label: string) -> datachannel.RTCDataChannel {
        return self.CreateDataChannel(label: label, options: datachannel.RTCDataChannelInit())
    }

    /// Updates the state of a registered DataChannel.
    public mutating func SetDataChannelState(channelId: uint16, state: int) {
        let idx = int(channelId)
        if idx < self.DataChannels.count {
            var dc = self.DataChannels[idx]
            dc.ReadyState = state
            self.DataChannels[idx] = dc
        }
    }

    /// Encapsulates a DataChannel text message through SCTP and DTLS 1.3 encryption.
    public mutating func ProtectTextMessage(channelId: uint16, text: string) throws -> [uint8] {
        let cIdx = int(channelId)
        if cIdx >= self.DataChannels.count {
            throw WebRtcError.invalidState("Invalid DataChannel id")
        }

        let outMsg = try self.DataChannels[cIdx].Send(text: text)

        var assoc = self.SctpAssoc
        let sctpBytes = assoc.SendData(
            streamId: outMsg.StreamId,
            ppid: outMsg.PPID,
            payload: outMsg.Payload,
            unordered: outMsg.Unordered
        )
        self.SctpAssoc = assoc

        // Encrypt with DTLS 1.3 Record Layer (ContentType.ApplicationData = 23)
        var cipher = self.DtlsCipher
        let encBytes = try cipher.Encrypt(contentType: dtls.ContentType.ApplicationData, plaintext: sctpBytes)
        self.DtlsCipher = cipher

        return encBytes
    }

    /// Decapsulates and decrypts a received datagram through DTLS 1.3, SCTP, and DataChannel.
    public mutating func ProcessIncomingDatagram(_ datagram: [uint8]) throws -> [datachannel.DataChannelInboundResult] {
        // 1. Decrypt DTLS datagram record
        var decipher = self.DtlsDecipher
        let decRecord = try decipher.Decrypt(record: datagram)
        self.DtlsDecipher = decipher

        // 2. Feed decrypted SCTP payload into SCTP association
        var assoc = self.SctpAssoc
        var sctpResp = try assoc.HandlePacket(decRecord.Data)

        // 3. Read delivered stream messages
        let delivered = assoc.ReadDelivered()
        self.SctpAssoc = assoc

        var results: [datachannel.DataChannelInboundResult] = []

        var i = 0
        while i < delivered.count {
            let msg = delivered[i]
            let sId = int(msg.StreamId)
            while self.DataChannels.count <= sId {
                // Synthesize inbound remote channel
                self.DataChannels.append(datachannel.RTCDataChannel(id: msg.StreamId, label: ""))
            }

            var dc = self.DataChannels[sId]
            let res = try dc.HandleInbound(ppid: msg.PPID, data: msg.Payload)
            self.DataChannels[sId] = dc
            results.append(res)
            i += 1
        }

        return results
    }

    /// Establishes the peer connection state to Connected.
    public mutating func SetConnected() {
        self.IceConnectionState = RTCIceConnectionState.Connected
        self.ConnectionState = RTCPeerConnectionState.Connected
    }

    /// Closes the peer connection and releases resources.
    public mutating func Close() {
        self.SignalingState = RTCSignalingState.Closed
        self.IceConnectionState = RTCIceConnectionState.Closed
        self.ConnectionState = RTCPeerConnectionState.Closed
        var agent = self.IceAgent
        agent.Socket.Close()
        self.IceAgent = agent
        var i = 0
        while i < self.DataChannels.count {
            var dc = self.DataChannels[i]
            dc.Close()
            self.DataChannels[i] = dc
            i += 1
        }
    }
}

/// Creates a new RTCPeerConnection configured with ICE Agent, DTLS ciphers, and SCTP association.
public func NewPeerConnection(socket: udp.UdpSocket, configuration: RTCConfiguration) -> RTCPeerConnection {
    return RTCPeerConnection(socket: socket, configuration: configuration)
}


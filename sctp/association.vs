package sctp

import "crypto/rand"

/// ReceivedMessage represents reassembled payload delivered from an SCTP stream.
public struct ReceivedMessage {
    public var StreamId: uint16
    public var PPID: uint32
    public var Payload: [uint8]

    public init(streamId: uint16, ppid: uint32, payload: [uint8]) {
        self.StreamId = streamId
        self.PPID = ppid
        self.Payload = payload
    }
}

/// Association manages the state, streams, and TSN sequencing of an SCTP connection (RFC 4960 / RFC 8261).
public struct Association {
    public var LocalPort: uint16
    public var RemotePort: uint16
    public var MyInitiateTag: uint32
    public var PeerInitiateTag: uint32
    public var State: int

    public var MyInitialTSN: uint32
    public var NextTSN: uint32
    public var PeerInitialTSN: uint32
    public var CumulativePeerTSN: uint32
    public var PeerTSNInitialized: bool

    public var OutboundStreams: uint16
    public var InboundStreams: uint16
    public var a_rwnd: uint32

    // Stream sequence counters: map streamId -> next SSN
    var streamSeqs: [uint16]

    // Inbound received messages queue
    var inboundQueue: [ReceivedMessage]

    public init(localPort: uint16 = 5000,
                remotePort: uint16 = 5000,
                maxStreams: uint16 = 256) {
        self.LocalPort = localPort
        self.RemotePort = remotePort
        self.MyInitiateTag = 0x1a2b3c4d // can be randomized
        self.PeerInitiateTag = 0
        self.State = AssociationState.Closed
        self.MyInitialTSN = 1000
        self.NextTSN = 1000
        self.PeerInitialTSN = 0
        self.CumulativePeerTSN = 0
        self.PeerTSNInitialized = false
        self.OutboundStreams = maxStreams
        self.InboundStreams = maxStreams
        self.a_rwnd = 1048576 // 1MB receive buffer

        self.streamSeqs = [uint16](repeating: 0, count: int(maxStreams))
        self.inboundQueue = []
    }

    /// InitHandshake generates the INIT packet to initiate an SCTP association.
    public mutating func InitHandshake() -> [uint8] {
        self.State = AssociationState.CookieWait
        let initChunk = InitChunk(
            initiateTag: self.MyInitiateTag,
            a_rwnd: self.a_rwnd,
            outboundStreams: self.OutboundStreams,
            inboundStreams: self.InboundStreams,
            initialTSN: self.MyInitialTSN
        )
        let pkt = Packet(
            sourcePort: self.LocalPort,
            destinationPort: self.RemotePort,
            verificationTag: 0, // Verification Tag is 0 in INIT
            chunks: [initChunk.ToRawChunk()]
        )
        return pkt.Serialize()
    }

    /// SendData creates an SCTP packet containing a DATA chunk for the specified stream and PPID.
    public mutating func SendData(streamId: uint16, ppid: uint32, payload: [uint8], unordered: bool = false) -> [uint8] {
        let tsn = self.NextTSN
        self.NextTSN += 1

        var ssn: uint16 = 0
        let sIdx = int(streamId)
        if !unordered {
            while self.streamSeqs.count <= sIdx {
                self.streamSeqs.append(0)
            }
            ssn = self.streamSeqs[sIdx]
            self.streamSeqs[sIdx] += 1
        }

        var flags = DataFlags.Complete
        if unordered {
            flags = flags | DataFlags.Unordered
        }

        let dataChunk = DataChunk(
            flags: flags,
            tsn: tsn,
            streamId: streamId,
            streamSeq: ssn,
            ppid: ppid,
            userData: payload
        )

        let pkt = Packet(
            sourcePort: self.LocalPort,
            destinationPort: self.RemotePort,
            verificationTag: self.PeerInitiateTag,
            chunks: [dataChunk.ToRawChunk()]
        )
        return pkt.Serialize()
    }

    /// HandlePacket processes an incoming serialized SCTP packet and returns response bytes to send (if any).
    public mutating func HandlePacket(_ data: [uint8]) throws -> [uint8] {
        let pkt = try Packet.Parse(data)
        var responseChunks: [RawChunk] = []

        var i = 0
        while i < pkt.Chunks.count {
            let raw = pkt.Chunks[i]

            if raw.Type == ChunkType.Init {
                let initChunk = InitChunk.Parse(raw)
                self.PeerInitiateTag = initChunk.InitiateTag
                self.PeerInitialTSN = initChunk.InitialTSN
                self.CumulativePeerTSN = initChunk.InitialTSN
                self.PeerTSNInitialized = true

                // Synthesize state cookie (echoing peer initiate tag & timestamp)
                var cookie: [uint8] = [0xde, 0xad, 0xbe, 0xef]
                let ackChunk = InitChunk(
                    initiateTag: self.MyInitiateTag,
                    a_rwnd: self.a_rwnd,
                    outboundStreams: self.OutboundStreams,
                    inboundStreams: self.InboundStreams,
                    initialTSN: self.MyInitialTSN,
                    cookie: cookie
                )
                responseChunks.append(ackChunk.ToRawChunk(isAck: true))
            } else if raw.Type == ChunkType.InitAck {
                let ack = InitChunk.Parse(raw)
                self.PeerInitiateTag = ack.InitiateTag
                self.PeerInitialTSN = ack.InitialTSN
                self.CumulativePeerTSN = ack.InitialTSN
                self.PeerTSNInitialized = true
                self.State = AssociationState.CookieEchoed

                let echoChunk = CookieEchoChunk(cookie: ack.Cookie)
                responseChunks.append(echoChunk.ToRawChunk())
            } else if raw.Type == ChunkType.CookieEcho {
                // In production, validate cookie; transition to Established
                self.State = AssociationState.Established
                let cookieAck = CookieAckChunk()
                responseChunks.append(cookieAck.ToRawChunk())
            } else if raw.Type == ChunkType.CookieAck {
                self.State = AssociationState.Established
            } else if raw.Type == ChunkType.Heartbeat {
                let hb = HeartbeatChunk.Parse(raw)
                let hbAck = HeartbeatChunk(info: hb.Info)
                responseChunks.append(hbAck.ToRawChunk(isAck: true))
            } else if raw.Type == ChunkType.Data {
                let d = DataChunk.Parse(raw)
                if !self.PeerTSNInitialized || d.TSN >= self.CumulativePeerTSN {
                    self.CumulativePeerTSN = d.TSN
                    self.PeerTSNInitialized = true
                }

                // Append received user data to inbound queue
                self.inboundQueue.append(ReceivedMessage(streamId: d.StreamId, ppid: d.PPID, payload: d.UserData))

                // Build SACK
                let sack = SackChunk(cumulativeTSNAck: self.CumulativePeerTSN, a_rwnd: self.a_rwnd)
                responseChunks.append(sack.ToRawChunk())
            } else if raw.Type == ChunkType.Sack {
                // Outbound SACK acknowledgement
                let sack = SackChunk.Parse(raw)
                // Peer acknowledged up to sack.CumulativeTSNAck
            } else if raw.Type == ChunkType.Abort || raw.Type == ChunkType.Shutdown {
                self.State = AssociationState.Closed
            }

            i += 1
        }

        if responseChunks.isEmpty {
            return []
        }

        let respPkt = Packet(
            sourcePort: self.LocalPort,
            destinationPort: self.RemotePort,
            verificationTag: self.PeerInitiateTag,
            chunks: responseChunks
        )
        return respPkt.Serialize()
    }

    /// ReadDelivered dequeues all available inbound messages from streams.
    public mutating func ReadDelivered() -> [ReceivedMessage] {
        let msgs = self.inboundQueue
        self.inboundQueue = []
        return msgs
    }

    /// IsEstablished checks if association handshake is complete.
    public func IsEstablished() -> bool {
        return self.State == AssociationState.Established
    }
}

package quic

import "net/udp"

/// QuicConnection represents an active QUIC connection managing streams, flow control,
/// packet numbers, encryption, and unreliable datagrams (RFC 9000 & RFC 9221).
public struct QuicConnection {
    public var IsClient: bool
    public var Socket: udp.UdpSocket
    public var RemoteAddress: udp.SocketAddress
    public var LocalCid: [uint8]
    public var RemoteCid: [uint8]
    public var Version: uint32
    public var Config: QuicConfig

    public var IsConnected: bool
    public var IsClosed: bool

    public var NextInitialPn: uint64
    public var NextHandshakePn: uint64
    public var NextAppPn: uint64
    public var LargestAckedPn: uint64

    public var NextBidiStreamId: uint64
    public var NextUniStreamId: uint64

    public var Streams: [QuicStream]
    public var InboundDatagrams: [[uint8]]

    public var ClientKeys: QuicCipherKeys
    public var ServerKeys: QuicCipherKeys
    public var AppKeys: QuicCipherKeys

    public var Rtt: RttEstimator
    public var Loss: LossDetector
    public var Congestion: NewRenoCongestionController

    public var MaxDataRemote: uint64
    public var SentDataBytes: uint64
    public var RecvDataBytes: uint64

    public init(socket: udp.UdpSocket,
                remoteAddress: udp.SocketAddress,
                localCid: [uint8],
                remoteCid: [uint8],
                isClient: bool,
                config: QuicConfig = QuicConfig()) {
        self.IsClient = isClient
        self.Socket = socket
        self.RemoteAddress = remoteAddress
        self.LocalCid = localCid
        self.RemoteCid = remoteCid
        self.Version = QuicVersion.V1
        self.Config = config

        self.IsConnected = false
        self.IsClosed = false

        self.NextInitialPn = 0
        self.NextHandshakePn = 0
        self.NextAppPn = 0
        self.LargestAckedPn = 0

        self.NextBidiStreamId = isClient ? 0 : 1
        self.NextUniStreamId = isClient ? 2 : 3

        self.Streams = []
        self.InboundDatagrams = []

        // Derive Initial Keys from RemoteCid (or local destination CID)
        let initSecret = hkdf.Extract(hash: .sha256, secret: isClient ? remoteCid : localCid, salt: QuicSalt.V1)
        let clientInitSec = HkdfExpandLabel(secret: initSecret, label: "client in", context: [], length: 32)
        let serverInitSec = HkdfExpandLabel(secret: initSecret, label: "server in", context: [], length: 32)

        self.ClientKeys = QuicCipherKeys.Derive(secret: clientInitSec)
        self.ServerKeys = QuicCipherKeys.Derive(secret: serverInitSec)
        self.AppKeys = QuicCipherKeys.Derive(secret: isClient ? clientInitSec : serverInitSec)

        self.Rtt = RttEstimator(initialRttMs: 100)
        self.Loss = LossDetector()
        self.Congestion = NewRenoCongestionController(maxDatagramSize: 1200)

        self.MaxDataRemote = config.InitialMaxData
        self.SentDataBytes = 0
        self.RecvDataBytes = 0
    }

    /// Opens a new bidirectional stream.
    public mutating func OpenStream() async throws -> QuicStream {
        if self.IsClosed {
            throw QuicError.transport(code: TransportErrorCode.InternalError, msg: "Connection is closed")
        }

        let id = self.NextBidiStreamId
        self.NextBidiStreamId += 4

        let stream = QuicStream(
            streamId: id,
            initialMaxSendData: self.Config.InitialMaxStreamDataBidiRemote,
            initialMaxRecvData: self.Config.InitialMaxStreamDataBidiLocal
        )
        self.Streams.append(stream)
        return stream
    }

    /// Opens a new unidirectional stream.
    public mutating func OpenUniStream() async throws -> QuicStream {
        if self.IsClosed {
            throw QuicError.transport(code: TransportErrorCode.InternalError, msg: "Connection is closed")
        }

        let id = self.NextUniStreamId
        self.NextUniStreamId += 4

        let stream = QuicStream(
            streamId: id,
            initialMaxSendData: self.Config.InitialMaxStreamDataUni,
            initialMaxRecvData: 0
        )
        self.Streams.append(stream)
        return stream
    }

    /// Accepts an incoming stream opened by the remote peer.
    public mutating func AcceptStream() async throws -> QuicStream {
        var i = 0
        while i < self.Streams.count {
            let s = self.Streams[i]
            let isPeerInitiated = (s.IsClientInitiated != self.IsClient)
            if isPeerInitiated && !s.RecvBuffer.isEmpty {
                return s
            }
            i += 1
        }

        // Return first peer-initiated stream or create placeholder
        let peerBidiId: uint64 = self.IsClient ? 1 : 0
        let stream = QuicStream(
            streamId: peerBidiId,
            initialMaxSendData: self.Config.InitialMaxStreamDataBidiRemote,
            initialMaxRecvData: self.Config.InitialMaxStreamDataBidiLocal
        )
        self.Streams.append(stream)
        return stream
    }

    /// Transmits an unreliable application datagram (RFC 9221).
    public mutating func SendDatagram(_ data: [uint8]) async throws {
        if !self.Config.EnableDatagrams {
            throw QuicError.transport(code: TransportErrorCode.ProtocolViolation, msg: "Datagrams disabled")
        }

        let frame = QuicFrame.datagram(data)
        try await self.SendPacket(frames: [frame], packetType: QuicPacketType.OneRtt)
    }

    /// Receives an unreliable application datagram (RFC 9221).
    public mutating func ReceiveDatagram() async throws -> [uint8] {
        if self.InboundDatagrams.isEmpty {
            return []
        }

        let first = self.InboundDatagrams[0]
        var remaining: [[uint8]] = []
        var i = 1
        while i < self.InboundDatagrams.count {
            remaining.append(self.InboundDatagrams[i])
            i += 1
        }
        self.InboundDatagrams = remaining
        return first
    }

    /// Builds, encrypts, protects, and sends a QUIC packet containing the given frames.
    public mutating func SendPacket(frames: [QuicFrame], packetType: uint8) async throws {
        let payload = EncodeFrames(frames)
        let keys = self.IsClient ? self.ClientKeys : self.ServerKeys

        var packet: [uint8] = []

        if packetType == QuicPacketType.OneRtt {
            let pn = self.NextAppPn
            self.NextAppPn += 1

            let pnLen = 4
            let header = BuildShortHeader(
                dcid: self.RemoteCid,
                spin: false,
                keyPhase: false,
                packetNumber: pn,
                pnLength: pnLen
            )
            let pnOffset = header.count - pnLen

            packet = try SealPacket(
                header: header,
                payload: payload,
                pn: pn,
                pnOffset: pnOffset,
                pnLen: pnLen,
                keys: keys
            )
        } else {
            let pn = (packetType == QuicPacketType.Initial) ? self.NextInitialPn : self.NextHandshakePn
            if packetType == QuicPacketType.Initial {
                self.NextInitialPn += 1
            } else {
                self.NextHandshakePn += 1
            }

            let pnLen = 4
            let header = BuildLongHeader(
                packetType: packetType,
                version: self.Version,
                dcid: self.RemoteCid,
                scid: self.LocalCid,
                token: [],
                packetNumber: pn,
                pnLength: pnLen,
                payloadLength: payload.count + 16 // payload + Poly1305 tag
            )
            let pnOffset = header.count - pnLen

            packet = try SealPacket(
                header: header,
                payload: payload,
                pn: pn,
                pnOffset: pnOffset,
                pnLen: pnLen,
                keys: keys
            )

            // RFC 9000 Section 14: Client Initial packets must be padded to at least 1200 bytes
            if packetType == QuicPacketType.Initial && self.IsClient {
                while packet.count < 1200 {
                    packet.append(0x00) // PADDING
                }
            }
        }

        _ = try await self.Socket.SendTo(packet, to: self.RemoteAddress)
    }

    /// Processes an inbound raw protected UDP datagram.
    public mutating func ProcessInboundDatagram(_ raw: [uint8]) throws -> [QuicFrame] {
        if raw.isEmpty {
            return []
        }

        let isLong = (raw[0] & 0x80) != 0
        let keys = self.IsClient ? self.ServerKeys : self.ClientKeys

        var pnOffset = 0
        if isLong {
            let longHeader = try ParseLongHeader(raw)
            pnOffset = longHeader.HeaderBytes.count - longHeader.PnLength
        } else {
            // Short header: 1 byte flags + remote CID length
            pnOffset = 1 + self.LocalCid.count
        }

        let res = try OpenPacket(packet: raw, pnOffset: pnOffset, keys: keys, largestAcked: self.LargestAckedPn)
        let pn = res.PacketNumber
        let frames = res.Frames

        if pn > self.LargestAckedPn {
            self.LargestAckedPn = pn
        }

        var i = 0
        while i < frames.count {
            let f = frames[i]
            switch f {
            case .stream(let sf):
                var found = false
                var si = 0
                while si < self.Streams.count {
                    if self.Streams[si].StreamId == sf.StreamId {
                        self.Streams[si].ReceiveStreamData(offset: sf.Offset, fin: sf.Fin, data: sf.Data)
                        found = true
                        break
                    }
                    si += 1
                }
                if !found {
                    var s = QuicStream(streamId: sf.StreamId)
                    s.ReceiveStreamData(offset: sf.Offset, fin: sf.Fin, data: sf.Data)
                    self.Streams.append(s)
                }

            case .datagram(let df):
                self.InboundDatagrams.append(df)

            case .maxData(let md):
                self.MaxDataRemote = md

            case .connectionClose(_):
                self.IsClosed = true

            default:
                break
            }
            i += 1
        }

        return frames
    }

    /// Bound local port number.
    public var Port: uint16 {
        return self.Socket.LocalAddress.Port()
    }

    /// Bound local address formatted as "ip:port".
    public var Address: string {
        return self.Socket.LocalAddress.ToString()
    }

    /// Receives an inbound datagram from the socket, decrypts it, and processes frames.
    public mutating func ReceivePacket() async throws -> [QuicFrame] {
        var buf = [uint8](repeating: 0, count: 2048)
        let (n, _) = try await self.Socket.ReceiveFrom(into: &buf)
        var rawPkt: [uint8] = []
        var bi = 0
        while bi < n { rawPkt.append(buf[bi]); bi += 1 }
        return try self.ProcessInboundDatagram(rawPkt)
    }

    /// Closes the QUIC connection cleanly by transmitting a CONNECTION_CLOSE frame.
    public mutating func Close(errorCode: uint64 = 0) async throws {
        if self.IsClosed { return }
        self.IsClosed = true

        let closeFrame = QuicFrame.connectionClose(ConnectionCloseData(isApp: true, errorCode: errorCode, frameType: 0))
        try await self.SendPacket(frames: [closeFrame], packetType: QuicPacketType.OneRtt)
        self.Socket.Close()
    }
}

/// Creates a new QuicConnection with an autonomously bound UDP socket and resolved string address.
public func CreateConnection(to remoteAddress: string, isClient: bool = true) throws -> QuicConnection {
    let socket = try udp.Bind("0.0.0.0:0")
    let parsed = try udp.SocketAddress.Parse(remoteAddress)
    let clientCid: [uint8] = [0x43, 0x4c, 0x49, 0x01, 0x02, 0x03, 0x04, 0x05]
    let serverCid: [uint8] = [0x53, 0x52, 0x56, 0x01, 0x02, 0x03, 0x04, 0x05]
    return QuicConnection(
        socket: socket,
        remoteAddress: parsed,
        localCid: isClient ? clientCid : serverCid,
        remoteCid: isClient ? serverCid : clientCid,
        isClient: isClient
    )
}


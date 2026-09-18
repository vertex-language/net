package quic

/// QUIC Transport Parameters (RFC 9000 Section 18.2 & RFC 9221).
public struct TransportParameters {
    public var OriginalDestinationConnectionId: [uint8]
    public var InitialSourceConnectionId: [uint8]
    public var MaxIdleTimeoutMs: uint64
    public var StatelessResetToken: [uint8]
    public var MaxUdpPayloadSize: uint64
    public var InitialMaxData: uint64
    public var InitialMaxStreamDataBidiLocal: uint64
    public var InitialMaxStreamDataBidiRemote: uint64
    public var InitialMaxStreamDataUni: uint64
    public var InitialMaxStreamsBidi: uint64
    public var InitialMaxStreamsUni: uint64
    public var AckDelayExponent: uint64
    public var MaxAckDelayMs: uint64
    public var DisableActiveMigration: bool
    public var ActiveConnectionIdLimit: uint64
    public var MaxDatagramFrameSize: uint64

    public init() {
        self.OriginalDestinationConnectionId = []
        self.InitialSourceConnectionId = []
        self.MaxIdleTimeoutMs = 30000
        self.StatelessResetToken = []
        self.MaxUdpPayloadSize = 65527
        self.InitialMaxData = 1048576               // 1 MB
        self.InitialMaxStreamDataBidiLocal = 262144 // 256 KB
        self.InitialMaxStreamDataBidiRemote = 262144
        self.InitialMaxStreamDataUni = 262144
        self.InitialMaxStreamsBidi = 100
        self.InitialMaxStreamsUni = 100
        self.AckDelayExponent = 3
        self.MaxAckDelayMs = 25
        self.DisableActiveMigration = false
        self.ActiveConnectionIdLimit = 2
        self.MaxDatagramFrameSize = 1200
    }
}

/// Encodes transport parameters into a byte array suitable for TLS extension 0x39.
public func EncodeTransportParameters(_ params: TransportParameters) -> [uint8] {
    var buf: [uint8] = []

    func writeParamVarint(id: uint64, val: uint64) {
        let valBytes = EncodeVarint(val)
        for b in EncodeVarint(id) { buf.append(b) }
        for b in EncodeVarint(uint64(valBytes.count)) { buf.append(b) }
        for b in valBytes { buf.append(b) }
    }

    func writeParamBytes(id: uint64, bytes: [uint8]) {
        for b in EncodeVarint(id) { buf.append(b) }
        for b in EncodeVarint(uint64(bytes.count)) { buf.append(b) }
        for b in bytes { buf.append(b) }
    }

    if !params.OriginalDestinationConnectionId.isEmpty {
        writeParamBytes(id: 0x00, bytes: params.OriginalDestinationConnectionId)
    }
    if params.MaxIdleTimeoutMs > 0 {
        writeParamVarint(id: 0x01, val: params.MaxIdleTimeoutMs)
    }
    if !params.StatelessResetToken.isEmpty {
        writeParamBytes(id: 0x02, bytes: params.StatelessResetToken)
    }
    if params.MaxUdpPayloadSize > 0 {
        writeParamVarint(id: 0x03, val: params.MaxUdpPayloadSize)
    }
    if params.InitialMaxData > 0 {
        writeParamVarint(id: 0x04, val: params.InitialMaxData)
    }
    if params.InitialMaxStreamDataBidiLocal > 0 {
        writeParamVarint(id: 0x05, val: params.InitialMaxStreamDataBidiLocal)
    }
    if params.InitialMaxStreamDataBidiRemote > 0 {
        writeParamVarint(id: 0x06, val: params.InitialMaxStreamDataBidiRemote)
    }
    if params.InitialMaxStreamDataUni > 0 {
        writeParamVarint(id: 0x07, val: params.InitialMaxStreamDataUni)
    }
    if params.InitialMaxStreamsBidi > 0 {
        writeParamVarint(id: 0x08, val: params.InitialMaxStreamsBidi)
    }
    if params.InitialMaxStreamsUni > 0 {
        writeParamVarint(id: 0x09, val: params.InitialMaxStreamsUni)
    }
    if params.AckDelayExponent != 3 {
        writeParamVarint(id: 0x0a, val: params.AckDelayExponent)
    }
    if params.MaxAckDelayMs != 25 {
        writeParamVarint(id: 0x0b, val: params.MaxAckDelayMs)
    }
    if params.DisableActiveMigration {
        writeParamBytes(id: 0x0c, bytes: [])
    }
    if params.ActiveConnectionIdLimit > 0 {
        writeParamVarint(id: 0x0e, val: params.ActiveConnectionIdLimit)
    }
    if !params.InitialSourceConnectionId.isEmpty {
        writeParamBytes(id: 0x0f, bytes: params.InitialSourceConnectionId)
    }
    if params.MaxDatagramFrameSize > 0 {
        writeParamVarint(id: 0x20, val: params.MaxDatagramFrameSize)
    }

    return buf
}

/// Decodes transport parameters from a TLS extension buffer.
public func DecodeTransportParameters(_ data: [uint8]) throws -> TransportParameters {
    var params = TransportParameters()
    var offset = 0

    while offset < data.count {
        let idDec = try DecodeVarint(data, offset: offset); offset += idDec.BytesRead
        let lenDec = try DecodeVarint(data, offset: offset); offset += lenDec.BytesRead
        let len = Int(lenDec.Value)

        if offset + len > data.count {
            throw QuicError.transport(code: TransportErrorCode.TransportParameterError, msg: "Truncated transport parameter value")
        }

        let id = idDec.Value
        if id == 0x00 {
            var cid: [uint8] = []
            var i = 0; while i < len { cid.append(data[offset + i]); i += 1 }
            params.OriginalDestinationConnectionId = cid
        } else if id == 0x01 {
            let vDec = try DecodeVarint(data, offset: offset)
            params.MaxIdleTimeoutMs = vDec.Value
        } else if id == 0x02 {
            var token: [uint8] = []
            var i = 0; while i < len { token.append(data[offset + i]); i += 1 }
            params.StatelessResetToken = token
        } else if id == 0x03 {
            let vDec = try DecodeVarint(data, offset: offset)
            params.MaxUdpPayloadSize = vDec.Value
        } else if id == 0x04 {
            let vDec = try DecodeVarint(data, offset: offset)
            params.InitialMaxData = vDec.Value
        } else if id == 0x05 {
            let vDec = try DecodeVarint(data, offset: offset)
            params.InitialMaxStreamDataBidiLocal = vDec.Value
        } else if id == 0x06 {
            let vDec = try DecodeVarint(data, offset: offset)
            params.InitialMaxStreamDataBidiRemote = vDec.Value
        } else if id == 0x07 {
            let vDec = try DecodeVarint(data, offset: offset)
            params.InitialMaxStreamDataUni = vDec.Value
        } else if id == 0x08 {
            let vDec = try DecodeVarint(data, offset: offset)
            params.InitialMaxStreamsBidi = vDec.Value
        } else if id == 0x09 {
            let vDec = try DecodeVarint(data, offset: offset)
            params.InitialMaxStreamsUni = vDec.Value
        } else if id == 0x0a {
            let vDec = try DecodeVarint(data, offset: offset)
            params.AckDelayExponent = vDec.Value
        } else if id == 0x0b {
            let vDec = try DecodeVarint(data, offset: offset)
            params.MaxAckDelayMs = vDec.Value
        } else if id == 0x0c {
            params.DisableActiveMigration = true
        } else if id == 0x0e {
            let vDec = try DecodeVarint(data, offset: offset)
            params.ActiveConnectionIdLimit = vDec.Value
        } else if id == 0x0f {
            var cid: [uint8] = []
            var i = 0; while i < len { cid.append(data[offset + i]); i += 1 }
            params.InitialSourceConnectionId = cid
        } else if id == 0x20 {
            let vDec = try DecodeVarint(data, offset: offset)
            params.MaxDatagramFrameSize = vDec.Value
        }

        offset += len
    }

    return params
}

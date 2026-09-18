package stun

import "net/udp"

/// Client queries STUN servers to discover NAT mappings and reflexive IP addresses.
public struct Client {
    public var TimeoutMs: int32

    public init(timeoutMs: int32 = 3000) {
        self.TimeoutMs = timeoutMs
    }

    /// Query sends an RFC 8489 Binding Request to the specified STUN server
    /// (e.g. "stun.cloudflare.com:3478" or "127.0.0.1:3478") and returns the reflexive address.
    public func Query(server: string) async throws -> udp.SocketAddress {
        var serverHost = server
        var serverPort: uint16 = 3478

        var colon = -1
        var bytes: [uint8] = []
        for b in server.utf8 { bytes.append(b) }
        var i = 0
        while i < bytes.count {
            if bytes[i] == 58 { // ':'
                colon = i
                break
            }
            i += 1
        }
        if colon >= 0 {
            var hBytes: [uint8] = []
            var hi = 0
            while hi < colon { hBytes.append(bytes[hi]); hi += 1 }
            serverHost = string(decoding: hBytes, as: UTF8.self)

            var pVal = 0
            var pi = colon + 1
            while pi < bytes.count {
                let b = bytes[pi]
                if b >= 48 && b <= 57 {
                    pVal = pVal * 10 + int(b - 48)
                }
                pi += 1
            }
            if pVal > 0 && pVal <= 65535 {
                serverPort = uint16(pVal)
            }
        }

        var socket = try udp.Bind("0.0.0.0:0")
        defer { socket.Close() }
        socket.ReadTimeoutMs = self.TimeoutMs
        socket.WriteTimeoutMs = self.TimeoutMs

        var req = Message(type: BindingRequest)
        req.AddAttribute(MakeSoftware("Vertex-STUN-Client"))
        req.AddFingerprint()

        let reqData = req.Encode()
        _ = try await socket.SendTo(reqData, to: "\(serverHost):\(serverPort)")

        var buf = [uint8](repeating: 0, count: 1500)
        let (n, _) = try await socket.ReceiveFrom(into: &buf)
        if n == 0 {
            throw StunError.timedOut("empty response from STUN server")
        }

        var rawResp: [uint8] = []
        var ri = 0
        while ri < n {
            rawResp.append(buf[ri])
            ri += 1
        }

        let res = try Message.Decode(rawResp)
        if res.Type != BindingResponse {
            throw StunError.invalidHeader("expected BindingResponse (0x0101), got 0x\(res.Type)")
        }

        // Check transaction ID
        var matchTid = true
        var ti = 0
        while ti < 12 {
            if res.TransactionId[ti] != req.TransactionId[ti] {
                matchTid = false
                break
            }
            ti += 1
        }
        if !matchTid {
            throw StunError.transactionMismatch
        }

        // Try XOR-MAPPED-ADDRESS first (RFC 8489 standard)
        if let xorAttr = res.GetAttribute(AttrXorMappedAddress) {
            return try ParseXorMappedAddress(xorAttr, transactionId: res.TransactionId)
        }

        // Fallback to legacy MAPPED-ADDRESS
        if let mappedAttr = res.GetAttribute(AttrMappedAddress) {
            return try ParseMappedAddress(mappedAttr)
        }

        throw StunError.attributeNotFound(AttrXorMappedAddress)
    }
}

/// Discover sends a STUN binding request to server and returns the discovered public/reflexive address.
public func Discover(server: string = "stun.cloudflare.com:3478", timeoutMs: int32 = 3000) async throws -> udp.SocketAddress {
    let client = Client(timeoutMs: timeoutMs)
    return try await client.Query(server: server)
}

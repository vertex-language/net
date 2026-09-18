package turn

import "net/udp"
import "net/stun"
import "crypto/md5"

/// Computes the TURN Long-Term Credential Key (RFC 5389 Section 15.4 / RFC 8656 Section 9.1.1):
/// key = MD5(username ":" realm ":" password)
public func GenerateKey(username: string, realm: string, password: string) -> [uint8] {
    let raw = "\(username):\(realm):\(password)"
    return md5.SumString(raw)
}

/// Client coordinates RFC 8656 TURN relay allocation, permissions, and packet transport over UDP.
public struct Client {
    public var Socket: udp.UdpSocket
    public var ServerAddress: udp.SocketAddress
    public var Username: string
    public var Password: string
    public var Realm: string
    public var Nonce: string
    public var Key: [uint8]
    public var RelayedAddress: udp.SocketAddress
    public var MappedAddress: udp.SocketAddress
    public var Lifetime: uint32

    /// Allocates a relayed transport address on the TURN server via 401 challenge (RFC 8656 Section 6).
    public mutating func Allocate(lifetime: uint32 = 600) async throws -> Allocation {
        // Step 1: Send initial unauthenticated Allocate Request to solicit 401 challenge
        var req1 = stun.Message(type: MessageType.AllocateRequest)
        req1.AddAttribute(stun.MakeRequestedTransport(17)) // UDP
        req1.AddFingerprint()
        _ = try await Socket.SendTo(req1.Encode(), to: ServerAddress)

        // Step 2: Receive response (expected 401 Unauthorized with REALM and NONCE)
        var buf1 = [uint8](repeating: 0, count: 1500)
        let (n1, _) = try await Socket.ReceiveFrom(into: &buf1)
        if n1 == 0 {
            throw TurnError.timedOut("empty response from TURN server")
        }
        var data1: [uint8] = []
        var i1 = 0
        while i1 < n1 {
            data1.append(buf1[i1])
            i1 += 1
        }
        let res1 = try stun.Message.Decode(data1)

        if res1.Type == MessageType.AllocateResponse {
            // Server allowed allocation without credentials
            return try parseAllocationResponse(res1, defaultLifetime: lifetime)
        }

        if res1.Type != MessageType.AllocateErrorResponse {
            throw TurnError.protocolError("unexpected initial response type")
        }

        // Extract REALM and NONCE
        guard let realmAttr = res1.GetAttribute(stun.AttributeType.Realm),
              let nonceAttr = res1.GetAttribute(stun.AttributeType.Nonce) else {
            throw TurnError.unauthorized("missing REALM or NONCE in server challenge")
        }

        self.Realm = stun.ParseRealm(realmAttr)
        self.Nonce = stun.ParseNonce(nonceAttr)
        self.Key = GenerateKey(username: self.Username, realm: self.Realm, password: self.Password)

        // Step 3: Send authenticated Allocate Request
        var req2 = stun.Message(type: MessageType.AllocateRequest)
        req2.AddAttribute(stun.MakeRequestedTransport(17))
        req2.AddAttribute(stun.MakeLifetime(lifetime))
        req2.AddAttribute(stun.MakeUsername(self.Username))
        req2.AddAttribute(stun.MakeRealm(self.Realm))
        req2.AddAttribute(stun.MakeNonce(self.Nonce))
        req2.AddMessageIntegrity(key: self.Key)
        req2.AddFingerprint()
        _ = try await Socket.SendTo(req2.Encode(), to: ServerAddress)

        // Step 4: Receive Allocate Response
        var buf2 = [uint8](repeating: 0, count: 1500)
        let (n2, _) = try await Socket.ReceiveFrom(into: &buf2)
        if n2 == 0 {
            throw TurnError.timedOut("empty authenticated response from TURN server")
        }
        var data2: [uint8] = []
        var i2 = 0
        while i2 < n2 {
            data2.append(buf2[i2])
            i2 += 1
        }
        let res2 = try stun.Message.Decode(data2)

        if res2.Type != MessageType.AllocateResponse {
            if let errAttr = res2.GetAttribute(stun.AttributeType.ErrorCode) {
                let err = stun.ParseErrorCode(errAttr)
                throw TurnError.serverError(err.Code, err.Reason)
            }
            throw TurnError.allocationFailed("allocation rejected by server")
        }

        let alloc = try parseAllocationResponse(res2, defaultLifetime: lifetime)
        self.RelayedAddress = alloc.RelayedAddress
        self.MappedAddress = alloc.MappedAddress
        self.Lifetime = alloc.Lifetime
        return alloc
    }

    func parseAllocationResponse(_ msg: stun.Message, defaultLifetime: uint32) throws -> Allocation {
        guard let relayedAttr = msg.GetAttribute(stun.AttributeType.XorRelayedAddress) else {
            throw TurnError.allocationFailed("missing XOR-RELAYED-ADDRESS in Allocate Response")
        }
        let relayedAddr = try stun.ParseXorRelayedAddress(relayedAttr, transactionId: msg.TransactionId)

        var mappedAddr = relayedAddr
        if let mappedAttr = msg.GetAttribute(stun.AttributeType.XorMappedAddress) {
            if let m = try? stun.ParseXorMappedAddress(mappedAttr, transactionId: msg.TransactionId) {
                mappedAddr = m
            }
        }

        var grantedLifetime = defaultLifetime
        if let lifeAttr = msg.GetAttribute(stun.AttributeType.Lifetime) {
            grantedLifetime = stun.ParseLifetime(lifeAttr)
        }

        return Allocation(RelayedAddress: relayedAddr,
                          MappedAddress: mappedAddr,
                          Lifetime: grantedLifetime,
                          Realm: self.Realm,
                          Nonce: self.Nonce)
    }

    /// Creates a permission for the peer address to send data to our allocation (RFC 8656 Section 8).
    public func CreatePermission(peerAddress: udp.SocketAddress) async throws {
        var req = stun.Message(type: MessageType.CreatePermissionRequest)
        req.AddAttribute(stun.MakeXorPeerAddress(address: peerAddress, transactionId: req.TransactionId))
        req.AddAttribute(stun.MakeUsername(self.Username))
        req.AddAttribute(stun.MakeRealm(self.Realm))
        req.AddAttribute(stun.MakeNonce(self.Nonce))
        req.AddMessageIntegrity(key: self.Key)
        req.AddFingerprint()
        _ = try await Socket.SendTo(req.Encode(), to: ServerAddress)

        var buf = [uint8](repeating: 0, count: 1500)
        let (n, _) = try await Socket.ReceiveFrom(into: &buf)
        if n == 0 {
            throw TurnError.timedOut("empty response to CreatePermission")
        }
        var data: [uint8] = []
        var i = 0
        while i < n {
            data.append(buf[i])
            i += 1
        }
        let res = try stun.Message.Decode(data)

        if res.Type != MessageType.CreatePermissionResponse {
            if let errAttr = res.GetAttribute(stun.AttributeType.ErrorCode) {
                let err = stun.ParseErrorCode(errAttr)
                throw TurnError.permissionDenied(err.Reason)
            }
            throw TurnError.permissionDenied("failed to create TURN permission")
        }
    }

    /// Sends data to a peer through the TURN relay using a Send Indication (RFC 8656 Section 9).
    public func SendTo(data: [uint8], peerAddress: udp.SocketAddress) async throws {
        var ind = stun.Message(type: MessageType.SendIndication)
        ind.AddAttribute(stun.MakeXorPeerAddress(address: peerAddress, transactionId: ind.TransactionId))
        ind.AddAttribute(stun.MakeData(data))
        ind.AddFingerprint()
        _ = try await Socket.SendTo(ind.Encode(), to: ServerAddress)
    }

    /// Refreshes the lifetime of the current allocation (RFC 8656 Section 7).
    public mutating func Refresh(lifetime: uint32 = 600) async throws -> uint32 {
        var req = stun.Message(type: MessageType.RefreshRequest)
        req.AddAttribute(stun.MakeLifetime(lifetime))
        req.AddAttribute(stun.MakeUsername(self.Username))
        req.AddAttribute(stun.MakeRealm(self.Realm))
        req.AddAttribute(stun.MakeNonce(self.Nonce))
        req.AddMessageIntegrity(key: self.Key)
        req.AddFingerprint()
        _ = try await Socket.SendTo(req.Encode(), to: ServerAddress)

        var buf = [uint8](repeating: 0, count: 1500)
        let (n, _) = try await Socket.ReceiveFrom(into: &buf)
        if n == 0 {
            throw TurnError.timedOut("empty response to Refresh")
        }
        var data: [uint8] = []
        var i = 0
        while i < n {
            data.append(buf[i])
            i += 1
        }
        let res = try stun.Message.Decode(data)

        if res.Type != MessageType.RefreshResponse {
            if let errAttr = res.GetAttribute(stun.AttributeType.ErrorCode) {
                let err = stun.ParseErrorCode(errAttr)
                throw TurnError.serverError(err.Code, err.Reason)
            }
            throw TurnError.protocolError("refresh rejected")
        }

        if let lifeAttr = res.GetAttribute(stun.AttributeType.Lifetime) {
            let granted = stun.ParseLifetime(lifeAttr)
            self.Lifetime = granted
            return granted
        }
        return lifetime
    }
}

/// Creates a new unallocated TURN Client instance.
public func NewClient(socket: udp.UdpSocket,
                      serverAddress: udp.SocketAddress,
                      username: string,
                      password: string) -> Client {
    return Client(
        Socket: socket,
        ServerAddress: serverAddress,
        Username: username,
        Password: password,
        Realm: "",
        Nonce: "",
        Key: [],
        RelayedAddress: .v4(ip: "0.0.0.0", port: 0),
        MappedAddress: .v4(ip: "0.0.0.0", port: 0),
        Lifetime: 0
    )
}

/// Decodes an incoming TURN Data Indication packet (RFC 8656 Section 10).
public func ParseDataIndication(_ msg: stun.Message) throws -> (data: [uint8], peerAddress: udp.SocketAddress) {
    guard let peerAttr = msg.GetAttribute(stun.AttributeType.XorPeerAddress) else {
        throw TurnError.protocolError("missing XOR-PEER-ADDRESS in DataIndication")
    }
    guard let dataAttr = msg.GetAttribute(stun.AttributeType.Data) else {
        throw TurnError.protocolError("missing DATA in DataIndication")
    }
    let peer = try stun.ParseXorPeerAddress(peerAttr, transactionId: msg.TransactionId)
    let payload = stun.ParseData(dataAttr)
    return (data: payload, peerAddress: peer)
}

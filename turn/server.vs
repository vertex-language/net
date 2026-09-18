package turn

import "net/udp"
import "net/stun"

/// ServerSession tracks an active allocation on the mock/local TURN server.
public struct ServerSession {
    public var ClientAddress: udp.SocketAddress
    public var RelayedAddress: udp.SocketAddress
    public var Username: string
    public var Realm: string
    public var Nonce: string
    public var Key: [uint8]
    public var Lifetime: uint32
}

/// Server provides lightweight RFC 8656 TURN server logic for local testing and relay coordination.
public struct Server {
    public var Realm: string = "vertex.local"
    public var Nonce: string = "vertex-nonce-12345678"
    public var Users: [string: string] = [:] // username -> password
    public var Sessions: [ServerSession] = []
    public var NextRelayPort: uint16 = 34000

    public init(realm: string = "vertex.local") {
        self.Realm = realm
    }

    func findSessionIndex(_ from: udp.SocketAddress) -> int {
        let key = "\(from)"
        var i = 0
        while i < self.Sessions.count {
            if "\(self.Sessions[i].ClientAddress)" == key {
                return i
            }
            i += 1
        }
        return -1
    }

    public mutating func AddUser(username: string, password: string) {
        self.Users[username] = password
    }

    /// Handles an incoming UDP datagram to the TURN server.
    /// Returns raw response bytes to send back to client, or nil if none.
    public mutating func HandlePacket(_ raw: [uint8], from: udp.SocketAddress) -> [uint8]? {
        guard let req = try? stun.Message.Decode(raw) else {
            return nil
        }

        switch req.Type {
        case AllocateRequest:
            return handleAllocate(req, from: from)
        case CreatePermissionRequest:
            return handleCreatePermission(req, from: from)
        case RefreshRequest:
            return handleRefresh(req, from: from)
        default:
            return nil
        }
    }

    mutating func handleAllocate(_ req: stun.Message, from: udp.SocketAddress) -> [uint8] {
        // Check for credentials
        guard let userAttr = req.GetAttribute(stun.AttributeType.Username),
              let miAttr = req.GetAttribute(stun.AttributeType.MessageIntegrity) else {
            // Unauthenticated: Send 401 Unauthorized challenge
            var err = stun.Message(type: AllocateErrorResponse, transactionId: req.TransactionId)
            err.AddAttribute(stun.MakeErrorCode(401, "Unauthorized"))
            err.AddAttribute(stun.MakeRealm(self.Realm))
            err.AddAttribute(stun.MakeNonce(self.Nonce))
            err.AddFingerprint()
            return err.Encode()
        }

        let username = stun.ParseUsername(userAttr)
        guard let expectedPass = self.Users[username] else {
            var err = stun.Message(type: AllocateErrorResponse, transactionId: req.TransactionId)
            err.AddAttribute(stun.MakeErrorCode(401, "Unknown User"))
            err.AddFingerprint()
            return err.Encode()
        }

        let key = GenerateKey(username: username, realm: self.Realm, password: expectedPass)
        if !req.VerifyMessageIntegrity(key: key) {
            var err = stun.Message(type: AllocateErrorResponse, transactionId: req.TransactionId)
            err.AddAttribute(stun.MakeErrorCode(401, "Bad Message-Integrity"))
            err.AddFingerprint()
            return err.Encode()
        }

        // Allocate relayed address
        let relayPort = self.NextRelayPort
        self.NextRelayPort += 1
        let relayedAddr = udp.SocketAddress.v4(ip: "127.0.0.1", port: relayPort)

        var lifetime: uint32 = 600
        if let lifeAttr = req.GetAttribute(stun.AttributeType.Lifetime) {
            lifetime = stun.ParseLifetime(lifeAttr)
        }

        var res = stun.Message(type: AllocateResponse, transactionId: req.TransactionId)
        res.AddAttribute(stun.MakeXorRelayedAddress(address: relayedAddr, transactionId: req.TransactionId))
        res.AddAttribute(stun.MakeLifetime(lifetime))
        res.AddAttribute(stun.MakeXorMappedAddress(address: from, transactionId: req.TransactionId))
        res.AddAttribute(stun.MakeSoftware("Vertex-TURN/RFC8656"))
        res.AddMessageIntegrity(key: key)
        res.AddFingerprint()

        let newSession = ServerSession(ClientAddress: from,
                                       RelayedAddress: relayedAddr,
                                       Username: username,
                                       Realm: self.Realm,
                                       Nonce: self.Nonce,
                                       Key: key,
                                       Lifetime: lifetime)
        let idx = findSessionIndex(from)
        if idx >= 0 {
            self.Sessions[idx] = newSession
        } else {
            self.Sessions.append(newSession)
        }

        return res.Encode()
    }

    mutating func handleCreatePermission(_ req: stun.Message, from: udp.SocketAddress) -> [uint8] {
        let idx = findSessionIndex(from)
        if idx < 0 {
            var err = stun.Message(type: CreatePermissionErrorResponse, transactionId: req.TransactionId)
            err.AddAttribute(stun.MakeErrorCode(437, "Allocation Mismatch"))
            err.AddFingerprint()
            return err.Encode()
        }
        let session = self.Sessions[idx]

        if !req.VerifyMessageIntegrity(key: session.Key) {
            var err = stun.Message(type: CreatePermissionErrorResponse, transactionId: req.TransactionId)
            err.AddAttribute(stun.MakeErrorCode(401, "Unauthorized"))
            err.AddFingerprint()
            return err.Encode()
        }

        var res = stun.Message(type: CreatePermissionResponse, transactionId: req.TransactionId)
        res.AddMessageIntegrity(key: session.Key)
        res.AddFingerprint()
        return res.Encode()
    }

    mutating func handleRefresh(_ req: stun.Message, from: udp.SocketAddress) -> [uint8] {
        let idx = findSessionIndex(from)
        if idx < 0 {
            var err = stun.Message(type: RefreshErrorResponse, transactionId: req.TransactionId)
            err.AddAttribute(stun.MakeErrorCode(437, "Allocation Mismatch"))
            err.AddFingerprint()
            return err.Encode()
        }
        var session = self.Sessions[idx]

        if !req.VerifyMessageIntegrity(key: session.Key) {
            var err = stun.Message(type: RefreshErrorResponse, transactionId: req.TransactionId)
            err.AddAttribute(stun.MakeErrorCode(401, "Unauthorized"))
            err.AddFingerprint()
            return err.Encode()
        }

        var lifetime: uint32 = 600
        if let lifeAttr = req.GetAttribute(stun.AttributeType.Lifetime) {
            lifetime = stun.ParseLifetime(lifeAttr)
        }
        session.Lifetime = lifetime
        self.Sessions[idx] = session

        var res = stun.Message(type: RefreshResponse, transactionId: req.TransactionId)
        res.AddAttribute(stun.MakeLifetime(lifetime))
        res.AddMessageIntegrity(key: session.Key)
        res.AddFingerprint()
        return res.Encode()
    }
}

package stun

import "net/udp"

/// HandleBindingRequest inspects a raw UDP datagram. If it is a valid STUN Binding Request,
/// it generates a corresponding Binding Success Response containing an XOR-MAPPED-ADDRESS
/// attribute with the sender's reflexive address and a valid FINGERPRINT.
public func HandleBindingRequest(_ raw: [uint8], sender: udp.SocketAddress) -> [uint8]? {
    guard let req = try? Message.Decode(raw) else {
        return nil
    }

    if req.Type != BindingRequest {
        return nil
    }

    var res = Message(type: BindingResponse, transactionId: req.TransactionId)
    res.AddAttribute(MakeXorMappedAddress(address: sender, transactionId: req.TransactionId))
    res.AddAttribute(MakeSoftware("Vertex-STUN/RFC8489"))
    res.AddFingerprint()
    return res.Encode()
}

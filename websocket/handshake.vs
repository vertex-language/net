package websocket

import "net/http"
import "crypto/sha1"
import "crypto/rand"

public func WebSocketGuid() -> string {
    return "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
}

/// Computes the Sec-WebSocket-Accept header value per RFC 6455 Section 1.3 & 4.2.2.
public func ComputeAcceptKey(_ clientKey: string) -> string {
    let combined = clientKey + WebSocketGuid()
    var bytes: [uint8] = []
    for b in combined.utf8 {
        bytes.append(b)
    }
    let digest = sha1.Sum1(bytes)
    return Base64Encode(digest)
}

/// Generates a random 16-byte base64-encoded client handshake key per RFC 6455 Section 4.1.
public func GenerateClientKey() -> string {
    if let b = try? rand.Bytes(16) {
        return Base64Encode(b)
    }
    var fallback: [uint8] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    ]
    return Base64Encode(fallback)
}

/// Builds the HTTP/1.1 Opening Handshake GET request text per RFC 6455 Section 4.1.
public func BuildClientHandshake(host: string,
                                 port: uint16,
                                 path: string,
                                 key: string) -> string {
    let emptyProtos: [string] = []
    return BuildClientHandshake(host: host, port: port, path: path, key: key, subprotocols: emptyProtos)
}

/// Builds the HTTP/1.1 Opening Handshake GET request text with subprotocols per RFC 6455 Section 4.1.
public func BuildClientHandshake(host: string,
                                 port: uint16,
                                 path: string,
                                 key: string,
                                 subprotocols: [string]) -> string {
    let targetPath = path.isEmpty ? "/" : path
    var hostHeader = host
    if port != 80 && port != 443 {
        hostHeader = "\(host):\(port)"
    }

    var req = "GET \(targetPath) HTTP/1.1\r\n"
    req += "Host: \(hostHeader)\r\n"
    req += "Upgrade: websocket\r\n"
    req += "Connection: Upgrade\r\n"
    req += "Sec-WebSocket-Key: \(key)\r\n"
    req += "Sec-WebSocket-Version: 13\r\n"

    if !subprotocols.isEmpty {
        var protoStr = ""
        var i = 0
        while i < subprotocols.count {
            if i > 0 { protoStr += ", " }
            protoStr += subprotocols[i]
            i += 1
        }
        req += "Sec-WebSocket-Protocol: \(protoStr)\r\n"
    }

    req += "\r\n"
    return req
}

/// Builds the HTTP/1.1 101 Switching Protocols response text per RFC 6455 Section 4.2.2.
public func BuildServerHandshake(clientKey: string) -> string {
    return BuildServerHandshake(clientKey: clientKey, subprotocol: "")
}

/// Builds the HTTP/1.1 101 Switching Protocols response text with subprotocol per RFC 6455 Section 4.2.2.
public func BuildServerHandshake(clientKey: string, subprotocol: string) -> string {
    let acceptKey = ComputeAcceptKey(clientKey)
    var resp = "HTTP/1.1 101 Switching Protocols\r\n"
    resp += "Upgrade: websocket\r\n"
    resp += "Connection: Upgrade\r\n"
    resp += "Sec-WebSocket-Accept: \(acceptKey)\r\n"

    if !subprotocol.isEmpty {
        resp += "Sec-WebSocket-Protocol: \(subprotocol)\r\n"
    }

    resp += "\r\n"
    return resp
}

func lowerString(_ s: string) -> string {
    var out: [uint8] = []
    for b in s.utf8 {
        if b >= 65 && b <= 90 {
            out.append(b + 32)
        } else {
            out.append(b)
        }
    }
    return string(decoding: out, as: UTF8.self)
}

func headerContainsToken(_ headerValue: string, token: string) -> bool {
    let lowerVal = lowerString(headerValue)
    let lowerTok = lowerString(token)
    return lowerVal.contains(lowerTok)
}

/// Validates the server's 101 Switching Protocols handshake response per RFC 6455 Section 4.2.2.
public func VerifyServerHandshake(response: http.Response, expectedAcceptKey: string) throws {
    if response.StatusCode != 101 {
        throw WebSocketError.handshakeFailed("Expected HTTP 101 Switching Protocols, got \(response.StatusCode)")
    }

    guard let upgrade = response.Headers.Get("Upgrade") else {
        throw WebSocketError.handshakeFailed("Missing Upgrade header in server handshake response")
    }
    if !headerContainsToken(upgrade, token: "websocket") {
        throw WebSocketError.handshakeFailed("Invalid Upgrade header: '\(upgrade)'")
    }

    guard let connection = response.Headers.Get("Connection") else {
        throw WebSocketError.handshakeFailed("Missing Connection header in server handshake response")
    }
    if !headerContainsToken(connection, token: "upgrade") {
        throw WebSocketError.handshakeFailed("Invalid Connection header: '\(connection)'")
    }

    guard let acceptKey = response.Headers.Get("Sec-WebSocket-Accept") else {
        throw WebSocketError.handshakeFailed("Missing Sec-WebSocket-Accept header in server handshake response")
    }
    if acceptKey != expectedAcceptKey {
        throw WebSocketError.handshakeFailed("Sec-WebSocket-Accept mismatch: expected '\(expectedAcceptKey)', got '\(acceptKey)'")
    }
}

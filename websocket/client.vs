package websocket

import (
    "crypto/tls"
    "net/http"
    "net/tcp"
    "net/url"
)

/// A WebSocket endpoint's URL, parsed: ws:// or wss://, with a host.
public func ParseEndpoint(_ address: string) throws -> url.URL {
    let u: url.URL
    do {
        u = try url.Parse(address)
    } catch {
        throw WebSocketError.invalidUrl("not a URL: '\(address)'")
    }
    if u.Scheme != "ws" && u.Scheme != "wss" {
        throw WebSocketError.invalidUrl("URL must start with ws:// or wss://: '\(address)'")
    }
    return u
}

/// Client configuration options.
public struct ClientConfig {
    public var Subprotocols: [string]
    public var TLSConfig: tls.Config
    public var TimeoutMs: int32

    public init() {
        self.Subprotocols = []
        self.TLSConfig = tls.Config()
        self.TimeoutMs = 10000
    }

    public init(subprotocols: [string]) {
        self.Subprotocols = subprotocols
        self.TLSConfig = tls.Config()
        self.TimeoutMs = 10000
    }

    public init(subprotocols: [string], tlsConfig: tls.Config, timeoutMs: int32) {
        self.Subprotocols = subprotocols
        self.TLSConfig = tlsConfig
        self.TimeoutMs = timeoutMs
    }
}

/// Connects to a WebSocket endpoint written as text ("ws://..." or "wss://...").
public func Connect(_ address: string) async throws -> WebSocket {
    let cfg = ClientConfig()
    return try await Connect(address, config: cfg)
}

/// Connects to a WebSocket endpoint with specified subprotocols.
public func Connect(_ address: string, subprotocols: [string]) async throws -> WebSocket {
    let cfg = ClientConfig(subprotocols: subprotocols)
    return try await Connect(address, config: cfg)
}

/// Connects to a WebSocket endpoint with custom client configuration.
public func Connect(_ address: string, config: ClientConfig) async throws -> WebSocket {
    let parsedUrl = try ParseEndpoint(address)
    let clientKey = GenerateClientKey()
    let expectedAccept = ComputeAcceptKey(clientKey)
    let handshakeReqText = BuildClientHandshake(
        host: parsedUrl.Host,
        port: parsedUrl.EffectivePort,
        path: parsedUrl.RequestURI,
        key: clientKey,
        subprotocols: config.Subprotocols
    )

    if parsedUrl.Scheme == "wss" {
        var tlsCfg = config.TLSConfig
        if tlsCfg.ServerName.isEmpty {
            tlsCfg.ServerName = parsedUrl.Host
        }

        var tlsConn = try await tls.Connect(host: parsedUrl.Host, port: parsedUrl.EffectivePort, config: tlsCfg)
        do {
            try await tlsConn.WriteText(handshakeReqText)
            let response = try await http.ReadResponseTls(from: &tlsConn)
            try VerifyServerHandshake(response: response, expectedAcceptKey: expectedAccept)

            let subproto = response.Headers.Get("Sec-WebSocket-Protocol") ?? ""
            var ws = WebSocket(tlsConn: tlsConn, isClient: true, subprotocol: subproto)
            ws.readBuffer = response.Body
            return ws
        } catch {
            tlsConn.Close()
            throw error
        }
    } else {
        let stream = try await tcp.Connect(host: parsedUrl.Host, port: parsedUrl.EffectivePort, timeoutMs: config.TimeoutMs)
        do {
            try await stream.WriteText(handshakeReqText)
            let response = try await http.ReadResponse(from: stream)
            try VerifyServerHandshake(response: response, expectedAcceptKey: expectedAccept)

            let subproto = response.Headers.Get("Sec-WebSocket-Protocol") ?? ""
            var ws = WebSocket(stream: stream, isClient: true, subprotocol: subproto)
            ws.readBuffer = response.Body
            return ws
        } catch {
            stream.Close()
            throw error
        }
    }
}

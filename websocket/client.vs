package websocket

import (
    "crypto/tls"
    "net/http"
    "net/tcp"
)

/// Parsed WebSocket URL representation.
public struct WebSocketURL {
    public var Scheme: string
    public var Host: string
    public var Port: uint16
    public var Path: string

    public init(scheme: string, host: string, port: uint16, path: string) {
        self.Scheme = scheme
        self.Host = host
        self.Port = port
        self.Path = path
    }

    public static func Parse(_ url: string) throws -> WebSocketURL {
        let wssPrefix = "wss://"
        let wsPrefix = "ws://"
        var urlBytes: [uint8] = []
        for b in url.utf8 { urlBytes.append(b) }

        var scheme = "ws"
        var offset = 0
        var defaultPort: uint16 = 80

        if url.hasPrefix(wssPrefix) {
            scheme = "wss"
            offset = 6
            defaultPort = 443
        } else if url.hasPrefix(wsPrefix) {
            scheme = "ws"
            offset = 5
            defaultPort = 80
        } else {
            throw WebSocketError.invalidUrl("URL must start with ws:// or wss://: '\(url)'")
        }

        var pathStart = -1
        var i = offset
        while i < urlBytes.count {
            if urlBytes[i] == 47 { // '/'
                pathStart = i
                break
            }
            i += 1
        }

        var hostPortBytes: [uint8] = []
        let hpEnd = (pathStart < 0) ? urlBytes.count : pathStart
        var hi = offset
        while hi < hpEnd {
            hostPortBytes.append(urlBytes[hi])
            hi += 1
        }
        let hostPortStr = string(decoding: hostPortBytes, as: UTF8.self)

        var path = "/"
        if pathStart >= 0 {
            var pathBytes: [uint8] = []
            var pi = pathStart
            while pi < urlBytes.count {
                pathBytes.append(urlBytes[pi])
                pi += 1
            }
            path = string(decoding: pathBytes, as: UTF8.self)
        }

        var colon = -1
        var ci = 0
        while ci < hostPortBytes.count {
            if hostPortBytes[ci] == 58 { // ':'
                colon = ci
                break
            }
            ci += 1
        }

        var host = hostPortStr
        var port = defaultPort

        if colon >= 0 {
            var hBytes: [uint8] = []
            var k = 0
            while k < colon { hBytes.append(hostPortBytes[k]); k += 1 }
            host = string(decoding: hBytes, as: UTF8.self)

            var pVal: uint16 = 0
            k = colon + 1
            while k < hostPortBytes.count {
                let b = hostPortBytes[k]
                if b >= 48 && b <= 57 {
                    pVal = pVal * 10 + uint16(b - 48)
                }
                k += 1
            }
            if pVal > 0 {
                port = pVal
            }
        }

        if host.isEmpty {
            throw WebSocketError.invalidUrl("Host cannot be empty in URL: '\(url)'")
        }

        return WebSocketURL(scheme: scheme, host: host, port: port, path: path)
    }
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
public func Connect(_ url: string) async throws -> WebSocket {
    let cfg = ClientConfig()
    return try await Connect(url, config: cfg)
}

/// Connects to a WebSocket endpoint with specified subprotocols.
public func Connect(_ url: string, subprotocols: [string]) async throws -> WebSocket {
    let cfg = ClientConfig(subprotocols: subprotocols)
    return try await Connect(url, config: cfg)
}

/// Connects to a WebSocket endpoint with custom client configuration.
public func Connect(_ url: string, config: ClientConfig) async throws -> WebSocket {
    let parsedUrl = try WebSocketURL.Parse(url)
    let clientKey = GenerateClientKey()
    let expectedAccept = ComputeAcceptKey(clientKey)
    let handshakeReqText = BuildClientHandshake(
        host: parsedUrl.Host,
        port: parsedUrl.Port,
        path: parsedUrl.Path,
        key: clientKey,
        subprotocols: config.Subprotocols
    )

    if parsedUrl.Scheme == "wss" {
        var tlsCfg = config.TLSConfig
        if tlsCfg.ServerName.isEmpty {
            tlsCfg.ServerName = parsedUrl.Host
        }

        var tlsConn = try await tls.Connect(host: parsedUrl.Host, port: parsedUrl.Port, config: tlsCfg)
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
        let stream = try await tcp.Connect(host: parsedUrl.Host, port: parsedUrl.Port, timeoutMs: config.TimeoutMs)
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

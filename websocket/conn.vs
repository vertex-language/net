package websocket

import (
    "crypto/tls"
    "net/tcp"
)

/// WebSocket represents an established WebSocket connection over plain TCP or TLS 1.3.
public struct WebSocket {
    public var IsClient: bool
    public var IsClosed: bool
    public var Subprotocol: string

    var isTls: bool
    var stream: tcp.TcpStream
    var tlsConn: tls.Conn
    var readBuffer: [uint8]

    public init(stream: tcp.TcpStream, isClient: bool) {
        self.IsClient = isClient
        self.IsClosed = false
        self.Subprotocol = ""
        self.isTls = false
        self.stream = stream
        self.tlsConn = tls.Conn(stream: stream)
        self.readBuffer = []
    }

    public init(stream: tcp.TcpStream, isClient: bool, subprotocol: string) {
        self.IsClient = isClient
        self.IsClosed = false
        self.Subprotocol = subprotocol
        self.isTls = false
        self.stream = stream
        self.tlsConn = tls.Conn(stream: stream)
        self.readBuffer = []
    }

    public init(tlsConn: tls.Conn, isClient: bool) {
        self.IsClient = isClient
        self.IsClosed = false
        self.Subprotocol = ""
        self.isTls = true
        self.stream = tlsConn.stream
        self.tlsConn = tlsConn
        self.readBuffer = []
    }

    public init(tlsConn: tls.Conn, isClient: bool, subprotocol: string) {
        self.IsClient = isClient
        self.IsClosed = false
        self.Subprotocol = subprotocol
        self.isTls = true
        self.stream = tlsConn.stream
        self.tlsConn = tlsConn
        self.readBuffer = []
    }

    mutating func writeBytes(_ bytes: [uint8]) async throws {
        if self.IsClosed {
            throw WebSocketError.connectionClosed
        }
        if self.isTls {
            try await self.tlsConn.Write(bytes)
        } else {
            try await self.stream.Write(bytes)
        }
    }

    mutating func readInto(_ buf: inout [uint8]) async throws -> int {
        if self.IsClosed {
            return 0
        }
        if self.isTls {
            return try await self.tlsConn.Read(into: &buf)
        } else {
            return try await self.stream.Read(into: &buf)
        }
    }

    /// Sends a Text message (masked if client).
    public mutating func SendText(_ text: string) async throws {
        var bytes: [uint8] = []
        for b in text.utf8 {
            bytes.append(b)
        }
        let frame = BuildFrame(fin: true, opcode: Opcode.Text, masked: self.IsClient, payload: bytes)
        try await self.writeBytes(frame)
    }

    /// Sends a Binary message (masked if client).
    public mutating func SendBinary(_ data: [uint8]) async throws {
        let frame = BuildFrame(fin: true, opcode: Opcode.Binary, masked: self.IsClient, payload: data)
        try await self.writeBytes(frame)
    }

    /// Sends a Ping control frame without payload.
    public mutating func SendPing() async throws {
        let empty: [uint8] = []
        try await self.SendPing(empty)
    }

    /// Sends a Ping control frame (max 125 bytes payload).
    public mutating func SendPing(_ data: [uint8]) async throws {
        if data.count > 125 {
            throw WebSocketError.protocolError("Ping payload must be <= 125 bytes")
        }
        let frame = BuildFrame(fin: true, opcode: Opcode.Ping, masked: self.IsClient, payload: data)
        try await self.writeBytes(frame)
    }

    /// Sends a Pong control frame without payload.
    public mutating func SendPong() async throws {
        let empty: [uint8] = []
        try await self.SendPong(empty)
    }

    /// Sends a Pong control frame echoing ping data.
    public mutating func SendPong(_ data: [uint8]) async throws {
        if data.count > 125 {
            throw WebSocketError.protocolError("Pong payload must be <= 125 bytes")
        }
        let frame = BuildFrame(fin: true, opcode: Opcode.Pong, masked: self.IsClient, payload: data)
        try await self.writeBytes(frame)
    }

    /// Closes the WebSocket connection with NormalClosure (1000).
    public mutating func Close() async throws {
        try await self.Close(code: CloseCode.NormalClosure, reason: "")
    }

    /// Closes the WebSocket connection with an RFC 6455 Close code.
    public mutating func Close(code: uint16) async throws {
        try await self.Close(code: code, reason: "")
    }

    /// Closes the WebSocket connection with an RFC 6455 Close frame and terminates the socket.
    public mutating func Close(code: uint16, reason: string) async throws {
        if self.IsClosed {
            return
        }
        let closePayload = BuildClosePayload(code: code, reason: reason)
        let closeFrame = BuildFrame(fin: true, opcode: Opcode.Close, masked: self.IsClient, payload: closePayload)
        do {
            try await self.writeBytes(closeFrame)
        } catch {
        }
        self.IsClosed = true

        if self.isTls {
            self.tlsConn.Close()
        } else {
            self.stream.Close()
        }
    }

    /// Internal helper reading the next single frame from the transport buffer.
    mutating func readNextFrame() async throws -> Frame {
        var buf = [uint8](repeating: 0, count: 4096)

        while true {
            if self.readBuffer.count >= 2 {
                let b1 = self.readBuffer[1]
                let masked = (b1 & 0x80) != 0
                let lenIndicator = int(b1 & 0x7f)
                var minHeaderLen = 2 + (masked ? 4 : 0)
                if lenIndicator == 126 { minHeaderLen += 2 }
                else if lenIndicator == 127 { minHeaderLen += 8 }

                if self.readBuffer.count >= minHeaderLen {
                    var payloadLen = lenIndicator
                    if lenIndicator == 126 {
                        payloadLen = (int(self.readBuffer[2]) << 8) | int(self.readBuffer[3])
                    } else if lenIndicator == 127 {
                        var l = 0
                        var s = 56
                        var i = 0
                        while i < 8 {
                            l = l | (int(self.readBuffer[2 + i]) << s)
                            s -= 8
                            i += 1
                        }
                        payloadLen = l
                    }

                    if self.readBuffer.count >= minHeaderLen + payloadLen {
                        let parsed = try ParseFrame(data: self.readBuffer, offset: 0)
                        let frame = parsed.Frame
                        let consumed = parsed.BytesRead

                        var rem: [uint8] = []
                        var ri = consumed
                        while ri < self.readBuffer.count {
                            rem.append(self.readBuffer[ri])
                            ri += 1
                        }
                        self.readBuffer = rem
                        return frame
                    }
                }
            }

            let n = try await self.readInto(&buf)
            if n <= 0 {
                throw WebSocketError.connectionClosed
            }
            var bi = 0
            while bi < n {
                self.readBuffer.append(buf[bi])
                bi += 1
            }
        }
    }

    /// Receives the next complete WebSocket message, automatically reassembling fragments and handling control frames.
    public mutating func Receive() async throws -> Message {
        var initialOpcode: uint8 = 0
        var isFragmented = false
        var accumulatedPayload: [uint8] = []

        while true {
            let frame = try await self.readNextFrame()

            // Control frames (Close, Ping, Pong)
            if frame.Opcode == Opcode.Close {
                if !self.IsClosed {
                    let closePayload = BuildClosePayload(code: CloseCode.NormalClosure, reason: "")
                    let ackFrame = BuildFrame(fin: true, opcode: Opcode.Close, masked: self.IsClient, payload: closePayload)
                    try? await self.writeBytes(ackFrame)
                    self.IsClosed = true
                }
                return Message(type: MessageType.close, data: frame.Payload)
            } else if frame.Opcode == Opcode.Ping {
                // Auto-reply with Pong echoing ping payload
                try await self.SendPong(frame.Payload)
                return Message(type: MessageType.ping, data: frame.Payload)
            } else if frame.Opcode == Opcode.Pong {
                return Message(type: MessageType.pong, data: frame.Payload)
            }

            // Data frames (Text, Binary, Continuation)
            if frame.Opcode == Opcode.Text || frame.Opcode == Opcode.Binary {
                if isFragmented {
                    throw WebSocketError.protocolError("Received new data frame before previous fragment was completed")
                }
                initialOpcode = frame.Opcode
                for b in frame.Payload { accumulatedPayload.append(b) }

                if frame.Fin {
                    let msgType = (initialOpcode == Opcode.Text) ? MessageType.text : MessageType.binary
                    return Message(type: msgType, data: accumulatedPayload)
                } else {
                    isFragmented = true
                }
            } else if frame.Opcode == Opcode.Continuation {
                if !isFragmented {
                    throw WebSocketError.protocolError("Unexpected continuation frame without initial fragment")
                }
                for b in frame.Payload { accumulatedPayload.append(b) }

                if frame.Fin {
                    let msgType = (initialOpcode == Opcode.Text) ? MessageType.text : MessageType.binary
                    return Message(type: msgType, data: accumulatedPayload)
                }
            } else {
                throw WebSocketError.unexpectedOpcode(frame.Opcode)
            }
        }
    }
}

/// Backward-compatible typealias for WebSocket connection.
public typealias Conn = WebSocket


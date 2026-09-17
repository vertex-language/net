package http

import "net/tcp"

/// ResponseWriter provides an interface for constructing and sending an HTTP response.
public struct ResponseWriter {
    public var StatusCode: int32 = 200
    public var Headers: Header = Header()
    public var Body: [uint8] = []

    public init() {}

    public mutating func SetStatus(_ code: int32) {
        self.StatusCode = code
    }

    public mutating func SetHeader(_ key: string, _ value: string) {
        Headers.Set(key, value)
    }

    public mutating func Write(_ data: [uint8]) {
        var i = 0
        while i < data.count {
            Body.append(data[i])
            i += 1
        }
    }

    public mutating func WriteText(_ s: string) {
        for b in s.utf8 {
            Body.append(b)
        }
    }
}

/// ServeConn handles a single HTTP client connection.
public func ServeConn(stream: tcp.TcpStream, handle: (Request) async throws -> ResponseWriter) async {
    defer { stream.Close() }
    do {
        let req = try await ReadRequest(from: stream)
        var writer = try await handle(req)

        var res = Response(statusCode: writer.StatusCode)
        res.Headers = writer.Headers
        if res.Headers.Get("Content-Length") == nil {
            res.Headers.Set("Content-Length", "\(writer.Body.count)")
        }
        if res.Headers.Get("Connection") == nil {
            res.Headers.Set("Connection", "close")
        }
        res.Body = writer.Body
        try await res.Write(to: stream)
    } catch {
        // Connection closed or error
    }
}

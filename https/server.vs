package https

import "net/http"
import "crypto/tls"

/// ServeConn handles a single incoming HTTPS client connection over an established TLS session.
public func ServeConn(conn: inout tls.Conn, handle: (http.Request) async throws -> http.ResponseWriter) async {
    defer { conn.Close() }
    do {
        let req = try await ReadRequest(from: &conn)
        var writer = try await handle(req)

        var res = http.Response(statusCode: writer.StatusCode)
        res.Headers = writer.Headers
        if res.Headers.Get("Content-Length") == nil {
            res.Headers.Set("Content-Length", "\(writer.Body.count)")
        }
        if res.Headers.Get("Connection") == nil {
            res.Headers.Set("Connection", "close")
        }
        res.Body = writer.Body
        try await res.Write(to: &conn)
    } catch {
        // Connection closed or error
    }
}

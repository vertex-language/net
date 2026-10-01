# net/http

HTTP client and server for HTTP/1.1, HTTP/2, and HTTP/3, with TLS 1.3, header compression, and streamed response bodies.

## Example

```vertex
import "net/http"

func main() async throws {
    let response = try await http.Get("http://example.com/")
    print(response.StatusCode)
}
```

## Types

- **`AltSvcService`** (struct): Represents an alternative service advertisement (RFC 7838).
- **`AltSvcCacheEntry`** (struct): An in-memory cache for RFC 7838 alternative services.
- **`AltSvcCache`** (struct)
- **`ClientConfig`** (struct): ClientConfig specifies protocol preferences, timeouts, and TLS options for Client.
- **`Client`** (struct): Client is a unified multi-protocol HTTP client supporting HTTP/1.1, HTTP/2, and HTTP/3.
- **`H2FrameType`** (struct)
- **`H2Flag`** (struct)
- **`H2ErrorCode`** (struct)
- **`H2SettingId`** (struct)
- **`H2Setting`** (struct)
- and 32 more

## Functions

- `func ParseAltSvcHeader(_ value: string, defaultHost: string = "") -> [AltSvcService]`: Parses an Alt-Svc header value into a list of advertised alternative services. Example: `h3=":443"; ma=86400` or `h3="alt.example.com:8443"`
- `func WriteRequestTls(_ req: Request, to conn: inout tls.Conn) async throws`: Writes an HTTP request to an active TLS connection.
- `func ReadResponseTls(from conn: inout tls.Conn) async throws -> Response`: Reads an HTTP/1.1 response from a connected TLS session.
- `func Get(_ address: string) async throws -> Response`: Get sends an HTTP GET request to url using DefaultClient.
- `func Post(_ address: string, contentType: string, body: [uint8]) async throws -> Response`: Post sends an HTTP POST request to url using DefaultClient.
- `func GetH3(_ address: string) async throws -> Response`: GetH3 sends an HTTP/3 GET request to url directly over QUIC.
- `func DecodeChunked(_ d: [uint8]) -> [uint8]`: A chunked body's data, its chunks joined; as much as there is when it was cut short.
- `func H2FrameContent(_ frame: H2Frame) throws -> [uint8]`: A DATA or HEADERS frame's content: without the pad length and padding a PADDED frame carries (RFC 9113 6.1, 6.2), and for HEADERS without the PRIORITY flag's dependency and weight.
- `func H2ClientPreface() -> [uint8]`: 24-byte client connection preface (RFC 9113 Section 3.4).
- `func BuildH2Frame(type: uint8, flags: uint8, streamId: uint32, payload: [uint8]) -> [uint8]`: Serializes an RFC 9113 9-byte frame header and payload.
- and 28 more

Part of the [`net`](https://github.com/vertex-language/net) repository.

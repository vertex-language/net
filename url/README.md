# net/url

Parses URLs and resolves references against them, as RFC 3986 describes, with the leniency the web's URLs need (WHATWG URL): a backslash is a slash in http(s), ws(s), ftp and file URLs, tabs and newlines are dropped, and the host of those schemes is lowercase.

## Example

```vertex
import "net/url"

let u = try url.Parse("https://example.com:8080/docs?page=2")
print(u.Scheme, u.Host, u.Port, u.Path)
```

## Types

- **`URL`** (struct): A parsed URL. Components are kept as written, percent-encoding and all; Scheme and a special scheme's Host are lowercased.
- **`URLError`** (enum): Why a URL doesn't parse.
- **`Values`** (struct): A query's parameters, in order, a key allowed more than once.

## Functions

- `func PathEscape(_ s: string) -> string`: A string escaped to be one path segment: '/' is escaped too.
- `func QueryEscape(_ s: string) -> string`: A string escaped to be a query key or value, as forms send it: spaces become '+'.
- `func PathUnescape(_ s: string) -> string`: A path's %XX sequences decoded. A '%' not followed by two hex digits is kept, as browsers keep it.
- `func QueryUnescape(_ s: string) -> string`: A query key or value decoded: %XX, and '+' as a space.
- `func DefaultPort(_ scheme: string) -> uint16`: The port a scheme uses when a URL names none, or 0.
- `func Parse(_ text: string) throws -> URL`: Parses an absolute URL or a relative reference.
- `func ParseQuery(_ query: string) -> Values`: A query string's parameters: "a=1&b=two+words" (without its '?'). A pair without '=' has an empty value; empty pairs are skipped.

Part of the [`net`](https://github.com/vertex-language/net) repository.

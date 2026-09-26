package udp

// SocketAddress is a host and a port.
public enum SocketAddress {
    case v4(ip: string, port: uint16)
    case v6(ip: string, port: uint16)

    /// Reads "127.0.0.1:8080", ":8080" (any interface), "localhost:80", or
    /// "[::1]:9000". A bare IPv6 address must be bracketed.
    public static func Parse(_ text: string) throws -> SocketAddress {
        var bytes: [uint8] = []
        for b in text.utf8 {
            bytes.append(b)
        }
        let colon: uint8 = 58   // ':'
        let open: uint8 = 91    // '['
        let close: uint8 = 93   // ']'

        if !bytes.isEmpty && bytes[0] == open {
            var end = -1
            var i = 1
            while i < bytes.count {
                if bytes[i] == close {
                    end = i
                    break
                }
                i += 1
            }
            if end < 0 || end + 1 >= bytes.count || bytes[end + 1] != colon {
                throw UdpError.invalidAddress(text)
            }
            guard let port = parsePort(bytes, from: end + 2) else {
                throw UdpError.invalidAddress(text)
            }
            return .v6(ip: asciiText(bytes, from: 1, to: end), port: port)
        }

        var last = -1
        var colons = 0
        var i = 0
        while i < bytes.count {
            if bytes[i] == colon {
                last = i
                colons += 1
            }
            i += 1
        }
        if last < 0 || colons > 1 {
            throw UdpError.invalidAddress(text)
        }
        guard let port = parsePort(bytes, from: last + 1) else {
            throw UdpError.invalidAddress(text)
        }
        let host = last == 0 ? "0.0.0.0" : asciiText(bytes, from: 0, to: last)
        return .v4(ip: host, port: port)
    }

    /// An IPv4 address from its four octets.
    public static func IPv4(_ a: uint8, _ b: uint8, _ c: uint8, _ d: uint8,
                            port: uint16) -> SocketAddress {
        return .v4(ip: "\(a).\(b).\(c).\(d)", port: port)
    }

    // fromC reads an address formatted by sock.cpp.
    static func fromC(ip: string, port: int32) -> SocketAddress {
        let p = uint16(truncatingIfNeeded: port)
        for b in ip.utf8 {
            if b == 58 {
                return .v6(ip: ip, port: p)
            }
        }
        return .v4(ip: ip, port: p)
    }
}

/// The host, without the port, as it was written.
public func (a: borrowing SocketAddress) Host() -> string {
    switch a {
    case .v4(let ip, _): return ip
    case .v6(let ip, _): return ip
    }
}

/// The port, whichever family the address is.
public func (a: borrowing SocketAddress) Port() -> uint16 {
    switch a {
    case .v4(_, let port): return port
    case .v6(_, let port): return port
    }
}

/// The address as written: "host:port", and "[host]:port" for IPv6.
public func (a: borrowing SocketAddress) ToString() -> string {
    switch a {
    case .v4(let ip, let port): return "\(ip):\(port)"
    case .v6(let ip, let port): return "[\(ip)]:\(port)"
    }
}

/// Resolves host to datagram addresses for port.
public func Resolve(host: string, port: uint16) throws -> [SocketAddress] {
    let capacity = 16
    let slot = addressTextCapacity
    var text = [CChar](repeating: 0, count: capacity * slot)
    var families = [int32](repeating: 0, count: capacity)
    let n = host.withCString { h -> int32 in
        text.withUnsafeMutableBufferPointer { tp -> int32 in
            families.withUnsafeMutableBufferPointer { fp -> int32 in
                sockResolve(h, int32(port), tp.baseAddress, int32(slot),
                             int32(capacity), fp.baseAddress)
            }
        }
    }
    if n < 0 {
        throw errorFor(n, host)
    }
    var out: [SocketAddress] = []
    var i = 0
    while i < int(n) {
        var one: [CChar] = []
        var j = i * slot
        while j < (i + 1) * slot && text[j] != 0 {
            one.append(text[j])
            j += 1
        }
        one.append(0)
        let ip = string(cString: one)
        out.append(families[i] == 6 ? .v6(ip: ip, port: port) : .v4(ip: ip, port: port))
        i += 1
    }
    return out
}

func parsePort(_ bytes: [uint8], from start: int) -> uint16? {
    if start >= bytes.count {
        return nil
    }
    var value = 0
    var i = start
    while i < bytes.count {
        let b = bytes[i]
        if b < 48 || b > 57 {
            return nil
        }
        value = value * 10 + int(b - 48)
        if value > 65535 {
            return nil
        }
        i += 1
    }
    return uint16(value)
}

func asciiText(_ bytes: [uint8], from start: int, to end: int) -> string {
    var chars: [CChar] = []
    var i = start
    while i < end {
        chars.append(CChar(truncatingIfNeeded: bytes[i]))
        i += 1
    }
    chars.append(0)
    return string(cString: chars)
}

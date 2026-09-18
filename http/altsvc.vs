package http

/// Represents an alternative service advertisement (RFC 7838).
public struct AltSvcService {
    public var Protocol: string
    public var Host: string
    public var Port: uint16
    public var MaxAgeSeconds: int64

    public init(proto: string, host: string, port: uint16, maxAgeSeconds: int64 = 86400) {
        self.Protocol = proto
        self.Host = host
        self.Port = port
        self.MaxAgeSeconds = maxAgeSeconds
    }
}

/// Parses an Alt-Svc header value into a list of advertised alternative services.
/// Example: `h3=":443"; ma=86400` or `h3="alt.example.com:8443"`
public func ParseAltSvcHeader(_ value: string, defaultHost: string = "") -> [AltSvcService] {
    var services: [AltSvcService] = []
    var vBytes: [uint8] = []
    for b in value.utf8 { vBytes.append(b) }

    // Split on comma for multiple service entries
    var entries: [string] = []
    var start = 0
    var inQuotes = false
    var i = 0
    while i < vBytes.count {
        let b = vBytes[i]
        if b == 34 { // '"'
            inQuotes = !inQuotes
        } else if b == 44 && !inQuotes { // ','
            entries.append(asciiString(vBytes, from: start, to: i))
            start = i + 1
        }
        i += 1
    }
    if start < vBytes.count {
        entries.append(asciiString(vBytes, from: start, to: vBytes.count))
    }

    var ei = 0
    while ei < entries.count {
        let entry = trimSpaces(entries[ei])
        ei += 1
        if entry.isEmpty || entry == "clear" {
            continue
        }

        var eBytes: [uint8] = []
        for b in entry.utf8 { eBytes.append(b) }

        // Format: protocol="host:port"; param1=val1; ...
        var eqIdx = -1
        var j = 0
        while j < eBytes.count {
            if eBytes[j] == 61 { // '='
                eqIdx = j
                break
            }
            j += 1
        }
        if eqIdx <= 0 { continue }

        let proto = trimSpaces(asciiString(eBytes, from: 0, to: eqIdx))
        var rest = trimSpaces(asciiString(eBytes, from: eqIdx + 1, to: eBytes.count))

        // Extract value inside quotes
        var hostPortStr = ""
        var semiIdx = -1
        var rBytes: [uint8] = []
        for b in rest.utf8 { rBytes.append(b) }

        var qStart = -1
        var qEnd = -1
        var k = 0
        while k < rBytes.count {
            if rBytes[k] == 34 { // '"'
                if qStart < 0 {
                    qStart = k + 1
                } else if qEnd < 0 {
                    qEnd = k
                }
            } else if rBytes[k] == 59 && qEnd >= 0 { // ';' after closing quote
                semiIdx = k
                break
            }
            k += 1
        }

        if qStart >= 0 && qEnd > qStart {
            hostPortStr = asciiString(rBytes, from: qStart, to: qEnd)
        } else {
            // Unquoted
            var end = rBytes.count
            k = 0
            while k < rBytes.count {
                if rBytes[k] == 59 { // ';'
                    end = k
                    semiIdx = k
                    break
                }
                k += 1
            }
            hostPortStr = trimSpaces(asciiString(rBytes, from: 0, to: end))
        }

        var host = defaultHost
        var port: uint16 = 443

        var hpBytes: [uint8] = []
        for b in hostPortStr.utf8 { hpBytes.append(b) }
        var colonIdx = -1
        k = 0
        while k < hpBytes.count {
            if hpBytes[k] == 58 { // ':'
                colonIdx = k
                break
            }
            k += 1
        }

        if colonIdx == 0 {
            // Port only, e.g. ":443"
            let pStr = asciiString(hpBytes, from: 1, to: hpBytes.count)
            port = uint16(parseContentLength(pStr))
        } else if colonIdx > 0 {
            host = asciiString(hpBytes, from: 0, to: colonIdx)
            let pStr = asciiString(hpBytes, from: colonIdx + 1, to: hpBytes.count)
            port = uint16(parseContentLength(pStr))
        }

        var maxAge: int64 = 86400
        if semiIdx >= 0 {
            let paramsStr = asciiString(rBytes, from: semiIdx + 1, to: rBytes.count)
            var pBytes2: [uint8] = []
            for b in paramsStr.utf8 { pBytes2.append(b) }
            // Look for ma=
            var m = 0
            while m + 3 < pBytes2.count {
                if pBytes2[m] == 109 && pBytes2[m+1] == 97 && pBytes2[m+2] == 61 { // "ma="
                    var maEnd = pBytes2.count
                    var n = m + 3
                    while n < pBytes2.count {
                        if pBytes2[n] == 59 || pBytes2[n] == 32 {
                            maEnd = n
                            break
                        }
                        n += 1
                    }
                    let maStr = asciiString(pBytes2, from: m + 3, to: maEnd)
                    maxAge = int64(parseContentLength(maStr))
                    break
                }
                m += 1
            }
        }

        if port > 0 {
            services.append(AltSvcService(proto: proto, host: host, port: port, maxAgeSeconds: maxAge))
        }
    }

    return services
}

/// An in-memory cache for RFC 7838 alternative services.
public struct AltSvcCacheEntry {
    public var Origin: string
    public var Service: AltSvcService
    public init(origin: string, service: AltSvcService) {
        self.Origin = origin
        self.Service = service
    }
}

public struct AltSvcCache {
    public var entries: [AltSvcCacheEntry]

    public init() {
        self.entries = []
    }

    public mutating func Set(origin: string, service: AltSvcService) {
        var i = 0
        while i < entries.count {
            if entries[i].Origin == origin && entries[i].Service.Protocol == service.Protocol {
                entries[i].Service = service
                return
            }
            i += 1
        }
        entries.append(AltSvcCacheEntry(origin: origin, service: service))
    }

    public func Get(origin: string, protocolName: string) -> AltSvcService? {
        var i = 0
        while i < entries.count {
            if entries[i].Origin == origin && entries[i].Service.Protocol == protocolName {
                return entries[i].Service
            }
            i += 1
        }
        return nil
    }

    public mutating func Clear() {
        self.entries = []
    }

    public mutating func Clear(origin: string) {
        var filtered: [AltSvcCacheEntry] = []
        var i = 0
        while i < entries.count {
            if entries[i].Origin != origin {
                filtered.append(entries[i])
            }
            i += 1
        }
        entries = filtered
    }
}

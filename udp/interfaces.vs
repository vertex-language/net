package udp

/// NetworkInterface represents an active local network adapter and its IP address.
public struct NetworkInterface {
    public var Name: string
    public var IP: string
    public var IsIPv6: bool
    public var IsUp: bool
    public var IsLoopback: bool
    public var IsPointToPoint: bool

    public init(name: string, ip: string, isIPv6: bool, isUp: bool, isLoopback: bool, isPointToPoint: bool) {
        self.Name = name
        self.IP = ip
        self.IsIPv6 = isIPv6
        self.IsUp = isUp
        self.IsLoopback = isLoopback
        self.IsPointToPoint = isPointToPoint
    }

    public func Address(port: uint16 = 0) -> SocketAddress {
        if IsIPv6 {
            return .v6(ip: IP, port: port)
        }
        return .v4(ip: IP, port: port)
    }
}

/// GetNetworkInterfaces enumerates all active network interfaces and IP addresses on this host.
public func GetNetworkInterfaces() throws -> [NetworkInterface] {
    let maxCount = 64
    let nameLen = 32
    let ipLen = 64

    var names = [CChar](repeating: 0, count: maxCount * nameLen)
    var ips = [CChar](repeating: 0, count: maxCount * ipLen)
    var families = [int32](repeating: 0, count: maxCount)
    var flags = [int32](repeating: 0, count: maxCount)

    let n = names.withUnsafeMutableBufferPointer { np in
        ips.withUnsafeMutableBufferPointer { ip in
            families.withUnsafeMutableBufferPointer { fp in
                flags.withUnsafeMutableBufferPointer { flp in
                    cudp_get_interfaces(np.baseAddress, int32(nameLen),
                                        ip.baseAddress, int32(ipLen),
                                        int32(maxCount),
                                        fp.baseAddress,
                                        flp.baseAddress)
                }
            }
        }
    }

    if n < 0 {
        throw errorFor(n, "enumerating network interfaces")
    }

    var result: [NetworkInterface] = []
    var i = 0
    while i < int(n) {
        var nameChars: [CChar] = []
        var ni = i * nameLen
        while ni < (i + 1) * nameLen && names[ni] != 0 {
            nameChars.append(names[ni])
            ni += 1
        }
        nameChars.append(0)
        let name = string(cString: nameChars)

        var ipChars: [CChar] = []
        var ii = i * ipLen
        while ii < (i + 1) * ipLen && ips[ii] != 0 {
            ipChars.append(ips[ii])
            ii += 1
        }
        ipChars.append(0)
        let ip = string(cString: ipChars)

        let isIPv6 = (families[i] == 6)
        let f = flags[i]
        let isUp = (f & 1) != 0
        let isLoopback = (f & 2) != 0
        let isP2P = (f & 4) != 0

        result.append(NetworkInterface(name: name, ip: ip, isIPv6: isIPv6, isUp: isUp, isLoopback: isLoopback, isPointToPoint: isP2P))
        i += 1
    }

    return result
}

package ice

import "net/udp"
import "net/stun"

/// CandidateGatherer manages local host and server-reflexive ICE candidate discovery.
public struct CandidateGatherer {
    public var LocalPort: uint16
    public var StunServers: [string]

    public init(localPort: uint16 = 0, stunServers: [string] = []) {
        self.LocalPort = localPort
        self.StunServers = stunServers
    }

    /// Gathers all local host and reflexive candidates.
    /// Binds a UDP socket on the specified local port (or ephemeral) and returns the socket and candidates.
    public func Gather() async throws -> (socket: udp.UdpSocket, candidates: [Candidate]) {
        let sock = try udp.Bind(host: "0.0.0.0", port: self.LocalPort)
        let actualPort = sock.LocalAddress.Port()

        var candidates: [Candidate] = []
        var foundationId = 1

        // 1. Gather Host Candidates from Network Interfaces
        if let ifaces = try? udp.GetNetworkInterfaces() {
            var localPref: uint16 = 65535
            var i = 0
            while i < ifaces.count {
                let iface = ifaces[i]
                if iface.IsUp && !iface.IsIPv6 && !iface.IsLoopback {
                    let addr = udp.SocketAddress.v4(ip: iface.IP, port: actualPort)
                    let cand = NewHostCandidate(foundation: "\(foundationId)", address: addr, localPref: localPref)
                    candidates.append(cand)
                    foundationId += 1
                    if localPref > 100 { localPref -= 100 }
                }
                i += 1
            }
        }

        // Always ensure at least loopback host candidate if none found
        if candidates.isEmpty {
            let loopbackAddr = udp.SocketAddress.v4(ip: "127.0.0.1", port: actualPort)
            candidates.append(NewHostCandidate(foundation: "\(foundationId)", address: loopbackAddr, localPref: 65535))
            foundationId += 1
        }

        let primaryHostAddr = candidates[0].Address

        // 2. Gather Server Reflexive (srflx) Candidates via STUN
        var si = 0
        while si < self.StunServers.count {
            let serverStr = self.StunServers[si]
            if let srflxAddr = try? await stun.Discover(server: serverStr) {
                let srflxCand = NewServerReflexiveCandidate(
                    foundation: "\(foundationId)",
                    address: srflxAddr,
                    relatedAddress: primaryHostAddr,
                    localPref: 65535
                )
                candidates.append(srflxCand)
                foundationId += 1
            }
            si += 1
        }

        return (socket: sock, candidates: candidates)
    }
}

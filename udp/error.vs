package udp

// UdpError is every way an operation in this package fails.
public enum UdpError: Error {
    /// Nothing was listening at the address or target rejected packet.
    case connectionRefused(string)
    /// A deadline set on the operation passed before it could finish.
    case timedOut(string)
    /// The peer reset the connection (for connected UDP sockets).
    case connectionReset(string)
    /// The address is already bound by another socket.
    case addressInUse(string)
    /// There is no route to the address.
    case networkUnreachable(string)
    /// The peer closed the socket.
    case brokenPipe(string)
    /// The text is not an address, or names a host that did not resolve.
    case invalidAddress(string)
    /// The datagram is too large for the network interface MTU.
    case datagramTooLarge(string)
    /// The operation requires a connected socket.
    case notConnected(string)
    /// Anything else, with the number the operating system reported.
    case systemError(code: int32, context: string)

    /// A formatted sentence naming what failed.
    public var Message: string {
        switch self {
        case .connectionRefused(let what): return "connection refused: \(what)"
        case .timedOut(let what): return "timed out: \(what)"
        case .connectionReset(let what): return "connection reset by peer: \(what)"
        case .addressInUse(let what): return "address already in use: \(what)"
        case .networkUnreachable(let what): return "network unreachable: \(what)"
        case .brokenPipe(let what): return "broken pipe: \(what)"
        case .invalidAddress(let what): return "invalid address: \(what)"
        case .datagramTooLarge(let what): return "datagram too large: \(what)"
        case .notConnected(let what): return "socket not connected: \(what)"
        case .systemError(let code, let what): return "system error \(code): \(what)"
        }
    }
}

// errorFor translates a negative sock.cpp result code into a UdpError.
func errorFor(_ code: int32, _ context: string) -> UdpError {
    switch code {
    case Code.refused: return .connectionRefused(context)
    case Code.timedOut: return .timedOut(context)
    case Code.addressInUse: return .addressInUse(context)
    case Code.reset: return .connectionReset(context)
    case Code.brokenPipe: return .brokenPipe(context)
    case Code.unreachable: return .networkUnreachable(context)
    case Code.invalidAddress: return .invalidAddress(context)
    case Code.tooLarge: return .datagramTooLarge(context)
    case Code.notConnected: return .notConnected(context)
    default: return .systemError(code: sockLastError(), context: context)
    }
}

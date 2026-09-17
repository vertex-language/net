package tcp

// TcpError is every way an operation in this package fails.
//
// Each case carries what was being attempted, because the same failure
// means different things in different places: "connection refused" wants
// to name the address that refused it, and "timed out" the read that
// waited. `Message` is that, formatted.
public enum TcpError: Error {
    /// Nothing was listening at the address.
    case connectionRefused(string)
    /// A deadline set on the operation passed before it could finish.
    case timedOut(string)
    /// The peer reset the connection.
    case connectionReset(string)
    /// The address is already bound by another socket.
    case addressInUse(string)
    /// There is no route to the address.
    case networkUnreachable(string)
    /// The peer closed the connection and this end went on writing.
    case brokenPipe(string)
    /// The text is not an address, or names a host that did not resolve.
    case invalidAddress(string)
    /// The stream held more than the caller was willing to read.
    case limitExceeded(limit: int, context: string)
    /// The stream ended in the middle of something that had to be whole.
    case unexpectedEnd(string)
    /// Anything else, with the number the operating system reported.
    case systemError(code: int32, context: string)

    /// A sentence naming what failed and what was being attempted.
    public var Message: string {
        switch self {
        case .connectionRefused(let what): return "connection refused: \(what)"
        case .timedOut(let what): return "timed out: \(what)"
        case .connectionReset(let what): return "connection reset by peer: \(what)"
        case .addressInUse(let what): return "address already in use: \(what)"
        case .networkUnreachable(let what): return "network unreachable: \(what)"
        case .brokenPipe(let what): return "broken pipe: \(what)"
        case .invalidAddress(let what): return "invalid address: \(what)"
        case .limitExceeded(let limit, let what): return "more than \(limit) bytes: \(what)"
        case .unexpectedEnd(let what): return "stream ended early: \(what)"
        case .systemError(let code, let what): return "system error \(code): \(what)"
        }
    }
}

// errorFor is the error a negative ctcp result stands for. context names
// what was being attempted -- an address, or "read from 10.0.0.2:443" --
// and becomes the message.
//
// Code.wouldBlock never reaches here: it is not a failure, it is a caller
// that has to wait for the socket and ask again, and every loop in this
// package handles it before it gets this far.
func errorFor(_ code: int32, _ context: string) -> TcpError {
    switch code {
    case Code.refused: return .connectionRefused(context)
    case Code.timedOut: return .timedOut(context)
    case Code.addressInUse: return .addressInUse(context)
    case Code.reset: return .connectionReset(context)
    case Code.brokenPipe: return .brokenPipe(context)
    case Code.unreachable: return .networkUnreachable(context)
    case Code.invalidAddress: return .invalidAddress(context)
    default: return .systemError(code: ctcp_last_error(), context: context)
    }
}

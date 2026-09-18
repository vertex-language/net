package ice

// Candidate Pair States (RFC 8445 Section 6.1.2.6)
public struct PairState {
    public static let Frozen: string     = "frozen"
    public static let Waiting: string    = "waiting"
    public static let InProgress: string = "in_progress"
    public static let Succeeded: string  = "succeeded"
    public static let Failed: string     = "failed"
}

/// Calculates pair priority according to RFC 8445 Section 6.1.2.3:
/// pair_priority = (2^32 * MIN(G, D)) + (2 * MAX(G, D)) + (G > D ? 1 : 0)
/// where G is the priority of controlling agent candidate, D is controlled agent candidate.
public func CalculatePairPriority(controllingPriority: uint32, controlledPriority: uint32) -> uint64 {
    let g = uint64(controllingPriority)
    let d = uint64(controlledPriority)
    let minVal = (g < d) ? g : d
    let maxVal = (g > d) ? g : d
    let tie: uint64 = (g > d) ? 1 : 0
    return (minVal << 32) | (maxVal << 1) | tie
}

/// CandidatePair represents a checklist entry of a local and remote candidate (RFC 8445 Section 6.1.2).
public struct CandidatePair {
    public var Local: Candidate
    public var Remote: Candidate
    public var Priority: uint64
    public var State: string
    public var Nominated: bool
}

/// Creates a new CandidatePair and computes its pair priority.
public func NewCandidatePair(local: Candidate,
                             remote: Candidate,
                             isControlling: bool) -> CandidatePair {
    let controllingPrio = isControlling ? local.Priority : remote.Priority
    let controlledPrio = isControlling ? remote.Priority : local.Priority
    let prio = CalculatePairPriority(controllingPriority: controllingPrio, controlledPriority: controlledPrio)
    return CandidatePair(
        Local: local,
        Remote: remote,
        Priority: prio,
        State: PairState.Waiting,
        Nominated: false
    )
}

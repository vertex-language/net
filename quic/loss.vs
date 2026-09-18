package quic

/// Sent packet metadata for loss detection and ACK processing.
public struct SentPacket {
    public var PacketNumber: uint64
    public var SentTimeMs: int64
    public var BytesSent: int
    public var AckEliciting: bool

    public init(packetNumber: uint64, sentTimeMs: int64, bytesSent: int, ackEliciting: bool) {
        self.PacketNumber = packetNumber
        self.SentTimeMs = sentTimeMs
        self.BytesSent = bytesSent
        self.AckEliciting = ackEliciting
    }
}

/// RTT Estimator according to RFC 9002 Section 5.
public struct RttEstimator {
    public var LatestRttMs: int64
    public var SmoothedRttMs: int64
    public var RttVarMs: int64
    public var MinRttMs: int64
    public var FirstSample: bool

    public init(initialRttMs: int64 = 100) {
        self.LatestRttMs = initialRttMs
        self.SmoothedRttMs = initialRttMs
        self.RttVarMs = initialRttMs / 2
        self.MinRttMs = initialRttMs
        self.FirstSample = true
    }

    public mutating func UpdateRtt(latestSampleMs: int64, ackDelayMs: int64 = 0) {
        self.LatestRttMs = latestSampleMs

        if self.FirstSample {
            self.MinRttMs = latestSampleMs
            self.SmoothedRttMs = latestSampleMs
            self.RttVarMs = latestSampleMs / 2
            self.FirstSample = false
            return
        }

        if latestSampleMs < self.MinRttMs {
            self.MinRttMs = latestSampleMs
        }

        var adjustedRtt = latestSampleMs
        if latestSampleMs > ackDelayMs {
            adjustedRtt = latestSampleMs - ackDelayMs
        }
        if adjustedRtt < self.MinRttMs {
            adjustedRtt = self.MinRttMs
        }

        var diff = self.SmoothedRttMs - adjustedRtt
        if diff < 0 { diff = -diff }

        self.RttVarMs = (3 * self.RttVarMs + diff) / 4
        self.SmoothedRttMs = (7 * self.SmoothedRttMs + adjustedRtt) / 8
    }

    /// Computes the Probe Timeout (PTO) duration in milliseconds (RFC 9002 Section 5.2).
    public func ComputePto(maxAckDelayMs: int64 = 25) -> int64 {
        var varPart = 4 * self.RttVarMs
        if varPart < 1 { varPart = 1 }
        return self.SmoothedRttMs + varPart + maxAckDelayMs
    }
}

/// Loss Detector according to RFC 9002 Section 6.
public struct LossDetector {
    public var InFlight: [SentPacket]
    public var LargestAckedPn: uint64
    public var LostPackets: [SentPacket]

    public static let PacketThreshold: uint64 = 3
    public static let TimeThresholdNumerator: int64 = 9
    public static let TimeThresholdDenominator: int64 = 8

    public init() {
        self.InFlight = []
        self.LargestAckedPn = 0
        self.LostPackets = []
    }

    public mutating func OnPacketSent(_ packet: SentPacket) {
        self.InFlight.append(packet)
    }

    /// Evaluates acknowledgments and declares lost packets based on packet & time thresholds.
    public mutating func OnAckReceived(largestAcked: uint64, nowMs: int64, rtt: RttEstimator) -> [SentPacket] {
        if largestAcked > self.LargestAckedPn {
            self.LargestAckedPn = largestAcked
        }

        var maxRtt = rtt.SmoothedRttMs
        if rtt.LatestRttMs > maxRtt {
            maxRtt = rtt.LatestRttMs
        }
        let timeLossThreshold = (LossDetector.TimeThresholdNumerator * maxRtt) / LossDetector.TimeThresholdDenominator

        var remaining: [SentPacket] = []
        var lost: [SentPacket] = []

        var i = 0
        while i < self.InFlight.count {
            let p = self.InFlight[i]

            if p.PacketNumber <= largestAcked {
                // Check if lost
                let isPacketLostByThreshold = (largestAcked >= p.PacketNumber + LossDetector.PacketThreshold)
                let isPacketLostByTime = (nowMs - p.SentTimeMs >= timeLossThreshold)

                if isPacketLostByThreshold || isPacketLostByTime {
                    lost.append(p)
                } else if p.PacketNumber == largestAcked {
                    // Acknowledged, drop from in-flight
                } else {
                    remaining.append(p)
                }
            } else {
                remaining.append(p)
            }
            i += 1
        }

        self.InFlight = remaining
        for p in lost {
            self.LostPackets.append(p)
        }
        return lost
    }
}

/// Standard RFC 9002 NewReno Congestion Controller.
public struct NewRenoCongestionController {
    public var CongestionWindow: int
    public var SlowStartThreshold: int
    public var MaxDatagramSize: int
    public var BytesInFlight: int

    public init(maxDatagramSize: int = 1200) {
        self.MaxDatagramSize = maxDatagramSize
        self.CongestionWindow = 10 * maxDatagramSize // Initial window (approx 12 KB)
        self.SlowStartThreshold = 1048576            // 1 MB
        self.BytesInFlight = 0
    }

    public mutating func OnPacketSent(bytes: int) {
        self.BytesInFlight += bytes
    }

    public mutating func OnPacketAcked(bytes: int) {
        if self.BytesInFlight >= bytes {
            self.BytesInFlight -= bytes
        } else {
            self.BytesInFlight = 0
        }

        if self.CongestionWindow < self.SlowStartThreshold {
            // Slow start
            self.CongestionWindow += bytes
        } else {
            // Congestion avoidance
            let addition = (self.MaxDatagramSize * bytes) / self.CongestionWindow
            if addition > 0 {
                self.CongestionWindow += addition
            } else {
                self.CongestionWindow += 1
            }
        }
    }

    public mutating func OnPacketLost(bytes: int) {
        if self.BytesInFlight >= bytes {
            self.BytesInFlight -= bytes
        } else {
            self.BytesInFlight = 0
        }

        self.SlowStartThreshold = self.CongestionWindow / 2
        let minWindow = 2 * self.MaxDatagramSize
        if self.SlowStartThreshold < minWindow {
            self.SlowStartThreshold = minWindow
        }
        self.CongestionWindow = self.SlowStartThreshold
    }

    public func CanSend() -> bool {
        return self.BytesInFlight < self.CongestionWindow
    }
}

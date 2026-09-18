// The 'net' package: TCP and UDP networking for Vertex.
import PackageDescription

let package = Package(
    name: "net",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(name: "net/tcp", targets: ["tcp"]),
        .library(name: "net/udp", targets: ["udp"]),
        .library(name: "net/http", targets: ["http"]),
        .executable(name: "tcp-echo", targets: ["tcp_echo"]),
        .executable(name: "tcp-client", targets: ["tcp_client"]),
        .executable(name: "tcp-concurrent", targets: ["tcp_concurrent"]),
        .executable(name: "udp-echo", targets: ["udp_echo"]),
        .executable(name: "udp-client", targets: ["udp_client"]),
        .executable(name: "tcp-loopback", targets: ["tcp_loopback"]),
        .executable(name: "udp-loopback", targets: ["udp_loopback"]),
        .executable(name: "loopback", targets: ["loopback"]),
        .executable(name: "http-test", targets: ["http_test"]),
        .library(name: "net/stun", targets: ["stun"]),
        .executable(name: "stun-test", targets: ["stun_test"]),
        .library(name: "net/turn", targets: ["turn"]),
        .executable(name: "turn-test", targets: ["turn_test"]),
        .library(name: "net/ice", targets: ["ice"]),
        .executable(name: "ice-test", targets: ["ice_test"]),
        .library(name: "net/sctp", targets: ["sctp"]),
        .executable(name: "sctp-test", targets: ["sctp_test"]),
        .library(name: "net/datachannel", targets: ["datachannel"]),
        .executable(name: "datachannel-test", targets: ["datachannel_test"]),
        .library(name: "net/webrtc", targets: ["webrtc"]),
        .executable(name: "webrtc-test", targets: ["webrtc_test"]),
        .library(name: "net/quic", targets: ["quic"]),
        .executable(name: "quic-test", targets: ["quic_test"]),
        .library(name: "net/websocket", targets: ["websocket"]),
        .executable(name: "websocket-test", targets: ["websocket_test"]),
    ],
    targets: [
        // The operating system's TCP sockets, as a C ABI.
        .target(
            name: "ctcp",
            path: "tcp/ctcp",
            publicHeadersPath: "include"
        ),
        // The TCP package: Vertex types over ctcp.
        .target(
            name: "tcp",
            dependencies: ["ctcp"],
            path: "tcp"
        ),
        // The operating system's UDP sockets, as a C ABI.
        .target(
            name: "cudp",
            path: "udp/cudp",
            publicHeadersPath: "include"
        ),
        // The UDP package: Vertex types over cudp.
        .target(
            name: "udp",
            dependencies: ["cudp"],
            path: "udp"
        ),
        // The HTTP package: HTTP client and server (HTTP/1.1, HTTP/2, HTTP/3).
        .target(
            name: "http",
            dependencies: ["tcp", "udp", "quic"],
            path: "http"
        ),
        .executableTarget(
            name: "http_test",
            dependencies: ["http", "tcp", "udp", "quic"],
            path: "tests/http"
        ),
        // The STUN package: RFC 8489 NAT traversal.
        .target(
            name: "stun",
            dependencies: ["udp"],
            path: "stun"
        ),
        .executableTarget(
            name: "stun_test",
            dependencies: ["stun", "udp"],
            path: "tests/stun"
        ),
        // The TURN package: RFC 8656 relay traversal.
        .target(
            name: "turn",
            dependencies: ["stun", "udp"],
            path: "turn"
        ),
        .executableTarget(
            name: "turn_test",
            dependencies: ["turn", "stun", "udp"],
            path: "tests/turn"
        ),
        // The ICE package: RFC 8445 Interactive Connectivity Establishment.
        .target(
            name: "ice",
            dependencies: ["stun", "turn", "udp"],
            path: "ice"
        ),
        .executableTarget(
            name: "ice_test",
            dependencies: ["ice", "stun", "udp"],
            path: "tests/ice"
        ),
        // The SCTP package: RFC 4960 / RFC 8261 Stream Control Transmission Protocol.
        .target(
            name: "sctp",
            dependencies: [],
            path: "sctp"
        ),
        .executableTarget(
            name: "sctp_test",
            dependencies: ["sctp"],
            path: "tests/sctp"
        ),
        // The DataChannel package: RFC 8831 / RFC 8832 WebRTC Data Channels.
        .target(
            name: "datachannel",
            dependencies: ["sctp"],
            path: "datachannel"
        ),
        .executableTarget(
            name: "datachannel_test",
            dependencies: ["datachannel", "sctp"],
            path: "tests/datachannel"
        ),
        // The WebRTC package: RFC 9429 PeerConnection, JSEP, and DataChannels.
        .target(
            name: "webrtc",
            dependencies: ["ice", "sctp", "datachannel", "udp", "stun"],
            path: "webrtc"
        ),
        .executableTarget(
            name: "webrtc_test",
            dependencies: ["webrtc", "ice", "sctp", "datachannel", "udp"],
            path: "tests/webrtc"
        ),
        // The QUIC package: RFC 9000 / RFC 9001 / RFC 9002 / RFC 9221.
        .target(
            name: "quic",
            dependencies: ["udp"],
            path: "quic"
        ),
        .executableTarget(
            name: "quic_test",
            dependencies: ["quic", "udp"],
            path: "tests/quic"
        ),
        // The WebSocket package: RFC 6455 over TCP or TLS.
        .target(
            name: "websocket",
            dependencies: ["tcp", "http"],
            path: "websocket"
        ),
        .executableTarget(
            name: "websocket_test",
            dependencies: ["websocket", "tcp", "http"],
            path: "tests/websocket"
        ),
        // TCP Examples
        .executableTarget(
            name: "tcp_echo",
            dependencies: ["tcp"],
            path: "examples/tcp/echo"
        ),
        .executableTarget(
            name: "tcp_client",
            dependencies: ["tcp"],
            path: "examples/tcp/client"
        ),
        .executableTarget(
            name: "tcp_concurrent",
            dependencies: ["tcp"],
            path: "examples/tcp/concurrent"
        ),
        // UDP Examples
        .executableTarget(
            name: "udp_echo",
            dependencies: ["udp"],
            path: "examples/udp/echo"
        ),
        .executableTarget(
            name: "udp_client",
            dependencies: ["udp"],
            path: "examples/udp/client"
        ),
        // Tests
        .executableTarget(
            name: "tcp_loopback",
            dependencies: ["tcp"],
            path: "tests/tcp/loopback"
        ),
        .executableTarget(
            name: "udp_loopback",
            dependencies: ["udp"],
            path: "tests/udp/loopback"
        ),
        .executableTarget(
            name: "loopback",
            dependencies: ["tcp", "udp"],
            path: "tests/loopback"
        ),
    ],
    cxxLanguageStandard: "c++20"
)

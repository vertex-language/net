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
        // The HTTP package: HTTP/1.1 client and server over TCP.
        .target(
            name: "http",
            dependencies: ["tcp"],
            path: "http"
        ),
        .executableTarget(
            name: "http_test",
            dependencies: ["http", "tcp"],
            path: "tests/http"
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

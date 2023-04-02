// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SecureEnclave",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13)
    ],
    products: [
        // C API to CryptoKit secure enclave
        .library(
            name: "SecureEnclave-Static",
            type: .static,
            targets: ["SecureEnclave"]),
        .library(
            name: "SecureEnclave-Dylib",
            type: .dynamic,
            targets: ["SecureEnclave"]),
        // Example executable
        .executable(
            name: "SecureEnclave-Example",
            targets: ["SecureEnclave-Example"])
    ],
    targets: [
        // Swift bridging lib
        .target(
            name: "SecureEnclave-Swift",
            dependencies: []),
        // C API lib
        .target(
            name: "SecureEnclave",
            dependencies: ["SecureEnclave-Swift"],
            publicHeadersPath: "include"),
        // Example target
        .executableTarget(
            name: "SecureEnclave-Example",
            dependencies: ["SecureEnclave"]),
    ]
)

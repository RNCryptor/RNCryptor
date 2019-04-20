// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "RNCryptor",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "RNCryptor",
            targets: ["RNCryptor"]),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "RNCryptor",
            dependencies: []),
        .testTarget(
            name: "RNCryptorTests",
            dependencies: ["RNCryptor"]),
    ]
)

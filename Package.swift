import PackageDescription

let package = Package(
    name: "RNCryptor",
    targets: [
        Target(name: "RNCryptor", dependencies: ["Cryptor"])
    ]
)

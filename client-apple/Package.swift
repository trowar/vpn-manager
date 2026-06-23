// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "CompanyVPNApple",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "CompanyVPNMac", targets: ["CompanyVPNMac"]),
        .library(name: "CompanyVPNShared", targets: ["CompanyVPNShared"])
    ],
    targets: [
        .target(name: "CompanyVPNShared"),
        .executableTarget(
            name: "CompanyVPNMac",
            dependencies: ["CompanyVPNShared"]
        )
    ]
)

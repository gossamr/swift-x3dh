// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "X3DH",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "X3DH",
            targets: ["X3DH"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
         .package(url: "https://github.com/gossamr/SwiftEdDSA", from: "3.6.2"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "X3DH",
            dependencies: ["SwiftEdDSA"]),
        .testTarget(
            name: "X3DHTests",
            dependencies: ["X3DH"]),
    ]
)

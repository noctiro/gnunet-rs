// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "GNUnetNode",
    platforms: [.iOS(.v15)],
    products: [.library(name: "GNUnetNode", targets: ["GNUnetNode"])],
    targets: [
        .binaryTarget(name: "GNUnetNodeNative", path: "GNUnetNodeNative.xcframework"),
        .target(name: "GNUnetNode", dependencies: ["GNUnetNodeNative"], resources: [.copy("Resources")]),
    ]
)

// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "FirewallPolicy",
    platforms: [.macOS(.v13)],
    products: [.library(name: "FirewallPolicy", targets: ["FirewallPolicy"])],
    targets: [
        .target(name: "FirewallPolicy"),
        .testTarget(name: "FirewallPolicyTests", dependencies: ["FirewallPolicy"])
    ]
)

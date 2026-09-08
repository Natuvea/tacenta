// swift-tools-version:5.9
import PackageDescription

// The Tacenta Swift SDK. Run `./build-xcframework.sh` first to produce
// `dist/TacentaFFI.xcframework` and `dist/Sources/Tacenta/Tacenta.swift`
// (with the hand-written `Sources/Tacenta/Inbound.swift` copied beside it);
// this package wraps them so an app can depend on Tacenta with a single
// Swift Package reference.
//
// For distribution the xcframework is zipped, uploaded, and the
// `binaryTarget` switched from `path:` to `url:` + `checksum:`; the local
// path form here is what the example app and CI build against.
let package = Package(
    name: "Tacenta",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "Tacenta", targets: ["Tacenta"]),
        .executable(name: "quickstart", targets: ["quickstart"]),
        .executable(name: "conformance", targets: ["conformance"]),
    ],
    targets: [
        .binaryTarget(
            name: "TacentaFFI",
            path: "dist/TacentaFFI.xcframework"
        ),
        .target(
            name: "Tacenta",
            dependencies: ["TacentaFFI"],
            path: "dist/Sources/Tacenta"
        ),
        // A runnable example that consumes the SDK end to end, compiled by
        // `swift build` so it cannot drift from the exported API.
        .executableTarget(
            name: "quickstart",
            dependencies: ["Tacenta"],
            path: "examples/quickstart"
        ),
        // The conformance run's Swift head (decision 0090, choice 6): the
        // release workflow runs it against hosted Tacenta on every tag.
        .executableTarget(
            name: "conformance",
            dependencies: ["Tacenta"],
            path: "conformance"
        ),
    ]
)

// swift-tools-version: 6.1
//===----------------------------------------------------------------------===//
//
// This source file is part of the fltrECC open source project
//
// Copyright (c) 2022-2026 fltrWallet AG and the fltrECC project authors
// Licensed under Apache License v2.0
//
// See LICENSE.md for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import PackageDescription

// Optional libsecp256k1 modules compiled into the `Csecp256k1` target. The
// matching public headers always ship in `Sources/secp256k1/include`; only the
// implementations gated by these defines are linked in.
let enableModuleEcdh = true
let enableModuleRecovery = true
let enableModuleExtraKeys = true
let enableModuleSchnorrsig = true

// Modern libsecp256k1 (>= 0.3.0) no longer consumes the autoconf `HAVE_*` /
// `STDC_HEADERS` defines or `ECMULT_GEN_PREC_BITS`; the only knobs left are the
// window size and the per-module enables.
var cSettings: [CSetting] = [
    .headerSearchPath("src"),
    .define("ECMULT_WINDOW_SIZE", to: "15"),
]

if enableModuleEcdh {
    cSettings.append(.define("ENABLE_MODULE_ECDH", to: "1"))
}
if enableModuleRecovery {
    cSettings.append(.define("ENABLE_MODULE_RECOVERY", to: "1"))
}
if enableModuleExtraKeys {
    cSettings.append(.define("ENABLE_MODULE_EXTRAKEYS", to: "1"))
}
if enableModuleSchnorrsig {
    cSettings.append(.define("ENABLE_MODULE_SCHNORRSIG", to: "1"))
}

// When building on Windows the headers are consumed in-tree against the
// statically compiled sources, so suppress the `__declspec(dllimport)` markers.
#if os(Windows)
    cSettings.append(.define("SECP256K1_STATIC", to: "1"))
#endif

let package = Package(
    name: "fltrECC",
    // Deployment floor is dictated by `Synchronization.Mutex` (SE-0433), which
    // backs the thread-safe public-key caches. Linux / Android / Windows are
    // unconstrained by `platforms:` and supported via the same code paths.
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(name: "fltrECC", targets: ["fltrECC"]),
        .library(name: "fltrECCTesting", targets: ["fltrECCTesting"]),
        .library(name: "fltrECCAdapter", targets: ["fltrECCAdapter"]),
    ],
    targets: [
        .target(
            name: "Csecp256k1",
            path: "Sources/secp256k1",
            sources: [
                "src/secp256k1.c",
                "src/precomputed_ecmult.c",
                "src/precomputed_ecmult_gen.c",
            ],
            cSettings: cSettings
        ),
        .target(
            name: "CfltrECC"
        ),
        .target(
            name: "fltrECCAdapter",
            dependencies: ["Csecp256k1", "CfltrECC"]
        ),
        .target(
            name: "fltrECC",
            dependencies: ["fltrECCAdapter"]
        ),
        .target(
            name: "fltrECCTesting",
            dependencies: ["fltrECCAdapter"]
        ),
        .testTarget(
            name: "fltrECCTests",
            dependencies: ["fltrECC", "fltrECCTesting"],
            resources: [.copy("Resources/bip340-test-vectors.csv")]
        ),
        .testTarget(
            name: "fltrECCAdapterTests",
            dependencies: ["fltrECCAdapter", "fltrECCTesting"]
        ),
    ],
    swiftLanguageModes: [.v6]
)

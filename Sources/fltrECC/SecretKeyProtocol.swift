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
import fltrECCAdapter

public protocol SecretKeyProtocol: Sendable {
    associatedtype Signature: Sendable
    init(_ scalar: Scalar)
    var scalar: Scalar { get }
    static func random() -> Self
    func sign(message: [UInt8], nonce: Entropy) throws -> Signature
}

public extension SecretKeyProtocol {
    static func random() -> Self {
        let random = Scalar.random()
        return self.init(random)
    }
}

public extension SecretKeyProtocol where Self: Equatable {
    @inlinable
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.scalar == rhs.scalar
    }
}

public extension SecretKeyProtocol where Self: Hashable {
    @inlinable
    func hash(into hasher: inout Hasher) {
        self.scalar.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
}

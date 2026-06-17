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

public enum Entropy: Sendable {
    case some([UInt8])
    case none

    @inlinable
    public static func random() -> Self {
        .some((0..<32).map { _ in .random(in: .min ... .max) })
    }

    @inlinable
    public var value: [UInt8]? {
        switch self {
        case .some(let value): return value
        case .none: return nil
        }
    }
}

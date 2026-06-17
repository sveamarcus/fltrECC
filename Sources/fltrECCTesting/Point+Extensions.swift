//===----------------------------------------------------------------------===//
//
// This source file is part of the fltrECC open source project
//
// Copyright (c) 2022-2026 fltrWallet AG and the fltrECC project authors
// Licensed under Apache License v2.0
//
// See LICENSE.md for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import fltrECCAdapter

extension Point: ExpressibleByIntegerLiteral {
    @inlinable
    public init(_ value: Int) {
        self.init(Scalar(value))
    }

    @inlinable
    public init(integerLiteral value: Int) {
        self.init(value)
    }
}

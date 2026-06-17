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

public extension Scalar {
    @inlinable
    static prefix func - (value: Self) -> Self {
        value.negated()
    }

    @inlinable
    static func + (lhs: Self, rhs: Self) -> Self? {
        lhs.add(rhs)
    }

    @inlinable
    static func - (lhs: Self, rhs: Self) -> Self? {
        lhs.add(rhs.negated())
    }

    @inlinable
    static func * (lhs: Self, rhs: Self) -> Self {
        lhs.mul(rhs)
    }
}

public extension Point {
    @inlinable
    static prefix func - (value: Self) -> Self {
        value.negated()
    }

    @inlinable
    static func + (lhs: Self, rhs: Self) -> Self? {
        lhs.add(rhs)
    }

    @inlinable
    static func - (lhs: Self, rhs: Self) -> Self? {
        lhs.add(rhs.negated())
    }

    @inlinable
    static func * (lhs: Self, rhs: Scalar) -> Self {
        lhs.mul(rhs)
    }

    @inlinable
    static func * (lhs: Scalar, rhs: Self) -> Self {
        rhs.mul(lhs)
    }
}

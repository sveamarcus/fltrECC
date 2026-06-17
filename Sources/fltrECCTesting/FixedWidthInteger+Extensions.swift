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
extension FixedWidthInteger {
    @usableFromInline
    init<I>(littleEndianBytes iterator: inout I)
    where I: IteratorProtocol, I.Element == UInt8 {
        self = stride(from: 0, to: Self.bitWidth, by: 8).reduce(into: 0) {
            $0 |= Self(truncatingIfNeeded: iterator.next()!) &<< $1
        }
    }

    @usableFromInline
    init<C>(littleEndianBytes bytes: C) where C: Collection, C.Element == UInt8 {
        precondition(bytes.count == (Self.bitWidth + 7) / 8)
        var iter = bytes.makeIterator()
        self.init(littleEndianBytes: &iter)
    }
}

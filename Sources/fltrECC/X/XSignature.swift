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

public extension X {
    struct Signature: Sendable {
        @usableFromInline
        internal let _data: [UInt8]

        @usableFromInline
        internal init(_data: [UInt8]) {
            self._data = _data
        }

        @inlinable
        public init?(from serialized: [UInt8]) {
            guard serialized.count == C.SCHNORR_SIGNATURE_SIZE
            else { return nil }
            self.init(_data: serialized)
        }

        @inlinable
        public func serialize() -> [UInt8] {
            self._data
        }
    }
}

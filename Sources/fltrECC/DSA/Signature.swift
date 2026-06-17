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

public extension DSA {
    struct Signature: Sendable {
        @usableFromInline
        internal let _data: [UInt8]

        @usableFromInline
        internal init(_data: [UInt8]) {
            self._data = _data
        }

        @inlinable
        public init?(from serialized: [UInt8]) {
            self.init(from: serialized[...])
        }

        @inlinable
        public init?(from serialized: ArraySlice<UInt8>) {
            guard
                let data: [UInt8] = {
                    if let der = try? C.deSerialize(derSignature: serialized) {
                        return der
                    } else if let compact = try? C.deSerialize(compactSignature: serialized) {
                        return compact
                    } else {
                        return nil
                    }
                }()
            else { return nil }

            self.init(_data: C.normalize(signature: data).signature)
        }

        @inlinable
        public func serializeCompact() -> [UInt8] {
            C.serializeCompact(signature: self._data)
        }

        @inlinable
        public func serializeDer() -> [UInt8] {
            C.serializeDer(signature: self._data)
        }
    }
}

extension DSA.Signature: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs._data.elementsEqual(rhs._data)
    }
}

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
    struct RecoverableSignature: Sendable {
        @usableFromInline
        let _data: [UInt8]

        @usableFromInline
        internal init(_data: [UInt8]) {
            self._data = _data
        }

        @inlinable
        public init?(from serialized: [UInt8], id: Int) {
            guard
                let signature = try? C.deSerialize(
                    recoverable: serialized,
                    id: id)
            else { return nil }
            self.init(_data: signature)
        }

        @inlinable
        public func serialize() -> (data: [UInt8], id: Int) {
            C.serialize(recoverable: self._data)
        }

        @inlinable
        public func dsaSignature() -> DSA.Signature {
            let converted = C.convert(recoverable: self._data)
            return .init(_data: C.normalize(signature: converted).signature)
        }

        @inlinable
        public func recover(from message: [UInt8]) -> DSA.PublicKey? {
            guard message.count == 32
            else { return nil }

            do {
                let data = try C.recoverPoint(from: self._data, message: message)
                return .init(_data: data)
            } catch {
                return nil
            }
        }
    }
}

extension DSA.RecoverableSignature: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs._data.elementsEqual(rhs._data)
    }
}

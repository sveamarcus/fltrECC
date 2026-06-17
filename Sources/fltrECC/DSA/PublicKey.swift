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
    struct PublicKey: Hashable, Sendable {
        @usableFromInline
        let _data: [UInt8]

        @usableFromInline
        internal init(_data: [UInt8]) {
            self._data = _data
        }

        @inlinable
        public init?(from serialized: [UInt8]) {
            guard let data = try? C.deSerialize(point: serialized)
            else { return nil }
            self.init(_data: data)
        }

        @inlinable
        public init(_ point: Point) {
            self.init(_data: point._data)
        }

        public enum Format: Sendable {
            case compressed
            case uncompressed
        }

        @inlinable
        public func serialize(format: Format = .compressed) -> [UInt8] {
            switch format {
            case .compressed: return C.compressed(point: self._data)
            case .uncompressed: return C.uncompressed(point: self._data)
            }
        }

        @inlinable
        public func verify(signature: DSA.Signature, message: [UInt8]) -> Bool {
            guard message.count == 32
            else { return false }

            return C.verify(
                dsa: signature._data,
                point: self._data,
                message: message)
        }

        @inlinable
        public func xOnly() -> (negated: Bool, xPubkey: X.PublicKey) {
            let result = C.xPoint(from: self._data)
            return (result.negated, .init(_data: result.xPoint))
        }
    }
}

extension DSA.PublicKey: Equatable {
    @inlinable
    public static func == (lhs: Self, rhs: Self) -> Bool {
        Point.equalsDSAPoints(lhs: lhs._data, rhs: rhs._data)
    }
}

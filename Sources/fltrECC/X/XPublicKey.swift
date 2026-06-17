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
    struct PublicKey: Sendable {
        @usableFromInline
        let _data: [UInt8]

        @usableFromInline
        internal init(_data: [UInt8]) {
            self._data = _data
        }

        @inlinable
        public init?(from serialized: [UInt8]) {
            guard let data = try? C.deSerialize(xPoint: serialized)
            else { return nil }
            self.init(_data: data)
        }

        @inlinable
        public init?(from serialized: ArraySlice<UInt8>) {
            guard let data = try? C.deSerialize(xPoint: serialized)
            else { return nil }
            self.init(_data: data)
        }

        @inlinable
        public init(_ point: Point) {
            let (_, xPoint) = C.xPoint(from: point._data)
            self.init(_data: xPoint)
        }

        @inlinable
        public func tweak(add scalar: Scalar) -> DSA.PublicKey? {
            do {
                let point = try C.addXTweak(xPoint: self._data, scalar: scalar)
                return .init(_data: point)
            } catch {
                return nil
            }
        }

        @inlinable
        public func check(base point: X.PublicKey, tweak: [UInt8], negated: Bool) -> Bool {
            guard Scalar(tweak) != nil
            else { return false }

            return C.checkAddXTweak(
                tweaked: self.serialize(),
                negated: negated,
                xPoint: point._data,
                tweak: tweak)
        }

        @inlinable
        public func dsa() -> DSA.PublicKey {
            let serialized = [0x02] + self.serialize()
            return .init(from: serialized)!
        }

        @inlinable
        public func serialize() -> [UInt8] {
            C.serialize(xPoint: self._data)
        }

        @inlinable
        public func verify(signature: X.Signature, message: [UInt8]) -> Bool {
            guard message.count == 32
            else { return false }

            return C.verify(
                schnorr: signature._data,
                xPoint: self._data,
                message: message)
        }
    }
}

extension X.PublicKey: Comparable, Equatable, Hashable {
    @inlinable
    public static func < (lhs: X.PublicKey, rhs: X.PublicKey) -> Bool {
        switch C.compareXPoints(lhs._data, rhs._data) {
        case .lessThan: return true
        case .equals, .greaterThan: return false
        }
    }

    @inlinable
    public static func == (lhs: X.PublicKey, rhs: X.PublicKey) -> Bool {
        C.compareXPoints(lhs._data, rhs._data).equals
    }
}

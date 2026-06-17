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
    struct SecretKey: SecretKeyProtocol, Equatable, Hashable {
        @usableFromInline
        let _scalar: Scalar
        @usableFromInline
        let _pubkey: LazyLockedCache<DSA.PublicKey> = .init()

        @inlinable
        public var scalar: Scalar { self._scalar }

        @inlinable
        public init(_ scalar: Scalar) {
            self._scalar = scalar
        }

        @inlinable
        public func pubkey() -> DSA.PublicKey {
            self._pubkey.cache {
                let data = try! C.point(from: self._scalar)
                return .init(_data: data)
            }
        }

        @inlinable
        public func sign(
            message: [UInt8],
            nonce entropy: Entropy = .random()
        ) throws -> DSA.Signature {
            let signature = try C.dsaSign(
                scalar: self._scalar,
                message: message,
                nonce: entropy.value)
            return .init(_data: signature)
        }

        @inlinable
        public func sign(
            recoverable message: [UInt8],
            nonce entropy: Entropy = .random()
        ) throws -> DSA.RecoverableSignature {
            let signature = try C.recoverableSign(
                scalar: self._scalar,
                message: message,
                nonce: entropy.value)
            return .init(_data: signature)
        }

        @inlinable
        public func ecdh(_ pubkey: DSA.PublicKey) -> EcdhSecret {
            try! C.ecdh(
                my: self._scalar,
                their: pubkey._data)
        }
    }
}

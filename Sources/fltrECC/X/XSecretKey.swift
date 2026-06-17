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
    struct SecretKey: SecretKeyProtocol, Equatable, Hashable {
        @usableFromInline
        let _data: EitherScalarOrKeypair

        @usableFromInline
        let _cache: LazyLockedCache<KeyPair> = .init()

        @usableFromInline
        var keypair: KeyPair {
            switch self._data {
            case .keypair(let keypair):
                return keypair
            case .scalar(let scalar):
                return self._cache.cache {
                    try! C.keypair(from: scalar)
                }
            }
        }

        @inlinable
        public var scalar: Scalar {
            switch self._data {
            case .keypair(let keypair):
                return C.scalar(from: keypair)!
            case .scalar(let scalar):
                return scalar
            }
        }

        @inlinable
        public init(_ scalar: Scalar) {
            self._data = .scalar(scalar)
        }

        @usableFromInline
        init(_ keypair: KeyPair) {
            self._data = .keypair(keypair)
        }

        @inlinable
        public func pubkey() -> (negated: Bool, xPoint: X.PublicKey) {
            let result = C.xPoint(from: self.keypair)
            return (result.negated, .init(_data: result.xPoint))
        }

        @inlinable
        public func tweak(add scalar: Scalar) -> X.SecretKey? {
            do {
                let copy = self.keypair.copy()
                try C.addXTweak(into: copy, scalar: scalar)
                return Self.init(copy)
            } catch {
                return nil
            }
        }

        @inlinable
        public func sign(message: [UInt8], nonce entropy: Entropy = .random()) throws -> X.Signature
        {
            let signature = try C.schnorrSign(
                keypair: self.keypair,
                message: message,
                nonce: entropy.value)
            assert(signature.count == C.SCHNORR_SIGNATURE_SIZE)
            return .init(_data: signature)
        }
    }
}

extension X.SecretKey {
    @usableFromInline
    enum EitherScalarOrKeypair: Sendable {
        case scalar(Scalar)
        case keypair(KeyPair)

        @usableFromInline
        var keypair: KeyPair? {
            switch self {
            case .keypair(let keypair): return keypair
            case .scalar: return nil
            }
        }

        @usableFromInline
        var scalar: Scalar? {
            switch self {
            case .scalar(let scalar): return scalar
            case .keypair: return nil
            }
        }
    }
}

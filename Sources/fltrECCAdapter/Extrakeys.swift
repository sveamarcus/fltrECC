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
import Csecp256k1

public extension C {
    @inlinable
    static func deSerialize(xPoint serialized: [UInt8]) throws -> [UInt8] {
        try serialized.withUnsafeBufferPointer(self.deSerialize(xPoint:))
    }

    @inlinable
    static func deSerialize(xPoint serialized: ArraySlice<UInt8>) throws -> [UInt8] {
        try serialized.withUnsafeBufferPointer(self.deSerialize(xPoint:))
    }

    @inlinable
    static func deSerialize(xPoint serialized: UnsafeBufferPointer<UInt8>) throws -> [UInt8] {
        guard serialized.count == 32 else {
            throw C.Error.illegalPointSerializationByteCount
        }

        return try Array(unsafeUninitializedCapacity: C.XPOINT_SIZE) { buffer, setSizeTo in
            let cRet = buffer.baseAddress!.withMemoryRebound(
                to: secp256k1_xonly_pubkey.self, capacity: 1
            ) { buffer in
                secp256k1_xonly_pubkey_parse(
                    self.context.pointer,
                    buffer,
                    serialized.baseAddress!)
            }
            guard cRet == 1 else {
                throw C.Error.illegalPointSerialization
            }
            setSizeTo = C.XPOINT_SIZE
        }
    }

    @inlinable
    static func serialize(xPoint: [UInt8]) -> [UInt8] {
        assert(xPoint.count == C.XPOINT_SIZE)

        return Array(unsafeUninitializedCapacity: 32) { buffer, setSizeTo in
            let cRet = xPoint.withUnsafeBytes { xPoint in
                secp256k1_xonly_pubkey_serialize(
                    self.context.pointer,
                    buffer.baseAddress!,
                    xPoint
                        .bindMemory(to: secp256k1_xonly_pubkey.self)
                        .baseAddress!)
            }
            assert(cRet == 1)
            setSizeTo = 32
        }
    }

    @inlinable
    static func compareXPoints(_ a: [UInt8], _ b: [UInt8]) -> Comparison {
        assert(a.count == C.XPOINT_SIZE && b.count == C.XPOINT_SIZE)
        let cRet = a.withUnsafeBytes { a in
            b.withUnsafeBytes { b in
                secp256k1_xonly_pubkey_cmp(
                    self.context.pointer,
                    a
                        .bindMemory(to: secp256k1_xonly_pubkey.self)
                        .baseAddress!,
                    b
                        .bindMemory(to: secp256k1_xonly_pubkey.self)
                        .baseAddress!)
            }
        }

        if cRet < 0 {
            return .lessThan
        } else if cRet > 0 {
            return .greaterThan
        } else {
            return .equals
        }
    }

    @inlinable
    static func xPoint(from point: [UInt8]) -> (negated: Bool, xPoint: [UInt8]) {
        assert(point.count == C.POINT_SIZE)

        var parity = Int32(-1)
        let xPoint: [UInt8] = Array(unsafeUninitializedCapacity: C.XPOINT_SIZE) {
            buffer, setSizeTo in
            let cRet = buffer
                .baseAddress!
                .withMemoryRebound(to: secp256k1_xonly_pubkey.self, capacity: 1) { buffer in
                    point.withUnsafeBytes { input in
                        secp256k1_xonly_pubkey_from_pubkey(
                            self.context.pointer,
                            buffer,
                            &parity,
                            input
                                .bindMemory(to: secp256k1_pubkey.self)
                                .baseAddress!)
                    }
                }
            assert(cRet == 1)

            setSizeTo = C.XPOINT_SIZE
        }

        let parityResult: Bool = {
            switch parity {
            case 0: return false
            case 1: return true
            default: preconditionFailure()
            }
        }()

        return (parityResult, xPoint)
    }

    //    @inlinable
    static func addXTweak(
        into keypair: KeyPair,
        scalar: Scalar
    ) throws {
        assert(
            keypair.count == C.KEYPAIR_SIZE
                && scalar.count == C.SCALAR_SIZE)

        return try keypair.withUnsafeMutableBytes { keyPairBytes in
            let cRet = scalar.withUnsafeBytes { tweak in
                secp256k1_keypair_xonly_tweak_add(
                    self.context.pointer,
                    keyPairBytes
                        .bindMemory(to: secp256k1_keypair.self)
                        .baseAddress!,
                    tweak
                        .bindMemory(to: UInt8.self)
                        .baseAddress!)
            }
            guard cRet == 1
            else {
                throw C.Error.illegalScalarValue
            }
        }
    }

    @inlinable
    static func addXTweak(
        xPoint: [UInt8],
        scalar: Scalar
    ) throws -> [UInt8] {
        assert(
            xPoint.count == C.XPOINT_SIZE
                && scalar.count == C.SCALAR_SIZE)

        return try Array(unsafeUninitializedCapacity: C.POINT_SIZE) { result, setSizeTo in
            let cRet = result.baseAddress!.withMemoryRebound(
                to: secp256k1_pubkey.self,
                capacity: 1
            ) { result in
                xPoint.withUnsafeBytes { xPoint in
                    scalar.withUnsafeBytes { tweak in
                        secp256k1_xonly_pubkey_tweak_add(
                            self.context.pointer,
                            result,
                            xPoint
                                .bindMemory(to: secp256k1_xonly_pubkey.self)
                                .baseAddress!,
                            tweak
                                .bindMemory(to: UInt8.self)
                                .baseAddress!)
                    }
                }
            }
            guard cRet == 1
            else {
                throw C.Error.illegalScalarValue
            }

            setSizeTo = C.POINT_SIZE
        }
    }

    @inlinable
    static func checkAddXTweak(
        tweaked serialization: [UInt8],
        negated: Bool,
        xPoint: [UInt8],
        tweak: [UInt8]
    ) -> Bool {
        assert(
            serialization.count == 32
                && xPoint.count == C.XPOINT_SIZE
                && tweak.count == C.SCALAR_SIZE)

        let cRet = serialization.withUnsafeBufferPointer { serialization in
            xPoint.withUnsafeBytes { point in
                tweak.withUnsafeBytes { tweak in
                    secp256k1_xonly_pubkey_tweak_add_check(
                        self.context.pointer,
                        serialization.baseAddress!,
                        negated ? Int32(1) : 0,
                        point.bindMemory(to: secp256k1_xonly_pubkey.self).baseAddress!,
                        tweak.baseAddress!)
                }
            }
        }

        switch cRet {
        case 0: return false
        case 1: return true
        default: preconditionFailure()
        }
    }

    @inlinable
    static func keypair(from scalar: Scalar) throws -> KeyPair {
        assert(scalar.count == C.SCALAR_SIZE)

        return try KeyPair(unsafeUninitializedCapacity: C.KEYPAIR_SIZE) { buffer, setSizeTo in
            let buffer = buffer.baseAddress!.bindMemory(to: secp256k1_keypair.self, capacity: 1)
            let cRet = scalar.withUnsafeBytes { scalar in
                secp256k1_keypair_create(
                    self.context.pointer,
                    buffer,
                    scalar.bindMemory(to: UInt8.self).baseAddress!)
            }
            guard cRet == 1 else {
                throw C.Error.illegalScalarValue
            }

            setSizeTo = C.KEYPAIR_SIZE
        }
    }

    @inlinable
    static func scalar(from keypair: KeyPair) -> Scalar? {
        assert(keypair.count == C.KEYPAIR_SIZE)

        let unchecked = UncheckedScalar(unsafeUninitializedCapacity: C.SCALAR_SIZE) {
            buffer, setSizeTo in
            let cRet = keypair.withUnsafeBytes { keypair in
                secp256k1_keypair_sec(
                    self.context.pointer,
                    buffer.baseAddress!,
                    keypair.bindMemory(to: secp256k1_keypair.self).baseAddress!)
            }
            assert(cRet == 1)

            setSizeTo = C.SCALAR_SIZE
        }

        return Scalar(unchecked)
    }

    @inlinable
    static func point(from keypair: KeyPair) -> [UInt8] {
        assert(keypair.count == C.KEYPAIR_SIZE)

        return Array(unsafeUninitializedCapacity: C.POINT_SIZE) { buffer, setSizeTo in
            let cRet = buffer.baseAddress!.withMemoryRebound(to: secp256k1_pubkey.self, capacity: 1)
            { buffer in
                keypair.withUnsafeBytes { keypair in
                    secp256k1_keypair_pub(
                        self.context.pointer,
                        buffer,
                        keypair.bindMemory(to: secp256k1_keypair.self).baseAddress!)
                }
            }
            assert(cRet == 1)

            setSizeTo = C.POINT_SIZE
        }
    }

    @inlinable
    static func xPoint(from keypair: KeyPair) -> (negated: Bool, xPoint: [UInt8]) {
        let point = self.point(from: keypair)
        return self.xPoint(from: point)
    }
}

extension C {
    @usableFromInline
    struct UncheckedScalar: SecretBytes {
        @usableFromInline
        let buffer: Buffer
        @usableFromInline
        init(_ buffer: Buffer) { self.buffer = buffer }
    }
}

// See `Buffer.swift` for the copy-before-mutate invariant backing `@unchecked`.
extension C.UncheckedScalar: @unchecked Sendable {}

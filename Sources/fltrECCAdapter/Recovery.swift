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
    static func deSerialize(recoverable serialized: [UInt8], id: Int) throws -> [UInt8] {
        guard serialized.count == 64
        else { throw C.Error.illegalSignature }

        // Validate the recovery id BEFORE the trapping `Int32(id)` conversion:
        // valid ids are 0...3, and an out-of-Int32-range id would abort the
        // process instead of letting the failable init? return nil.
        guard (0..<4).contains(id)
        else { throw C.Error.illegalSignature }

        return try Array(unsafeUninitializedCapacity: C.DSA_RECOVERABLE_SIGNATURE_SIZE) {
            buffer, setSizeTo in
            let cRet = buffer.baseAddress!.withMemoryRebound(
                to: secp256k1_ecdsa_recoverable_signature.self,
                capacity: 1
            ) { buffer in
                serialized.withUnsafeBufferPointer { serialized in
                    secp256k1_ecdsa_recoverable_signature_parse_compact(
                        self.context.pointer,
                        buffer,
                        serialized.baseAddress!,
                        Int32(id))
                }
            }
            guard cRet == 1
            else { throw C.Error.illegalSignature }

            setSizeTo = C.DSA_RECOVERABLE_SIGNATURE_SIZE
        }
    }

    @inlinable
    static func convert(recoverable: [UInt8]) -> [UInt8] {
        return Array(unsafeUninitializedCapacity: C.DSA_SIGNATURE_SIZE) { buffer, setSizeTo in
            let cRet = buffer
                .baseAddress!
                .withMemoryRebound(
                    to: secp256k1_ecdsa_signature.self,
                    capacity: 1
                ) { buffer in
                    recoverable.withUnsafeBytes { recoverable in
                        secp256k1_ecdsa_recoverable_signature_convert(
                            self.context.pointer,
                            buffer,
                            recoverable
                                .bindMemory(to: secp256k1_ecdsa_recoverable_signature.self)
                                .baseAddress!)
                    }
                }
            assert(cRet == 1)

            setSizeTo = C.DSA_SIGNATURE_SIZE
        }
    }

    @inlinable
    static func serialize(recoverable: [UInt8]) -> (data: [UInt8], id: Int) {
        var id: Int32 = -1
        let data: [UInt8] = Array(unsafeUninitializedCapacity: 64) { buffer, setSizeTo in
            let cRet = recoverable.withUnsafeBytes { recoverable in
                secp256k1_ecdsa_recoverable_signature_serialize_compact(
                    self.context.pointer,
                    buffer.baseAddress!,
                    &id,
                    recoverable
                        .bindMemory(to: secp256k1_ecdsa_recoverable_signature.self)
                        .baseAddress!)
            }
            assert(cRet == 1 && id >= 0 && id < 4)

            setSizeTo = 64
        }

        return (data: data, id: Int(id))
    }

    @inlinable
    static func recoverableSign(
        scalar: Scalar,
        message: [UInt8],
        nonce: [UInt8]?
    ) throws -> [UInt8] {
        assert(scalar.count == C.SCALAR_SIZE)
        guard message.count == C.MESSAGE_SIZE
        else { throw C.Error.illegalMessageLength }
        guard nonce == nil || nonce!.count == C.DSA_SIGNATURE_NONCE_SIZE
        else { throw C.Error.illegalNonceLength }

        return try Array(unsafeUninitializedCapacity: C.DSA_RECOVERABLE_SIGNATURE_SIZE) {
            signature, setSizeTo in
            let cRet = signature
                .baseAddress!
                .withMemoryRebound(
                    to: secp256k1_ecdsa_recoverable_signature.self,
                    capacity: 1
                ) { signature in
                    scalar.withUnsafeBytes { scalar in
                        secp256k1_ecdsa_sign_recoverable(
                            self.context.pointer,
                            signature,
                            message,
                            scalar.bindMemory(to: UInt8.self).baseAddress!,
                            nil,  // nonce_fp
                            nonce)  // nonce_data
                    }
                }
            guard cRet == 1 else {
                throw C.Error.illegalScalarValue
            }

            setSizeTo = C.DSA_RECOVERABLE_SIGNATURE_SIZE
        }
    }

    @inlinable
    static func recoverPoint(from recoverable: [UInt8], message: [UInt8]) throws -> [UInt8] {
        assert(recoverable.count == C.DSA_RECOVERABLE_SIGNATURE_SIZE)
        precondition(message.count == C.MESSAGE_SIZE)

        return try Array(unsafeUninitializedCapacity: C.POINT_SIZE) { point, setSizeTo in
            let cRet = point.baseAddress!.withMemoryRebound(
                to: secp256k1_pubkey.self,
                capacity: 1
            ) { point in
                recoverable.withUnsafeBytes { recoverable in
                    secp256k1_ecdsa_recover(
                        self.context.pointer,
                        point,
                        recoverable
                            .bindMemory(to: secp256k1_ecdsa_recoverable_signature.self)
                            .baseAddress!,
                        message)
                }
            }

            guard cRet == 1
            else { throw C.Error.illegalSignature }

            setSizeTo = C.POINT_SIZE
        }
    }
}

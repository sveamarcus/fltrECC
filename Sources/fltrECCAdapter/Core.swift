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

// MARK: Context
public extension C {
    @inlinable
    static func createContext() -> OpaquePointer {
        return secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
    }

    @inlinable
    static func destroy(context: OpaquePointer) {
        secp256k1_context_destroy(context)
    }

    @inlinable
    static func randomize(context: OpaquePointer) {
        func randomData(size: Int) -> [UInt8] {
            [UInt8](unsafeUninitializedCapacity: size) { seed32, setSizeTo in
                for i in (0..<size) {
                    seed32[i] = UInt8.random(in: .min ... .max)
                }
                setSizeTo = size
            }
        }

        var seed32 = randomData(size: 32)
        precondition(secp256k1_context_randomize(context, &seed32) == 1)
    }
}

// MARK: Scalar
public extension C {
    @inlinable
    static func scalarIsValid(scalar: Scalar) -> Bool {
        assert(scalar.count == C.SCALAR_SIZE)
        let cRet = scalar.withUnsafeBytes { scalar in
            secp256k1_ec_seckey_verify(
                self.context.pointer,
                scalar.bindMemory(to: UInt8.self).baseAddress!)
        }
        return cRet == 1
    }

    //    @inlinable
    static func negate(into scalar: Scalar) {
        assert(scalar.count == C.SCALAR_SIZE)
        let cRet = scalar.withUnsafeMutableBytes { scalar in
            secp256k1_ec_seckey_negate(
                self.context.pointer, scalar.bindMemory(to: UInt8.self).baseAddress!)
        }
        precondition(cRet == 1)
    }

    //    @inlinable
    static func add(
        into lhs: Scalar,
        scalar rhs: Scalar
    ) throws {
        assert(lhs.count == C.SCALAR_SIZE && rhs.count == C.SCALAR_SIZE)
        let cRet = lhs.withUnsafeMutableBytes { lhs in
            rhs.withUnsafeBytes { rhs in
                secp256k1_ec_seckey_tweak_add(
                    self.context.pointer,
                    lhs.bindMemory(to: UInt8.self).baseAddress!,
                    rhs.bindMemory(to: UInt8.self).baseAddress!)
            }
        }
        guard cRet == 1 else {
            throw C.Error.illegalScalarValue
        }
    }

    //    @inlinable
    static func mul(
        into lhs: Scalar,
        scalar rhs: Scalar
    ) throws {
        assert(lhs.count == C.SCALAR_SIZE && rhs.count == C.SCALAR_SIZE)
        let cRet = lhs.withUnsafeMutableBytes { lhs in
            rhs.withUnsafeBytes { rhs in
                secp256k1_ec_seckey_tweak_mul(
                    self.context.pointer,
                    lhs.bindMemory(to: UInt8.self).baseAddress!,
                    rhs.bindMemory(to: UInt8.self).baseAddress!)
            }
        }
        guard cRet == 1 else {
            throw C.Error.illegalScalarValue
        }
    }
}

// MARK: Point
public extension C {
    @inlinable
    static func deSerialize(point serialized: [UInt8]) throws -> [UInt8] {
        guard serialized.count == 33 || serialized.count == 65 else {
            throw C.Error.illegalPointSerializationByteCount
        }

        return try Array(unsafeUninitializedCapacity: C.POINT_SIZE) { buffer, setSizeTo in
            let cRet = buffer.baseAddress!.withMemoryRebound(to: secp256k1_pubkey.self, capacity: 1)
            { buffer in
                serialized.withUnsafeBufferPointer { input in
                    secp256k1_ec_pubkey_parse(
                        self.context.pointer, buffer, input.baseAddress!, input.count)
                }
            }
            guard cRet == 1 else {
                throw C.Error.illegalPointSerialization
            }
            setSizeTo = C.POINT_SIZE
        }
    }

    @usableFromInline
    internal static func serialize(compressed: Bool, point: [UInt8]) -> [UInt8] {
        assert(point.count == C.POINT_SIZE)
        let parameters: (flag: Int32, size: Int) =
            compressed
            ? (SECP256K1_EC_COMPRESSED, 33)
            : (SECP256K1_EC_UNCOMPRESSED, 65)

        return [UInt8](unsafeUninitializedCapacity: parameters.size) { buffer, setSizeTo in
            var request: Int = parameters.size
            let cRet = point.withUnsafeBytes { point in
                secp256k1_ec_pubkey_serialize(
                    self.context.pointer,
                    buffer.baseAddress!,
                    &request,
                    point
                        .baseAddress!
                        .bindMemory(to: secp256k1_pubkey.self, capacity: 1),
                    UInt32(parameters.flag))
            }
            assert(request == parameters.size)
            assert(cRet == 1)
            setSizeTo = request
        }
    }

    @inlinable
    static func compressed(point: [UInt8]) -> [UInt8] {
        Self.serialize(compressed: true, point: point)
    }

    @inlinable
    static func uncompressed(point: [UInt8]) -> [UInt8] {
        Self.serialize(compressed: false, point: point)
    }

    @inlinable
    static func comparePoints(_ a: [UInt8], _ b: [UInt8]) -> Comparison {
        assert(a.count == C.POINT_SIZE && b.count == C.POINT_SIZE)
        let cRet = a.withUnsafeBytes { a in
            b.withUnsafeBytes { b in
                secp256k1_ec_pubkey_cmp(
                    self.context.pointer,
                    a
                        .bindMemory(to: secp256k1_pubkey.self)
                        .baseAddress!,
                    b
                        .bindMemory(to: secp256k1_pubkey.self)
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
    static func point(from scalar: Scalar) throws -> [UInt8] {
        assert(scalar.count == C.SCALAR_SIZE)
        return try Array(unsafeUninitializedCapacity: C.POINT_SIZE) { point, setSizeTo in
            let cRet = point.baseAddress!.withMemoryRebound(to: secp256k1_pubkey.self, capacity: 1)
            { point in
                scalar.withUnsafeBytes { scalar in
                    secp256k1_ec_pubkey_create(
                        self.context.pointer,
                        point,
                        scalar.bindMemory(to: UInt8.self).baseAddress!)
                }
            }
            guard cRet == 1 else {
                throw C.Error.illegalPointValue
            }
            setSizeTo = C.POINT_SIZE
        }
    }

    @inlinable
    static func negate(into point: inout [UInt8]) {
        assert(point.count == C.POINT_SIZE)
        let cRet = point.withUnsafeMutableBytes { point in
            secp256k1_ec_pubkey_negate(
                self.context.pointer,
                point
                    .bindMemory(to: secp256k1_pubkey.self)
                    .baseAddress!)
        }
        precondition(cRet == 1)
    }

    @inlinable
    static func add(into point: inout [UInt8], scalar: Scalar) throws {
        assert(point.count == C.POINT_SIZE && scalar.count == C.SCALAR_SIZE)
        let cRet = point.withUnsafeMutableBytes { point in
            scalar.withUnsafeBytes { scalar in
                secp256k1_ec_pubkey_tweak_add(
                    self.context.pointer,
                    point
                        .bindMemory(to: secp256k1_pubkey.self)
                        .baseAddress!,
                    scalar
                        .bindMemory(to: UInt8.self)
                        .baseAddress!)
            }
        }
        guard cRet == 1 else {
            throw C.Error.illegalPointValue
        }
    }

    @inlinable
    static func mul(into point: inout [UInt8], scalar: Scalar) throws {
        assert(point.count == C.POINT_SIZE && scalar.count == C.SCALAR_SIZE)
        let cRet = point.withUnsafeMutableBytes { point in
            scalar.withUnsafeBytes { scalar in
                secp256k1_ec_pubkey_tweak_mul(
                    self.context.pointer,
                    point
                        .bindMemory(to: secp256k1_pubkey.self)
                        .baseAddress!,
                    scalar
                        .bindMemory(to: UInt8.self)
                        .baseAddress!)
            }
        }
        guard cRet == 1 else {
            throw C.Error.illegalPointValue
        }
    }

    @inlinable
    static func combine<Points: Collection>(points: Points) throws -> [UInt8]
    where Points.Element == [UInt8] {
        // Materialize the inputs as concrete secp256k1_pubkey values kept alive in
        // `pubkeys` for the whole call, then build the array of pointers into that
        // live storage. Binding a pointer inside each point's withUnsafeBytes and
        // letting it escape the closure (as before) is use-after-scope / UB.
        let pubkeys: [secp256k1_pubkey] = points.map { point in
            assert(point.count == C.POINT_SIZE)
            return point.withUnsafeBytes { $0.load(as: secp256k1_pubkey.self) }
        }

        return try Array(unsafeUninitializedCapacity: C.POINT_SIZE) { result, setSizeTo in
            let cRet = result
                .baseAddress!
                .withMemoryRebound(to: secp256k1_pubkey.self, capacity: 1) { result in
                    pubkeys.withUnsafeBufferPointer { buffer in
                        let pointers = buffer.indices.map { Optional(buffer.baseAddress! + $0) }
                        return pointers.withUnsafeBufferPointer { pointers in
                            secp256k1_ec_pubkey_combine(
                                self.context.pointer,
                                result,
                                pointers.baseAddress!,
                                pubkeys.count)
                        }
                    }
                }

            guard cRet == 1
            else { throw C.Error.illegalPointValue }

            setSizeTo = C.POINT_SIZE
        }
    }
}

// MARK: Signature
public extension C {
    @inlinable
    static func serializeCompact(signature: [UInt8]) -> [UInt8] {
        assert(signature.count == C.DSA_SIGNATURE_SIZE)
        return Array(unsafeUninitializedCapacity: C.DSA_SIGNATURE_SIZE) { result, setSizeTo in
            let cRet = signature.withUnsafeBytes { sig in
                secp256k1_ecdsa_signature_serialize_compact(
                    self.context.pointer,
                    result.baseAddress!,
                    sig
                        .bindMemory(to: secp256k1_ecdsa_signature.self)
                        .baseAddress!)
            }
            precondition(cRet == 1)

            setSizeTo = C.DSA_SIGNATURE_SIZE
        }
    }

    @inlinable
    static func deSerialize(compactSignature: [UInt8]) throws -> [UInt8] {
        try compactSignature.withUnsafeBufferPointer(self.deSerialize(compactSignature:))
    }

    @inlinable
    static func deSerialize(compactSignature: ArraySlice<UInt8>) throws -> [UInt8] {
        try compactSignature.withUnsafeBufferPointer(self.deSerialize(compactSignature:))
    }

    @inlinable
    static func deSerialize(compactSignature: UnsafeBufferPointer<UInt8>) throws -> [UInt8] {
        guard compactSignature.count == C.DSA_SIGNATURE_SIZE
        else { throw C.Error.illegalSignature }

        return try Array(unsafeUninitializedCapacity: C.DSA_SIGNATURE_SIZE) { output, setSizeTo in
            let cRet = output
                .baseAddress!
                .withMemoryRebound(to: secp256k1_ecdsa_signature.self, capacity: 1) { output in
                    secp256k1_ecdsa_signature_parse_compact(
                        self.context.pointer,
                        output,
                        compactSignature.baseAddress!)
                }
            guard cRet == 1 else {
                throw C.Error.illegalSignature
            }

            setSizeTo = C.DSA_SIGNATURE_SIZE
        }
    }

    @inlinable
    static func serializeDer(signature: [UInt8]) -> [UInt8] {
        assert(signature.count == C.DSA_SIGNATURE_SIZE)
        return Array(unsafeUninitializedCapacity: C.DSA_DER_SIGNATURE_SIZE) { result, setSizeTo in
            signature.withUnsafeBytes { sig in
                setSizeTo = C.DSA_DER_SIGNATURE_SIZE
                let cRet = secp256k1_ecdsa_signature_serialize_der(
                    self.context.pointer,
                    result.baseAddress!,
                    &setSizeTo,
                    sig
                        .bindMemory(to: secp256k1_ecdsa_signature.self)
                        .baseAddress!)
                precondition(
                    cRet == 1,
                    "cannot serialize to DER due to output array being too small (256 bytes)")
            }
        }
    }

    @inlinable
    static func deSerialize(derSignature: [UInt8]) throws -> [UInt8] {
        try derSignature.withUnsafeBufferPointer(self.deSerialize(derSignature:))
    }

    @inlinable
    static func deSerialize(derSignature: ArraySlice<UInt8>) throws -> [UInt8] {
        try derSignature.withUnsafeBufferPointer(self.deSerialize(derSignature:))
    }

    @inlinable
    static func deSerialize(derSignature: UnsafeBufferPointer<UInt8>) throws -> [UInt8] {
        guard derSignature.count <= C.DSA_DER_SIGNATURE_SIZE
        else { throw C.Error.illegalSignature }

        return try Array(unsafeUninitializedCapacity: C.DSA_SIGNATURE_SIZE) { output, setSizeTo in
            let cRet = output
                .baseAddress!
                .withMemoryRebound(to: secp256k1_ecdsa_signature.self, capacity: 1) { output in
                    secp256k1_ecdsa_signature_parse_der(
                        self.context.pointer,
                        output,
                        derSignature.baseAddress!,
                        derSignature.count)
                }
            guard cRet == 1 else {
                throw C.Error.illegalSignature
            }

            setSizeTo = C.DSA_SIGNATURE_SIZE
        }
    }

    @inlinable
    static func verify(dsa signature: [UInt8], point: [UInt8], message data: [UInt8]) -> Bool {
        assert(signature.count == C.DSA_SIGNATURE_SIZE && point.count == C.POINT_SIZE)
        precondition(data.count == C.MESSAGE_SIZE)

        let cRet = signature.withUnsafeBytes { sig in
            point.withUnsafeBytes { point in
                data.withUnsafeBufferPointer { data in
                    secp256k1_ecdsa_verify(
                        self.context.pointer,
                        sig
                            .bindMemory(to: secp256k1_ecdsa_signature.self)
                            .baseAddress!,
                        data.baseAddress!,
                        point
                            .bindMemory(to: secp256k1_pubkey.self)
                            .baseAddress!)
                }
            }
        }

        return cRet == 1
    }

    @inlinable
    static func normalize(signature: [UInt8]) -> (normal: Bool, signature: [UInt8]) {
        assert(signature.count == C.DSA_SIGNATURE_SIZE)
        var cRet: Int32? = nil
        let signature: [UInt8] = Array(unsafeUninitializedCapacity: C.DSA_SIGNATURE_SIZE) {
            result, setSizeTo in
            cRet = result
                .baseAddress!
                .withMemoryRebound(to: secp256k1_ecdsa_signature.self, capacity: 1) { result in
                    signature.withUnsafeBytes { sig in
                        secp256k1_ecdsa_signature_normalize(
                            self.context.pointer,
                            result,
                            sig
                                .bindMemory(to: secp256k1_ecdsa_signature.self)
                                .baseAddress!)

                    }
                }

            setSizeTo = C.DSA_SIGNATURE_SIZE
        }

        let normal: Bool = {
            switch cRet {
            case 0: return true
            case 1: return false
            default: preconditionFailure()
            }
        }()

        return (normal, signature)
    }

    @inlinable
    static func dsaSign(
        scalar: Scalar,
        message: [UInt8],
        nonce: [UInt8]?
    ) throws -> [UInt8] {
        assert(scalar.count == C.SCALAR_SIZE)
        guard message.count == C.MESSAGE_SIZE
        else { throw C.Error.illegalMessageLength }
        guard nonce == nil || nonce!.count == C.DSA_SIGNATURE_NONCE_SIZE
        else { throw C.Error.illegalNonceLength }

        return try Array(unsafeUninitializedCapacity: C.DSA_SIGNATURE_SIZE) {
            signature, setSizeTo in
            let cRet = signature
                .baseAddress!
                .withMemoryRebound(to: secp256k1_ecdsa_signature.self, capacity: 1) { signature in
                    message.withUnsafeBufferPointer { data in
                        scalar.withUnsafeBytes { scalar in
                            secp256k1_ecdsa_sign(
                                self.context.pointer,
                                signature,
                                data.baseAddress!,
                                scalar.bindMemory(to: UInt8.self).baseAddress!,
                                nil,  // nonce_fp
                                nonce)  // nonce_data
                        }
                    }
                }
            guard cRet == 1 else {
                throw C.Error.illegalScalarValue
            }

            setSizeTo = C.DSA_SIGNATURE_SIZE
        }
    }
}

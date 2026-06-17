import Testing
import fltrECCTesting

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
@testable import fltrECCAdapter

@Suite struct CoreTests {
    // A fresh suite instance is created per test, so these can be immutable `let`
    // properties initialized once — no `setUp`/`tearDown` needed.
    let scalarZero: Scalar
    let scalarOutOfOrder: Scalar

    init() {
        // `Scalar(unsafeUninitializedCapacity:)` validates on construction, so
        // start from valid `1`-bytes and overwrite through the unchecked mutable
        // path to reach the deliberately-invalid test values (all-zero / all-255).
        let zero = Scalar(unsafeUninitializedCapacity: 32) { buffer, size in
            (0..<32).forEach { buffer[$0] = 1 }
            size = 32
        }
        zero.withUnsafeMutableBytes { scalar in
            (0..<32).forEach { scalar[$0] = 0 }
        }
        self.scalarZero = zero

        let outOfOrder = Scalar(unsafeUninitializedCapacity: 32) { buffer, size in
            (0..<32).forEach { buffer[$0] = 1 }
            size = 32
        }
        outOfOrder.withUnsafeMutableBytes { scalar in
            (0..<32).forEach { scalar[$0] = 255 }
        }
        self.scalarOutOfOrder = outOfOrder
    }

    // MARK: Scalar
    @Test func scalarOneValid() {
        #expect(C.scalarIsValid(scalar: 1))
    }

    @Test func scalarInvalid() {
        #expect(!C.scalarIsValid(scalar: self.scalarZero))
        #expect(!C.scalarIsValid(scalar: self.scalarOutOfOrder))
    }

    @Test func negate() {
        let one = Scalar(1)
        let alsoOne = Scalar(1)
        C.negate(into: one)
        #expect(one != alsoOne)
        C.negate(into: one)
        #expect(one == alsoOne)
    }

    @Test func addOne() throws {
        let one = Scalar(1)
        let alsoOne = Scalar(1)
        try C.add(into: one, scalar: alsoOne)
        #expect(one == 2)
    }

    @Test func addFail() {
        let one = Scalar(1)
        let negate = Scalar(1)
        C.negate(into: negate)
        #expect(throws: (any Error).self) {
            try C.add(into: one, scalar: negate)
        }
    }

    @Test func mul() throws {
        let result = Scalar(2)
        let alsoTwo = Scalar(2)
        try C.mul(into: result, scalar: alsoTwo)
        #expect(result == Scalar(4))
    }

    @Test func mulFail() {
        let one = Scalar(1)
        let zero = self.scalarZero
        #expect(throws: (any Error).self) {
            try C.mul(into: one, scalar: zero)
        }
    }

    // MARK: Point
    @Test func createPoint() throws {
        let result = try C.point(from: Scalar(1))
        #expect(result.count == C.POINT_SIZE)
    }

    @Test func comparePointsEquals() {
        let a = Point(4)
        let b = Point(4)
        #expect(C.comparePoints(a._data, b._data).equals)
    }

    @Test func comparePointsLessThan() {
        let a = Point(2)
        let b = Point(4)
        #expect(C.comparePoints(a._data, b._data) == .lessThan)
    }

    @Test func comparePointsGreaterThan() {
        let a = Point(4)
        let b = Point(2)
        #expect(C.comparePoints(a._data, b._data) == .greaterThan)
    }

    @Test func negatePoint() throws {
        let point = Point(5)._data
        var negated = point
        C.negate(into: &negated)
        #expect(point != negated)
        let scalar = Scalar(5)
        C.negate(into: scalar)
        let point2 = try C.point(from: scalar)
        #expect(negated == point2)
    }

    @Test func addPoint() throws {
        var one = Point(1)._data
        let scalarOne = Scalar(1)
        try C.add(into: &one, scalar: scalarOne)
        #expect(one == Point(2)._data)
    }

    @Test func mulPoint() throws {
        var result = Point(2)._data
        let scalarTwo = Scalar(2)
        try C.mul(into: &result, scalar: scalarTwo)
        #expect(result == Point(4)._data)
    }

    @Test func combinePoint() throws {
        let ones = (0..<10).map { _ in try! C.point(from: Scalar(1)) }
        let result = try C.combine(points: ones)
        let ten = try C.point(from: Scalar(10))
        #expect(C.comparePoints(result, ten).equals)
    }

    @Test func serializeDeserialize() throws {
        let h = Point(100)._data
        let compressed = C.compressed(point: h)
        let uncompressed = C.uncompressed(point: h)
        #expect(compressed.count == 33)
        #expect(uncompressed.count == 65)

        #expect(try C.deSerialize(point: compressed) == h)
        #expect(try C.deSerialize(point: uncompressed) == h)
    }

    // MARK: DSA Signature
    @Test func dsaSign() throws {
        let secret = Scalar(20)
        let pubkey = try C.point(from: secret)
        let message = (1...32).map(UInt8.init)
        let nonce = (1...32).map { _ in UInt8(1) }
        let signature = try C.dsaSign(scalar: secret, message: message, nonce: nil)
        let signatureNonce = try C.dsaSign(scalar: secret, message: message, nonce: nonce)
        #expect(signature != signatureNonce)

        #expect(C.verify(dsa: signature, point: pubkey, message: message))
        #expect(C.verify(dsa: signatureNonce, point: pubkey, message: message))
    }

    // MARK: Extrakeys
    @Test func serializeDeserializeXPoint() throws {
        let point = Point(100)._data
        let (_, xPoint) = C.xPoint(from: point)
        let serialized = C.serialize(xPoint: xPoint)
        #expect(serialized.count == 32)

        let result = try C.deSerialize(xPoint: serialized)
        #expect(C.compareXPoints(xPoint, result).equals)
    }

    @Test func compareXPointEquals() {
        let (_, a) = C.xPoint(from: Point(200)._data)
        let (_, b) = C.xPoint(from: Point(200)._data)
        #expect(C.compareXPoints(a, b).equals)
    }

    @Test func compareXPointLessThan() {
        let (_, a) = C.xPoint(from: Point(2)._data)
        let (_, b) = C.xPoint(from: Point(4)._data)
        #expect(C.compareXPoints(a, b) == .lessThan)
    }

    @Test func compareXPointGreaterThan() {
        let (_, a) = C.xPoint(from: Point(4)._data)
        let (_, b) = C.xPoint(from: Point(2)._data)
        #expect(C.compareXPoints(a, b) == .greaterThan)
    }

    @Test func xPointFromPoint() throws {
        let scalar = Scalar(10)
        let point = try C.point(from: scalar)
        let (parity, xPoint) = C.xPoint(from: point)
        let negate = scalar
        C.negate(into: negate)
        let (parityNegated, xPointNegated) = try C.xPoint(from: C.point(from: negate))
        #expect(parity != parityNegated)
        #expect(xPoint == xPointNegated)
    }

    @Test func createKeypair() throws {
        let scalar = Scalar(30)
        let keypair = try C.keypair(from: scalar)
        let backToScalar = C.scalar(from: keypair)
        #expect(scalar == backToScalar)
    }

    @Test func pointFromKeypair() throws {
        let scalar = Scalar(40)
        let keypair = try C.keypair(from: scalar)
        let point = C.point(from: keypair)
        #expect(C.comparePoints(point, Point(40)._data).equals)
    }

    @Test func addXTweakCheckXTweak() throws {
        let keypair = try C.keypair(from: Scalar(6))  // odd
        try C.addXTweak(into: keypair, scalar: Scalar(1))
        let point = C.point(from: keypair)
        #expect(point != Point(7)._data)

        let keypair2 = try C.keypair(from: Scalar(2))  // even
        try C.addXTweak(into: keypair2, scalar: Scalar(1))
        let point2 = C.point(from: keypair2)
        #expect(point2 == Point(3)._data)
    }

    @Test func checkXTweak() throws {
        let keypair = try C.keypair(from: Scalar(4))
        let keypairXPoint = C.xPoint(from: keypair)
        let scalar = Scalar(2)
        let copy = keypair
        try C.addXTweak(into: copy, scalar: scalar)
        let xPoint = C.xPoint(from: copy)
        let ser = C.serialize(xPoint: xPoint.xPoint)
        #expect(xPoint.negated)

        scalar.withUnsafeBytes {
            #expect(
                C.checkAddXTweak(
                    tweaked: ser,
                    negated: xPoint.negated,
                    xPoint: keypairXPoint.xPoint,
                    tweak: Array($0)))
        }
    }

    // MARK: Schnorr Signature
    @Test func schnorrSign() throws {
        let secret = Scalar(20)
        let keypair = try C.keypair(from: secret)
        let (_, xPoint) = C.xPoint(from: keypair)
        let message = (1...32).map(UInt8.init)
        let nonce = (1...32).map { _ in UInt8(1) }
        let signature = try C.schnorrSign(keypair: keypair, message: message, nonce: nil)
        let signatureNonce = try C.schnorrSign(keypair: keypair, message: message, nonce: nonce)
        #expect(signature != signatureNonce)

        #expect(C.verify(schnorr: signature, xPoint: xPoint, message: message))
        #expect(C.verify(schnorr: signatureNonce, xPoint: xPoint, message: message))
    }

    // MARK: ECDH
    @Test func ecdh() throws {
        let scalarAlice = Scalar(100)
        let scalarBob = Scalar(200)
        let pointAlice = Point(100)._data
        let pointBob = Point(200)._data

        let secretAlice = try C.ecdh(my: scalarAlice, their: pointBob)
        let secretBob = try C.ecdh(my: scalarBob, their: pointAlice)
        #expect(secretAlice == secretBob)
    }

    @Test func ecdhFail() throws {
        let scalarAlice = Scalar(101)
        let scalarBob = Scalar(200)
        let pointAlice = Point(100)._data
        let pointBob = Point(200)._data

        let secretAlice = try C.ecdh(my: scalarAlice, their: pointBob)
        let secretBob = try C.ecdh(my: scalarBob, their: pointAlice)
        #expect(secretAlice != secretBob)
    }

    @Test func ecdhFailIllegalScalar() throws {
        let scalarAlice: Scalar = self.scalarZero
        let scalarBob = Scalar(11)
        let pointBob = try C.point(from: scalarBob)
        #expect(throws: (any Error).self) {
            try C.ecdh(my: scalarAlice, their: pointBob)
        }
    }

    // MARK: Recoverable
    @Test func recoverableSignRecoverPoint() throws {
        let secret = Scalar(120)
        let pubkey = try C.point(from: secret)
        let message = (1...32).map(UInt8.init)
        let nonce = (1...32).map { _ in UInt8(1) }
        let signature = try C.recoverableSign(scalar: secret, message: message, nonce: nonce)
        let recoverPoint = try C.recoverPoint(from: signature, message: message)
        #expect(pubkey == recoverPoint)
    }

    @Test func recoverableSignVerify() throws {
        let secret = Scalar(120)
        let pubkey = try C.point(from: secret)
        let message = (1...32).map(UInt8.init)
        let signature = try C.recoverableSign(scalar: secret, message: message, nonce: nil)
        let dsa: [UInt8] = C.convert(recoverable: signature)
        #expect(C.verify(dsa: dsa, point: pubkey, message: message))
    }

    @Test func recoverableSerializeDeserialize() throws {
        let secret = Scalar(120)
        let message = (1...32).map(UInt8.init)
        let nonce = (1...32).map { _ in UInt8(1) }
        let signature = try C.recoverableSign(scalar: secret, message: message, nonce: nonce)
        let serialized = C.serialize(recoverable: signature)
        let deser = try C.deSerialize(recoverable: serialized.data, id: serialized.id)
        #expect(signature == deser)
    }

    @Test func customScalarType() {
        struct TestScalar: SecretBytes {
            let buffer: Buffer
            init(_ buffer: Buffer) {
                self.buffer = buffer
            }
        }

        let validScalar = TestScalar(unsafeUninitializedCapacity: 32) { b, s in
            (UInt8(0)..<32).forEach { b[Int($0)] = $0 }
            s = 32
        }
        #expect(Scalar(validScalar) != nil)

        let invalidScalar = TestScalar(unsafeUninitializedCapacity: 32) { b, s in
            (UInt8(0)..<32).forEach { b[Int($0)] = 0 }
            s = 32
        }
        #expect(Scalar(invalidScalar) == nil)

        let shortScalar = TestScalar(unsafeUninitializedCapacity: 32) { b, s in
            (UInt8(0)..<32).forEach { b[Int($0)] = $0 }
            s = 31
        }
        #expect(Scalar(shortScalar) == nil)
    }

    @Test func customKeyPairType() throws {
        struct TestKeyPair: SecretBytes {
            let buffer: Buffer
            init(_ buffer: Buffer) {
                self.buffer = buffer
            }
        }

        let validScalar = Scalar(1000)
        let validKeyPair = try C.keypair(from: validScalar)
        let kpBytes: [UInt8] = validKeyPair.withUnsafeBytes { Array($0) }
        let testKeyPair = TestKeyPair(unsafeUninitializedCapacity: C.KEYPAIR_SIZE) { b, s in
            (0..<C.KEYPAIR_SIZE).forEach { i in
                b[i] = kpBytes[i]
            }
            s = C.KEYPAIR_SIZE
        }
        #expect(KeyPair(testKeyPair) != nil)

        let invalidKeyPair = TestKeyPair(unsafeUninitializedCapacity: C.KEYPAIR_SIZE) { b, s in
            (0..<C.KEYPAIR_SIZE).forEach { i in
                b[i] = 0
            }
            s = C.KEYPAIR_SIZE
        }
        #expect(KeyPair(invalidKeyPair) == nil)

        let shortKeyPair = TestKeyPair(unsafeUninitializedCapacity: C.KEYPAIR_SIZE) { b, s in
            (0..<C.KEYPAIR_SIZE).forEach { i in
                b[i] = kpBytes[i]
            }
            s = C.KEYPAIR_SIZE - 1
        }
        #expect(KeyPair(shortKeyPair) == nil)
    }

    @Test func customEcdhSecret() {
        struct TestEcdhSecret: SecretBytes {
            let buffer: Buffer
            init(_ buffer: Buffer) {
                self.buffer = buffer
            }
        }
        let validSecret = TestEcdhSecret(unsafeUninitializedCapacity: C.ECDH_SECRET_SIZE) { b, s in
            (0..<C.ECDH_SECRET_SIZE).forEach {
                b[$0] = 0
            }
            s = C.ECDH_SECRET_SIZE
        }
        #expect(EcdhSecret(validSecret) != nil)

        let shortSecret = TestEcdhSecret(unsafeUninitializedCapacity: C.ECDH_SECRET_SIZE) { b, s in
            (0..<C.ECDH_SECRET_SIZE).forEach {
                b[$0] = 0
            }
            s = C.ECDH_SECRET_SIZE - 1
        }
        #expect(EcdhSecret(shortSecret) == nil)
    }
}

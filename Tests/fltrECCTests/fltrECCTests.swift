import Testing
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
import fltrECC
import fltrECCTesting

@Suite struct FltrECCTests {
    @Test func pointNegate() {
        let s = Scalar(5)
        let p = Point(s)
        let negatedS = -s
        let negatedP = -p
        #expect(Point(negatedS) == negatedP)
        #expect(p == -negatedP)
    }

    @Test func pointCombine() {
        let ss = (1...10).map(Scalar.init)
        let ps = ss.map(Point.init)
        let combine = ps[0].combine(ps[1], ps[2], ps[3], ps[4], ps[5], ps[6], ps[7], ps[8], ps[9])  // 55
        #expect(combine == 55)
    }

    @Test func pointAdd() throws {
        let p1 = Point(1)
        let p2 = Point(2)
        let sum = p1 + p2
        let p3 = try #require(sum)
        #expect(p3 == Point(3))
        #expect(p1 + p2 == p2 + p1)
        #expect(-p1 - p2 == -p2 - p1)

        #expect(p1 + -p1 == nil)
        #expect(p1 - 1 == nil)
        #expect(p2 + -p2 == nil)
        #expect(p2 - 2 == nil)
        #expect(p1 + -p2 != nil)
        #expect(p2 + -p1 != nil)
    }

    @Test func pointMul() {
        let p = Point(200_000)
        let s = Scalar(1_000)
        #expect(p * s == s * p)
        #expect(p * s == Point(200_000_000))
    }

    @Test func pointComparable() {
        let p1 = Point(8)
        let p2 = Point(11)
        #expect(p1 < p2)
        #expect(p1 != p2)
        let p3 = Point(8)
        #expect(p2 != p3)
        #expect(p1 <= p3)
    }

    @Test func privkeyPubkey() {
        let privkey = DSA.SecretKey(5)
        let pubkey = privkey.pubkey()
        #expect(pubkey.serialize() == DSA.PublicKey(5).serialize())
        #expect(pubkey.serialize() != DSA.PublicKey(6).serialize())
    }

    @Test func privkeySign() throws {
        let privkey = DSA.SecretKey(200)
        let pubkey = privkey.pubkey()
        let message = (0..<32).map(UInt8.init)
        let signature = try privkey.sign(message: message)
        #expect(pubkey.verify(signature: signature, message: message))
    }

    @Test func privkeyRecoverable() throws {
        let privkey = DSA.SecretKey(201)
        let pubkey = privkey.pubkey()
        let message = (0..<32).map(UInt8.init)
        let recoverable = try privkey.sign(recoverable: message)
        let signature = recoverable.dsaSignature()
        let pubkeyRecover = try #require(recoverable.recover(from: message))
        #expect(pubkey.serialize() == pubkeyRecover.serialize())
        #expect(pubkey.verify(signature: signature, message: message))
    }

    @Test func privkeyEcdh() {
        let s10 = DSA.SecretKey(10_000_000_000_000)
        let s20 = DSA.SecretKey(20_000_000_000_000)
        let p10 = s10.pubkey()
        let p20 = s20.pubkey()
        let ecdhAlice = s10.ecdh(p20)
        let ecdhBob = s20.ecdh(p10)
        #expect(ecdhAlice == ecdhBob)
    }

    @Test func dsaSignatureSerialize() throws {
        let privkey = DSA.SecretKey(200)
        let message = (0..<32).map(UInt8.init)
        let signature = try privkey.sign(message: message)
        let serialDer = signature.serializeDer()
        let serialCompact = signature.serializeCompact()
        #expect(DSA.Signature(from: serialDer) == signature)
        #expect(DSA.Signature(from: serialCompact) == signature)
    }

    @Test func recoverableSignatureSerialize() throws {
        let privkey = DSA.SecretKey(202)
        let message = (1..<33).map(UInt8.init)
        let recoverable = try privkey.sign(recoverable: message)
        let (serial, id) = recoverable.serialize()
        #expect(DSA.RecoverableSignature(from: serial, id: id) == recoverable)
        let signature = try #require(DSA.Signature(from: serial))

        let pubkey = DSA.PublicKey(202)
        #expect(pubkey.verify(signature: signature, message: message))
    }

    @Test func pubkeySerialize() {
        let pubkey = DSA.PublicKey(1_203_456_689_123_123)
        let compressed = pubkey.serialize(format: .compressed)
        let uncompressed = pubkey.serialize(format: .uncompressed)
        #expect(pubkey == DSA.PublicKey(from: compressed))
        #expect(pubkey == DSA.PublicKey(from: uncompressed))
    }

    @Test func xOnlyFromPubkey() {
        let eight = DSA.PublicKey(8)
        #expect(!eight.xOnly().negated)
        #expect(eight.xOnly().xPubkey == .init(8))

        let nine = DSA.PublicKey(9)
        #expect(nine.xOnly().negated)
        #expect(nine.xOnly().xPubkey == .init(-9))
    }

    @Test func xPrivkeyPubkey() {
        let privkey = X.SecretKey(5)
        let pubkey = privkey.pubkey().xPoint
        #expect(pubkey.serialize() == X.PublicKey(5).serialize())
        #expect(pubkey.serialize() != X.PublicKey(6).serialize())
    }

    @Test func xSecretKeyTweak() {
        let sk2 = X.SecretKey(2)
        let sk3 = X.SecretKey(3)

        #expect(sk2.tweak(add: 3) == X.SecretKey(5))
        #expect(sk3.tweak(add: 2) == sk2.tweak(add: 3))
        #expect(sk2.tweak(add: -2) == nil)
        #expect(sk2.tweak(add: -2) == sk3.tweak(add: -3))
    }

    @Test func xPublicKeyTweak() {
        let pk2 = X.PublicKey(20_000)
        let pk3 = X.PublicKey(30_000)
        #expect(pk2.tweak(add: 30_000) == DSA.PublicKey(50_000))
        #expect(pk3.tweak(add: 20_000) == pk2.tweak(add: 30_000))
        #expect(pk2.tweak(add: -20_000) == nil)
        #expect(pk2.tweak(add: -20_000) == pk3.tweak(add: -30_000))
    }

    @Test func xPublicKeyCheck() {
        let base = X.PublicKey(3)
        let tweak: [UInt8] = Scalar(2).withUnsafeBytes { Array($0) }
        let check = X.PublicKey(5)
        #expect(check.check(base: base, tweak: tweak, negated: false))
    }

    @Test func xPublicKeyCheckNegated() {
        let base = X.PublicKey(8)
        let tweak: [UInt8] = Scalar(9).withUnsafeBytes { Array($0) }
        let check = X.PublicKey(17)
        #expect(check.check(base: base, tweak: tweak, negated: true))
    }

    @Test func xPublicKeySerialize() {
        let pk = X.PublicKey(123_456_789)
        let serialized = pk.serialize()
        #expect(X.PublicKey(from: serialized) == X.PublicKey(123_456_789))
    }

    @Test func xSignVerify() throws {
        let sk = X.SecretKey(777_999_888_111)
        let pk = X.PublicKey(777_999_888_111)
        #expect(pk == sk.pubkey().xPoint)
        let message = (2..<34).map(UInt8.init)
        let signature = try sk.sign(message: message)
        #expect(pk.verify(signature: signature, message: message))
        #expect(signature.serialize() == X.Signature(from: signature.serialize())?.serialize())
    }

    @Test func xPublicKeyDsa() {
        let pk = DSA.PublicKey(-8)
        let x = pk.xOnly()
        #expect(x.negated)
        #expect(x.xPubkey.dsa() == .init(8))
    }

    @Test func random() {
        let t1 = DSA.SecretKey.random()
        let t2 = X.SecretKey.random()
        #expect(t1.scalar >= 1)
        #expect(t2.scalar >= 1)

        for _ in 0..<100 {
            let t3 = X.SecretKey.random()
            guard t3.scalar < Scalar(Int.max)
            else {
                #expect(t3.scalar >= Scalar(Int.max))
                return
            }
        }
    }
}

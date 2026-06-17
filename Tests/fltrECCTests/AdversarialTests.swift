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

private func message(seed: Int) -> [UInt8] {
    (0..<32).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ seed) }
}

// MARK: - ECDSA (DSA)

@Suite struct AdversarialDSATests {
    static let secrets: [Int] = [1, 2, 7, 255, 65_537, 1_234_567, 999_999_937]

    @Test(arguments: secrets)
    func signVerifyRoundTrip(secret: Int) throws {
        let key = DSA.SecretKey(Scalar(secret))
        let pubkey = key.pubkey()
        let msg = message(seed: secret)
        let signature = try key.sign(message: msg, nonce: .none)
        #expect(pubkey.verify(signature: signature, message: msg))
    }

    @Test(arguments: secrets)
    func wrongMessageRejected(secret: Int) throws {
        let key = DSA.SecretKey(Scalar(secret))
        let pubkey = key.pubkey()
        let msg = message(seed: secret)
        let signature = try key.sign(message: msg, nonce: .none)
        var tampered = msg
        tampered[secret % 32] ^= 0x01
        #expect(!pubkey.verify(signature: signature, message: tampered))
    }

    @Test(arguments: secrets)
    func wrongKeyRejected(secret: Int) throws {
        let key = DSA.SecretKey(Scalar(secret))
        let msg = message(seed: secret)
        let signature = try key.sign(message: msg, nonce: .none)
        let otherPubkey = DSA.SecretKey(Scalar(secret &+ 1)).pubkey()
        #expect(!otherPubkey.verify(signature: signature, message: msg))
    }

    @Test func deterministicSigningWithoutAux() throws {
        let key = DSA.SecretKey(Scalar(42))
        let msg = message(seed: 42)
        // `.none` selects RFC6979 deterministic signing — identical every time.
        let first = try key.sign(message: msg, nonce: .none)
        let second = try key.sign(message: msg, nonce: .none)
        #expect(first == second)
    }

    @Test func wrongLengthMessageThrows() {
        let key = DSA.SecretKey(Scalar(7))
        #expect(throws: (any Error).self) {
            try key.sign(message: [UInt8](repeating: 0, count: 31))
        }
        #expect(throws: (any Error).self) { try key.sign(message: []) }
        #expect(throws: (any Error).self) {
            try key.sign(message: message(seed: 1), nonce: .some([UInt8](repeating: 0, count: 16)))
        }
    }

    @Test(arguments: secrets)
    func derAndCompactRoundTrip(secret: Int) throws {
        let key = DSA.SecretKey(Scalar(secret))
        let signature = try key.sign(message: message(seed: secret), nonce: .none)
        #expect(DSA.Signature(from: signature.serializeDer()) == signature)
        #expect(DSA.Signature(from: signature.serializeCompact()) == signature)
    }

    /// Signature malleability: a high-S encoding (s' = n - s) must normalise back
    /// to the canonical low-S signature on parse, and still verify.
    @Test(arguments: secrets)
    func highSMalleabilityNormalized(secret: Int) throws {
        let key = DSA.SecretKey(Scalar(secret))
        let pubkey = key.pubkey()
        let msg = message(seed: secret)
        let signature = try key.sign(message: msg, nonce: .none)

        let compact = signature.serializeCompact()
        let r = Array(compact[0..<32])
        let s = try #require(Scalar(Array(compact[32..<64])))
        let highS = s.negated().withUnsafeBytes { Array($0) }  // n - s
        #expect(highS != Array(compact[32..<64]))

        let malleable = try #require(DSA.Signature(from: r + highS))
        #expect(malleable == signature)  // normalised to canonical low-S
        #expect(pubkey.verify(signature: malleable, message: msg))
    }

    @Test(arguments: Array(0..<64))
    func singleBitFlipRejected(byteIndex: Int) throws {
        let key = DSA.SecretKey(Scalar(7))
        let pubkey = key.pubkey()
        let msg = message(seed: 7)
        let signature = try key.sign(message: msg, nonce: .none)

        var compact = signature.serializeCompact()
        compact[byteIndex] ^= 0x01
        guard let tampered = DSA.Signature(from: compact) else { return }  // parse rejection is fine
        if tampered == signature { return }  // absorbed by normalisation — not a real change
        #expect(!pubkey.verify(signature: tampered, message: msg))
    }

    @Test(
        arguments: [
            [UInt8](),
            [UInt8](repeating: 0, count: 10),  // wrong length
            [UInt8](repeating: 0xff, count: 64),  // r, s >= n (out of range)
        ] as [[UInt8]])
    func malformedSignatureRejected(bytes: [UInt8]) {
        // Note: an all-zero 64-byte compact encoding (r = s = 0) *parses* — it is
        // in range — but can never verify; encoding validity is not signature
        // validity. So only length and out-of-range cases are rejected at parse.
        #expect(DSA.Signature(from: bytes) == nil)
    }
}

// MARK: - Recoverable ECDSA

@Suite struct AdversarialRecoveryTests {
    static let secrets: [Int] = [1, 99, 120, 7_777, 31_415_926]

    @Test(arguments: secrets)
    func recoversSigner(secret: Int) throws {
        let key = DSA.SecretKey(Scalar(secret))
        let pubkey = key.pubkey()
        let msg = message(seed: secret)
        let recoverable = try key.sign(recoverable: msg, nonce: .none)
        let recovered = try #require(recoverable.recover(from: msg))
        #expect(recovered == pubkey)
    }

    @Test(arguments: secrets)
    func wrongMessageRecoversDifferentKey(secret: Int) throws {
        let key = DSA.SecretKey(Scalar(secret))
        let pubkey = key.pubkey()
        let msg = message(seed: secret)
        let recoverable = try key.sign(recoverable: msg, nonce: .none)
        var wrong = msg
        wrong[0] ^= 0x80
        if let recovered = recoverable.recover(from: wrong) {
            #expect(recovered != pubkey)
        }
    }

    @Test(arguments: secrets)
    func convertedSignatureVerifies(secret: Int) throws {
        let key = DSA.SecretKey(Scalar(secret))
        let pubkey = key.pubkey()
        let msg = message(seed: secret)
        let recoverable = try key.sign(recoverable: msg, nonce: .none)
        #expect(pubkey.verify(signature: recoverable.dsaSignature(), message: msg))
    }

    @Test(arguments: secrets)
    func serializeRoundTrip(secret: Int) throws {
        let key = DSA.SecretKey(Scalar(secret))
        let recoverable = try key.sign(recoverable: message(seed: secret), nonce: .none)
        let (data, id) = recoverable.serialize()
        #expect(DSA.RecoverableSignature(from: data, id: id) == recoverable)
    }

    /// Regression: an out-of-range recovery id must return nil from the failable
    /// initializer, not abort the process (the `Int32(id)` trap was a DoS).
    @Test func outOfRangeRecoveryIdRejectedNotCrash() throws {
        let recoverable = try DSA.SecretKey(Scalar(99)).sign(
            recoverable: message(seed: 99), nonce: .none)
        let (data, _) = recoverable.serialize()
        #expect(DSA.RecoverableSignature(from: data, id: Int.max) == nil)  // outside Int32
        #expect(DSA.RecoverableSignature(from: data, id: Int.min) == nil)  // outside Int32
        #expect(DSA.RecoverableSignature(from: data, id: -1) == nil)  // negative
        #expect(DSA.RecoverableSignature(from: data, id: 4) == nil)  // in range, invalid
    }
}

// MARK: - Schnorr (X)

@Suite struct AdversarialSchnorrTests {
    static let secrets: [Int] = [1, 2, 5, 4242, 7_777_777]

    @Test(arguments: secrets)
    func signVerifyRoundTrip(secret: Int) throws {
        let key = X.SecretKey(Scalar(secret))
        let pubkey = key.pubkey().xPoint
        let msg = message(seed: secret)
        let signature = try key.sign(message: msg, nonce: .none)
        #expect(pubkey.verify(signature: signature, message: msg))
    }

    @Test(arguments: Array(0..<64))
    func singleBitFlipRejected(byteIndex: Int) throws {
        let key = X.SecretKey(Scalar(31337))
        let pubkey = key.pubkey().xPoint
        let msg = message(seed: 31337)
        let signature = try key.sign(message: msg, nonce: .none)

        var bytes = signature.serialize()
        bytes[byteIndex] ^= 0x01
        let tampered = try #require(X.Signature(from: bytes))
        #expect(!pubkey.verify(signature: tampered, message: msg))
    }

    @Test(arguments: secrets)
    func wrongMessageRejected(secret: Int) throws {
        let key = X.SecretKey(Scalar(secret))
        let pubkey = key.pubkey().xPoint
        let msg = message(seed: secret)
        let signature = try key.sign(message: msg, nonce: .none)
        var wrong = msg
        wrong[31] ^= 0x01
        #expect(!pubkey.verify(signature: signature, message: wrong))
    }

    @Test func auxRandStillVerifies() throws {
        let key = X.SecretKey(Scalar(88))
        let pubkey = key.pubkey().xPoint
        let msg = message(seed: 88)
        let withAux = try key.sign(message: msg, nonce: .some([UInt8](repeating: 0x5a, count: 32)))
        let withoutAux = try key.sign(message: msg, nonce: .none)
        #expect(pubkey.verify(signature: withAux, message: msg))
        #expect(pubkey.verify(signature: withoutAux, message: msg))
    }

    @Test func wrongLengthMessageThrows() {
        let key = X.SecretKey(Scalar(5))
        #expect(throws: (any Error).self) {
            try key.sign(message: [UInt8](repeating: 0, count: 33))
        }
        #expect(throws: (any Error).self) {
            try key.sign(message: message(seed: 1), nonce: .some([UInt8](repeating: 0, count: 8)))
        }
    }

    @Test(
        arguments: [
            [UInt8](repeating: 0, count: 63),
            [UInt8](repeating: 0, count: 65),
            [UInt8](),
        ] as [[UInt8]])
    func malformedSignatureRejected(bytes: [UInt8]) {
        #expect(X.Signature(from: bytes) == nil)
    }
}

// MARK: - ECDH

@Suite struct AdversarialECDHTests {
    @Test(arguments: Array(0..<16))
    func symmetry(iteration: Int) {
        let alice = DSA.SecretKey.random()
        let bob = DSA.SecretKey.random()
        let shared1 = alice.ecdh(bob.pubkey())
        let shared2 = bob.ecdh(alice.pubkey())
        #expect(shared1 == shared2)
    }

    @Test func distinctPairsDiffer() {
        let alice = DSA.SecretKey(Scalar(1_000))
        let bob = DSA.SecretKey(Scalar(2_000))
        let eve = DSA.SecretKey(Scalar(3_000))
        #expect(alice.ecdh(bob.pubkey()) != alice.ecdh(eve.pubkey()))
    }
}

// MARK: - X-only / taproot tweak

@Suite struct AdversarialTweakTests {
    static let cases: [(base: Int, tweak: Int)] = [
        (3, 2), (5, 7), (20_000, 30_000), (8, 9), (123, 456),
    ]

    /// BIP-341-style consistency: tweaking the x-only public key and recomputing
    /// the parity must satisfy the on-chain `tweak_add_check` predicate.
    @Test(arguments: cases)
    func tweakAddCheckConsistency(base: Int, tweak: Int) throws {
        let basePubkey = X.PublicKey(Point(base))
        let tweakScalar = Scalar(tweak)
        let tweakBytes = tweakScalar.withUnsafeBytes { Array($0) }

        let tweaked = try #require(basePubkey.tweak(add: tweakScalar))
        let (negated, xTweaked) = tweaked.xOnly()
        #expect(xTweaked.check(base: basePubkey, tweak: tweakBytes, negated: negated))
    }

    /// The secret-side and public-side tweak must agree on the resulting x-only key.
    @Test(arguments: cases)
    func secretAndPublicTweakAgree(base: Int, tweak: Int) throws {
        let secret = X.SecretKey(Scalar(base))
        let tweakScalar = Scalar(tweak)

        let secretTweaked = try #require(secret.tweak(add: tweakScalar))
        let secretSideXOnly = secretTweaked.pubkey().xPoint

        let publicTweaked = try #require(secret.pubkey().xPoint.tweak(add: tweakScalar))
        #expect(publicTweaked.xOnly().xPubkey == secretSideXOnly)
    }

    @Test(arguments: [4, 15, 161, 90_210])
    func dsaRoundTrip(value: Int) {
        let xPubkey = X.PublicKey(Point(value))
        #expect(xPubkey.dsa().xOnly().xPubkey == xPubkey)
    }
}

// MARK: - Malformed public-key parsing

@Suite struct AdversarialParsingTests {
    @Test(
        arguments: [
            [UInt8](),
            [UInt8](repeating: 0, count: 32),
            [UInt8](repeating: 0, count: 33),  // valid length, all-zero
            [0x02] + [UInt8](repeating: 0xff, count: 32),  // x >= p
            [0x05] + [UInt8](repeating: 0x01, count: 64),  // invalid prefix
            [0x04] + [UInt8](repeating: 0x00, count: 64),  // uncompressed all-zero
        ] as [[UInt8]])
    func dsaPublicKeyRejected(bytes: [UInt8]) {
        #expect(DSA.PublicKey(from: bytes) == nil)
    }

    @Test(
        arguments: [
            [UInt8](repeating: 0, count: 31),  // too short
            [UInt8](repeating: 0, count: 33),  // too long
            [UInt8](repeating: 0xff, count: 32),  // x >= p
        ] as [[UInt8]])
    func xOnlyPublicKeyRejected(bytes: [UInt8]) {
        #expect(X.PublicKey(from: bytes) == nil)
    }

    @Test(arguments: [1, 42, 7_777, 314_159, 2_718_281_828])
    func pubkeyCompressedAndUncompressedRoundTrip(value: Int) {
        let pubkey = DSA.PublicKey(Point(value))
        #expect(DSA.PublicKey(from: pubkey.serialize(format: .compressed)) == pubkey)
        #expect(DSA.PublicKey(from: pubkey.serialize(format: .uncompressed)) == pubkey)
    }
}

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
import Foundation
import Testing
import fltrECC
import fltrECCTesting

// Official BIP-340 Schnorr known-answer + adversarial verification vectors,
// loaded verbatim from the upstream test-vectors.csv (vendored under Resources):
// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
// Columns: index, secret key, public key, aux_rand, message, signature, result, comment.
// Vectors 15-18 use non-32-byte messages, which this library's fixed-size
// `schnorrsig_sign32` / 32-byte verify API does not accept, and are filtered out.
private struct BIP340Vector {
    let index: Int
    let secretKey: [UInt8]?
    let publicKey: [UInt8]
    let auxRand: [UInt8]?
    let message: [UInt8]
    let signature: [UInt8]
    let valid: Bool
    let comment: String
}

private func loadBIP340Vectors() throws -> [BIP340Vector] {
    let url = try #require(
        Bundle.module.url(forResource: "bip340-test-vectors", withExtension: "csv"),
        "BIP-340 test-vectors.csv resource is missing")
    let csv = try String(contentsOf: url, encoding: .utf8)

    return
        csv
        .split(whereSeparator: \.isNewline)
        .dropFirst()  // header
        .compactMap { line -> BIP340Vector? in
            let f = line.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            let message = hexBytes(f[4])
            // Library only signs/verifies 32-byte messages.
            guard message.count == 32 else { return nil }
            return BIP340Vector(
                index: Int(f[0])!,
                secretKey: f[1].isEmpty ? nil : hexBytes(f[1]),
                publicKey: hexBytes(f[2]),
                auxRand: f[3].isEmpty ? nil : hexBytes(f[3]),
                message: message,
                signature: hexBytes(f[5]),
                valid: f[6] == "TRUE",
                comment: f.count > 7 ? f[7...].joined(separator: ",") : ""
            )
        }
}

@Suite struct SchnorrBIP340Tests {
    private let vectors: [BIP340Vector]

    init() throws {
        self.vectors = try loadBIP340Vectors()
    }

    /// Signing known-answer test: the library must reproduce the exact BIP-340
    /// signature byte-for-byte, including correct use of `aux_rand`. (This is a
    /// direct regression guard for the nonce-pointer bug.)
    @Test func signingKnownAnswers() throws {
        for v in vectors {
            guard let secretKeyBytes = v.secretKey, let auxRand = v.auxRand else { continue }
            let scalar = try #require(Scalar(secretKeyBytes[...]), "vector \(v.index): secret key")
            let secretKey = X.SecretKey(scalar)

            // Derived x-only public key matches.
            #expect(
                secretKey.pubkey().xPoint.serialize() == v.publicKey,
                "BIP-340 vector \(v.index): public key derivation")

            // Signature is reproduced exactly with the given aux_rand.
            let signature = try secretKey.sign(message: v.message, nonce: .some(auxRand))
            #expect(
                signature.serialize() == v.signature,
                "BIP-340 vector \(v.index): signature reproduction")
        }
    }

    /// Verification test, including adversarial FALSE cases (off-curve key,
    /// has_even_y(R) false, negated message/s, infinite sG-eP, r/s out of range,
    /// key exceeding field size).
    @Test func verificationKnownAnswers() throws {
        for v in vectors {
            let publicKey = X.PublicKey(from: v.publicKey)
            let signature = try #require(
                X.Signature(from: v.signature), "vector \(v.index): signature parse")

            guard let publicKey else {
                // An unparseable public key can never verify — must be a FALSE vector.
                #expect(
                    !v.valid,
                    "BIP-340 vector \(v.index): unparseable key but expected valid (\(v.comment))")
                continue
            }

            let result = publicKey.verify(signature: signature, message: v.message)
            #expect(result == v.valid, "BIP-340 vector \(v.index): \(v.comment)")
        }
    }

    @Test func loadedExpectedVectorCount() {
        // Vectors 0-14 are 32-byte-message vectors; 15-18 are filtered out.
        #expect(vectors.count == 15)
        #expect(vectors.contains { $0.valid })
        #expect(vectors.contains { !$0.valid })
    }
}

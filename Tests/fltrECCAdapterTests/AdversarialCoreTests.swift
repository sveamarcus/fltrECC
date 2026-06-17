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

private func hexBytes(_ hex: String) -> [UInt8] {
    var result = [UInt8]()
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        result.append(UInt8(hex[index..<next], radix: 16)!)
        index = next
    }
    return result
}

// secp256k1 field prime p.
private let fieldSize = hexBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")

// MARK: - Elliptic-curve group law

@Suite struct GroupLawTests {
    static let triples: [(Int, Int, Int)] = [
        (1, 2, 3), (5, 7, 11), (100, 200, 300), (8, 13, 21), (999, 1, 1_000),
    ]

    @Test(arguments: triples)
    func additionIsCommutative(a: Int, b: Int, _ c: Int) throws {
        let ab = try #require(Point(a).add(Point(b)))
        let ba = try #require(Point(b).add(Point(a)))
        #expect(ab == ba)
    }

    @Test(arguments: triples)
    func additionIsAssociative(a: Int, b: Int, c: Int) throws {
        let ab = try #require(Point(a).add(Point(b)))
        let bc = try #require(Point(b).add(Point(c)))
        let left = try #require(ab.add(Point(c)))
        let right = try #require(Point(a).add(bc))
        #expect(left == right)
    }

    @Test(arguments: triples)
    func scalarAdditionDistributesOverPoints(a: Int, b: Int, _ c: Int) throws {
        let sum = try #require(Scalar(a).add(Scalar(b)))
        let lhs = Point(sum)
        let rhs = try #require(Point(a).add(Point(b)))
        #expect(lhs == rhs)
    }

    @Test(arguments: triples)
    func scalarMultiplicationCommutesOnPoints(a: Int, b: Int, _ c: Int) {
        let product = Scalar(a).mul(Scalar(b))
        #expect(Point(product) == Point(a).mul(Scalar(b)))
        #expect(Point(a).mul(Scalar(b)) == Point(b).mul(Scalar(a)))
    }

    @Test(arguments: [1, 2, 7, 65_537, 1_000_003])
    func negationIsInvolution(value: Int) {
        #expect(Point(value).negated().negated() == Point(value))
    }

    @Test(arguments: [1, 2, 7, 65_537, 1_000_003])
    func pointPlusItsNegativeIsInfinity(value: Int) {
        // P + (-P) = point at infinity, surfaced as nil.
        #expect(Point(value).add(Point(value).negated()) == nil)
    }

    @Test(arguments: [1, 2, 7, 65_537, 1_000_003])
    func negatedScalarYieldsNegatedPoint(value: Int) {
        #expect(Point(Scalar(value).negated()) == Point(value).negated())
    }
}

// MARK: - Scalar range / boundary validation

@Suite struct ScalarBoundaryTests {
    /// Invokes the validating, failable `Scalar.init?(_:)`. Passing an
    /// `ArraySlice` sidesteps `fltrECCTesting`'s non-failable `Scalar(_: [UInt8])`
    /// convenience overload, which traps on invalid input instead of returning nil.
    private func scalar(_ bytes: [UInt8]) -> Scalar? { Scalar(bytes[...]) }

    @Test func zeroIsInvalid() {
        #expect(scalar([UInt8](repeating: 0, count: 32)) == nil)
    }

    @Test func curveOrderIsInvalid() {
        // The secret key must be in [1, n-1]; exactly n is rejected.
        #expect(scalar(C.SCALAR_ORDER) == nil)
    }

    @Test func aboveCurveOrderIsInvalid() {
        var nPlusOne = C.SCALAR_ORDER
        nPlusOne[31] = nPlusOne[31] &+ 1  // ...41 -> ...42, no carry
        #expect(scalar(nPlusOne) == nil)
        #expect(scalar([UInt8](repeating: 0xff, count: 32)) == nil)
    }

    @Test func maxValidScalarIsAccepted() {
        var nMinusOne = C.SCALAR_ORDER
        nMinusOne[31] = nMinusOne[31] &- 1  // ...41 -> ...40
        #expect(scalar(nMinusOne) != nil)
    }

    @Test func wrongLengthIsInvalid() {
        #expect(scalar([UInt8](repeating: 1, count: 31)) == nil)
        #expect(scalar([UInt8](repeating: 1, count: 33)) == nil)
    }
}

// MARK: - Parsing / deserialization fuzz

@Suite struct ParsingFuzzTests {
    @Test(arguments: [0, 1, 32, 34, 64, 66])
    func pointParseWrongLengthRejected(length: Int) {
        #expect(Point(from: [UInt8](repeating: 0x02, count: length)) == nil)
    }

    @Test(arguments: [0x00, 0x01, 0x04, 0x05, 0xff] as [UInt8])
    func pointParseInvalidCompressedPrefixRejected(prefix: UInt8) {
        let body = (0..<32).map { UInt8($0 + 1) }
        #expect(Point(from: [prefix] + body) == nil)
    }

    @Test func pointParseXOutOfFieldRejected() {
        #expect(Point(from: [0x02] + fieldSize) == nil)  // x == p
        #expect(Point(from: [0x03] + [UInt8](repeating: 0xff, count: 32)) == nil)  // x > p
    }

    @Test func pointParseAllZeroRejected() {
        #expect(Point(from: [UInt8](repeating: 0, count: 33)) == nil)
        #expect(Point(from: [UInt8](repeating: 0, count: 65)) == nil)
    }

    @Test(arguments: [0, 1, 31, 33, 64])
    func xPointParseWrongLengthRejected(length: Int) {
        #expect(throws: (any Error).self) {
            try C.deSerialize(xPoint: [UInt8](repeating: 0x01, count: length))
        }
    }

    @Test func xPointParseOutOfFieldRejected() {
        #expect(throws: (any Error).self) {
            try C.deSerialize(xPoint: fieldSize)  // x == p
        }
        #expect(throws: (any Error).self) {
            try C.deSerialize(xPoint: [UInt8](repeating: 0xff, count: 32))  // x > p
        }
    }

    @Test(arguments: [0, 1, 63, 65, 100])
    func compactSignatureWrongLengthRejected(length: Int) {
        #expect(throws: (any Error).self) {
            try C.deSerialize(compactSignature: [UInt8](repeating: 0x01, count: length))
        }
    }

    @Test(
        arguments: [
            [UInt8](),
            [0x30, 0x00],  // empty SEQUENCE (no r, s)
            [UInt8](repeating: 0xff, count: 8),  // garbage
            [0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01],  // length lies about contents
        ] as [[UInt8]])
    func derSignatureMalformedRejected(bytes: [UInt8]) {
        #expect(throws: (any Error).self) {
            try C.deSerialize(derSignature: bytes)
        }
    }
}

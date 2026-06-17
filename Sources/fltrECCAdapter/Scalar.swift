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
public struct Scalar: SecretBytes, SecretMutableBytes, Equatable {
    public let buffer: Buffer

    @usableFromInline
    internal init(_buffer: Buffer) {
        self.buffer = _buffer
    }

    @inlinable
    public init?(_ buffer: Buffer) {
        guard buffer.count == C.SCALAR_SIZE
        else { return nil }
        let scalar = Self.init(_buffer: buffer)

        guard C.scalarIsValid(scalar: scalar)
        else { return nil }
        self = scalar
    }

    @inlinable
    public init?<Bytes: Collection>(_ bytes: Bytes)
    where Bytes.Element == UInt8, Bytes.Index == Int {
        guard bytes.count == C.SCALAR_SIZE
        else { return nil }

        let buffer = Buffer.create(capacity: C.SCALAR_SIZE) { raw, setSizeTo in
            for i in 0..<C.SCALAR_SIZE {
                raw[i] = bytes[bytes.startIndex + i]
            }
            setSizeTo = C.SCALAR_SIZE
        }

        self.init(buffer)
    }

    @inlinable
    public static func random() -> Scalar {
        while true {
            let buffer = Buffer.create(random: C.SCALAR_SIZE)
            let candidate = Scalar(_buffer: buffer)
            if C.scalarIsValid(scalar: candidate) { return candidate }
        }
    }

    @inlinable
    public func add(_ scalar: Scalar) -> Scalar? {
        do {
            let copy = self.copy()
            try C.add(into: copy, scalar: scalar)
            return copy
        } catch {
            return nil
        }
    }

    @inlinable
    public func negated() -> Scalar {
        let copy = self.copy()
        C.negate(into: copy)
        return copy
    }

    @inlinable
    public func mul(_ scalar: Scalar) -> Scalar {
        let copy = self.copy()
        try! C.mul(into: copy, scalar: scalar)
        return copy
    }
}

extension Scalar: @unchecked Sendable {}

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
import CfltrECC

public protocol ReadableBufferProtocol {
    var count: Int { get }
    static func create(
        capacity: Int,
        initializingWith: (inout UnsafeMutableRawBufferPointer, inout Int) throws -> Void
    ) rethrows -> Self
    func withUnsafeBytes<T>(_: (UnsafeRawBufferPointer) throws -> T) rethrows -> T
}

internal protocol WritableBufferProtocol {
    func withUnsafeMutableBytes<T>(_: (UnsafeMutableRawBufferPointer) throws -> T) rethrows -> T
}

public struct ManagedHeader: Sendable {
    @usableFromInline
    var count: Int
    @usableFromInline
    let capacity: Int
}

public final class Buffer: ManagedBuffer<ManagedHeader, UInt8> {
    @usableFromInline
    class func nextPower2(_ x: UInt) -> UInt {
        guard x > 0 else { return 1 }

        let lessOne = x - 1

        let shift = x.bitWidth - lessOne.leadingZeroBitCount
        return 1 << shift
    }

    @usableFromInline
    class func _create(capacity: Int) -> Buffer {
        let minimumCapacity = Int(self.nextPower2(UInt(capacity)))
        let buffer = self.create(minimumCapacity: minimumCapacity) { _ in
            ManagedHeader(count: 0, capacity: capacity)
        }
        return buffer as! Buffer
    }

    @usableFromInline
    class func copy(buffer: Buffer) {
        let new = self._create(capacity: buffer.header.count)
        new.withUnsafeMutablePointerToElements { new in
            buffer.withUnsafeMutablePointerToElements { data in
                for i in 0..<buffer.header.count {
                    new[i] = data[i]
                }
            }
        }
    }

    @usableFromInline
    class func copy<C: Collection>(bytes: C) -> Buffer where C.Element == UInt8 {
        let buffer = self._create(capacity: bytes.count)
        buffer.withUnsafeMutablePointerToElements { buffer in
            bytes.enumerated().forEach { i, byte in
                buffer[i] = byte
            }
        }
        buffer.header.count = bytes.count
        return buffer
    }

    @usableFromInline
    class func create(random count: Int) -> Buffer {
        let buffer = self._create(capacity: count)
        buffer.withUnsafeMutablePointerToElements { buffer in
            for i in 0..<count {
                buffer[i] = .random(in: .min ... .max)
            }
        }
        buffer.header.count = count
        return buffer
    }

    deinit {
        self.withUnsafeMutablePointerToElements { buffer in
            fltrecc_secure_zero(buffer, self.header.capacity)
        }
    }
}

// `Buffer` subclasses `ManagedBuffer`, whose `Sendable` conformance the standard
// library marks explicitly unavailable, so `Buffer` itself cannot be `Sendable`.
// Instead each value-typed wrapper (`Scalar`, `KeyPair`, `EcdhSecret`, ...) is
// declared `@unchecked Sendable`, justified by a copy-before-mutate invariant:
// every in-place `C.*(into:)` operation is preceded by `.copy()`, so a `Buffer`
// reachable from more than one value is never mutated, and concurrent reads of
// the shared, effectively-immutable bytes are safe.
extension Buffer: ReadableBufferProtocol, WritableBufferProtocol {
    @inlinable
    public var count: Int { self.header.count }
    @inlinable
    public static func create(
        capacity: Int,
        initializingWith callback: (inout UnsafeMutableRawBufferPointer, inout Int) throws -> Void
    ) rethrows -> Self {
        let buffer = Buffer._create(capacity: capacity)
        try buffer.withUnsafeMutablePointerToElements { bytes in
            var mutable = UnsafeMutableRawBufferPointer(start: bytes, count: capacity)
            var initializedCount = 0
            try callback(&mutable, &initializedCount)
            buffer.header.count = initializedCount
        }
        return buffer as! Self
    }

    @inlinable
    public func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try self.withUnsafeMutablePointerToElements { buffer in
            let pointer = UnsafeRawBufferPointer(start: buffer, count: self.header.count)
            return try body(pointer)
        }
    }

    // Internal (@usableFromInline), NOT public: in-place mutation of a shared
    // secret Buffer must stay within the library's copy-before-mutate discipline.
    @usableFromInline
    func withUnsafeMutableBytes<T>(_ body: (UnsafeMutableRawBufferPointer) throws -> T) rethrows
        -> T
    {
        try self.withUnsafeMutablePointerToElements { buffer in
            let pointer = UnsafeMutableRawBufferPointer(start: buffer, count: self.header.count)
            return try body(pointer)
        }
    }
}

extension Buffer: Equatable {
    /// Constant-time equality. Every byte is always compared, so the position of
    /// the first difference is not leaked through timing — important because
    /// `Buffer` backs secret material (scalars, key pairs, ECDH secrets). Backed
    /// by `fltrecc_constant_time_equal` (branchless, `volatile`) so the optimizer
    /// cannot reintroduce a short-circuit. NOT `@inlinable`, to keep that opaque
    /// boundary intact.
    ///
    /// The length comparison can differ in timing, but lengths are not secret
    /// (and are fixed for every secret type this wraps).
    public static func == (lhs: Buffer, rhs: Buffer) -> Bool {
        guard lhs.header.count == rhs.header.count
        else { return false }

        return lhs.withUnsafeMutablePointerToElements { lPointer in
            rhs.withUnsafeMutablePointerToElements { rPointer in
                fltrecc_constant_time_equal(lPointer, rPointer, lhs.header.count) == 1
            }
        }
    }
}

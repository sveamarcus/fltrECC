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
public protocol SecretBytes {
    associatedtype BufferType: ReadableBufferProtocol
    var buffer: BufferType { get }
    var count: Int { get }
    func copy() -> Self
    func withUnsafeBytes<T>(_: (UnsafeRawBufferPointer) throws -> T) rethrows -> T
    init?(_: BufferType)
    init?<S: SecretBytes>(_: S) where S.BufferType == BufferType
    init(
        unsafeUninitializedCapacity: Int,
        initializingWith: (inout UnsafeMutableRawBufferPointer, inout Int) throws -> Void) rethrows
}

internal protocol SecretMutableBytes: SecretBytes where BufferType: WritableBufferProtocol {
    func withUnsafeMutableBytes<T>(_: (UnsafeMutableRawBufferPointer) throws -> T) rethrows -> T
}

extension SecretMutableBytes {
    @inlinable
    public func withUnsafeMutableBytes<T>(_ body: (UnsafeMutableRawBufferPointer) throws -> T)
        rethrows -> T
    {
        try self.buffer.withUnsafeMutableBytes(body)
    }
}

public extension SecretBytes {
    @inlinable
    var count: Int {
        self.buffer.count
    }

    @inlinable
    func copy() -> Self {
        .init(unsafeUninitializedCapacity: self.count) { buffer, setSizeTo in
            self.withUnsafeBytes { privateBytes in
                for i in 0..<self.count {
                    buffer[i] = privateBytes[i]
                }
            }

            setSizeTo = self.count
        }
    }

    @inlinable
    func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try self.buffer.withUnsafeBytes(body)
    }

    @inlinable
    init?<S: SecretBytes>(_ secretBytes: S) where S.BufferType == BufferType {
        self.init(secretBytes.buffer)
    }

    @inlinable
    init(
        unsafeUninitializedCapacity: Int,
        initializingWith callback: (inout UnsafeMutableRawBufferPointer, inout Int) throws -> Void
    ) rethrows {
        let buffer = try BufferType.create(
            capacity: unsafeUninitializedCapacity, initializingWith: callback)
        self.init(buffer)!
    }
}

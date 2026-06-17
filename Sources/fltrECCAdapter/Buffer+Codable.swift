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
#if canImport(Foundation)
    import struct Foundation.Data

    public struct CodableBuffer {
        @usableFromInline
        let buffer: Buffer

        @usableFromInline
        init(_buffer: Buffer) {
            self.buffer = _buffer
        }
    }

    // See `Buffer.swift` for the copy-before-mutate invariant backing `@unchecked`.
    extension CodableBuffer: @unchecked Sendable {}

    extension CodableBuffer: ReadableBufferProtocol {
        public enum CodingKeys: String, CodingKey {
            case data
        }

        public static func create(
            capacity: Int,
            initializingWith callback: (inout UnsafeMutableRawBufferPointer, inout Int) throws ->
                Void
        ) rethrows -> CodableBuffer {
            let buffer = Buffer._create(capacity: capacity)
            try buffer.withUnsafeMutablePointerToElements { bytes in
                var mutable = UnsafeMutableRawBufferPointer(start: bytes, count: capacity)
                var initializedCount = 0
                try callback(&mutable, &initializedCount)
                buffer.header.count = initializedCount
            }
            return self.init(_buffer: buffer)
        }

        @inlinable
        public var count: Int {
            self.buffer.count
        }

        @inlinable
        public func withUnsafeBytes<T>(_ f: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
            try self.buffer.withUnsafeBytes(f)
        }
    }

    extension CodableBuffer: WritableBufferProtocol {
        @usableFromInline
        func withUnsafeMutableBytes<T>(_ f: (UnsafeMutableRawBufferPointer) throws -> T) rethrows
            -> T
        {
            try self.buffer.withUnsafeMutableBytes(f)
        }
    }

    extension CodableBuffer: Equatable {
        @inlinable
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.buffer == rhs.buffer
        }
    }

    extension CodableBuffer: Encodable {
        @inlinable
        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try self.withUnsafeBytes { bytes in
                try container.encode(
                    Data(bytes: bytes.baseAddress!, count: self.count), forKey: .data)
            }
        }
    }

    extension CodableBuffer: Decodable {
        @inlinable
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            var data = try container.decode(Data.self, forKey: .data)
            let buffer = Buffer._create(capacity: data.count)
            buffer.withUnsafeMutablePointerToElements { buffer in
                data.withUnsafeBytes { data in
                    (0..<data.count).forEach { i in
                        buffer[i] = data[i]
                    }

                }
            }
            buffer.header.count = data.count
            data.withUnsafeMutableBytes { data in
                data.enumerated().forEach { i, _ in
                    data[i] = 0
                }
            }
            self.init(_buffer: buffer)
        }
    }
#endif

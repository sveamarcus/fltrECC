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
public struct Point: Sendable {
    public let _data: [UInt8]

    @usableFromInline
    init(_data: [UInt8]) {
        self._data = _data
    }

    @inlinable
    public init(_ scalar: Scalar) {
        self.init(_data: try! C.point(from: scalar))
    }

    @inlinable
    public init?(from serialized: [UInt8]) {
        guard let data = try? C.deSerialize(point: serialized)
        else { return nil }
        self.init(_data: data)
    }

    @usableFromInline
    func tryOperation(scalar: Scalar, _ fn: (inout [UInt8], Scalar) throws -> Void) -> Self? {
        do {
            var copy = self._data
            try fn(&copy, scalar)
            return Self.init(_data: copy)
        } catch {
            return nil
        }
    }

    @inlinable
    public func negated() -> Self {
        var copy = self._data
        C.negate(into: &copy)
        return Self.init(_data: copy)
    }

    @inlinable
    public func add(_ scalar: Scalar) -> Self? {
        tryOperation(scalar: scalar, C.add)
    }

    @inlinable
    public func combine(_ p1: Self, _ ps: Self...) -> Self? {
        do {
            let result = try C.combine(points: [[self._data, p1._data], ps.map(\._data)].joined())
            return .init(_data: result)
        } catch {
            return nil
        }
    }

    @inlinable
    public func add(_ point: Self) -> Self? {
        self.combine(point)
    }

    @inlinable
    public func mul(_ scalar: Scalar) -> Self {
        var copy = self._data
        try! C.mul(into: &copy, scalar: scalar)
        return .init(_data: copy)
    }
}

extension Point: Equatable {
    @inlinable
    public static func equalsDSAPoints(lhs: [UInt8], rhs: [UInt8]) -> Bool {
        switch C.comparePoints(lhs, rhs) {
        case .equals: return true
        case .lessThan, .greaterThan: return false
        }
    }

    @inlinable
    public static func == (lhs: Self, rhs: Self) -> Bool {
        self.equalsDSAPoints(lhs: lhs._data, rhs: rhs._data)
    }
}

extension Point: Comparable {
    @inlinable
    public static func lessThanDSAPoints(lhs: [UInt8], rhs: [UInt8]) -> Bool {
        switch C.comparePoints(lhs, rhs) {
        case .lessThan: return true
        case .equals, .greaterThan: return false
        }
    }

    @inlinable
    public static func < (lhs: Self, rhs: Self) -> Bool {
        self.lessThanDSAPoints(lhs: lhs._data, rhs: rhs._data)
    }
}

extension Point {
    public static let G = {
        let scalarOne = Scalar(unsafeUninitializedCapacity: 32) { scalar, size in
            (0..<31).forEach {
                scalar[$0] = 0
            }
            scalar[31] = 1
            size = 32
        }
        return Point(scalarOne)
    }()
}

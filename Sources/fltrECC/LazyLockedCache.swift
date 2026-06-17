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
import Synchronization

/// A reference-typed, thread-safe memoization cell shared by value copies of a
/// secret key. Backed by `Synchronization.Mutex`, it is portable across every
/// platform Swift 6 supports (Darwin, Linux, Android, Windows) — replacing the
/// previous Darwin-only `os_unfair_lock`.
///
/// The cached value is always a pure function of the immutable scalar that owns
/// the cache, so sharing a single cell across struct copies is benign and the
/// type is safely `Sendable`.
@usableFromInline
internal final class LazyLockedCache<T: Sendable>: Sendable {
    @usableFromInline
    let storage: Mutex<T?> = .init(nil)

    @usableFromInline
    init() {}

    @usableFromInline
    func cache(_ fn: () throws -> T) rethrows -> T {
        if let existing = self.storage.withLock({ $0 }) {
            return existing
        }

        let newValue = try fn()
        return self.storage.withLock { box in
            if let raced = box { return raced }  // another thread populated it first
            box = newValue
            return newValue
        }
    }
}

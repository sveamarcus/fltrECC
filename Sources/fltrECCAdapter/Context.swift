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
import Csecp256k1

public enum C {}

internal extension C {
    @usableFromInline
    final class Context {
        @usableFromInline
        let pointer: OpaquePointer

        init() {
            let context = C.createContext()
            C.randomize(context: context)
            self.pointer = context
        }

        deinit {
            C.destroy(context: self.pointer)
        }
    }
}

// A libsecp256k1 context is documented as safe for concurrent use once it has
// been randomized, provided it is never mutated afterwards. `pointer` is a
// `let` assigned exactly once (after a single `randomize`) and is never altered,
// so sharing the process-wide context across threads is sound.
extension C.Context: @unchecked Sendable {}

extension C {
    @usableFromInline
    static let context: Context = .init()
}

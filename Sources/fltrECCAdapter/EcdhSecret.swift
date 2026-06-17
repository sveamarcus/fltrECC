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
public struct EcdhSecret: SecretBytes, Equatable {
    public let buffer: Buffer

    @inlinable
    public init?(_ buffer: Buffer) {
        guard buffer.count == C.ECDH_SECRET_SIZE
        else { return nil }

        self.buffer = buffer
    }
}

extension EcdhSecret: @unchecked Sendable {}

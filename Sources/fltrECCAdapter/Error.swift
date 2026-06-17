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
public extension C {
    enum Error: Swift.Error, Sendable {
        case illegalKeyPairValue
        case illegalScalarValue
        case illegalPointSerialization
        case illegalPointSerializationByteCount
        case illegalPointValue
        case illegalSignature
        case illegalMessageLength
        case illegalNonceLength
    }
}

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
    static let SCALAR_SIZE = 32
    static let KEYPAIR_SIZE = 96
    static let POINT_SIZE = 64
    static let XPOINT_SIZE = 64
    static let MESSAGE_SIZE = 32
    static let DSA_SIGNATURE_SIZE = 64
    static let DSA_SIGNATURE_NONCE_SIZE = 32
    static let DSA_DER_SIGNATURE_SIZE = 256
    static let DSA_RECOVERABLE_SIGNATURE_SIZE = 65
    static let SCHNORR_SIGNATURE_NONCE_SIZE = 32
    static let SCHNORR_SIGNATURE_SIZE = 64
    static let ECDH_SECRET_SIZE = 32
    static let SCALAR_ORDER = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".hex
}

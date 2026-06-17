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

public extension C {
    @inlinable
    static func ecdh(
        my scalar: Scalar,
        their point: [UInt8]
    ) throws
        -> EcdhSecret
    {
        try EcdhSecret(unsafeUninitializedCapacity: C.ECDH_SECRET_SIZE) { output, setSizeTo in
            let cRet = point.withUnsafeBytes { point in
                scalar.withUnsafeBytes { scalar in
                    secp256k1_ecdh(
                        self.context.pointer,
                        output
                            .baseAddress!
                            .bindMemory(to: UInt8.self, capacity: C.ECDH_SECRET_SIZE),
                        point
                            .bindMemory(to: secp256k1_pubkey.self)
                            .baseAddress!,
                        scalar
                            .bindMemory(to: UInt8.self)
                            .baseAddress!,
                        nil,  // hashfp
                        nil)  // data
                }
            }

            guard cRet == 1
            else { throw C.Error.illegalScalarValue }

            setSizeTo = C.ECDH_SECRET_SIZE
        }
    }
}

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

/// Decodes an even-length hexadecimal string into bytes. Test-only helper.
func hexBytes(_ hex: some StringProtocol) -> [UInt8] {
    precondition(hex.count % 2 == 0, "hex string must have even length")
    var result = [UInt8]()
    result.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            preconditionFailure("invalid hex byte: \(hex[index..<next])")
        }
        result.append(byte)
        index = next
    }
    return result
}

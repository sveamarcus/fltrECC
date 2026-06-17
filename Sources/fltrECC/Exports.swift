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
@_exported import class fltrECCAdapter.Buffer
@_exported import struct fltrECCAdapter.EcdhSecret
@_exported import struct fltrECCAdapter.KeyPair
@_exported import struct fltrECCAdapter.Point
@_exported import struct fltrECCAdapter.Scalar
@_exported import protocol fltrECCAdapter.SecretBytes

#if canImport(Foundation)
    @_exported import struct fltrECCAdapter.CodableBuffer
#endif

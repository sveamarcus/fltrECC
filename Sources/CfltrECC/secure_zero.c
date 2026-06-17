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
#include "CfltrECC.h"

void fltrecc_secure_zero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }

    // Writes through a `volatile` pointer are observable side effects under the
    // C standard, so the compiler must emit every store and may not eliminate
    // them as dead. This is the portable secure-erase used as the baseline by
    // libraries such as libsodium, and works identically on Darwin, Linux,
    // Android, and Windows.
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
}

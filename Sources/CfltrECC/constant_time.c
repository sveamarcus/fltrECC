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

int fltrecc_constant_time_equal(const void *a, const void *b, size_t len) {
    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;

    // OR every per-byte XOR into a single accumulator: every byte is always
    // examined and no branch depends on the data. `diff` is non-zero iff any
    // byte differs. The only branch is on the aggregate result, which is exactly
    // the (public) value this function returns.
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (unsigned char)(pa[i] ^ pb[i]);
    }

    return diff == 0;
}

int fltrecc_constant_time_less(const void *a, const void *b, size_t len) {
    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;

    // Scan most-significant byte first; the first differing byte decides the
    // result. `undecided` freezes the outcome branchlessly once a difference is
    // seen, so every byte is examined and no branch depends on the data.
    unsigned int lt = 0, gt = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned int x = pa[i], y = pb[i];
        unsigned int x_lt = ((x - y) >> 8) & 1u;  // 1 iff x < y
        unsigned int x_gt = ((y - x) >> 8) & 1u;  // 1 iff x > y
        unsigned int undecided = 1u - (lt | gt);
        lt |= x_lt & undecided;
        gt |= x_gt & undecided;
    }

    return (int)lt;
}

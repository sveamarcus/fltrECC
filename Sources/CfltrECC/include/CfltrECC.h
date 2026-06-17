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
#ifndef FLTRECC_H
#define FLTRECC_H

#include <stddef.h>

/// Securely overwrites `len` bytes at `ptr` with zero.
///
/// This lives in C, behind a module boundary, specifically so the Swift/LLVM
/// optimizer cannot prove the stores are dead and remove them (as it legally
/// could for an inline zeroing loop in a `deinit`, where the memory is freed
/// immediately afterwards). The write itself goes through a `volatile` pointer
/// so the C compiler is likewise forbidden from eliding it. Safe to call with a
/// NULL pointer or `len == 0`.
void fltrecc_secure_zero(void *ptr, size_t len);

/// Returns 1 if the `len` bytes at `a` and `b` are equal, 0 otherwise, in time
/// that depends only on `len` and never on the byte values — for comparing
/// secret material without leaking the position of the first difference.
///
/// Accumulation is branchless and goes through `volatile` reads, so neither the
/// optimizer nor the C compiler may reintroduce a data-dependent short-circuit.
int fltrecc_constant_time_equal(const void *a, const void *b, size_t len);

/// Returns 1 if the big-endian unsigned integer in the `len` bytes at `a` is
/// strictly less than the one at `b`, else 0 — in time depending only on `len`,
/// for ordering secret values without leaking the position of the first
/// differing byte. Accumulation is branchless and through `volatile` reads.
int fltrecc_constant_time_less(const void *a, const void *b, size_t len);

#endif /* FLTRECC_H */

/*
 * Keccak-256 Hash Function (Ethereum variant)
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Note: Ethereum uses Keccak-256, NOT SHA3-256.
 * The difference is in the padding: Keccak uses 0x01, SHA3 uses 0x06.
 */

#ifndef KECCAK256_H
#define KECCAK256_H

#include <stdint.h>
#include <stddef.h>

#define KECCAK256_DIGEST_LENGTH 32
#define KECCAK256_BLOCK_LENGTH  136  /* Rate for 256-bit security */

/**
 * Keccak-256 context structure
 */
typedef struct {
    uint64_t state[25];
    uint8_t buffer[KECCAK256_BLOCK_LENGTH];
    size_t buffer_len;
} keccak256_ctx;

/**
 * Initialize Keccak-256 context
 *
 * @param ctx Context to initialize
 */
void keccak256_init(keccak256_ctx *ctx);

/**
 * Update Keccak-256 context with data
 *
 * @param ctx Context
 * @param data Input data
 * @param len Length of data
 */
void keccak256_update(keccak256_ctx *ctx, const uint8_t *data, size_t len);

/**
 * Finalize Keccak-256 and output digest
 *
 * @param ctx Context
 * @param digest Output buffer (32 bytes)
 */
void keccak256_final(keccak256_ctx *ctx, uint8_t digest[KECCAK256_DIGEST_LENGTH]);

/**
 * Compute Keccak-256 hash in one call
 *
 * @param data Input data
 * @param len Length of data
 * @param digest Output buffer (32 bytes)
 */
void keccak256(const uint8_t *data, size_t len, uint8_t digest[KECCAK256_DIGEST_LENGTH]);

#endif /* KECCAK256_H */

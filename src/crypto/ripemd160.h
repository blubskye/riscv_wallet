/*
 * RIPEMD-160 Hash Function
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RIPEMD160_H
#define RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

#define RIPEMD160_DIGEST_LENGTH 20
#define RIPEMD160_BLOCK_LENGTH  64

/**
 * RIPEMD-160 context structure
 */
typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[RIPEMD160_BLOCK_LENGTH];
} ripemd160_ctx;

/**
 * Initialize RIPEMD-160 context
 *
 * @param ctx Context to initialize
 */
void ripemd160_init(ripemd160_ctx *ctx);

/**
 * Update RIPEMD-160 context with data
 *
 * @param ctx Context
 * @param data Input data
 * @param len Length of data
 */
void ripemd160_update(ripemd160_ctx *ctx, const uint8_t *data, size_t len);

/**
 * Finalize RIPEMD-160 and output digest
 *
 * @param ctx Context
 * @param digest Output buffer (20 bytes)
 */
void ripemd160_final(ripemd160_ctx *ctx, uint8_t digest[RIPEMD160_DIGEST_LENGTH]);

/**
 * Compute RIPEMD-160 hash in one call
 *
 * @param data Input data
 * @param len Length of data
 * @param digest Output buffer (20 bytes)
 */
void ripemd160(const uint8_t *data, size_t len, uint8_t digest[RIPEMD160_DIGEST_LENGTH]);

/**
 * Compute HASH160 = RIPEMD160(SHA256(data))
 *
 * This is the standard Bitcoin hash function for public keys.
 *
 * @param data Input data
 * @param len Length of data
 * @param digest Output buffer (20 bytes)
 */
void hash160(const uint8_t *data, size_t len, uint8_t digest[RIPEMD160_DIGEST_LENGTH]);

#endif /* RIPEMD160_H */

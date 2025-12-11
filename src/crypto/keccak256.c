/*
 * Keccak-256 Hash Function (Ethereum variant)
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implementation of Keccak-256 as used by Ethereum.
 * Based on the Keccak specification by Guido Bertoni, Joan Daemen,
 * Michaël Peeters, and Gilles Van Assche.
 */

#include "keccak256.h"
#include "../security/memory.h"
#include <string.h>

/* Keccak-f[1600] round constants */
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Rotate left for 64-bit */
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/**
 * Keccak-f[1600] permutation
 */
static void keccak_f1600(uint64_t state[25])
{
    uint64_t t, bc[5];
    int round;

    for (round = 0; round < 24; round++) {
        /* Theta */
        bc[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        bc[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        bc[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        bc[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        bc[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        t = bc[4] ^ ROL64(bc[1], 1); state[0] ^= t; state[5] ^= t; state[10] ^= t; state[15] ^= t; state[20] ^= t;
        t = bc[0] ^ ROL64(bc[2], 1); state[1] ^= t; state[6] ^= t; state[11] ^= t; state[16] ^= t; state[21] ^= t;
        t = bc[1] ^ ROL64(bc[3], 1); state[2] ^= t; state[7] ^= t; state[12] ^= t; state[17] ^= t; state[22] ^= t;
        t = bc[2] ^ ROL64(bc[4], 1); state[3] ^= t; state[8] ^= t; state[13] ^= t; state[18] ^= t; state[23] ^= t;
        t = bc[3] ^ ROL64(bc[0], 1); state[4] ^= t; state[9] ^= t; state[14] ^= t; state[19] ^= t; state[24] ^= t;

        /* Rho Pi */
        t = state[1];
        bc[0] = state[10]; state[10] = ROL64(t,  1); t = bc[0];
        bc[0] = state[7];  state[7]  = ROL64(t,  3); t = bc[0];
        bc[0] = state[11]; state[11] = ROL64(t,  6); t = bc[0];
        bc[0] = state[17]; state[17] = ROL64(t, 10); t = bc[0];
        bc[0] = state[18]; state[18] = ROL64(t, 15); t = bc[0];
        bc[0] = state[3];  state[3]  = ROL64(t, 21); t = bc[0];
        bc[0] = state[5];  state[5]  = ROL64(t, 28); t = bc[0];
        bc[0] = state[16]; state[16] = ROL64(t, 36); t = bc[0];
        bc[0] = state[8];  state[8]  = ROL64(t, 45); t = bc[0];
        bc[0] = state[21]; state[21] = ROL64(t, 55); t = bc[0];
        bc[0] = state[24]; state[24] = ROL64(t,  2); t = bc[0];
        bc[0] = state[4];  state[4]  = ROL64(t, 14); t = bc[0];
        bc[0] = state[15]; state[15] = ROL64(t, 27); t = bc[0];
        bc[0] = state[23]; state[23] = ROL64(t, 41); t = bc[0];
        bc[0] = state[19]; state[19] = ROL64(t, 56); t = bc[0];
        bc[0] = state[13]; state[13] = ROL64(t,  8); t = bc[0];
        bc[0] = state[12]; state[12] = ROL64(t, 25); t = bc[0];
        bc[0] = state[2];  state[2]  = ROL64(t, 43); t = bc[0];
        bc[0] = state[20]; state[20] = ROL64(t, 62); t = bc[0];
        bc[0] = state[14]; state[14] = ROL64(t, 18); t = bc[0];
        bc[0] = state[22]; state[22] = ROL64(t, 39); t = bc[0];
        bc[0] = state[9];  state[9]  = ROL64(t, 61); t = bc[0];
        bc[0] = state[6];  state[6]  = ROL64(t, 20); t = bc[0];
        state[1] = ROL64(t, 44);

        /* Chi */
        bc[0] = state[0]; bc[1] = state[1]; bc[2] = state[2]; bc[3] = state[3]; bc[4] = state[4];
        state[0] ^= (~bc[1]) & bc[2]; state[1] ^= (~bc[2]) & bc[3]; state[2] ^= (~bc[3]) & bc[4]; state[3] ^= (~bc[4]) & bc[0]; state[4] ^= (~bc[0]) & bc[1];
        bc[0] = state[5]; bc[1] = state[6]; bc[2] = state[7]; bc[3] = state[8]; bc[4] = state[9];
        state[5] ^= (~bc[1]) & bc[2]; state[6] ^= (~bc[2]) & bc[3]; state[7] ^= (~bc[3]) & bc[4]; state[8] ^= (~bc[4]) & bc[0]; state[9] ^= (~bc[0]) & bc[1];
        bc[0] = state[10]; bc[1] = state[11]; bc[2] = state[12]; bc[3] = state[13]; bc[4] = state[14];
        state[10] ^= (~bc[1]) & bc[2]; state[11] ^= (~bc[2]) & bc[3]; state[12] ^= (~bc[3]) & bc[4]; state[13] ^= (~bc[4]) & bc[0]; state[14] ^= (~bc[0]) & bc[1];
        bc[0] = state[15]; bc[1] = state[16]; bc[2] = state[17]; bc[3] = state[18]; bc[4] = state[19];
        state[15] ^= (~bc[1]) & bc[2]; state[16] ^= (~bc[2]) & bc[3]; state[17] ^= (~bc[3]) & bc[4]; state[18] ^= (~bc[4]) & bc[0]; state[19] ^= (~bc[0]) & bc[1];
        bc[0] = state[20]; bc[1] = state[21]; bc[2] = state[22]; bc[3] = state[23]; bc[4] = state[24];
        state[20] ^= (~bc[1]) & bc[2]; state[21] ^= (~bc[2]) & bc[3]; state[22] ^= (~bc[3]) & bc[4]; state[23] ^= (~bc[4]) & bc[0]; state[24] ^= (~bc[0]) & bc[1];

        /* Iota */
        state[0] ^= RC[round];
    }
}

void keccak256_init(keccak256_ctx *ctx)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->buffer_len = 0;
}

void keccak256_update(keccak256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t i;

    while (len > 0) {
        size_t to_copy = KECCAK256_BLOCK_LENGTH - ctx->buffer_len;
        if (to_copy > len) {
            to_copy = len;
        }

        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;

        if (ctx->buffer_len == KECCAK256_BLOCK_LENGTH) {
            /* XOR buffer into state (little-endian) */
            for (i = 0; i < KECCAK256_BLOCK_LENGTH / 8; i++) {
                ctx->state[i] ^= ((uint64_t)ctx->buffer[i * 8 + 0]) |
                                 ((uint64_t)ctx->buffer[i * 8 + 1] << 8) |
                                 ((uint64_t)ctx->buffer[i * 8 + 2] << 16) |
                                 ((uint64_t)ctx->buffer[i * 8 + 3] << 24) |
                                 ((uint64_t)ctx->buffer[i * 8 + 4] << 32) |
                                 ((uint64_t)ctx->buffer[i * 8 + 5] << 40) |
                                 ((uint64_t)ctx->buffer[i * 8 + 6] << 48) |
                                 ((uint64_t)ctx->buffer[i * 8 + 7] << 56);
            }
            keccak_f1600(ctx->state);
            ctx->buffer_len = 0;
        }
    }
}

void keccak256_final(keccak256_ctx *ctx, uint8_t digest[KECCAK256_DIGEST_LENGTH])
{
    size_t i;

    /* Pad with Keccak padding (0x01 ... 0x80) */
    /* Note: SHA3 uses 0x06, Keccak uses 0x01 */
    ctx->buffer[ctx->buffer_len] = 0x01;
    memset(ctx->buffer + ctx->buffer_len + 1, 0,
           KECCAK256_BLOCK_LENGTH - ctx->buffer_len - 1);
    ctx->buffer[KECCAK256_BLOCK_LENGTH - 1] |= 0x80;

    /* XOR final block into state */
    for (i = 0; i < KECCAK256_BLOCK_LENGTH / 8; i++) {
        ctx->state[i] ^= ((uint64_t)ctx->buffer[i * 8 + 0]) |
                         ((uint64_t)ctx->buffer[i * 8 + 1] << 8) |
                         ((uint64_t)ctx->buffer[i * 8 + 2] << 16) |
                         ((uint64_t)ctx->buffer[i * 8 + 3] << 24) |
                         ((uint64_t)ctx->buffer[i * 8 + 4] << 32) |
                         ((uint64_t)ctx->buffer[i * 8 + 5] << 40) |
                         ((uint64_t)ctx->buffer[i * 8 + 6] << 48) |
                         ((uint64_t)ctx->buffer[i * 8 + 7] << 56);
    }
    keccak_f1600(ctx->state);

    /* Extract digest (little-endian) */
    for (i = 0; i < KECCAK256_DIGEST_LENGTH / 8; i++) {
        digest[i * 8 + 0] = (ctx->state[i]) & 0xFF;
        digest[i * 8 + 1] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 8 + 2] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 8 + 3] = (ctx->state[i] >> 24) & 0xFF;
        digest[i * 8 + 4] = (ctx->state[i] >> 32) & 0xFF;
        digest[i * 8 + 5] = (ctx->state[i] >> 40) & 0xFF;
        digest[i * 8 + 6] = (ctx->state[i] >> 48) & 0xFF;
        digest[i * 8 + 7] = (ctx->state[i] >> 56) & 0xFF;
    }

    /* Clear context */
    secure_wipe(ctx, sizeof(*ctx));
}

void keccak256(const uint8_t *data, size_t len, uint8_t digest[KECCAK256_DIGEST_LENGTH])
{
    keccak256_ctx ctx;

    keccak256_init(&ctx);
    keccak256_update(&ctx, data, len);
    keccak256_final(&ctx, digest);
}

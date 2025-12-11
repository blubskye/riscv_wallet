/*
 * RIPEMD-160 Hash Function
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Based on the RIPEMD-160 specification by Hans Dobbertin, Antoon Bosselaers,
 * and Bart Preneel.
 */

#include "ripemd160.h"
#include "../security/memory.h"
#include <string.h>
#include <sodium.h>

/* Initial hash values */
#define H0 0x67452301UL
#define H1 0xEFCDAB89UL
#define H2 0x98BADCFEUL
#define H3 0x10325476UL
#define H4 0xC3D2E1F0UL

/* Round constants for left path */
#define KL0 0x00000000UL
#define KL1 0x5A827999UL
#define KL2 0x6ED9EBA1UL
#define KL3 0x8F1BBCDCUL
#define KL4 0xA953FD4EUL

/* Round constants for right path */
#define KR0 0x50A28BE6UL
#define KR1 0x5C4DD124UL
#define KR2 0x6D703EF3UL
#define KR3 0x7A6D76E9UL
#define KR4 0x00000000UL

/* Rotate left */
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Boolean functions */
#define F0(x, y, z) ((x) ^ (y) ^ (z))
#define F1(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define F2(x, y, z) (((x) | ~(y)) ^ (z))
#define F3(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define F4(x, y, z) ((x) ^ ((y) | ~(z)))

/* Message schedule for left rounds */
static const int RL[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

/* Message schedule for right rounds */
static const int RR[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

/* Shift amounts for left rounds */
static const int SL[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

/* Shift amounts for right rounds */
static const int SR[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

/* Process a single 512-bit block */
static void ripemd160_transform(ripemd160_ctx *ctx, const uint8_t block[64])
{
    uint32_t X[16];
    uint32_t AL, BL, CL, DL, EL;
    uint32_t AR, BR, CR, DR, ER;
    uint32_t T;
    int j;

    /* Parse block into 16 32-bit words (little-endian) */
    for (j = 0; j < 16; j++) {
        X[j] = ((uint32_t)block[j * 4 + 0]) |
               ((uint32_t)block[j * 4 + 1] << 8) |
               ((uint32_t)block[j * 4 + 2] << 16) |
               ((uint32_t)block[j * 4 + 3] << 24);
    }

    /* Initialize working variables */
    AL = AR = ctx->state[0];
    BL = BR = ctx->state[1];
    CL = CR = ctx->state[2];
    DL = DR = ctx->state[3];
    EL = ER = ctx->state[4];

    /* 80 rounds */
    for (j = 0; j < 80; j++) {
        /* Left path */
        if (j < 16) {
            T = AL + F0(BL, CL, DL) + X[RL[j]] + KL0;
        } else if (j < 32) {
            T = AL + F1(BL, CL, DL) + X[RL[j]] + KL1;
        } else if (j < 48) {
            T = AL + F2(BL, CL, DL) + X[RL[j]] + KL2;
        } else if (j < 64) {
            T = AL + F3(BL, CL, DL) + X[RL[j]] + KL3;
        } else {
            T = AL + F4(BL, CL, DL) + X[RL[j]] + KL4;
        }
        T = ROL(T, SL[j]) + EL;
        AL = EL;
        EL = DL;
        DL = ROL(CL, 10);
        CL = BL;
        BL = T;

        /* Right path */
        if (j < 16) {
            T = AR + F4(BR, CR, DR) + X[RR[j]] + KR0;
        } else if (j < 32) {
            T = AR + F3(BR, CR, DR) + X[RR[j]] + KR1;
        } else if (j < 48) {
            T = AR + F2(BR, CR, DR) + X[RR[j]] + KR2;
        } else if (j < 64) {
            T = AR + F1(BR, CR, DR) + X[RR[j]] + KR3;
        } else {
            T = AR + F0(BR, CR, DR) + X[RR[j]] + KR4;
        }
        T = ROL(T, SR[j]) + ER;
        AR = ER;
        ER = DR;
        DR = ROL(CR, 10);
        CR = BR;
        BR = T;
    }

    /* Final addition */
    T = ctx->state[1] + CL + DR;
    ctx->state[1] = ctx->state[2] + DL + ER;
    ctx->state[2] = ctx->state[3] + EL + AR;
    ctx->state[3] = ctx->state[4] + AL + BR;
    ctx->state[4] = ctx->state[0] + BL + CR;
    ctx->state[0] = T;

    /* Clear sensitive data */
    secure_wipe(X, sizeof(X));
}

void ripemd160_init(ripemd160_ctx *ctx)
{
    ctx->state[0] = H0;
    ctx->state[1] = H1;
    ctx->state[2] = H2;
    ctx->state[3] = H3;
    ctx->state[4] = H4;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void ripemd160_update(ripemd160_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t buffer_idx;
    size_t fill;

    if (len == 0) {
        return;
    }

    buffer_idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    /* Fill buffer if we have partial data */
    if (buffer_idx > 0) {
        fill = 64 - buffer_idx;
        if (len < fill) {
            memcpy(ctx->buffer + buffer_idx, data, len);
            return;
        }
        memcpy(ctx->buffer + buffer_idx, data, fill);
        ripemd160_transform(ctx, ctx->buffer);
        data += fill;
        len -= fill;
    }

    /* Process full blocks */
    while (len >= 64) {
        ripemd160_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    /* Save remaining data */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

void ripemd160_final(ripemd160_ctx *ctx, uint8_t digest[RIPEMD160_DIGEST_LENGTH])
{
    uint8_t padding[64];
    uint64_t bit_count;
    size_t pad_len;
    size_t buffer_idx;
    int i;

    /* Calculate padding */
    buffer_idx = (size_t)(ctx->count & 0x3F);
    pad_len = (buffer_idx < 56) ? (56 - buffer_idx) : (120 - buffer_idx);

    /* Bit count (little-endian) */
    bit_count = ctx->count << 3;

    /* Pad with 0x80 followed by zeros */
    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;
    ripemd160_update(ctx, padding, pad_len);

    /* Append length (little-endian) */
    padding[0] = (bit_count) & 0xFF;
    padding[1] = (bit_count >> 8) & 0xFF;
    padding[2] = (bit_count >> 16) & 0xFF;
    padding[3] = (bit_count >> 24) & 0xFF;
    padding[4] = (bit_count >> 32) & 0xFF;
    padding[5] = (bit_count >> 40) & 0xFF;
    padding[6] = (bit_count >> 48) & 0xFF;
    padding[7] = (bit_count >> 56) & 0xFF;
    ripemd160_update(ctx, padding, 8);

    /* Output digest (little-endian) */
    for (i = 0; i < 5; i++) {
        digest[i * 4 + 0] = (ctx->state[i]) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 3] = (ctx->state[i] >> 24) & 0xFF;
    }

    /* Clear context */
    secure_wipe(ctx, sizeof(*ctx));
}

void ripemd160(const uint8_t *data, size_t len, uint8_t digest[RIPEMD160_DIGEST_LENGTH])
{
    ripemd160_ctx ctx;

    ripemd160_init(&ctx);
    ripemd160_update(&ctx, data, len);
    ripemd160_final(&ctx, digest);
}

void hash160(const uint8_t *data, size_t len, uint8_t digest[RIPEMD160_DIGEST_LENGTH])
{
    uint8_t sha256_digest[32];

    /* SHA256 first */
    crypto_hash_sha256(sha256_digest, data, len);

    /* Then RIPEMD160 */
    ripemd160(sha256_digest, 32, digest);

    /* Clear intermediate hash */
    secure_wipe(sha256_digest, sizeof(sha256_digest));
}

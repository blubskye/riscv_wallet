/*
 * PBKDF2 Key Derivation Function
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "pbkdf2.h"
#include "../security/memory.h"
#include <string.h>
#include <sodium.h>

#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_LENGTH  64
#define SHA512_DIGEST_LENGTH 64
#define SHA512_BLOCK_LENGTH  128

/**
 * HMAC-SHA512
 *
 * Computes HMAC-SHA512(key, data)
 */
static void hmac_sha512(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t output[SHA512_DIGEST_LENGTH])
{
    crypto_auth_hmacsha512_state state;

    crypto_auth_hmacsha512_init(&state, key, key_len);
    crypto_auth_hmacsha512_update(&state, data, data_len);
    crypto_auth_hmacsha512_final(&state, output);

    secure_wipe(&state, sizeof(state));
}

/**
 * PBKDF2-HMAC-SHA512 F function
 *
 * F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc
 * where:
 *   U1 = PRF(Password, Salt || INT(i))
 *   U2 = PRF(Password, U1)
 *   ...
 *   Uc = PRF(Password, Uc-1)
 */
static void pbkdf2_f(const uint8_t *password, size_t password_len,
                     const uint8_t *salt, size_t salt_len,
                     uint32_t iterations, uint32_t block_num,
                     uint8_t output[SHA512_DIGEST_LENGTH])
{
    uint8_t u[SHA512_DIGEST_LENGTH];
    uint8_t *salt_block;
    size_t salt_block_len;
    uint32_t i;
    int j;

    /* Allocate salt || INT(block_num) */
    salt_block_len = salt_len + 4;
    salt_block = malloc(salt_block_len);
    if (salt_block == NULL) {
        return;
    }

    /* Copy salt and append block number (big-endian) */
    memcpy(salt_block, salt, salt_len);
    salt_block[salt_len + 0] = (block_num >> 24) & 0xFF;
    salt_block[salt_len + 1] = (block_num >> 16) & 0xFF;
    salt_block[salt_len + 2] = (block_num >> 8) & 0xFF;
    salt_block[salt_len + 3] = block_num & 0xFF;

    /* U1 = PRF(Password, Salt || INT(i)) */
    hmac_sha512(password, password_len, salt_block, salt_block_len, u);
    memcpy(output, u, SHA512_DIGEST_LENGTH);

    /* U2 through Uc */
    for (i = 2; i <= iterations; i++) {
        /* Un = PRF(Password, Un-1) */
        hmac_sha512(password, password_len, u, SHA512_DIGEST_LENGTH, u);

        /* XOR into output */
        for (j = 0; j < SHA512_DIGEST_LENGTH; j++) {
            output[j] ^= u[j];
        }
    }

    /* Cleanup */
    secure_wipe(u, sizeof(u));
    secure_wipe(salt_block, salt_block_len);
    free(salt_block);
}

int pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations,
                       uint8_t *output, size_t output_len)
{
    uint8_t block[SHA512_DIGEST_LENGTH];
    uint32_t block_num;
    size_t offset = 0;
    size_t copy_len;

    if (password == NULL || salt == NULL || output == NULL) {
        return -1;
    }

    if (iterations == 0) {
        return -1;
    }

    /* Generate output blocks */
    block_num = 1;
    while (offset < output_len) {
        /* Compute F for this block */
        pbkdf2_f(password, password_len, salt, salt_len,
                 iterations, block_num, block);

        /* Copy to output (may be partial for last block) */
        copy_len = output_len - offset;
        if (copy_len > SHA512_DIGEST_LENGTH) {
            copy_len = SHA512_DIGEST_LENGTH;
        }
        memcpy(output + offset, block, copy_len);

        offset += copy_len;
        block_num++;
    }

    secure_wipe(block, sizeof(block));

    return 0;
}

/**
 * HMAC-SHA256
 *
 * Computes HMAC-SHA256(key, data)
 */
static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t output[SHA256_DIGEST_LENGTH])
{
    crypto_auth_hmacsha256_state state;

    crypto_auth_hmacsha256_init(&state, key, key_len);
    crypto_auth_hmacsha256_update(&state, data, data_len);
    crypto_auth_hmacsha256_final(&state, output);

    secure_wipe(&state, sizeof(state));
}

/**
 * PBKDF2-HMAC-SHA256 F function
 */
static void pbkdf2_f_sha256(const uint8_t *password, size_t password_len,
                             const uint8_t *salt, size_t salt_len,
                             uint32_t iterations, uint32_t block_num,
                             uint8_t output[SHA256_DIGEST_LENGTH])
{
    uint8_t u[SHA256_DIGEST_LENGTH];
    uint8_t *salt_block;
    size_t salt_block_len;
    uint32_t i;
    int j;

    /* Allocate salt || INT(block_num) */
    salt_block_len = salt_len + 4;
    salt_block = malloc(salt_block_len);
    if (salt_block == NULL) {
        return;
    }

    /* Copy salt and append block number (big-endian) */
    memcpy(salt_block, salt, salt_len);
    salt_block[salt_len + 0] = (block_num >> 24) & 0xFF;
    salt_block[salt_len + 1] = (block_num >> 16) & 0xFF;
    salt_block[salt_len + 2] = (block_num >> 8) & 0xFF;
    salt_block[salt_len + 3] = block_num & 0xFF;

    /* U1 = PRF(Password, Salt || INT(i)) */
    hmac_sha256(password, password_len, salt_block, salt_block_len, u);
    memcpy(output, u, SHA256_DIGEST_LENGTH);

    /* U2 through Uc */
    for (i = 2; i <= iterations; i++) {
        /* Un = PRF(Password, Un-1) */
        hmac_sha256(password, password_len, u, SHA256_DIGEST_LENGTH, u);

        /* XOR into output */
        for (j = 0; j < SHA256_DIGEST_LENGTH; j++) {
            output[j] ^= u[j];
        }
    }

    /* Cleanup */
    secure_wipe(u, sizeof(u));
    secure_wipe(salt_block, salt_block_len);
    free(salt_block);
}

int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations,
                       uint8_t *output, size_t output_len)
{
    uint8_t block[SHA256_DIGEST_LENGTH];
    uint32_t block_num;
    size_t offset = 0;
    size_t copy_len;

    if (password == NULL || salt == NULL || output == NULL) {
        return -1;
    }

    if (iterations == 0) {
        return -1;
    }

    /* Generate output blocks */
    block_num = 1;
    while (offset < output_len) {
        /* Compute F for this block */
        pbkdf2_f_sha256(password, password_len, salt, salt_len,
                        iterations, block_num, block);

        /* Copy to output (may be partial for last block) */
        copy_len = output_len - offset;
        if (copy_len > SHA256_DIGEST_LENGTH) {
            copy_len = SHA256_DIGEST_LENGTH;
        }
        memcpy(output + offset, block, copy_len);

        offset += copy_len;
        block_num++;
    }

    secure_wipe(block, sizeof(block));

    return 0;
}

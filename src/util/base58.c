/*
 * Base58 Encoding/Decoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "base58.h"
#include <string.h>
#include <sodium.h>

static const char base58_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t base58_map[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

/* Stack buffer size for small inputs (covers most addresses and hashes) */
#define BASE58_STACK_BUF_SIZE 128

int base58_encode(const uint8_t *data, size_t data_len,
                  char *output, size_t output_len)
{
    size_t i, j, high, carry, size;
    uint8_t stack_buf[BASE58_STACK_BUF_SIZE];
    uint8_t *buf;
    int need_free = 0;

    if (data == NULL || output == NULL || data_len == 0) {
        return -1;
    }

    /* Estimate size: log(256) / log(58) ≈ 1.37 */
    size = data_len * 138 / 100 + 1;

    /* Use stack buffer for small inputs, heap for large */
    if (size <= BASE58_STACK_BUF_SIZE) {
        buf = stack_buf;
        memset(buf, 0, size);
    } else {
        buf = calloc(size, 1);
        if (buf == NULL) {
            return -1;
        }
        need_free = 1;
    }

    /* Convert to base58 */
    for (i = 0; i < data_len; i++) {
        carry = data[i];
        for (j = 0; j < size; j++) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
    }

    /* Skip leading zeros in buf */
    for (j = size - 1; j > 0 && buf[j] == 0; j--)
        ;

    /* Count leading zeros in input */
    size_t leading_zeros = 0;
    for (i = 0; i < data_len && data[i] == 0; i++) {
        leading_zeros++;
    }

    /* Check output buffer size */
    size_t result_len = leading_zeros + j + 1;
    if (result_len >= output_len) {
        if (need_free) free(buf);
        return -1;
    }

    /* Fill output with leading '1's for zeros */
    for (i = 0; i < leading_zeros; i++) {
        output[i] = '1';
    }

    /* Fill rest with base58 digits */
    for (high = j; ; high--) {
        output[i++] = base58_alphabet[buf[high]];
        if (high == 0) break;
    }
    output[i] = '\0';

    if (need_free) free(buf);
    return (int)i;
}

int base58_decode(const char *input, uint8_t *output, size_t *output_len)
{
    size_t input_len, i, j;
    int carry;
    size_t size;
    uint8_t stack_buf[BASE58_STACK_BUF_SIZE];
    uint8_t *buf;
    int need_free = 0;
    size_t leading_ones = 0;

    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    input_len = strlen(input);
    if (input_len == 0) {
        *output_len = 0;
        return 0;
    }

    /* Count leading ones (represent leading zeros) */
    for (i = 0; i < input_len && input[i] == '1'; i++) {
        leading_ones++;
    }

    /* Estimate size */
    size = input_len * 733 / 1000 + 1;

    /* Use stack buffer for small inputs, heap for large */
    if (size <= BASE58_STACK_BUF_SIZE) {
        buf = stack_buf;
        memset(buf, 0, size);
    } else {
        buf = calloc(size, 1);
        if (buf == NULL) {
            return -1;
        }
        need_free = 1;
    }

    /* Convert from base58 */
    for (i = leading_ones; i < input_len; i++) {
        int8_t digit = base58_map[(unsigned char)input[i]];
        if (digit < 0) {
            if (need_free) free(buf);
            return -1;  /* Invalid character */
        }

        carry = digit;
        for (j = 0; j < size; j++) {
            carry += 58 * buf[j];
            buf[j] = carry % 256;
            carry /= 256;
        }
    }

    /* Skip leading zeros in buf */
    for (j = size - 1; j > 0 && buf[j] == 0; j--)
        ;

    /* Check output size */
    size_t result_len = leading_ones + j + 1;
    if (result_len > *output_len) {
        if (need_free) free(buf);
        return -1;
    }

    /* Fill output with leading zeros */
    for (i = 0; i < leading_ones; i++) {
        output[i] = 0;
    }

    /* Fill rest in reverse */
    for (size_t k = j + 1; k > 0; k--) {
        output[i++] = buf[k - 1];
    }

    *output_len = result_len;
    if (need_free) free(buf);
    return 0;
}

int base58check_encode(const uint8_t *data, size_t data_len,
                       char *output, size_t output_len)
{
    uint8_t *buf;
    uint8_t hash1[32], hash2[32];
    int result;

    if (data == NULL || output == NULL) {
        return -1;
    }

    /* Allocate buffer for data + 4 byte checksum */
    buf = malloc(data_len + 4);
    if (buf == NULL) {
        return -1;
    }

    memcpy(buf, data, data_len);

    /* Double SHA256 for checksum */
    crypto_hash_sha256(hash1, data, data_len);
    crypto_hash_sha256(hash2, hash1, 32);

    /* Append first 4 bytes of double-hash as checksum */
    memcpy(buf + data_len, hash2, 4);

    result = base58_encode(buf, data_len + 4, output, output_len);

    sodium_memzero(buf, data_len + 4);
    sodium_memzero(hash1, sizeof(hash1));
    sodium_memzero(hash2, sizeof(hash2));
    free(buf);

    return result;
}

int base58check_decode(const char *input, uint8_t *output, size_t *output_len)
{
    uint8_t buf[128];
    size_t buf_len = sizeof(buf);
    uint8_t hash1[32], hash2[32];

    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    /* Decode base58 */
    if (base58_decode(input, buf, &buf_len) != 0) {
        return -1;
    }

    if (buf_len < 4) {
        return -1;
    }

    /* Verify checksum */
    crypto_hash_sha256(hash1, buf, buf_len - 4);
    crypto_hash_sha256(hash2, hash1, 32);

    if (memcmp(buf + buf_len - 4, hash2, 4) != 0) {
        sodium_memzero(buf, sizeof(buf));
        return -1;  /* Checksum mismatch */
    }

    /* Copy data without checksum */
    size_t data_len = buf_len - 4;
    if (data_len > *output_len) {
        sodium_memzero(buf, sizeof(buf));
        return -1;
    }

    memcpy(output, buf, data_len);
    *output_len = data_len;

    sodium_memzero(buf, sizeof(buf));
    sodium_memzero(hash1, sizeof(hash1));
    sodium_memzero(hash2, sizeof(hash2));

    return 0;
}

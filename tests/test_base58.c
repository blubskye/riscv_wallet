/*
 * Base58 Encoding Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/util/base58.h"

extern void test_report(const char *name, int result);

/* Test vectors */

static int test_base58_encode(void)
{
    char output[100];
    size_t output_len = sizeof(output);

    /* "Hello World!" -> 2NEpo7TZRRrLZSi2U */
    const uint8_t data[] = "Hello World!";

    if (base58_encode(data, 12, output, output_len) < 0) {
        printf("    Encode failed\n");
        return -1;
    }

    if (strcmp(output, "2NEpo7TZRRrLZSi2U") != 0) {
        printf("    Expected: 2NEpo7TZRRrLZSi2U\n");
        printf("    Got:      %s\n", output);
        return -1;
    }

    return 0;
}

static int test_base58_decode(void)
{
    uint8_t output[100];
    size_t output_len = sizeof(output);

    /* 2NEpo7TZRRrLZSi2U -> "Hello World!" */
    if (base58_decode("2NEpo7TZRRrLZSi2U", output, &output_len) != 0) {
        printf("    Decode failed\n");
        return -1;
    }

    if (output_len != 12 || memcmp(output, "Hello World!", 12) != 0) {
        printf("    Decoded data mismatch\n");
        return -1;
    }

    return 0;
}

static int test_base58_leading_zeros(void)
{
    char output[100];
    size_t output_len = sizeof(output);

    /* Leading zeros become '1' characters */
    const uint8_t data[] = {0x00, 0x00, 0x00, 0x61, 0x62, 0x63}; /* 3 zeros + "abc" */

    if (base58_encode(data, 6, output, output_len) < 0) {
        printf("    Encode failed\n");
        return -1;
    }

    /* Should start with "111" (three 1s for three leading zeros) */
    if (strncmp(output, "111", 3) != 0) {
        printf("    Expected leading '111', got: %s\n", output);
        return -1;
    }

    return 0;
}

static int test_base58check_encode(void)
{
    char output[100];

    /* Bitcoin mainnet P2PKH address for all-zero pubkey hash */
    uint8_t data[21] = {0};  /* version 0x00 + 20 bytes of zeros */

    if (base58check_encode(data, 21, output, sizeof(output)) < 0) {
        printf("    Encode failed\n");
        return -1;
    }

    /* Expected: 1111111111111111111114oLvT2 */
    if (strcmp(output, "1111111111111111111114oLvT2") != 0) {
        printf("    Expected: 1111111111111111111114oLvT2\n");
        printf("    Got:      %s\n", output);
        return -1;
    }

    return 0;
}

static int test_base58check_decode(void)
{
    uint8_t output[100];
    size_t output_len = sizeof(output);

    if (base58check_decode("1111111111111111111114oLvT2", output, &output_len) != 0) {
        printf("    Decode failed\n");
        return -1;
    }

    if (output_len != 21) {
        printf("    Expected 21 bytes, got %zu\n", output_len);
        return -1;
    }

    /* First 21 bytes should be zeros */
    for (size_t i = 0; i < 21; i++) {
        if (output[i] != 0) {
            printf("    Expected zero at position %zu, got 0x%02x\n", i, output[i]);
            return -1;
        }
    }

    return 0;
}

static int test_base58check_invalid(void)
{
    uint8_t output[100];
    size_t output_len = sizeof(output);

    /* Corrupted checksum (last char changed) */
    if (base58check_decode("1111111111111111111114oLvT3", output, &output_len) == 0) {
        printf("    Should have failed on invalid checksum\n");
        return -1;
    }

    return 0;
}

static int test_roundtrip(void)
{
    /* Random data */
    const uint8_t original[] = {
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a
    };

    char encoded[100];
    uint8_t decoded[100];
    size_t decoded_len = sizeof(decoded);

    if (base58_encode(original, sizeof(original), encoded, sizeof(encoded)) < 0) {
        printf("    Encode failed\n");
        return -1;
    }

    if (base58_decode(encoded, decoded, &decoded_len) != 0) {
        printf("    Decode failed\n");
        return -1;
    }

    if (decoded_len != sizeof(original) || memcmp(decoded, original, sizeof(original)) != 0) {
        printf("    Roundtrip mismatch\n");
        return -1;
    }

    return 0;
}

int test_base58(void)
{
    int failures = 0;

    test_report("Base58 encode", test_base58_encode());
    test_report("Base58 decode", test_base58_decode());
    test_report("Leading zeros handling", test_base58_leading_zeros());
    test_report("Base58Check encode", test_base58check_encode());
    test_report("Base58Check decode", test_base58check_decode());
    test_report("Base58Check invalid checksum", test_base58check_invalid());
    test_report("Roundtrip", test_roundtrip());

    return failures;
}

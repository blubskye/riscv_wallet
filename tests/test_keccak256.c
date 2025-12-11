/*
 * Keccak-256 Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/crypto/keccak256.h"

extern void test_report(const char *name, int result);

/* Test vectors for Keccak-256 (Ethereum variant, NOT NIST SHA3-256) */

/* Empty string */
static const uint8_t expected_empty[32] = {
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
};

/* "abc" */
static const uint8_t expected_abc[32] = {
    0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f,
    0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8, 0xd6, 0x67,
    0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36,
    0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45
};

/* Testing message - computed from our implementation */
static const uint8_t expected_testing[32] = {
    0x5f, 0x16, 0xf4, 0xc7, 0xf1, 0x49, 0xac, 0x4f,
    0x95, 0x10, 0xd9, 0xcf, 0x8c, 0xf3, 0x84, 0x03,
    0x8a, 0xd3, 0x48, 0xb3, 0xbc, 0xdc, 0x01, 0x91,
    0x5f, 0x95, 0xde, 0x12, 0xdf, 0x9d, 0x1b, 0x02
};

static int test_empty_string(void)
{
    uint8_t digest[KECCAK256_DIGEST_LENGTH];

    keccak256((const uint8_t *)"", 0, digest);

    if (memcmp(digest, expected_empty, 32) != 0) {
        printf("    Hash mismatch for empty string\n");
        printf("    Expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected_empty[i]);
        printf("\n    Got:      ");
        for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
        printf("\n");
        return -1;
    }

    return 0;
}

static int test_abc(void)
{
    uint8_t digest[KECCAK256_DIGEST_LENGTH];

    keccak256((const uint8_t *)"abc", 3, digest);

    if (memcmp(digest, expected_abc, 32) != 0) {
        printf("    Hash mismatch for 'abc'\n");
        printf("    Expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected_abc[i]);
        printf("\n    Got:      ");
        for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
        printf("\n");
        return -1;
    }

    return 0;
}

static int test_testing(void)
{
    uint8_t digest[KECCAK256_DIGEST_LENGTH];

    keccak256((const uint8_t *)"testing", 7, digest);

    if (memcmp(digest, expected_testing, 32) != 0) {
        printf("    Hash mismatch for 'testing'\n");
        printf("    Expected: ");
        for (int i = 0; i < 32; i++) printf("%02x", expected_testing[i]);
        printf("\n    Got:      ");
        for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
        printf("\n");
        return -1;
    }

    return 0;
}

static int test_long_message(void)
{
    /* 1 million 'a' characters */
    /* Keccak-256 hash should be:
     * fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96 */
    static const uint8_t expected[32] = {
        0xfa, 0xda, 0xe6, 0xb4, 0x9f, 0x12, 0x9b, 0xbb,
        0x81, 0x2b, 0xe8, 0x40, 0x7b, 0x7b, 0x28, 0x94,
        0xf3, 0x4a, 0xec, 0xf6, 0xdb, 0xd1, 0xf9, 0xb0,
        0xf0, 0xc7, 0xe9, 0x85, 0x30, 0x98, 0xfc, 0x96
    };

    uint8_t *data = malloc(1000000);
    if (!data) {
        printf("    Memory allocation failed\n");
        return -1;
    }

    memset(data, 'a', 1000000);

    uint8_t digest[KECCAK256_DIGEST_LENGTH];
    keccak256(data, 1000000, digest);
    free(data);

    if (memcmp(digest, expected, 32) != 0) {
        printf("    Hash mismatch for 1M 'a' characters\n");
        return -1;
    }

    return 0;
}

int test_keccak256(void)
{
    int failures = 0;

    test_report("Empty string", test_empty_string());
    test_report("'abc'", test_abc());
    test_report("'testing'", test_testing());
    test_report("1M 'a' characters", test_long_message());

    return failures;
}

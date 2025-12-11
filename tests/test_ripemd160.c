/*
 * RIPEMD-160 Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/crypto/ripemd160.h"

extern void test_report(const char *name, int result);

/* Test vectors from RIPEMD-160 specification */

/* Empty string */
static const uint8_t expected_empty[20] = {
    0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
    0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31
};

/* "a" */
static const uint8_t expected_a[20] = {
    0x0b, 0xdc, 0x9d, 0x2d, 0x25, 0x6b, 0x3e, 0xe9, 0xda, 0xae,
    0x34, 0x7b, 0xe6, 0xf4, 0xdc, 0x83, 0x5a, 0x46, 0x7f, 0xfe
};

/* "abc" */
static const uint8_t expected_abc[20] = {
    0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04,
    0x4a, 0x8e, 0x98, 0xc6, 0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc
};

/* "message digest" */
static const uint8_t expected_md[20] = {
    0x5d, 0x06, 0x89, 0xef, 0x49, 0xd2, 0xfa, 0xe5, 0x72, 0xb8,
    0x81, 0xb1, 0x23, 0xa8, 0x5f, 0xfa, 0x21, 0x59, 0x5f, 0x36
};

/* "abcdefghijklmnopqrstuvwxyz" */
static const uint8_t expected_alpha[20] = {
    0xf7, 0x1c, 0x27, 0x10, 0x9c, 0x69, 0x2c, 0x1b, 0x56, 0xbb,
    0xdc, 0xeb, 0x5b, 0x9d, 0x28, 0x65, 0xb3, 0x70, 0x8d, 0xbc
};

static int test_empty_string(void)
{
    uint8_t digest[RIPEMD160_DIGEST_LENGTH];

    ripemd160((const uint8_t *)"", 0, digest);

    if (memcmp(digest, expected_empty, 20) != 0) {
        printf("    Hash mismatch for empty string\n");
        return -1;
    }

    return 0;
}

static int test_single_char(void)
{
    uint8_t digest[RIPEMD160_DIGEST_LENGTH];

    ripemd160((const uint8_t *)"a", 1, digest);

    if (memcmp(digest, expected_a, 20) != 0) {
        printf("    Hash mismatch for 'a'\n");
        return -1;
    }

    return 0;
}

static int test_abc(void)
{
    uint8_t digest[RIPEMD160_DIGEST_LENGTH];

    ripemd160((const uint8_t *)"abc", 3, digest);

    if (memcmp(digest, expected_abc, 20) != 0) {
        printf("    Hash mismatch for 'abc'\n");
        return -1;
    }

    return 0;
}

static int test_message_digest(void)
{
    uint8_t digest[RIPEMD160_DIGEST_LENGTH];

    ripemd160((const uint8_t *)"message digest", 14, digest);

    if (memcmp(digest, expected_md, 20) != 0) {
        printf("    Hash mismatch for 'message digest'\n");
        return -1;
    }

    return 0;
}

static int test_alphabet(void)
{
    uint8_t digest[RIPEMD160_DIGEST_LENGTH];

    ripemd160((const uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26, digest);

    if (memcmp(digest, expected_alpha, 20) != 0) {
        printf("    Hash mismatch for alphabet\n");
        return -1;
    }

    return 0;
}

static int test_hash160(void)
{
    /* Test HASH160 (RIPEMD160(SHA256(x))) */
    /* This is used in Bitcoin for address generation */
    uint8_t digest[RIPEMD160_DIGEST_LENGTH];

    /* Hash of empty string through HASH160 */
    /* SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    /* RIPEMD160(above) = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb */
    static const uint8_t expected[20] = {
        0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 0x37, 0x06,
        0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f, 0x7c, 0x3b, 0x9f, 0xcb
    };

    hash160((const uint8_t *)"", 0, digest);

    if (memcmp(digest, expected, 20) != 0) {
        printf("    HASH160 mismatch for empty string\n");
        return -1;
    }

    return 0;
}

int test_ripemd160(void)
{
    int failures = 0;

    test_report("Empty string", test_empty_string());
    test_report("Single char 'a'", test_single_char());
    test_report("'abc'", test_abc());
    test_report("'message digest'", test_message_digest());
    test_report("Alphabet", test_alphabet());
    test_report("HASH160", test_hash160());

    return failures;
}

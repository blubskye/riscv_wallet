/*
 * SLIP-39 Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/crypto/slip39.h"

/* External test report function */
extern void test_report(const char *name, int result);

/* Test secret (16 bytes for 128-bit) */
static const uint8_t test_secret_128[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

/* Test secret (32 bytes for 256-bit) */
static const uint8_t test_secret_256[32] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
};

static int test_slip39_wordlist(void)
{
    /* Test word lookup */
    const char *word = slip39_word_at(0);
    if (word == NULL || strcmp(word, "academic") != 0) {
        printf("    First word should be 'academic', got '%s'\n", word ? word : "NULL");
        return -1;
    }

    /* Test reverse lookup */
    int idx = slip39_word_index("academic");
    if (idx != 0) {
        printf("    'academic' should be at index 0, got %d\n", idx);
        return -1;
    }

    /* Test invalid word */
    idx = slip39_word_index("invalidword12345");
    if (idx != -1) {
        printf("    Invalid word should return -1, got %d\n", idx);
        return -1;
    }

    /* Test out of bounds */
    word = slip39_word_at(1024);
    if (word != NULL) {
        printf("    Index 1024 should return NULL\n");
        return -1;
    }

    return 0;
}

static int test_slip39_generate_2of3(void)
{
    char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN];
    size_t share_lens[SLIP39_MAX_SHARES];
    slip39_error_t err;

    /* Generate 2-of-3 shares from 128-bit secret */
    err = slip39_generate_shares(test_secret_128, sizeof(test_secret_128),
                                  NULL, 2, 3, shares, share_lens);
    if (err != SLIP39_OK) {
        printf("    Share generation failed with error %d\n", err);
        return -1;
    }

    /* Verify we got 3 shares */
    for (int i = 0; i < 3; i++) {
        if (share_lens[i] == 0) {
            printf("    Share %d has zero length\n", i);
            return -1;
        }

        /* Validate each share */
        err = slip39_validate_share(shares[i], NULL);
        if (err != SLIP39_OK) {
            printf("    Share %d validation failed: %d\n", i, err);
            return -1;
        }
    }

    slip39_wipe_shares(shares, 3);
    return 0;
}

static int test_slip39_recover_2of3(void)
{
    char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN];
    size_t share_lens[SLIP39_MAX_SHARES];
    uint8_t recovered[32];
    size_t recovered_len = sizeof(recovered);
    slip39_error_t err;

    /* Generate 2-of-3 shares */
    err = slip39_generate_shares(test_secret_128, sizeof(test_secret_128),
                                  NULL, 2, 3, shares, share_lens);
    if (err != SLIP39_OK) {
        printf("    Share generation failed\n");
        return -1;
    }

    /* Recover using shares 0 and 1 */
    const char *recovery_shares[2] = { shares[0], shares[1] };
    err = slip39_recover_secret(recovery_shares, 2, NULL, recovered, &recovered_len);
    if (err != SLIP39_OK) {
        printf("    Recovery from shares 0,1 failed: %d\n", err);
        return -1;
    }

    if (recovered_len != sizeof(test_secret_128)) {
        printf("    Recovered length mismatch: %zu vs %zu\n",
               recovered_len, sizeof(test_secret_128));
        return -1;
    }

    if (memcmp(recovered, test_secret_128, sizeof(test_secret_128)) != 0) {
        printf("    Recovered secret doesn't match original\n");
        return -1;
    }

    /* Recover using shares 1 and 2 */
    const char *recovery_shares2[2] = { shares[1], shares[2] };
    recovered_len = sizeof(recovered);
    err = slip39_recover_secret(recovery_shares2, 2, NULL, recovered, &recovered_len);
    if (err != SLIP39_OK) {
        printf("    Recovery from shares 1,2 failed: %d\n", err);
        return -1;
    }

    if (memcmp(recovered, test_secret_128, sizeof(test_secret_128)) != 0) {
        printf("    Recovered secret from 1,2 doesn't match\n");
        return -1;
    }

    /* Recover using shares 0 and 2 */
    const char *recovery_shares3[2] = { shares[0], shares[2] };
    recovered_len = sizeof(recovered);
    err = slip39_recover_secret(recovery_shares3, 2, NULL, recovered, &recovered_len);
    if (err != SLIP39_OK) {
        printf("    Recovery from shares 0,2 failed: %d\n", err);
        return -1;
    }

    if (memcmp(recovered, test_secret_128, sizeof(test_secret_128)) != 0) {
        printf("    Recovered secret from 0,2 doesn't match\n");
        return -1;
    }

    slip39_wipe_shares(shares, 3);
    return 0;
}

static int test_slip39_256bit_secret(void)
{
    char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN];
    size_t share_lens[SLIP39_MAX_SHARES];
    uint8_t recovered[32];
    size_t recovered_len = sizeof(recovered);
    slip39_error_t err;

    /* Generate 3-of-5 shares from 256-bit secret */
    err = slip39_generate_shares(test_secret_256, sizeof(test_secret_256),
                                  NULL, 3, 5, shares, share_lens);
    if (err != SLIP39_OK) {
        printf("    256-bit share generation failed: %d\n", err);
        return -1;
    }

    /* Recover using 3 shares */
    const char *recovery_shares[3] = { shares[0], shares[2], shares[4] };
    err = slip39_recover_secret(recovery_shares, 3, NULL, recovered, &recovered_len);
    if (err != SLIP39_OK) {
        printf("    256-bit recovery failed: %d\n", err);
        return -1;
    }

    if (recovered_len != sizeof(test_secret_256)) {
        printf("    256-bit recovered length mismatch\n");
        return -1;
    }

    if (memcmp(recovered, test_secret_256, sizeof(test_secret_256)) != 0) {
        printf("    256-bit recovered secret doesn't match\n");
        return -1;
    }

    slip39_wipe_shares(shares, 5);
    return 0;
}

static int test_slip39_insufficient_shares(void)
{
    char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN];
    size_t share_lens[SLIP39_MAX_SHARES];
    uint8_t recovered[32];
    size_t recovered_len = sizeof(recovered);
    slip39_error_t err;

    /* Generate 3-of-5 shares */
    err = slip39_generate_shares(test_secret_128, sizeof(test_secret_128),
                                  NULL, 3, 5, shares, share_lens);
    if (err != SLIP39_OK) {
        return -1;
    }

    /* Try to recover with only 2 shares (should fail) */
    const char *recovery_shares[2] = { shares[0], shares[1] };
    err = slip39_recover_secret(recovery_shares, 2, NULL, recovered, &recovered_len);
    if (err != SLIP39_ERR_INSUFFICIENT_SHARES) {
        printf("    Should fail with insufficient shares, got %d\n", err);
        return -1;
    }

    slip39_wipe_shares(shares, 5);
    return 0;
}

static int test_slip39_duplicate_shares(void)
{
    char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN];
    size_t share_lens[SLIP39_MAX_SHARES];
    uint8_t recovered[32];
    size_t recovered_len = sizeof(recovered);
    slip39_error_t err;

    /* Generate 2-of-3 shares */
    err = slip39_generate_shares(test_secret_128, sizeof(test_secret_128),
                                  NULL, 2, 3, shares, share_lens);
    if (err != SLIP39_OK) {
        return -1;
    }

    /* Try to recover with duplicate share (should fail) */
    const char *recovery_shares[2] = { shares[0], shares[0] };
    err = slip39_recover_secret(recovery_shares, 2, NULL, recovered, &recovered_len);
    if (err != SLIP39_ERR_DUPLICATE_SHARE) {
        printf("    Should fail with duplicate share, got %d\n", err);
        return -1;
    }

    slip39_wipe_shares(shares, 3);
    return 0;
}

static int test_slip39_share_info(void)
{
    char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN];
    size_t share_lens[SLIP39_MAX_SHARES];
    uint16_t identifier;
    uint8_t threshold;
    slip39_error_t err;

    /* Generate 3-of-5 shares */
    err = slip39_generate_shares(test_secret_128, sizeof(test_secret_128),
                                  NULL, 3, 5, shares, share_lens);
    if (err != SLIP39_OK) {
        return -1;
    }

    /* Get info from first share */
    err = slip39_get_share_info(shares[0], &identifier, &threshold, NULL);
    if (err != SLIP39_OK) {
        printf("    Failed to get share info: %d\n", err);
        return -1;
    }

    if (threshold != 3) {
        printf("    Expected threshold 3, got %d\n", threshold);
        return -1;
    }

    /* Verify all shares have same identifier */
    for (int i = 1; i < 5; i++) {
        uint16_t id2;
        err = slip39_get_share_info(shares[i], &id2, NULL, NULL);
        if (err != SLIP39_OK || id2 != identifier) {
            printf("    Share %d has different identifier\n", i);
            return -1;
        }
    }

    slip39_wipe_shares(shares, 5);
    return 0;
}

static int test_slip39_invalid_params(void)
{
    char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN];
    size_t share_lens[SLIP39_MAX_SHARES];
    slip39_error_t err;

    /* Invalid secret size */
    uint8_t bad_secret[15] = {0};
    err = slip39_generate_shares(bad_secret, sizeof(bad_secret),
                                  NULL, 2, 3, shares, share_lens);
    if (err != SLIP39_ERR_SECRET_SIZE) {
        printf("    Should reject invalid secret size\n");
        return -1;
    }

    /* Threshold > share_count */
    err = slip39_generate_shares(test_secret_128, sizeof(test_secret_128),
                                  NULL, 5, 3, shares, share_lens);
    if (err != SLIP39_ERR_THRESHOLD) {
        printf("    Should reject threshold > count\n");
        return -1;
    }

    /* Threshold < 2 */
    err = slip39_generate_shares(test_secret_128, sizeof(test_secret_128),
                                  NULL, 1, 3, shares, share_lens);
    if (err != SLIP39_ERR_THRESHOLD) {
        printf("    Should reject threshold < 2\n");
        return -1;
    }

    /* Share count > max */
    err = slip39_generate_shares(test_secret_128, sizeof(test_secret_128),
                                  NULL, 2, 20, shares, share_lens);
    if (err != SLIP39_ERR_SHARE_COUNT) {
        printf("    Should reject share count > max\n");
        return -1;
    }

    return 0;
}

int test_slip39(void)
{
    test_report("Wordlist lookup", test_slip39_wordlist());
    test_report("Generate 2-of-3 shares", test_slip39_generate_2of3());
    test_report("Recover from 2-of-3", test_slip39_recover_2of3());
    test_report("256-bit secret", test_slip39_256bit_secret());
    test_report("Insufficient shares", test_slip39_insufficient_shares());
    test_report("Duplicate shares", test_slip39_duplicate_shares());
    test_report("Share info extraction", test_slip39_share_info());
    test_report("Invalid parameters", test_slip39_invalid_params());

    return 0;
}

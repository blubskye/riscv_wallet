/*
 * BIP-39 Mnemonic Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/crypto/bip39.h"

extern void test_report(const char *name, int result);

/* Test vector from BIP-39 specification */
static const char *test_mnemonic_12 =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

/* Expected seed for above mnemonic with empty passphrase */
static const uint8_t expected_seed[64] = {
    0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
    0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
    0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
    0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
    0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
    0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
    0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
    0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4
};

static int test_mnemonic_validation(void)
{
    /* Valid mnemonic should pass */
    if (bip39_validate_mnemonic(test_mnemonic_12) != 0) {
        printf("    Valid mnemonic rejected\n");
        return -1;
    }

    /* Invalid mnemonic (wrong word) should fail */
    const char *invalid = "abandon abandon abandon abandon abandon abandon "
                          "abandon abandon abandon abandon abandon notaword";
    if (bip39_validate_mnemonic(invalid) == 0) {
        printf("    Invalid word accepted\n");
        return -1;
    }

    /* Invalid mnemonic (wrong checksum) should fail */
    const char *bad_checksum = "abandon abandon abandon abandon abandon abandon "
                               "abandon abandon abandon abandon abandon abandon";
    if (bip39_validate_mnemonic(bad_checksum) == 0) {
        printf("    Bad checksum accepted\n");
        return -1;
    }

    return 0;
}

static int test_mnemonic_to_seed(void)
{
    uint8_t seed[64];

    if (bip39_mnemonic_to_seed(test_mnemonic_12, "", seed) != 0) {
        printf("    Mnemonic to seed failed\n");
        return -1;
    }

    if (memcmp(seed, expected_seed, 64) != 0) {
        printf("    Seed mismatch!\n");
        printf("    Expected: ");
        for (int i = 0; i < 16; i++) printf("%02x", expected_seed[i]);
        printf("...\n");
        printf("    Got:      ");
        for (int i = 0; i < 16; i++) printf("%02x", seed[i]);
        printf("...\n");
        return -1;
    }

    return 0;
}

static int test_mnemonic_generation(void)
{
    char mnemonic[256];

    /* Generate 12-word mnemonic */
    if (bip39_generate_mnemonic(mnemonic, sizeof(mnemonic), 12) != 0) {
        printf("    Mnemonic generation failed\n");
        return -1;
    }

    /* Verify it's valid */
    if (bip39_validate_mnemonic(mnemonic) != 0) {
        printf("    Generated mnemonic failed validation: %s\n", mnemonic);
        return -1;
    }

    /* Count words (should be 12) */
    int word_count = 1;
    for (const char *p = mnemonic; *p; p++) {
        if (*p == ' ') word_count++;
    }
    if (word_count != 12) {
        printf("    Expected 12 words, got %d\n", word_count);
        return -1;
    }

    return 0;
}

static int test_wordlist_lookup(void)
{
    /* Test word lookup */
    const char *word = bip39_get_word(0);
    if (word == NULL || strcmp(word, "abandon") != 0) {
        printf("    Expected 'abandon' at index 0, got '%s'\n", word ? word : "NULL");
        return -1;
    }

    word = bip39_get_word(2047);
    if (word == NULL || strcmp(word, "zoo") != 0) {
        printf("    Expected 'zoo' at index 2047, got '%s'\n", word ? word : "NULL");
        return -1;
    }

    /* Test reverse lookup */
    int idx = bip39_find_word("abandon");
    if (idx != 0) {
        printf("    Expected index 0 for 'abandon', got %d\n", idx);
        return -1;
    }

    idx = bip39_find_word("zoo");
    if (idx != 2047) {
        printf("    Expected index 2047 for 'zoo', got %d\n", idx);
        return -1;
    }

    idx = bip39_find_word("notaword");
    if (idx != -1) {
        printf("    Expected -1 for invalid word, got %d\n", idx);
        return -1;
    }

    return 0;
}

static int test_24_word_mnemonic(void)
{
    char mnemonic[512];

    /* Generate 24-word mnemonic */
    if (bip39_generate_mnemonic(mnemonic, sizeof(mnemonic), 24) != 0) {
        printf("    24-word mnemonic generation failed\n");
        return -1;
    }

    /* Verify it's valid */
    if (bip39_validate_mnemonic(mnemonic) != 0) {
        printf("    Generated 24-word mnemonic failed validation\n");
        return -1;
    }

    /* Count words (should be 24) */
    int word_count = 1;
    for (const char *p = mnemonic; *p; p++) {
        if (*p == ' ') word_count++;
    }
    if (word_count != 24) {
        printf("    Expected 24 words, got %d\n", word_count);
        return -1;
    }

    return 0;
}

int test_bip39(void)
{
    int failures = 0;

    test_report("Mnemonic validation", test_mnemonic_validation());
    test_report("Mnemonic to seed", test_mnemonic_to_seed());
    test_report("Mnemonic generation (12 words)", test_mnemonic_generation());
    test_report("Wordlist lookup", test_wordlist_lookup());
    test_report("24-word mnemonic generation", test_24_word_mnemonic());

    return failures;
}

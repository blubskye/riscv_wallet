/*
 * BIP-32 Key Derivation Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/crypto/bip32.h"
#include "../src/crypto/bip39.h"

extern void test_report(const char *name, int result);

/* Test vector from BIP-32 specification */
/* Seed: 000102030405060708090a0b0c0d0e0f (padded to 64 bytes) */
static uint8_t test_seed[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static int test_master_key_generation(void)
{
    bip32_key_t master;

    if (bip32_master_key_from_seed(test_seed, &master) != 0) {
        printf("    Master key generation failed\n");
        return -1;
    }

    /* Verify depth is 0 */
    if (master.depth != 0) {
        printf("    Expected depth 0, got %u\n", master.depth);
        return -1;
    }

    /* Verify child index is 0 */
    if (master.child_index != 0) {
        printf("    Expected child index 0, got %u\n", master.child_index);
        return -1;
    }

    /* Verify parent fingerprint is zeros */
    for (int i = 0; i < 4; i++) {
        if (master.parent_fingerprint[i] != 0) {
            printf("    Expected zero parent fingerprint\n");
            return -1;
        }
    }

    return 0;
}

static int test_child_derivation(void)
{
    bip32_key_t master, child;

    if (bip32_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    /* Derive m/0' (hardened) */
    if (bip32_derive_child(&master, &child, BIP32_HARDENED_BIT) != 0) {
        printf("    Child derivation failed\n");
        return -1;
    }

    /* Verify depth */
    if (child.depth != 1) {
        printf("    Expected depth 1, got %u\n", child.depth);
        return -1;
    }

    /* Verify child index */
    if (child.child_index != BIP32_HARDENED_BIT) {
        printf("    Expected child index 0x80000000, got 0x%08x\n", child.child_index);
        return -1;
    }

    return 0;
}

static int test_path_derivation(void)
{
    bip32_key_t master, derived;

    if (bip32_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    /* Derive BIP-44 Bitcoin path: m/44'/0'/0'/0/0 */
    if (bip32_derive_path(&master, "m/44'/0'/0'/0/0", &derived) != 0) {
        printf("    Path derivation failed\n");
        return -1;
    }

    /* Verify depth */
    if (derived.depth != 5) {
        printf("    Expected depth 5, got %u\n", derived.depth);
        return -1;
    }

    return 0;
}

static int test_public_key_derivation(void)
{
    bip32_key_t master, child;

    if (bip32_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    /* Derive a non-hardened child */
    if (bip32_derive_child(&master, &child, 0) != 0) {
        return -1;
    }

    /* Verify public key starts with 0x02 or 0x03 (compressed) */
    if (child.public_key[0] != 0x02 && child.public_key[0] != 0x03) {
        printf("    Invalid public key prefix: 0x%02x\n", child.public_key[0]);
        return -1;
    }

    return 0;
}

static int test_extended_key_serialization(void)
{
    bip32_key_t master;
    char xprv[120];
    char xpub[120];

    if (bip32_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    /* Serialize extended private key */
    if (bip32_serialize_private(&master, xprv, sizeof(xprv), 1) != 0) {
        printf("    Failed to serialize xprv\n");
        return -1;
    }

    /* Should start with "xprv" for mainnet */
    if (strncmp(xprv, "xprv", 4) != 0) {
        printf("    Expected xprv prefix, got: %.4s\n", xprv);
        return -1;
    }

    /* Serialize extended public key */
    if (bip32_serialize_public(&master, xpub, sizeof(xpub), 1) != 0) {
        printf("    Failed to serialize xpub\n");
        return -1;
    }

    /* Should start with "xpub" for mainnet */
    if (strncmp(xpub, "xpub", 4) != 0) {
        printf("    Expected xpub prefix, got: %.4s\n", xpub);
        return -1;
    }

    return 0;
}

static int test_hardened_vs_normal(void)
{
    bip32_key_t master, hardened, normal;

    if (bip32_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    /* Derive hardened child m/0' */
    if (bip32_derive_child(&master, &hardened, BIP32_HARDENED_BIT) != 0) {
        printf("    Hardened derivation failed\n");
        return -1;
    }

    /* Derive normal child m/0 */
    if (bip32_derive_child(&master, &normal, 0) != 0) {
        printf("    Normal derivation failed\n");
        return -1;
    }

    /* Keys should be different */
    if (memcmp(hardened.private_key, normal.private_key, BIP32_KEY_SIZE) == 0) {
        printf("    Hardened and normal keys should differ\n");
        return -1;
    }

    return 0;
}

int test_bip32(void)
{
    int failures = 0;

    test_report("Master key generation", test_master_key_generation());
    test_report("Child derivation", test_child_derivation());
    test_report("Path derivation", test_path_derivation());
    test_report("Public key derivation", test_public_key_derivation());
    test_report("Extended key serialization", test_extended_key_serialization());
    test_report("Hardened vs normal derivation", test_hardened_vs_normal());

    return failures;
}

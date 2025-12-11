/*
 * Solana Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/chains/solana.h"
#include "../src/util/hex.h"

/* External test report function */
extern void test_report(const char *name, int result);

/* Test seed (example BIP-39 seed) */
static const uint8_t test_seed[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

static int test_sol_derive_keypair(void)
{
    sol_keypair_t keypair;

    /* Derive keypair for account 0, change 0 */
    if (sol_derive_keypair(test_seed, 0, 0, &keypair) != 0) {
        printf("    Keypair derivation failed\n");
        return -1;
    }

    /* Public key should be 32 bytes and non-zero */
    int all_zero = 1;
    for (int i = 0; i < SOL_PUBKEY_SIZE; i++) {
        if (keypair.public_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        printf("    Public key is all zeros\n");
        return -1;
    }

    /* Derive different account - should give different key */
    sol_keypair_t keypair2;
    if (sol_derive_keypair(test_seed, 1, 0, &keypair2) != 0) {
        printf("    Second keypair derivation failed\n");
        return -1;
    }

    if (memcmp(keypair.public_key, keypair2.public_key, SOL_PUBKEY_SIZE) == 0) {
        printf("    Different accounts produced same public key\n");
        return -1;
    }

    sol_keypair_wipe(&keypair);
    sol_keypair_wipe(&keypair2);
    return 0;
}

static int test_sol_pubkey_to_address(void)
{
    sol_keypair_t keypair;
    char address[SOL_ADDR_MAX];

    if (sol_derive_keypair(test_seed, 0, 0, &keypair) != 0) {
        return -1;
    }

    if (sol_pubkey_to_address(keypair.public_key, address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* Solana addresses are 32-44 characters */
    size_t len = strlen(address);
    if (len < 32 || len > 44) {
        printf("    Invalid address length: %zu (%s)\n", len, address);
        return -1;
    }

    /* Should only contain base58 characters */
    const char *base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for (size_t i = 0; i < len; i++) {
        if (strchr(base58_chars, address[i]) == NULL) {
            printf("    Invalid character in address: %c\n", address[i]);
            return -1;
        }
    }

    sol_keypair_wipe(&keypair);
    return 0;
}

static int test_sol_validate_address(void)
{
    sol_keypair_t keypair;
    char address[SOL_ADDR_MAX];

    /* Generate valid address */
    if (sol_derive_keypair(test_seed, 0, 0, &keypair) != 0) {
        return -1;
    }

    if (sol_pubkey_to_address(keypair.public_key, address, sizeof(address)) != 0) {
        return -1;
    }

    /* Should validate */
    if (sol_validate_address(address) != 0) {
        printf("    Valid address failed validation: %s\n", address);
        return -1;
    }

    /* Invalid: too short */
    if (sol_validate_address("abc") == 0) {
        printf("    Short address passed validation\n");
        return -1;
    }

    /* Invalid: contains invalid characters */
    if (sol_validate_address("0OIl123456789012345678901234567890123") == 0) {
        printf("    Address with invalid chars passed validation\n");
        return -1;
    }

    sol_keypair_wipe(&keypair);
    return 0;
}

static int test_sol_address_roundtrip(void)
{
    sol_keypair_t keypair;
    char address[SOL_ADDR_MAX];
    uint8_t recovered[SOL_PUBKEY_SIZE];

    if (sol_derive_keypair(test_seed, 0, 0, &keypair) != 0) {
        return -1;
    }

    if (sol_pubkey_to_address(keypair.public_key, address, sizeof(address)) != 0) {
        return -1;
    }

    if (sol_address_to_pubkey(address, recovered) != 0) {
        printf("    Address decode failed\n");
        return -1;
    }

    if (memcmp(keypair.public_key, recovered, SOL_PUBKEY_SIZE) != 0) {
        printf("    Pubkey roundtrip mismatch\n");
        return -1;
    }

    sol_keypair_wipe(&keypair);
    return 0;
}

static int test_sol_sign_verify(void)
{
    sol_keypair_t keypair;
    uint8_t message[] = "Hello, Solana!";
    uint8_t signature[SOL_SIGNATURE_SIZE];

    if (sol_derive_keypair(test_seed, 0, 0, &keypair) != 0) {
        return -1;
    }

    /* Sign message */
    if (sol_sign_message(&keypair, message, sizeof(message) - 1, signature) != 0) {
        printf("    Signing failed\n");
        return -1;
    }

    /* Verify signature */
    if (sol_verify_signature(keypair.public_key, message, sizeof(message) - 1,
                             signature) != 0) {
        printf("    Verification failed\n");
        return -1;
    }

    /* Modify message - verification should fail */
    message[0] = 'h';
    if (sol_verify_signature(keypair.public_key, message, sizeof(message) - 1,
                             signature) == 0) {
        printf("    Modified message passed verification\n");
        return -1;
    }

    sol_keypair_wipe(&keypair);
    return 0;
}

static int test_sol_amount_formatting(void)
{
    char output[32];

    /* 1 SOL */
    if (sol_format_amount(1000000000ULL, output, sizeof(output)) != 0) {
        return -1;
    }
    if (strcmp(output, "1.000000000 SOL") != 0) {
        printf("    Expected '1.000000000 SOL', got '%s'\n", output);
        return -1;
    }

    /* 0.001 SOL */
    if (sol_format_amount(1000000ULL, output, sizeof(output)) != 0) {
        return -1;
    }
    if (strcmp(output, "0.001000000 SOL") != 0) {
        printf("    Expected '0.001000000 SOL', got '%s'\n", output);
        return -1;
    }

    /* 123.456789012 SOL */
    if (sol_format_amount(123456789012ULL, output, sizeof(output)) != 0) {
        return -1;
    }

    return 0;
}

static int test_sol_derivation_path(void)
{
    char path[64];

    /* First account */
    if (sol_get_derivation_path(0, 0, path, sizeof(path)) != 0) {
        return -1;
    }
    if (strcmp(path, "m/44'/501'/0'/0'") != 0) {
        printf("    Expected 'm/44'/501'/0'/0'', got '%s'\n", path);
        return -1;
    }

    /* Second account */
    if (sol_get_derivation_path(1, 0, path, sizeof(path)) != 0) {
        return -1;
    }
    if (strcmp(path, "m/44'/501'/1'/0'") != 0) {
        printf("    Expected 'm/44'/501'/1'/0'', got '%s'\n", path);
        return -1;
    }

    return 0;
}

static int test_sol_transfer_instruction(void)
{
    sol_keypair_t keypair;
    sol_instruction_t instr;
    uint8_t to_pubkey[SOL_PUBKEY_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    if (sol_derive_keypair(test_seed, 0, 0, &keypair) != 0) {
        return -1;
    }

    /* Create transfer instruction for 1 SOL */
    if (sol_transfer_instruction(keypair.public_key, to_pubkey,
                                  1000000000ULL, &instr) != 0) {
        printf("    Transfer instruction creation failed\n");
        return -1;
    }

    /* Verify instruction structure */
    if (instr.account_count != 2) {
        printf("    Expected 2 accounts, got %zu\n", instr.account_count);
        return -1;
    }

    if (!instr.accounts[0].is_signer) {
        printf("    Sender should be signer\n");
        return -1;
    }

    if (instr.accounts[1].is_signer) {
        printf("    Recipient should not be signer\n");
        return -1;
    }

    if (instr.data_len != 12) {
        printf("    Expected 12 bytes instruction data, got %zu\n", instr.data_len);
        return -1;
    }

    /* Verify instruction type (2 = Transfer) */
    if (instr.data[0] != 2) {
        printf("    Expected transfer instruction (2), got %d\n", instr.data[0]);
        return -1;
    }

    sol_keypair_wipe(&keypair);
    return 0;
}

int test_solana(void)
{
    test_report("Keypair derivation", test_sol_derive_keypair());
    test_report("Public key to address", test_sol_pubkey_to_address());
    test_report("Address validation", test_sol_validate_address());
    test_report("Address roundtrip", test_sol_address_roundtrip());
    test_report("Sign and verify", test_sol_sign_verify());
    test_report("Amount formatting", test_sol_amount_formatting());
    test_report("Derivation path", test_sol_derivation_path());
    test_report("Transfer instruction", test_sol_transfer_instruction());

    return 0;
}

/*
 * Cardano (ADA) Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/chains/cardano.h"
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

static int test_ada_master_key(void)
{
    ada_extended_key_t master;

    if (ada_master_key_from_seed(test_seed, &master) != 0) {
        printf("    Master key derivation failed\n");
        return -1;
    }

    /* Check public key is not all zeros */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (master.public_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        printf("    Public key is all zeros\n");
        return -1;
    }

    ada_key_wipe(&master);
    return 0;
}

static int test_ada_derive_account(void)
{
    ada_extended_key_t master, account0, account1;

    if (ada_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    /* Derive account 0 */
    if (ada_derive_account(&master, 0, &account0) != 0) {
        printf("    Account 0 derivation failed\n");
        return -1;
    }

    /* Derive account 1 */
    if (ada_derive_account(&master, 1, &account1) != 0) {
        printf("    Account 1 derivation failed\n");
        return -1;
    }

    /* Different accounts should give different keys */
    if (memcmp(account0.public_key, account1.public_key, 32) == 0) {
        printf("    Different accounts produced same public key\n");
        return -1;
    }

    ada_key_wipe(&master);
    ada_key_wipe(&account0);
    ada_key_wipe(&account1);
    return 0;
}

static int test_ada_derive_address_key(void)
{
    ada_extended_key_t master, account, payment_key, stake_key;

    if (ada_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    if (ada_derive_account(&master, 0, &account) != 0) {
        return -1;
    }

    /* Derive payment key (role 0, index 0) */
    if (ada_derive_address_key(&account, ADA_ROLE_EXTERNAL, 0, &payment_key) != 0) {
        printf("    Payment key derivation failed\n");
        return -1;
    }

    /* Derive staking key (role 2, index 0) */
    if (ada_derive_address_key(&account, ADA_ROLE_STAKING, 0, &stake_key) != 0) {
        printf("    Staking key derivation failed\n");
        return -1;
    }

    /* Payment and staking keys should be different */
    if (memcmp(payment_key.public_key, stake_key.public_key, 32) == 0) {
        printf("    Payment and staking keys are the same\n");
        return -1;
    }

    ada_key_wipe(&master);
    ada_key_wipe(&account);
    ada_key_wipe(&payment_key);
    ada_key_wipe(&stake_key);
    return 0;
}

static int test_ada_base_address(void)
{
    ada_extended_key_t master, account, payment_key, stake_key;
    char address[ADA_ADDR_BECH32_MAX];

    if (ada_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    if (ada_derive_account(&master, 0, &account) != 0) {
        return -1;
    }

    if (ada_derive_address_key(&account, ADA_ROLE_EXTERNAL, 0, &payment_key) != 0) {
        return -1;
    }

    if (ada_derive_address_key(&account, ADA_ROLE_STAKING, 0, &stake_key) != 0) {
        return -1;
    }

    /* Create base address (mainnet) */
    if (ada_create_base_address(payment_key.public_key, stake_key.public_key,
                                ADA_MAINNET, address, sizeof(address)) != 0) {
        printf("    Base address creation failed\n");
        return -1;
    }

    /* Should start with "addr1" (mainnet base address) */
    if (strncmp(address, "addr1", 5) != 0) {
        printf("    Expected 'addr1' prefix, got '%.*s'\n", 5, address);
        return -1;
    }

    /* Test testnet address */
    if (ada_create_base_address(payment_key.public_key, stake_key.public_key,
                                ADA_TESTNET, address, sizeof(address)) != 0) {
        printf("    Testnet address creation failed\n");
        return -1;
    }

    /* Testnet should start with "addr_test1" */
    if (strncmp(address, "addr_test1", 10) != 0) {
        printf("    Expected 'addr_test1' prefix, got '%.*s'\n", 10, address);
        return -1;
    }

    ada_key_wipe(&master);
    ada_key_wipe(&account);
    ada_key_wipe(&payment_key);
    ada_key_wipe(&stake_key);
    return 0;
}

static int test_ada_enterprise_address(void)
{
    ada_extended_key_t master, account, payment_key;
    char address[ADA_ADDR_BECH32_MAX];

    if (ada_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    if (ada_derive_account(&master, 0, &account) != 0) {
        return -1;
    }

    if (ada_derive_address_key(&account, ADA_ROLE_EXTERNAL, 0, &payment_key) != 0) {
        return -1;
    }

    /* Create enterprise address (no staking) */
    if (ada_create_enterprise_address(payment_key.public_key, ADA_MAINNET,
                                      address, sizeof(address)) != 0) {
        printf("    Enterprise address creation failed\n");
        return -1;
    }

    /* Should start with "addr1" */
    if (strncmp(address, "addr1", 5) != 0) {
        printf("    Expected 'addr1' prefix, got '%.*s'\n", 5, address);
        return -1;
    }

    ada_key_wipe(&master);
    ada_key_wipe(&account);
    ada_key_wipe(&payment_key);
    return 0;
}

static int test_ada_reward_address(void)
{
    ada_extended_key_t master, account, stake_key;
    char address[ADA_ADDR_BECH32_MAX];

    if (ada_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    if (ada_derive_account(&master, 0, &account) != 0) {
        return -1;
    }

    if (ada_derive_address_key(&account, ADA_ROLE_STAKING, 0, &stake_key) != 0) {
        return -1;
    }

    /* Create reward/stake address */
    if (ada_create_reward_address(stake_key.public_key, ADA_MAINNET,
                                  address, sizeof(address)) != 0) {
        printf("    Reward address creation failed\n");
        return -1;
    }

    /* Should start with "stake1" */
    if (strncmp(address, "stake1", 6) != 0) {
        printf("    Expected 'stake1' prefix, got '%.*s'\n", 6, address);
        return -1;
    }

    ada_key_wipe(&master);
    ada_key_wipe(&account);
    ada_key_wipe(&stake_key);
    return 0;
}

static int test_ada_validate_address(void)
{
    ada_extended_key_t master, account, payment_key, stake_key;
    char address[ADA_ADDR_BECH32_MAX];

    if (ada_master_key_from_seed(test_seed, &master) != 0) {
        return -1;
    }

    if (ada_derive_account(&master, 0, &account) != 0) {
        return -1;
    }

    if (ada_derive_address_key(&account, ADA_ROLE_EXTERNAL, 0, &payment_key) != 0) {
        return -1;
    }

    if (ada_derive_address_key(&account, ADA_ROLE_STAKING, 0, &stake_key) != 0) {
        return -1;
    }

    if (ada_create_base_address(payment_key.public_key, stake_key.public_key,
                                ADA_MAINNET, address, sizeof(address)) != 0) {
        return -1;
    }

    /* Valid address should pass */
    if (ada_validate_address(address) != 1) {
        printf("    Valid address failed validation: %s\n", address);
        return -1;
    }

    /* Invalid addresses should fail */
    if (ada_validate_address("invalid") != 0) {
        printf("    Invalid address passed validation\n");
        return -1;
    }

    if (ada_validate_address("") != 0) {
        printf("    Empty address passed validation\n");
        return -1;
    }

    ada_key_wipe(&master);
    ada_key_wipe(&account);
    ada_key_wipe(&payment_key);
    ada_key_wipe(&stake_key);
    return 0;
}

static int test_ada_amount_formatting(void)
{
    char output[32];

    /* 1 ADA = 1,000,000 lovelace */
    if (ada_format_amount(1000000ULL, output, sizeof(output)) != 0) {
        return -1;
    }
    if (strcmp(output, "1.000000 ADA") != 0) {
        printf("    Expected '1.000000 ADA', got '%s'\n", output);
        return -1;
    }

    /* 0.5 ADA */
    if (ada_format_amount(500000ULL, output, sizeof(output)) != 0) {
        return -1;
    }
    if (strcmp(output, "0.500000 ADA") != 0) {
        printf("    Expected '0.500000 ADA', got '%s'\n", output);
        return -1;
    }

    /* 1234.567890 ADA */
    if (ada_format_amount(1234567890ULL, output, sizeof(output)) != 0) {
        return -1;
    }
    if (strcmp(output, "1234.567890 ADA") != 0) {
        printf("    Expected '1234.567890 ADA', got '%s'\n", output);
        return -1;
    }

    return 0;
}

static int test_ada_derivation_path(void)
{
    char path[64];

    /* First account, external address 0 */
    if (ada_get_derivation_path(0, ADA_ROLE_EXTERNAL, 0, path, sizeof(path)) != 0) {
        return -1;
    }
    if (strcmp(path, "m/1852'/1815'/0'/0/0") != 0) {
        printf("    Expected 'm/1852'/1815'/0'/0/0', got '%s'\n", path);
        return -1;
    }

    /* Second account, staking */
    if (ada_get_derivation_path(1, ADA_ROLE_STAKING, 0, path, sizeof(path)) != 0) {
        return -1;
    }
    if (strcmp(path, "m/1852'/1815'/1'/2/0") != 0) {
        printf("    Expected 'm/1852'/1815'/1'/2/0', got '%s'\n", path);
        return -1;
    }

    return 0;
}

static int test_ada_network_name(void)
{
    if (strcmp(ada_network_name(ADA_MAINNET), "Cardano Mainnet") != 0) {
        printf("    Expected 'Cardano Mainnet', got '%s'\n", ada_network_name(ADA_MAINNET));
        return -1;
    }

    if (strcmp(ada_network_name(ADA_TESTNET), "Cardano Testnet") != 0) {
        printf("    Expected 'Cardano Testnet', got '%s'\n", ada_network_name(ADA_TESTNET));
        return -1;
    }

    return 0;
}

static int test_ada_hash_pubkey(void)
{
    uint8_t pubkey[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    uint8_t hash[28];

    if (ada_hash_pubkey(pubkey, hash) != 0) {
        printf("    Public key hashing failed\n");
        return -1;
    }

    /* Verify hash is not all zeros */
    int all_zero = 1;
    for (int i = 0; i < 28; i++) {
        if (hash[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        printf("    Hash is all zeros\n");
        return -1;
    }

    /* Hash same key should give same result */
    uint8_t hash2[28];
    if (ada_hash_pubkey(pubkey, hash2) != 0) {
        return -1;
    }
    if (memcmp(hash, hash2, 28) != 0) {
        printf("    Same key produced different hashes\n");
        return -1;
    }

    return 0;
}

int test_cardano(void)
{
    test_report("Master key derivation", test_ada_master_key());
    test_report("Account derivation", test_ada_derive_account());
    test_report("Address key derivation", test_ada_derive_address_key());
    test_report("Base address generation", test_ada_base_address());
    test_report("Enterprise address", test_ada_enterprise_address());
    test_report("Reward address", test_ada_reward_address());
    test_report("Address validation", test_ada_validate_address());
    test_report("Amount formatting", test_ada_amount_formatting());
    test_report("Derivation path", test_ada_derivation_path());
    test_report("Network name", test_ada_network_name());
    test_report("Public key hashing", test_ada_hash_pubkey());

    return 0;
}

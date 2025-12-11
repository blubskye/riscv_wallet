/*
 * Litecoin Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/chains/litecoin.h"
#include "../src/util/hex.h"

/* External test report function */
extern void test_report(const char *name, int result);

/* Test public key (example compressed secp256k1 pubkey) */
static const uint8_t test_pubkey[33] = {
    0x02,
    0x5b, 0xc9, 0x96, 0x4c, 0x51, 0x93, 0x4b, 0xcd,
    0x3c, 0x00, 0x0b, 0x13, 0x48, 0xb5, 0x25, 0x2f,
    0x83, 0x8a, 0x00, 0xa7, 0x41, 0x4f, 0x2e, 0xce,
    0x99, 0xce, 0x54, 0x4e, 0x23, 0x6c, 0x87, 0x1c
};

static int test_ltc_p2pkh_mainnet(void)
{
    char address[LTC_ADDR_LEGACY_MAX];

    if (ltc_pubkey_to_address(test_pubkey, LTC_ADDR_P2PKH, LTC_MAINNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* Litecoin P2PKH mainnet starts with L or M */
    if (address[0] != 'L' && address[0] != 'M') {
        printf("    Expected L/M prefix, got: %c (%s)\n", address[0], address);
        return -1;
    }

    /* Validate the generated address */
    if (ltc_validate_address(address, NULL) != 0) {
        printf("    Generated address failed validation: %s\n", address);
        return -1;
    }

    return 0;
}

static int test_ltc_p2pkh_testnet(void)
{
    char address[LTC_ADDR_LEGACY_MAX];

    if (ltc_pubkey_to_address(test_pubkey, LTC_ADDR_P2PKH, LTC_TESTNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* Litecoin P2PKH testnet starts with m or n */
    if (address[0] != 'm' && address[0] != 'n') {
        printf("    Expected m/n prefix, got: %c (%s)\n", address[0], address);
        return -1;
    }

    return 0;
}

static int test_ltc_p2wpkh_mainnet(void)
{
    char address[LTC_ADDR_BECH32_MAX];

    if (ltc_pubkey_to_address(test_pubkey, LTC_ADDR_P2WPKH, LTC_MAINNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* Litecoin native SegWit starts with ltc1q */
    if (strncmp(address, "ltc1q", 5) != 0) {
        printf("    Expected ltc1q prefix, got: %.5s (%s)\n", address, address);
        return -1;
    }

    /* Validate the generated address */
    if (ltc_validate_address(address, NULL) != 0) {
        printf("    Generated address failed validation: %s\n", address);
        return -1;
    }

    return 0;
}

static int test_ltc_p2wpkh_testnet(void)
{
    char address[LTC_ADDR_BECH32_MAX];

    if (ltc_pubkey_to_address(test_pubkey, LTC_ADDR_P2WPKH, LTC_TESTNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* Litecoin testnet SegWit starts with tltc1q */
    if (strncmp(address, "tltc1q", 6) != 0) {
        printf("    Expected tltc1q prefix, got: %.6s (%s)\n", address, address);
        return -1;
    }

    return 0;
}

static int test_ltc_validate_address(void)
{
    ltc_network_t mainnet = LTC_MAINNET;

    /* Valid mainnet legacy address (example) */
    /* Note: This is a placeholder - real test should use known valid address */
    char addr1[48];
    if (ltc_pubkey_to_address(test_pubkey, LTC_ADDR_P2PKH, LTC_MAINNET,
                               addr1, sizeof(addr1)) == 0) {
        if (ltc_validate_address(addr1, &mainnet) != 0) {
            printf("    Valid mainnet P2PKH failed validation\n");
            return -1;
        }
    }

    /* Valid mainnet SegWit address */
    char addr2[48];
    if (ltc_pubkey_to_address(test_pubkey, LTC_ADDR_P2WPKH, LTC_MAINNET,
                               addr2, sizeof(addr2)) == 0) {
        if (ltc_validate_address(addr2, &mainnet) != 0) {
            printf("    Valid mainnet P2WPKH failed validation\n");
            return -1;
        }
    }

    /* Invalid address (wrong checksum) - should fail */
    if (ltc_validate_address("LTC1invalidaddress", NULL) == 0) {
        printf("    Invalid address passed validation\n");
        return -1;
    }

    /* Network mismatch test */
    char testnet_addr[48];
    if (ltc_pubkey_to_address(test_pubkey, LTC_ADDR_P2PKH, LTC_TESTNET,
                               testnet_addr, sizeof(testnet_addr)) == 0) {
        if (ltc_validate_address(testnet_addr, &mainnet) == 0) {
            printf("    Testnet address passed mainnet validation\n");
            return -1;
        }
    }

    return 0;
}

static int test_ltc_amount_formatting(void)
{
    char output[32];

    /* 1 LTC */
    if (ltc_format_amount(100000000ULL, output, sizeof(output)) != 0) {
        return -1;
    }
    if (strcmp(output, "1.00000000 LTC") != 0) {
        printf("    Expected '1.00000000 LTC', got '%s'\n", output);
        return -1;
    }

    /* 0.001 LTC */
    if (ltc_format_amount(100000ULL, output, sizeof(output)) != 0) {
        return -1;
    }
    if (strcmp(output, "0.00100000 LTC") != 0) {
        printf("    Expected '0.00100000 LTC', got '%s'\n", output);
        return -1;
    }

    /* 21000000 LTC (hypothetical max) */
    if (ltc_format_amount(2100000000000000ULL, output, sizeof(output)) != 0) {
        return -1;
    }

    return 0;
}

static int test_ltc_derivation_path(void)
{
    char path[64];

    /* First receiving address */
    if (ltc_get_derivation_path(0, 0, 0, path, sizeof(path)) != 0) {
        return -1;
    }
    if (strcmp(path, "m/84'/2'/0'/0/0") != 0) {
        printf("    Expected 'm/84'/2'/0'/0/0', got '%s'\n", path);
        return -1;
    }

    /* Second account, first change address */
    if (ltc_get_derivation_path(1, 1, 0, path, sizeof(path)) != 0) {
        return -1;
    }
    if (strcmp(path, "m/84'/2'/1'/1/0") != 0) {
        printf("    Expected 'm/84'/2'/1'/1/0', got '%s'\n", path);
        return -1;
    }

    return 0;
}

static int test_ltc_script_to_address(void)
{
    char address[LTC_ADDR_BECH32_MAX];

    /* P2WPKH script: OP_0 <20-byte hash> */
    uint8_t p2wpkh_script[22] = {
        0x00, 0x14,  /* OP_0, PUSH 20 */
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
        0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
        0xf1, 0x43, 0x3b, 0xd6
    };

    if (ltc_script_to_address(p2wpkh_script, sizeof(p2wpkh_script),
                               LTC_MAINNET, address, sizeof(address)) != 0) {
        printf("    P2WPKH script decode failed\n");
        return -1;
    }

    /* Should produce ltc1q address */
    if (strncmp(address, "ltc1q", 5) != 0) {
        printf("    Expected ltc1q prefix, got: %.5s\n", address);
        return -1;
    }

    /* P2PKH script test */
    uint8_t p2pkh_script[25] = {
        0x76, 0xa9, 0x14,  /* OP_DUP, OP_HASH160, PUSH 20 */
        0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba,
        0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba,
        0xab, 0xba, 0xab, 0xba,
        0x88, 0xac  /* OP_EQUALVERIFY, OP_CHECKSIG */
    };

    if (ltc_script_to_address(p2pkh_script, sizeof(p2pkh_script),
                               LTC_MAINNET, address, sizeof(address)) != 0) {
        printf("    P2PKH script decode failed\n");
        return -1;
    }

    /* Should produce L/M address */
    if (address[0] != 'L' && address[0] != 'M') {
        printf("    Expected L/M prefix, got: %c\n", address[0]);
        return -1;
    }

    return 0;
}

int test_litecoin(void)
{
    test_report("P2PKH mainnet address", test_ltc_p2pkh_mainnet());
    test_report("P2PKH testnet address", test_ltc_p2pkh_testnet());
    test_report("P2WPKH mainnet address", test_ltc_p2wpkh_mainnet());
    test_report("P2WPKH testnet address", test_ltc_p2wpkh_testnet());
    test_report("Address validation", test_ltc_validate_address());
    test_report("Amount formatting", test_ltc_amount_formatting());
    test_report("Derivation path", test_ltc_derivation_path());
    test_report("Script to address decode", test_ltc_script_to_address());

    return 0;
}

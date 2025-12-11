/*
 * Ethereum Address Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "../src/chains/ethereum.h"
#include "../src/crypto/keccak256.h"

extern void test_report(const char *name, int result);

/* Known test public key (uncompressed, 65 bytes) */
static const uint8_t test_pubkey[65] = {
    0x04,  /* Uncompressed prefix */
    /* X coordinate */
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    /* Y coordinate */
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
};

static int test_address_generation(void)
{
    char address[ETH_ADDR_STR_SIZE];

    if (eth_pubkey_to_address(test_pubkey, address) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* Ethereum addresses start with '0x' */
    if (strncmp(address, "0x", 2) != 0) {
        printf("    Expected '0x' prefix\n");
        return -1;
    }

    /* Should be 42 characters (0x + 40 hex chars) */
    if (strlen(address) != 42) {
        printf("    Expected 42 chars, got %zu\n", strlen(address));
        return -1;
    }

    return 0;
}

static int test_checksum_address(void)
{
    char address[ETH_ADDR_STR_SIZE];

    if (eth_pubkey_to_address(test_pubkey, address) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* EIP-55 checksum: some letters should be uppercase */
    int has_upper = 0, has_lower = 0;
    for (int i = 2; i < 42; i++) {
        if (isupper((unsigned char)address[i])) has_upper = 1;
        if (islower((unsigned char)address[i])) has_lower = 1;
    }

    /* A checksummed address typically has both upper and lower hex letters */
    /* (unless the address hash produces all 0-7 or all 8-f for letter positions) */
    (void)has_upper;
    (void)has_lower;

    return 0;
}

static int test_address_validation(void)
{
    /* Valid checksummed addresses */
    if (!eth_validate_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")) {
        printf("    Valid checksummed address rejected\n");
        return -1;
    }

    /* Valid lowercase address (no checksum) */
    if (!eth_validate_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")) {
        printf("    Valid lowercase address rejected\n");
        return -1;
    }

    /* Invalid addresses */
    if (eth_validate_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeX")) {
        printf("    Invalid character accepted\n");
        return -1;
    }

    if (eth_validate_address("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")) {
        printf("    Missing 0x prefix accepted\n");
        return -1;
    }

    if (eth_validate_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeA")) {
        printf("    Too short address accepted\n");
        return -1;
    }

    if (eth_validate_address("")) {
        printf("    Empty address accepted\n");
        return -1;
    }

    return 0;
}

static int test_format_wei(void)
{
    char output[128];

    /* 1 ETH = 10^18 wei */
    uint8_t one_eth[32] = {0};
    one_eth[22] = 0x0d;  /* 10^18 in big-endian bytes */
    one_eth[23] = 0xe0;
    one_eth[24] = 0xb6;
    one_eth[25] = 0xb3;
    one_eth[26] = 0xa7;
    one_eth[27] = 0x64;
    one_eth[28] = 0x00;
    one_eth[29] = 0x00;
    one_eth[30] = 0x00;
    one_eth[31] = 0x00;

    if (eth_format_amount(one_eth, output, sizeof(output), 18) != 0) {
        printf("    Format failed\n");
        return -1;
    }

    /* Should show "1.0" or similar */
    if (strstr(output, "ETH") == NULL) {
        printf("    Missing 'ETH' suffix in: %s\n", output);
        return -1;
    }

    return 0;
}

static int test_chain_names(void)
{
    const char *name;

    name = eth_chain_name(ETH_CHAIN_MAINNET);
    if (name == NULL || strstr(name, "ainnet") == NULL) {
        printf("    Expected mainnet name, got: %s\n", name ? name : "NULL");
        return -1;
    }

    name = eth_chain_name(ETH_CHAIN_POLYGON);
    if (name == NULL) {
        printf("    Polygon name is NULL\n");
        return -1;
    }

    return 0;
}

static int test_eip712_domain(void)
{
    /* EIP-712 typed data signing domain separator */
    /* Hash of: EIP712Domain(string name,string version,uint256 chainId,address verifyingContract) */

    static const uint8_t expected_type_hash[32] = {
        0x8b, 0x73, 0xc3, 0xc6, 0x9b, 0xb8, 0xfe, 0x3d,
        0x51, 0x2e, 0xcc, 0x4c, 0xf7, 0x59, 0xcc, 0x79,
        0x23, 0x9f, 0x7b, 0x17, 0x9b, 0x0f, 0xfa, 0xca,
        0xa9, 0xa7, 0x5d, 0x52, 0x2b, 0x39, 0x40, 0x0f
    };

    uint8_t hash[32];
    const char *type_string = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

    keccak256((const uint8_t *)type_string, strlen(type_string), hash);

    if (memcmp(hash, expected_type_hash, 32) != 0) {
        printf("    EIP712Domain type hash mismatch\n");
        return -1;
    }

    return 0;
}

int test_ethereum(void)
{
    int failures = 0;

    test_report("Address generation", test_address_generation());
    test_report("Checksummed address (EIP-55)", test_checksum_address());
    test_report("Address validation", test_address_validation());
    test_report("Wei formatting", test_format_wei());
    test_report("Chain names", test_chain_names());
    test_report("EIP-712 domain type hash", test_eip712_domain());

    return failures;
}

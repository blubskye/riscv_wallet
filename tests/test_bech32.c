/*
 * Bech32/Bech32m Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/util/bech32.h"

extern void test_report(const char *name, int result);

/* Test vectors from BIP-173 and BIP-350 */

static int test_bech32_encode(void)
{
    char output[100];
    uint8_t data[] = {0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22};

    int len = bech32_encode("bc", data, sizeof(data), output, sizeof(output), BECH32_ENCODING_BECH32);

    if (len < 0) {
        printf("    Encoding failed\n");
        return -1;
    }

    /* Expected: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 */
    if (strcmp(output, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") != 0) {
        printf("    Expected: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\n");
        printf("    Got:      %s\n", output);
        return -1;
    }

    return 0;
}

static int test_bech32_decode(void)
{
    const char *input = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    char hrp[10];
    uint8_t data[100];
    size_t data_len = sizeof(data);
    bech32_encoding_t encoding;

    if (bech32_decode(input, hrp, sizeof(hrp), data, &data_len, &encoding) != 0) {
        printf("    Decoding failed\n");
        return -1;
    }

    if (strcmp(hrp, "bc") != 0) {
        printf("    Expected HRP 'bc', got '%s'\n", hrp);
        return -1;
    }

    if (encoding != BECH32_ENCODING_BECH32) {
        printf("    Expected BECH32 encoding\n");
        return -1;
    }

    return 0;
}

static int test_bech32m_encode(void)
{
    /* BIP-350 test vector for witness version 1 (taproot) */
    char output[100];

    /* Witness program (32 bytes) converted to 5-bit */
    uint8_t witness_prog[32] = {
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
    };

    if (bech32_encode_segwit("bc", 1, witness_prog, 32, output, sizeof(output)) < 0) {
        printf("    Encoding failed\n");
        return -1;
    }

    /* Should produce a bech32m address starting with bc1p */
    if (strncmp(output, "bc1p", 4) != 0) {
        printf("    Expected bc1p prefix, got: %.4s\n", output);
        return -1;
    }

    return 0;
}

static int test_segwit_encode_decode(void)
{
    /* P2WPKH address encoding/decoding */
    uint8_t pubkey_hash[20] = {
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
        0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
        0xf1, 0x43, 0x3b, 0xd6
    };

    char address[100];

    /* Encode */
    if (bech32_encode_segwit("bc", 0, pubkey_hash, 20, address, sizeof(address)) < 0) {
        printf("    Encode failed\n");
        return -1;
    }

    /* Should start with bc1q (witness v0) */
    if (strncmp(address, "bc1q", 4) != 0) {
        printf("    Expected bc1q prefix\n");
        return -1;
    }

    /* Decode back */
    int witness_version;
    uint8_t decoded[40];
    size_t decoded_len = sizeof(decoded);

    if (bech32_decode_segwit(address, NULL, 0, &witness_version, decoded, &decoded_len) != 0) {
        printf("    Decode failed\n");
        return -1;
    }

    if (witness_version != 0) {
        printf("    Expected witness version 0, got %d\n", witness_version);
        return -1;
    }

    if (decoded_len != 20) {
        printf("    Expected 20 bytes, got %zu\n", decoded_len);
        return -1;
    }

    if (memcmp(decoded, pubkey_hash, 20) != 0) {
        printf("    Decoded data mismatch\n");
        return -1;
    }

    return 0;
}

static int test_invalid_checksum(void)
{
    /* Intentionally corrupted address */
    const char *invalid = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"; /* last char changed */
    char hrp[10];
    uint8_t data[100];
    size_t data_len = sizeof(data);
    bech32_encoding_t encoding;

    /* Should fail to decode */
    if (bech32_decode(invalid, hrp, sizeof(hrp), data, &data_len, &encoding) == 0) {
        printf("    Should have failed on invalid checksum\n");
        return -1;
    }

    return 0;
}

static int test_testnet_address(void)
{
    uint8_t pubkey_hash[20] = {0};
    char address[100];

    /* Testnet address */
    if (bech32_encode_segwit("tb", 0, pubkey_hash, 20, address, sizeof(address)) < 0) {
        printf("    Encode failed\n");
        return -1;
    }

    /* Should start with tb1q */
    if (strncmp(address, "tb1q", 4) != 0) {
        printf("    Expected tb1q prefix, got: %.4s\n", address);
        return -1;
    }

    return 0;
}

int test_bech32(void)
{
    int failures = 0;

    test_report("Bech32 encode", test_bech32_encode());
    test_report("Bech32 decode", test_bech32_decode());
    test_report("Bech32m encode (taproot)", test_bech32m_encode());
    test_report("SegWit encode/decode roundtrip", test_segwit_encode_decode());
    test_report("Invalid checksum detection", test_invalid_checksum());
    test_report("Testnet address", test_testnet_address());

    return failures;
}

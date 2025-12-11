/*
 * Bitcoin Address and PSBT Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/chains/bitcoin.h"
#include "../src/crypto/bip32.h"
#include "../src/crypto/bip39.h"
#include "../src/util/base64.h"
#include "../src/crypto/ripemd160.h"

extern void test_report(const char *name, int result);

/* Known test vector compressed public key */
static const uint8_t test_pubkey[33] = {
    0x02,  /* Compressed prefix */
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
};

static int test_p2pkh_mainnet(void)
{
    char address[64];

    if (btc_pubkey_to_address(test_pubkey, BTC_ADDR_P2PKH, BTC_MAINNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* P2PKH addresses start with '1' on mainnet */
    if (address[0] != '1') {
        printf("    Expected '1' prefix, got '%c'\n", address[0]);
        return -1;
    }

    /* Validate the address */
    if (!btc_validate_address(address, BTC_MAINNET)) {
        printf("    Generated address failed validation\n");
        return -1;
    }

    return 0;
}

static int test_p2pkh_testnet(void)
{
    char address[64];

    if (btc_pubkey_to_address(test_pubkey, BTC_ADDR_P2PKH, BTC_TESTNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* P2PKH addresses start with 'm' or 'n' on testnet */
    if (address[0] != 'm' && address[0] != 'n') {
        printf("    Expected 'm' or 'n' prefix, got '%c'\n", address[0]);
        return -1;
    }

    return 0;
}

static int test_p2sh_mainnet(void)
{
    char address[64];

    if (btc_pubkey_to_address(test_pubkey, BTC_ADDR_P2SH, BTC_MAINNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* P2SH addresses start with '3' on mainnet */
    if (address[0] != '3') {
        printf("    Expected '3' prefix, got '%c'\n", address[0]);
        return -1;
    }

    return 0;
}

static int test_p2wpkh_mainnet(void)
{
    char address[100];

    if (btc_pubkey_to_address(test_pubkey, BTC_ADDR_P2WPKH, BTC_MAINNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* Native SegWit addresses start with 'bc1q' on mainnet */
    if (strncmp(address, "bc1q", 4) != 0) {
        printf("    Expected 'bc1q' prefix, got: %.4s\n", address);
        return -1;
    }

    return 0;
}

static int test_p2wpkh_testnet(void)
{
    char address[100];

    if (btc_pubkey_to_address(test_pubkey, BTC_ADDR_P2WPKH, BTC_TESTNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* Native SegWit addresses start with 'tb1q' on testnet */
    if (strncmp(address, "tb1q", 4) != 0) {
        printf("    Expected 'tb1q' prefix, got: %.4s\n", address);
        return -1;
    }

    return 0;
}

static int test_p2tr_mainnet(void)
{
    char address[100];

    if (btc_pubkey_to_address(test_pubkey, BTC_ADDR_P2TR, BTC_MAINNET,
                               address, sizeof(address)) != 0) {
        printf("    Address generation failed\n");
        return -1;
    }

    /* Taproot addresses start with 'bc1p' on mainnet */
    if (strncmp(address, "bc1p", 4) != 0) {
        printf("    Expected 'bc1p' prefix, got: %.4s\n", address);
        return -1;
    }

    return 0;
}

static int test_address_validation(void)
{
    /* Valid mainnet addresses */
    if (!btc_validate_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", BTC_MAINNET)) {
        printf("    Valid P2PKH address rejected\n");
        return -1;
    }

    if (!btc_validate_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", BTC_MAINNET)) {
        printf("    Valid P2SH address rejected\n");
        return -1;
    }

    if (!btc_validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", BTC_MAINNET)) {
        printf("    Valid bech32 address rejected\n");
        return -1;
    }

    /* Invalid addresses */
    if (btc_validate_address("invalid_address", BTC_MAINNET)) {
        printf("    Invalid address accepted\n");
        return -1;
    }

    if (btc_validate_address("", BTC_MAINNET)) {
        printf("    Empty address accepted\n");
        return -1;
    }

    return 0;
}

static int test_fee_calculation(void)
{
    btc_tx_t tx;
    memset(&tx, 0, sizeof(tx));

    /* Set up a simple transaction */
    tx.inputs[0].amount = 100000;  /* 0.001 BTC */
    tx.outputs[0].amount = 90000;  /* 0.0009 BTC */
    tx.input_count = 1;
    tx.output_count = 1;

    uint64_t fee = btc_calculate_fee(&tx);

    if (fee != 10000) {  /* 0.0001 BTC fee */
        printf("    Expected fee 10000, got %lu\n", (unsigned long)fee);
        return -1;
    }

    return 0;
}

static int test_format_amount(void)
{
    char output[32];

    /* 1 BTC */
    btc_format_amount(100000000, output, sizeof(output));
    if (strcmp(output, "1.00000000 BTC") != 0) {
        printf("    Expected '1.00000000 BTC', got '%s'\n", output);
        return -1;
    }

    /* 0.00000001 BTC (1 satoshi) */
    btc_format_amount(1, output, sizeof(output));
    if (strcmp(output, "0.00000001 BTC") != 0) {
        printf("    Expected '0.00000001 BTC', got '%s'\n", output);
        return -1;
    }

    /* 21 million BTC */
    btc_format_amount(2100000000000000ULL, output, sizeof(output));
    if (strcmp(output, "21000000.00000000 BTC") != 0) {
        printf("    Expected '21000000.00000000 BTC', got '%s'\n", output);
        return -1;
    }

    return 0;
}

/*
 * Minimal PSBT for testing: just magic + global unsigned tx
 * This is a hand-crafted minimal PSBT for testing the parser.
 *
 * Structure:
 * - Magic: "psbt\xff"
 * - Global key 0x00 (unsigned tx): compact_size + tx
 * - Separator 0x00
 * - Input map separator 0x00
 * - Output map separator 0x00
 */
static int test_psbt_parse(void)
{
    btc_tx_t tx;

    /*
     * Minimal PSBT:
     * 70736274ff    - magic "psbt\xff"
     * 01             - key length = 1
     * 00             - key type = PSBT_GLOBAL_UNSIGNED_TX
     * 3e             - value length = 62 bytes (unsigned tx)
     * [62-byte tx]   - version(4) + input_count(1) + input(41) + output_count(1) + output(12) + locktime(4)
     * 00             - global map separator
     * 00             - input map separator
     * 00             - output map separator
     *
     * Unsigned tx:
     * 02000000       - version 2
     * 01             - 1 input
     * <32 bytes>     - prev_txid (all zeros)
     * 00000000       - prev_index = 0
     * 00             - scriptSig length = 0
     * ffffffff       - sequence
     * 01             - 1 output
     * 1027000000000000 - amount = 10000 satoshis
     * 00             - scriptPubKey length = 0
     * 00000000       - locktime = 0
     */
    uint8_t minimal_psbt[] = {
        /* Magic */
        0x70, 0x73, 0x62, 0x74, 0xff,
        /* Global unsigned tx key */
        0x01, 0x00,
        /* Value length (62 bytes) */
        0x3e,
        /* Unsigned transaction */
        0x02, 0x00, 0x00, 0x00,  /* version = 2 */
        0x01,                    /* input count = 1 */
        /* prev_txid (32 zeros) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  /* prev_index = 0 */
        0x00,                    /* scriptSig length = 0 */
        0xff, 0xff, 0xff, 0xff,  /* sequence */
        0x01,                    /* output count = 1 */
        /* amount = 10000 satoshis (little-endian) */
        0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,                    /* scriptPubKey length = 0 */
        0x00, 0x00, 0x00, 0x00,  /* locktime = 0 */
        /* Global map separator */
        0x00,
        /* Input map separator */
        0x00,
        /* Output map separator */
        0x00
    };

    /* Parse PSBT */
    if (btc_parse_psbt(minimal_psbt, sizeof(minimal_psbt), &tx) != 0) {
        printf("    Failed to parse minimal PSBT\n");
        return -1;
    }

    /* Verify parsed values */
    if (tx.version != 2) {
        printf("    Expected version 2, got %u\n", tx.version);
        return -1;
    }

    if (tx.input_count != 1) {
        printf("    Expected 1 input, got %zu\n", tx.input_count);
        return -1;
    }

    if (tx.output_count != 1) {
        printf("    Expected 1 output, got %zu\n", tx.output_count);
        return -1;
    }

    /* Verify output amount */
    if (tx.outputs[0].amount != 10000) {
        printf("    Expected amount 10000, got %lu\n",
               (unsigned long)tx.outputs[0].amount);
        return -1;
    }

    return 0;
}

static int test_psbt_magic_validation(void)
{
    btc_tx_t tx;

    /* Invalid magic bytes */
    uint8_t bad_magic[] = {0x70, 0x73, 0x62, 0x74, 0x00};  /* "psbt" + 0x00 instead of 0xff */
    if (btc_parse_psbt(bad_magic, sizeof(bad_magic), &tx) == 0) {
        printf("    Invalid PSBT magic accepted\n");
        return -1;
    }

    /* Too short */
    uint8_t too_short[] = {0x70, 0x73, 0x62, 0x74};  /* Only "psbt" */
    if (btc_parse_psbt(too_short, sizeof(too_short), &tx) == 0) {
        printf("    Too-short PSBT accepted\n");
        return -1;
    }

    /* Empty input */
    if (btc_parse_psbt(NULL, 0, &tx) == 0) {
        printf("    NULL PSBT accepted\n");
        return -1;
    }

    return 0;
}

static int test_script_to_address(void)
{
    char address[BTC_ADDR_BECH32_MAX];
    int ret;

    /* P2WPKH script: OP_0 <20-byte hash> */
    uint8_t p2wpkh_script[22] = {
        0x00, 0x14,  /* OP_0, PUSH 20 */
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
        0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
        0xf1, 0x43, 0x3b, 0xd6
    };

    ret = btc_script_to_address(p2wpkh_script, sizeof(p2wpkh_script),
                                 BTC_MAINNET, address, sizeof(address));
    if (ret != 0) {
        printf("    P2WPKH script decode failed (ret=%d, script_len=%zu, buf_len=%zu)\n",
               ret, sizeof(p2wpkh_script), sizeof(address));
        printf("    Script: %02x %02x %02x...\n", p2wpkh_script[0], p2wpkh_script[1], p2wpkh_script[2]);
        return -1;
    }

    /* Should produce bc1q address */
    if (strncmp(address, "bc1q", 4) != 0) {
        printf("    Expected bc1q prefix, got: %.4s\n", address);
        return -1;
    }

    /* P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG */
    uint8_t p2pkh_script[25] = {
        0x76, 0xa9, 0x14,  /* OP_DUP, OP_HASH160, PUSH 20 */
        0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba,
        0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba,
        0xab, 0xba, 0xab, 0xba,
        0x88, 0xac  /* OP_EQUALVERIFY, OP_CHECKSIG */
    };

    if (btc_script_to_address(p2pkh_script, sizeof(p2pkh_script),
                               BTC_MAINNET, address, sizeof(address)) != 0) {
        printf("    P2PKH script decode failed\n");
        return -1;
    }

    /* Should produce 1... address */
    if (address[0] != '1') {
        printf("    Expected '1' prefix, got: %c\n", address[0]);
        return -1;
    }

    /* P2TR script: OP_1 <32-byte x-only pubkey> */
    uint8_t p2tr_script[34] = {
        0x51, 0x20,  /* OP_1, PUSH 32 */
        0xa6, 0x0b, 0x69, 0x6a, 0xd7, 0xbc, 0x15, 0xbe,
        0x69, 0xbd, 0xbc, 0x14, 0x18, 0x06, 0x28, 0xc1,
        0xe3, 0x42, 0x7d, 0x1c, 0x34, 0x5e, 0x47, 0xb5,
        0x56, 0xf9, 0xbc, 0x50, 0x9f, 0x7c, 0x4a, 0x8d
    };

    if (btc_script_to_address(p2tr_script, sizeof(p2tr_script),
                               BTC_MAINNET, address, sizeof(address)) != 0) {
        printf("    P2TR script decode failed\n");
        return -1;
    }

    /* Should produce bc1p address (Taproot) */
    if (strncmp(address, "bc1p", 4) != 0) {
        printf("    Expected bc1p prefix, got: %.4s\n", address);
        return -1;
    }

    return 0;
}

static int test_psbt_sign_flow(void)
{
    /*
     * Create a simple transaction structure and verify signing works.
     * We don't have a complete PSBT with matching keys in test vectors,
     * so we test the signing mechanics manually.
     */
    btc_tx_t tx;
    bip32_key_t key;
    uint8_t signed_tx[1024];
    size_t signed_tx_len;

    memset(&tx, 0, sizeof(tx));

    /* Create a simple P2WPKH transaction */
    tx.version = 2;
    tx.locktime = 0;
    tx.input_count = 1;
    tx.output_count = 1;

    /* Fake input with P2WPKH script */
    tx.inputs[0].amount = 100000;  /* 0.001 BTC */
    tx.inputs[0].prev_index = 0;
    /* P2WPKH script: OP_0 <20-byte-pubkey-hash> */
    tx.inputs[0].script_pubkey[0] = 0x00;
    tx.inputs[0].script_pubkey[1] = 0x14;
    tx.inputs[0].script_pubkey_len = 22;

    /* Output */
    tx.outputs[0].amount = 90000;  /* 0.0009 BTC - fee is 10000 */
    tx.outputs[0].script_pubkey[0] = 0x00;
    tx.outputs[0].script_pubkey[1] = 0x14;
    tx.outputs[0].script_pubkey_len = 22;

    /* Generate a test key */
    uint8_t seed[64];
    memset(seed, 0x42, sizeof(seed));  /* Deterministic seed for testing */
    if (bip32_master_key_from_seed(seed, &key) != 0) {
        printf("    Failed to generate test key\n");
        return -1;
    }

    /* Put the correct pubkey hash in the input script */
    uint8_t pubkey_hash[20];
    hash160(key.public_key, 33, pubkey_hash);
    memcpy(tx.inputs[0].script_pubkey + 2, pubkey_hash, 20);

    /* Sign */
    signed_tx_len = sizeof(signed_tx);
    if (btc_sign_tx(&tx, &key, 1, signed_tx, &signed_tx_len) != 0) {
        printf("    Failed to sign transaction\n");
        bip32_key_wipe(&key);
        return -1;
    }

    /* Verify we got a valid signed transaction */
    if (signed_tx_len < 100) {
        printf("    Signed tx too short: %zu bytes\n", signed_tx_len);
        bip32_key_wipe(&key);
        return -1;
    }

    /* Check for SegWit marker (0x00, 0x01 after version) */
    if (signed_tx[4] != 0x00 || signed_tx[5] != 0x01) {
        printf("    Missing SegWit marker in signed tx\n");
        bip32_key_wipe(&key);
        return -1;
    }

    bip32_key_wipe(&key);
    return 0;
}

int test_bitcoin(void)
{
    int failures = 0;

    test_report("P2PKH mainnet address", test_p2pkh_mainnet());
    test_report("P2PKH testnet address", test_p2pkh_testnet());
    test_report("P2SH mainnet address", test_p2sh_mainnet());
    test_report("P2WPKH mainnet address", test_p2wpkh_mainnet());
    test_report("P2WPKH testnet address", test_p2wpkh_testnet());
    test_report("P2TR mainnet address", test_p2tr_mainnet());
    test_report("Address validation", test_address_validation());
    test_report("Fee calculation", test_fee_calculation());
    test_report("Amount formatting", test_format_amount());
    test_report("PSBT parsing", test_psbt_parse());
    test_report("PSBT magic validation", test_psbt_magic_validation());
    test_report("PSBT sign flow", test_psbt_sign_flow());
    test_report("Script to address decode", test_script_to_address());

    return failures;
}

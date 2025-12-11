/*
 * Test Suite Main Entry
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "../src/crypto/secp256k1.h"

/* Test declarations */
int test_bip39(void);
int test_bip32(void);
int test_ripemd160(void);
int test_keccak256(void);
int test_bech32(void);
int test_rlp(void);
int test_base58(void);
int test_bitcoin(void);
int test_ethereum(void);
int test_litecoin(void);
int test_solana(void);
int test_slip39(void);
int test_monero(void);
int test_cardano(void);
int test_ratelimit(void);
int test_walletconnect(void);

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

void test_report(const char *name, int result)
{
    if (result == 0) {
        printf("  [PASS] %s\n", name);
        tests_passed++;
    } else {
        printf("  [FAIL] %s\n", name);
        tests_failed++;
    }
}

int main(void)
{
    int result = 0;

    printf("===========================================\n");
    printf("  RISC-V Wallet Test Suite\n");
    printf("===========================================\n\n");

    /* Initialize libsodium */
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    /* Initialize secp256k1 context */
    if (secp256k1_ctx_init() != 0) {
        fprintf(stderr, "Failed to initialize secp256k1\n");
        return 1;
    }

    printf("[BIP-39 Mnemonic Tests]\n");
    if (test_bip39() != 0) result = 1;
    printf("\n");

    printf("[BIP-32 Key Derivation Tests]\n");
    if (test_bip32() != 0) result = 1;
    printf("\n");

    printf("[RIPEMD-160 Tests]\n");
    if (test_ripemd160() != 0) result = 1;
    printf("\n");

    printf("[Keccak-256 Tests]\n");
    if (test_keccak256() != 0) result = 1;
    printf("\n");

    printf("[Bech32 Tests]\n");
    if (test_bech32() != 0) result = 1;
    printf("\n");

    printf("[RLP Tests]\n");
    if (test_rlp() != 0) result = 1;
    printf("\n");

    printf("[Base58 Tests]\n");
    if (test_base58() != 0) result = 1;
    printf("\n");

    printf("[Bitcoin Tests]\n");
    if (test_bitcoin() != 0) result = 1;
    printf("\n");

    printf("[Ethereum Tests]\n");
    if (test_ethereum() != 0) result = 1;
    printf("\n");

    printf("[Litecoin Tests]\n");
    if (test_litecoin() != 0) result = 1;
    printf("\n");

    printf("[Solana Tests]\n");
    if (test_solana() != 0) result = 1;
    printf("\n");

    printf("[SLIP-39 Tests]\n");
    if (test_slip39() != 0) result = 1;
    printf("\n");

    printf("[Monero Tests]\n");
    if (test_monero() != 0) result = 1;
    printf("\n");

    printf("[Cardano Tests]\n");
    if (test_cardano() != 0) result = 1;
    printf("\n");

    printf("[Rate Limiting Tests]\n");
    if (test_ratelimit() != 0) result = 1;
    printf("\n");

    printf("[WalletConnect Tests]\n");
    if (test_walletconnect() != 0) result = 1;
    printf("\n");

    printf("===========================================\n");
    printf("  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("===========================================\n");

    /* Cleanup */
    secp256k1_ctx_cleanup();

    return result;
}

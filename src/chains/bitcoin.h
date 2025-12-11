/*
 * Bitcoin Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/bip32.h"

/* Address sizes */
#define BTC_ADDR_LEGACY_MAX    35
#define BTC_ADDR_BECH32_MAX    90
#define BTC_TXID_SIZE          32

/* Transaction limits */
#define BTC_MAX_INPUTS         256
#define BTC_MAX_OUTPUTS        256

/* Network types */
typedef enum {
    BTC_MAINNET = 0,
    BTC_TESTNET
} btc_network_t;

/* Address types */
typedef enum {
    BTC_ADDR_P2PKH = 0,      /* Legacy (1...) */
    BTC_ADDR_P2SH,           /* Script hash (3...) */
    BTC_ADDR_P2WPKH,         /* Native SegWit (bc1q...) */
    BTC_ADDR_P2TR            /* Taproot (bc1p...) */
} btc_addr_type_t;

/* Transaction input */
typedef struct {
    uint8_t prev_txid[BTC_TXID_SIZE];
    uint32_t prev_index;
    uint64_t amount;
    uint8_t script_pubkey[64];
    size_t script_pubkey_len;
} btc_tx_input_t;

/* Transaction output */
typedef struct {
    uint64_t amount;
    uint8_t script_pubkey[64];
    size_t script_pubkey_len;
    char address[BTC_ADDR_BECH32_MAX];
} btc_tx_output_t;

/* Unsigned transaction */
typedef struct {
    uint32_t version;
    uint32_t locktime;
    btc_tx_input_t inputs[BTC_MAX_INPUTS];
    size_t input_count;
    btc_tx_output_t outputs[BTC_MAX_OUTPUTS];
    size_t output_count;
    btc_network_t network;
} btc_tx_t;

/**
 * Generate Bitcoin address from public key
 *
 * @param pubkey Compressed public key (33 bytes)
 * @param addr_type Address type
 * @param network Network (mainnet/testnet)
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int btc_pubkey_to_address(const uint8_t pubkey[33], btc_addr_type_t addr_type,
                          btc_network_t network, char *address, size_t address_len);

/**
 * Parse PSBT (Partially Signed Bitcoin Transaction)
 *
 * @param psbt_data PSBT binary data
 * @param psbt_len Length of PSBT data
 * @param tx Output transaction structure
 * @return 0 on success, -1 on error
 */
int btc_parse_psbt(const uint8_t *psbt_data, size_t psbt_len, btc_tx_t *tx);

/**
 * Sign Bitcoin transaction
 *
 * @param tx Transaction to sign
 * @param keys Array of private keys for signing
 * @param key_count Number of keys
 * @param signed_tx Output buffer for signed transaction
 * @param signed_tx_len Size of output buffer / bytes written
 * @return 0 on success, -1 on error
 */
int btc_sign_tx(btc_tx_t *tx, const bip32_key_t *keys, size_t key_count,
                uint8_t *signed_tx, size_t *signed_tx_len);

/**
 * Calculate transaction fee
 *
 * @param tx Transaction
 * @return Fee in satoshis
 */
uint64_t btc_calculate_fee(const btc_tx_t *tx);

/**
 * Validate Bitcoin address
 *
 * @param address Address string
 * @param network Expected network
 * @return 1 if valid, 0 if invalid
 */
int btc_validate_address(const char *address, btc_network_t network);

/**
 * Format satoshi amount as BTC string
 *
 * @param satoshis Amount in satoshis
 * @param output Output buffer
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int btc_format_amount(uint64_t satoshis, char *output, size_t output_len);

/**
 * Decode scriptPubKey to address
 *
 * Supports: P2PKH, P2SH, P2WPKH, P2WSH, P2TR
 *
 * @param script_pubkey Script bytes
 * @param script_len Script length
 * @param network Network (mainnet/testnet)
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 if script type not recognized
 */
int btc_script_to_address(const uint8_t *script_pubkey, size_t script_len,
                          btc_network_t network, char *address, size_t address_len);

#endif /* BITCOIN_H */

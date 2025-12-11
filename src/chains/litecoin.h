/*
 * Litecoin Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Litecoin is a Bitcoin fork with different network parameters:
 * - P2PKH prefix: 0x30 (L/M addresses)
 * - P2SH prefix: 0x32 or 0x05 (3/M addresses)
 * - Bech32 HRP: "ltc" (mainnet), "tltc" (testnet)
 * - BIP44 coin type: 2
 */

#ifndef LITECOIN_H
#define LITECOIN_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/bip32.h"

/* Address sizes */
#define LTC_ADDR_LEGACY_MAX    35
#define LTC_ADDR_BECH32_MAX    90
#define LTC_TXID_SIZE          32

/* Transaction limits */
#define LTC_MAX_INPUTS         256
#define LTC_MAX_OUTPUTS        256

/* BIP44 coin type */
#define LTC_COIN_TYPE          2

/* Network types */
typedef enum {
    LTC_MAINNET = 0,
    LTC_TESTNET
} ltc_network_t;

/* Address types */
typedef enum {
    LTC_ADDR_P2PKH = 0,      /* Legacy (L...) */
    LTC_ADDR_P2SH,           /* Script hash (M...) */
    LTC_ADDR_P2WPKH,         /* Native SegWit (ltc1q...) */
    LTC_ADDR_P2WSH           /* SegWit script hash (ltc1q...) */
} ltc_addr_type_t;

/* Transaction input */
typedef struct {
    uint8_t prev_txid[LTC_TXID_SIZE];
    uint32_t prev_index;
    uint64_t amount;
    uint8_t script_pubkey[64];
    size_t script_pubkey_len;
} ltc_tx_input_t;

/* Transaction output */
typedef struct {
    uint64_t amount;
    uint8_t script_pubkey[64];
    size_t script_pubkey_len;
    char address[LTC_ADDR_BECH32_MAX];
} ltc_tx_output_t;

/* Unsigned transaction */
typedef struct {
    uint32_t version;
    uint32_t locktime;
    ltc_tx_input_t inputs[LTC_MAX_INPUTS];
    size_t input_count;
    ltc_tx_output_t outputs[LTC_MAX_OUTPUTS];
    size_t output_count;
    ltc_network_t network;
} ltc_tx_t;

/**
 * Generate Litecoin address from public key
 *
 * @param pubkey Compressed public key (33 bytes)
 * @param addr_type Address type
 * @param network Network (mainnet/testnet)
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int ltc_pubkey_to_address(const uint8_t pubkey[33], ltc_addr_type_t addr_type,
                          ltc_network_t network, char *address, size_t address_len);

/**
 * Validate Litecoin address
 *
 * @param address Address string
 * @param network Expected network (NULL to skip network validation)
 * @return 0 if valid, -1 if invalid
 */
int ltc_validate_address(const char *address, const ltc_network_t *network);

/**
 * Parse Litecoin transaction from raw bytes
 *
 * @param raw_tx Raw transaction data
 * @param raw_len Length of raw data
 * @param tx Output transaction structure
 * @return 0 on success, -1 on error
 */
int ltc_parse_tx(const uint8_t *raw_tx, size_t raw_len, ltc_tx_t *tx);

/**
 * Sign Litecoin transaction
 *
 * @param tx Transaction to sign
 * @param keys Array of private keys for signing
 * @param key_count Number of keys
 * @param signed_tx Output buffer for signed transaction
 * @param signed_tx_len Size of output buffer / bytes written
 * @return 0 on success, -1 on error
 */
int ltc_sign_tx(ltc_tx_t *tx, const bip32_key_t *keys, size_t key_count,
                uint8_t *signed_tx, size_t *signed_tx_len);

/**
 * Create P2PKH scriptPubKey
 *
 * @param pubkey_hash 20-byte hash160 of public key
 * @param script Output script buffer
 * @param script_len Output: script length
 * @return 0 on success, -1 on error
 */
int ltc_script_p2pkh(const uint8_t pubkey_hash[20], uint8_t *script, size_t *script_len);

/**
 * Create P2WPKH scriptPubKey (native SegWit)
 *
 * @param pubkey_hash 20-byte hash160 of public key
 * @param script Output script buffer
 * @param script_len Output: script length
 * @return 0 on success, -1 on error
 */
int ltc_script_p2wpkh(const uint8_t pubkey_hash[20], uint8_t *script, size_t *script_len);

/**
 * Get BIP44 derivation path for Litecoin
 *
 * @param account Account index
 * @param change 0 for external, 1 for change
 * @param index Address index
 * @param path Output buffer for path string
 * @param path_len Size of path buffer
 * @return 0 on success, -1 on error
 */
int ltc_get_derivation_path(uint32_t account, uint32_t change, uint32_t index,
                            char *path, size_t path_len);

/**
 * Format litoshi amount to LTC string
 *
 * @param litoshis Amount in litoshis (1 LTC = 100,000,000 litoshis)
 * @param output Output string buffer
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int ltc_format_amount(uint64_t litoshis, char *output, size_t output_len);

/**
 * Calculate transaction fee
 *
 * @param tx Transaction
 * @return Fee in litoshis, or 0 if inputs < outputs (invalid)
 */
uint64_t ltc_calculate_fee(const ltc_tx_t *tx);

/**
 * Decode scriptPubKey to Litecoin address
 * Supports: P2PKH, P2SH, P2WPKH, P2WSH
 *
 * @param script_pubkey Script bytes
 * @param script_len Script length
 * @param network Network for address encoding
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int ltc_script_to_address(const uint8_t *script_pubkey, size_t script_len,
                          ltc_network_t network, char *address, size_t address_len);

#endif /* LITECOIN_H */

/*
 * Dogecoin Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Dogecoin is a Litecoin/Bitcoin fork with different network parameters:
 * - P2PKH prefix: 0x1E (D addresses)
 * - P2SH prefix: 0x16 (9/A addresses)
 * - BIP44 coin type: 3
 * - Note: Dogecoin does not support SegWit
 */

#ifndef DOGECOIN_H
#define DOGECOIN_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/bip32.h"

/* Address sizes */
#define DOGE_ADDR_MAX          35
#define DOGE_TXID_SIZE         32

/* Transaction limits */
#define DOGE_MAX_INPUTS        256
#define DOGE_MAX_OUTPUTS       256

/* BIP44 coin type */
#define DOGE_COIN_TYPE         3

/* Network types */
typedef enum {
    DOGE_MAINNET = 0,
    DOGE_TESTNET
} doge_network_t;

/* Address types (Dogecoin has no SegWit) */
typedef enum {
    DOGE_ADDR_P2PKH = 0,     /* Legacy (D...) */
    DOGE_ADDR_P2SH           /* Script hash (9.../A...) */
} doge_addr_type_t;

/* Transaction input */
typedef struct {
    uint8_t prev_txid[DOGE_TXID_SIZE];
    uint32_t prev_index;
    uint64_t amount;
    uint8_t script_pubkey[64];
    size_t script_pubkey_len;
} doge_tx_input_t;

/* Transaction output */
typedef struct {
    uint64_t amount;
    uint8_t script_pubkey[64];
    size_t script_pubkey_len;
    char address[DOGE_ADDR_MAX];
} doge_tx_output_t;

/* Unsigned transaction */
typedef struct {
    uint32_t version;
    uint32_t locktime;
    doge_tx_input_t inputs[DOGE_MAX_INPUTS];
    size_t input_count;
    doge_tx_output_t outputs[DOGE_MAX_OUTPUTS];
    size_t output_count;
    doge_network_t network;
} doge_tx_t;

/**
 * Generate Dogecoin address from public key
 *
 * @param pubkey Compressed public key (33 bytes)
 * @param addr_type Address type (P2PKH or P2SH)
 * @param network Network (mainnet/testnet)
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int doge_pubkey_to_address(const uint8_t pubkey[33], doge_addr_type_t addr_type,
                           doge_network_t network, char *address, size_t address_len);

/**
 * Validate Dogecoin address
 *
 * @param address Address string
 * @param network Expected network (NULL to skip network validation)
 * @return 0 if valid, -1 if invalid
 */
int doge_validate_address(const char *address, const doge_network_t *network);

/**
 * Parse Dogecoin transaction from raw bytes
 *
 * @param raw_tx Raw transaction data
 * @param raw_len Length of raw data
 * @param tx Output transaction structure
 * @return 0 on success, -1 on error
 */
int doge_parse_tx(const uint8_t *raw_tx, size_t raw_len, doge_tx_t *tx);

/**
 * Sign Dogecoin transaction
 *
 * @param tx Transaction to sign
 * @param keys Array of private keys for signing
 * @param key_count Number of keys
 * @param signed_tx Output buffer for signed transaction
 * @param signed_tx_len Size of output buffer / bytes written
 * @return 0 on success, -1 on error
 */
int doge_sign_tx(doge_tx_t *tx, const bip32_key_t *keys, size_t key_count,
                 uint8_t *signed_tx, size_t *signed_tx_len);

/**
 * Create P2PKH scriptPubKey
 *
 * @param pubkey_hash 20-byte hash160 of public key
 * @param script Output script buffer
 * @param script_len Output: script length
 * @return 0 on success, -1 on error
 */
int doge_script_p2pkh(const uint8_t pubkey_hash[20], uint8_t *script, size_t *script_len);

/**
 * Create P2SH scriptPubKey
 *
 * @param script_hash 20-byte hash160 of script
 * @param script Output script buffer
 * @param script_len Output: script length
 * @return 0 on success, -1 on error
 */
int doge_script_p2sh(const uint8_t script_hash[20], uint8_t *script, size_t *script_len);

/**
 * Get BIP44 derivation path for Dogecoin
 *
 * @param account Account index
 * @param change 0 for external, 1 for change
 * @param index Address index
 * @param path Output buffer for path string
 * @param path_len Size of path buffer
 * @return 0 on success, -1 on error
 */
int doge_get_derivation_path(uint32_t account, uint32_t change, uint32_t index,
                             char *path, size_t path_len);

/**
 * Format satoshi amount to DOGE string
 *
 * @param satoshis Amount in satoshis (1 DOGE = 100,000,000 satoshis)
 * @param output Output string buffer
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int doge_format_amount(uint64_t satoshis, char *output, size_t output_len);

/**
 * Calculate transaction fee
 *
 * @param tx Transaction
 * @return Fee in satoshis, or 0 if inputs < outputs (invalid)
 */
uint64_t doge_calculate_fee(const doge_tx_t *tx);

/**
 * Decode scriptPubKey to Dogecoin address
 * Supports: P2PKH, P2SH
 *
 * @param script_pubkey Script bytes
 * @param script_len Script length
 * @param network Network for address encoding
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int doge_script_to_address(const uint8_t *script_pubkey, size_t script_len,
                           doge_network_t network, char *address, size_t address_len);

#endif /* DOGECOIN_H */

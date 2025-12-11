/*
 * Ethereum Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef ETHEREUM_H
#define ETHEREUM_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/bip32.h"

/* Address and hash sizes */
#define ETH_ADDR_SIZE       20
#define ETH_ADDR_STR_SIZE   43  /* 0x + 40 hex chars + null */
#define ETH_HASH_SIZE       32
#define ETH_SIG_SIZE        65  /* r(32) + s(32) + v(1) */

/* Chain IDs */
#define ETH_CHAIN_MAINNET   1
#define ETH_CHAIN_GOERLI    5
#define ETH_CHAIN_SEPOLIA   11155111
#define ETH_CHAIN_POLYGON   137
#define ETH_CHAIN_ARBITRUM  42161
#define ETH_CHAIN_OPTIMISM  10
#define ETH_CHAIN_BSC       56
#define ETH_CHAIN_AVALANCHE 43114

/* Transaction types (EIP-2718) */
typedef enum {
    ETH_TX_LEGACY = 0,       /* Legacy transaction */
    ETH_TX_ACCESS_LIST = 1,  /* EIP-2930 */
    ETH_TX_EIP1559 = 2       /* EIP-1559 */
} eth_tx_type_t;

/* Transaction structure */
typedef struct {
    eth_tx_type_t type;
    uint64_t chain_id;
    uint64_t nonce;

    /* Gas */
    uint8_t gas_price[32];       /* Legacy: gas price */
    uint8_t max_fee[32];         /* EIP-1559: max fee per gas */
    uint8_t max_priority_fee[32];/* EIP-1559: max priority fee */
    uint64_t gas_limit;

    /* Transfer */
    uint8_t to[ETH_ADDR_SIZE];
    uint8_t value[32];           /* Wei amount */
    uint8_t *data;               /* Contract data */
    size_t data_len;

    /* For display */
    char to_str[ETH_ADDR_STR_SIZE];
    char value_str[64];
    char gas_str[64];
} eth_tx_t;

/**
 * Generate Ethereum address from public key
 *
 * @param pubkey Uncompressed public key (65 bytes, with 0x04 prefix)
 * @param address Output address buffer (43 bytes with 0x prefix)
 * @return 0 on success, -1 on error
 */
int eth_pubkey_to_address(const uint8_t pubkey[65], char *address);

/**
 * Generate checksummed address (EIP-55)
 *
 * @param address Raw address (with or without 0x prefix)
 * @param output Output buffer for checksummed address
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int eth_checksum_address(const char *address, char *output, size_t output_len);

/**
 * Parse RLP-encoded transaction
 *
 * @param rlp_data RLP-encoded transaction data
 * @param rlp_len Length of RLP data
 * @param tx Output transaction structure
 * @return 0 on success, -1 on error
 */
int eth_parse_tx(const uint8_t *rlp_data, size_t rlp_len, eth_tx_t *tx);

/**
 * Sign Ethereum transaction
 *
 * @param tx Transaction to sign
 * @param key Private key for signing
 * @param signed_tx Output buffer for signed transaction (RLP-encoded)
 * @param signed_tx_len Size of output buffer / bytes written
 * @return 0 on success, -1 on error
 */
int eth_sign_tx(eth_tx_t *tx, const bip32_key_t *key,
                uint8_t *signed_tx, size_t *signed_tx_len);

/**
 * Sign EIP-712 typed data
 *
 * @param domain_hash Domain separator hash
 * @param message_hash Message hash
 * @param key Private key
 * @param signature Output signature (65 bytes)
 * @return 0 on success, -1 on error
 */
int eth_sign_typed_data(const uint8_t domain_hash[32],
                        const uint8_t message_hash[32],
                        const bip32_key_t *key,
                        uint8_t signature[ETH_SIG_SIZE]);

/**
 * Sign personal message (EIP-191)
 *
 * @param message Message to sign
 * @param message_len Length of message
 * @param key Private key
 * @param signature Output signature (65 bytes)
 * @return 0 on success, -1 on error
 */
int eth_sign_message(const uint8_t *message, size_t message_len,
                     const bip32_key_t *key,
                     uint8_t signature[ETH_SIG_SIZE]);

/**
 * Validate Ethereum address
 *
 * @param address Address string (with 0x prefix)
 * @return 1 if valid, 0 if invalid
 */
int eth_validate_address(const char *address);

/**
 * Format Wei amount as ETH string
 *
 * @param wei Wei amount (32 bytes, big-endian)
 * @param output Output buffer
 * @param output_len Size of output buffer
 * @param decimals Decimal places (18 for ETH)
 * @return 0 on success, -1 on error
 */
int eth_format_amount(const uint8_t wei[32], char *output, size_t output_len, int decimals);

/**
 * Get chain name from chain ID
 *
 * @param chain_id Chain ID
 * @return Chain name string
 */
const char *eth_chain_name(uint64_t chain_id);

/**
 * Free transaction data
 *
 * @param tx Transaction to free
 */
void eth_tx_free(eth_tx_t *tx);

#endif /* ETHEREUM_H */

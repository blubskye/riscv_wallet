/*
 * Wallet Management
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef WALLET_H
#define WALLET_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/bip32.h"

/* Maximum accounts per wallet */
#define WALLET_MAX_ACCOUNTS  256

/* Maximum address label length */
#define WALLET_LABEL_MAX_LEN  64

/* Supported chains */
typedef enum {
    CHAIN_BITCOIN = 0,
    CHAIN_BITCOIN_TESTNET,
    CHAIN_ETHEREUM,
    CHAIN_LITECOIN,
    CHAIN_SOLANA,
    CHAIN_DOGECOIN,
    CHAIN_XRP,
    CHAIN_CARDANO,
    CHAIN_COUNT
} chain_type_t;

/* Address types */
typedef enum {
    ADDR_TYPE_LEGACY = 0,      /* P2PKH (1...) */
    ADDR_TYPE_SEGWIT_COMPAT,   /* P2SH-P2WPKH (3...) */
    ADDR_TYPE_SEGWIT_NATIVE,   /* P2WPKH (bc1q...) */
    ADDR_TYPE_TAPROOT          /* P2TR (bc1p...) */
} address_type_t;

/* Account flags */
#define ACCOUNT_FLAG_WATCH_ONLY  (1 << 0)  /* Watch-only account (no private keys) */
#define ACCOUNT_FLAG_DISABLED    (1 << 1)  /* Account disabled/hidden */

/* Wallet flags */
#define WALLET_FLAG_HAS_PASSPHRASE  (1 << 0)  /* Wallet uses BIP-39 passphrase */

/* Account structure */
typedef struct {
    uint32_t index;
    chain_type_t chain;
    address_type_t addr_type;
    uint32_t flags;                        /* Account flags (watch-only, etc) */
    char label[WALLET_LABEL_MAX_LEN];
    bip32_key_t account_key;
    uint32_t next_external_index;
    uint32_t next_internal_index;
} wallet_account_t;

/* Wallet structure */
typedef struct {
    uint8_t seed[64];
    bip32_key_t master_key;
    wallet_account_t accounts[WALLET_MAX_ACCOUNTS];
    size_t account_count;
    uint32_t flags;            /* Wallet flags (passphrase, etc) */
    int is_initialized;
} wallet_t;

/**
 * Create a new wallet with generated mnemonic
 *
 * @param wallet Wallet structure to initialize
 * @param word_count Number of mnemonic words (12, 18, or 24)
 * @param passphrase Optional BIP-39 passphrase (NULL for none)
 * @param mnemonic Output buffer for generated mnemonic
 * @param mnemonic_len Size of mnemonic buffer
 * @return 0 on success, -1 on error
 */
int wallet_create(wallet_t *wallet, int word_count, const char *passphrase,
                  char *mnemonic, size_t mnemonic_len);

/**
 * Check if wallet uses a passphrase
 *
 * @param wallet Wallet structure
 * @return 1 if wallet uses passphrase, 0 if not
 */
int wallet_has_passphrase(const wallet_t *wallet);

/**
 * Restore wallet from mnemonic
 *
 * @param wallet Wallet structure to initialize
 * @param mnemonic Mnemonic phrase
 * @param passphrase Optional passphrase (can be NULL)
 * @return 0 on success, -1 on error
 */
int wallet_restore(wallet_t *wallet, const char *mnemonic,
                   const char *passphrase);

/**
 * Add new account to wallet
 *
 * @param wallet Wallet structure
 * @param chain Blockchain type
 * @param addr_type Address type
 * @param label Account label
 * @return Account index on success, -1 on error
 */
int wallet_add_account(wallet_t *wallet, chain_type_t chain,
                       address_type_t addr_type, const char *label);

/**
 * Get account by index
 *
 * @param wallet Wallet structure
 * @param index Account index
 * @return Pointer to account, or NULL if not found
 */
wallet_account_t *wallet_get_account(wallet_t *wallet, size_t index);

/**
 * Generate new receiving address for account
 *
 * @param account Account structure
 * @param address Output buffer for address string
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int wallet_get_new_address(wallet_account_t *account,
                           char *address, size_t address_len);

/**
 * Securely wipe wallet from memory
 *
 * @param wallet Wallet to wipe
 */
void wallet_wipe(wallet_t *wallet);

/**
 * Get chain name string
 *
 * @param chain Chain type
 * @return Chain name string
 */
const char *wallet_chain_name(chain_type_t chain);

/**
 * Serialize wallet to binary format for encrypted storage
 *
 * @param wallet Wallet to serialize
 * @param output Output buffer
 * @param output_len Size of buffer / bytes written
 * @return 0 on success, -1 on error
 */
int wallet_serialize(const wallet_t *wallet, uint8_t *output, size_t *output_len);

/**
 * Deserialize wallet from binary format
 *
 * @param data Serialized data
 * @param data_len Length of data
 * @param wallet Output wallet structure
 * @return 0 on success, -1 on error
 */
int wallet_deserialize(const uint8_t *data, size_t data_len, wallet_t *wallet);

/**
 * Save wallet to encrypted storage
 *
 * @param wallet Wallet to save
 * @param pin User PIN
 * @return 0 on success, -1 on error
 */
int wallet_save(const wallet_t *wallet, const char *pin);

/**
 * Load wallet from encrypted storage
 *
 * @param wallet Output wallet structure
 * @param pin User PIN
 * @return 0 on success, -1 on error
 */
int wallet_load(wallet_t *wallet, const char *pin);

/* ============================================================================
 * Watch-Only Account Support
 * ============================================================================ */

/**
 * Add watch-only account from extended public key (xpub/ypub/zpub)
 *
 * @param wallet Wallet structure
 * @param xpub Extended public key string
 * @param chain Blockchain type
 * @param label Account label
 * @return Account index on success, -1 on error
 */
int wallet_add_watch_only(wallet_t *wallet, const char *xpub,
                          chain_type_t chain, const char *label);

/**
 * Check if account is watch-only
 *
 * @param account Account structure
 * @return 1 if watch-only, 0 if full account
 */
int wallet_account_is_watch_only(const wallet_account_t *account);

/**
 * Export extended public key from account
 *
 * @param account Account structure
 * @param xpub Output buffer for xpub string
 * @param xpub_len Size of buffer
 * @return 0 on success, -1 on error
 */
int wallet_export_xpub(const wallet_account_t *account,
                       char *xpub, size_t xpub_len);

/**
 * Get xpub type prefix for chain and address type
 *
 * @param chain Chain type
 * @param addr_type Address type
 * @return 4-byte version prefix
 */
uint32_t wallet_get_xpub_version(chain_type_t chain, address_type_t addr_type);

#endif /* WALLET_H */

/*
 * BIP-32 Hierarchical Deterministic Keys
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef BIP32_H
#define BIP32_H

#include <stdint.h>
#include <stddef.h>

/* Key sizes */
#define BIP32_KEY_SIZE       32
#define BIP32_CHAINCODE_SIZE 32
#define BIP32_PUBKEY_SIZE    33  /* Compressed public key */
#define BIP32_SEED_SIZE      64

/* Derivation path constants */
#define BIP32_HARDENED_BIT   0x80000000

/* Common derivation purposes */
#define BIP32_PURPOSE_BIP44  44
#define BIP32_PURPOSE_BIP49  49
#define BIP32_PURPOSE_BIP84  84

/* Coin types (BIP-44) */
#define BIP32_COIN_BTC       0
#define BIP32_COIN_BTC_TEST  1
#define BIP32_COIN_LTC       2
#define BIP32_COIN_ETH       60
#define BIP32_COIN_SOL       501

/**
 * Extended key structure
 */
typedef struct {
    uint8_t private_key[BIP32_KEY_SIZE];
    uint8_t public_key[BIP32_PUBKEY_SIZE];
    uint8_t chain_code[BIP32_CHAINCODE_SIZE];
    uint32_t depth;
    uint32_t child_index;
    uint8_t parent_fingerprint[4];
} bip32_key_t;

/**
 * Initialize master key from seed
 *
 * @param seed 64-byte seed (from BIP-39)
 * @param key Output key structure
 * @return 0 on success, -1 on error
 */
int bip32_master_key_from_seed(const uint8_t seed[BIP32_SEED_SIZE], bip32_key_t *key);

/**
 * Derive child key
 *
 * @param parent Parent key
 * @param child Output child key
 * @param index Child index (add BIP32_HARDENED_BIT for hardened derivation)
 * @return 0 on success, -1 on error
 */
int bip32_derive_child(const bip32_key_t *parent, bip32_key_t *child, uint32_t index);

/**
 * Derive key from path string
 *
 * @param master Master key
 * @param path Derivation path (e.g., "m/44'/0'/0'/0/0")
 * @param result Output key
 * @return 0 on success, -1 on error
 */
int bip32_derive_path(const bip32_key_t *master, const char *path, bip32_key_t *result);

/**
 * Serialize extended private key to Base58Check
 *
 * @param key Key to serialize
 * @param output Output buffer
 * @param output_len Size of output buffer
 * @param mainnet Use mainnet version bytes
 * @return 0 on success, -1 on error
 */
int bip32_serialize_private(const bip32_key_t *key, char *output,
                            size_t output_len, int mainnet);

/**
 * Serialize extended public key to Base58Check
 *
 * @param key Key to serialize
 * @param output Output buffer
 * @param output_len Size of output buffer
 * @param mainnet Use mainnet version bytes
 * @return 0 on success, -1 on error
 */
int bip32_serialize_public(const bip32_key_t *key, char *output,
                           size_t output_len, int mainnet);

/**
 * Securely wipe key from memory
 *
 * @param key Key to wipe
 */
void bip32_key_wipe(bip32_key_t *key);

/**
 * Serialize extended key to Base58Check with custom version
 *
 * @param key Key to serialize
 * @param is_private 1 for private key, 0 for public key
 * @param version 4-byte version prefix
 * @param output Output buffer
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int bip32_serialize_key(const bip32_key_t *key, int is_private,
                        uint32_t version, char *output, size_t output_len);

/**
 * Deserialize extended key from Base58Check
 *
 * @param input Base58Check encoded string
 * @param key Output key structure
 * @param version Output version bytes
 * @return 0 on success, -1 on error
 */
int bip32_deserialize_key(const char *input, bip32_key_t *key, uint32_t *version);

#endif /* BIP32_H */

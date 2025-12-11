/*
 * Cardano (ADA) Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Cardano is a third-generation blockchain with unique characteristics:
 * - Uses Ed25519 extended keys (Ed25519-BIP32)
 * - Bech32 addresses with "addr" (mainnet) / "addr_test" (testnet) prefix
 * - BIP44 coin type: 1815
 * - Multiple address types: Base, Enterprise, Pointer, Reward/Stake
 * - Extended UTXO model with smart contracts
 * - Native multi-asset support
 */

#ifndef CARDANO_H
#define CARDANO_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/bip32.h"

/* Address sizes */
#define ADA_ADDR_BECH32_MAX     128  /* Bech32 address string */
#define ADA_ADDR_RAW_MAX        57   /* Raw address bytes (base address) */
#define ADA_PUBKEY_SIZE         32   /* Ed25519 public key */
#define ADA_PRIVKEY_SIZE        64   /* Ed25519 extended private key */
#define ADA_SIG_SIZE            64   /* Ed25519 signature */
#define ADA_HASH_SIZE           28   /* Blake2b-224 hash (key hash) */
#define ADA_TX_HASH_SIZE        32   /* Blake2b-256 hash (tx hash) */

/* BIP44 coin type for Cardano */
#define ADA_COIN_TYPE           1815

/* ADA currency precision: 1 ADA = 1,000,000 lovelace */
#define ADA_LOVELACE_PER_ADA    1000000ULL

/* Minimum UTXO value (in lovelace) - depends on protocol parameters */
#define ADA_MIN_UTXO_LOVELACE   1000000ULL  /* ~1 ADA */

/* Network types */
typedef enum {
    ADA_MAINNET = 0,
    ADA_TESTNET,          /* Preprod, Preview, etc. */
    ADA_TESTNET_LEGACY    /* Legacy testnet */
} ada_network_t;

/* Network magic (for testnet identification) */
#define ADA_MAINNET_MAGIC       764824073
#define ADA_TESTNET_PREPROD     1
#define ADA_TESTNET_PREVIEW     2

/* Address types (Shelley era and later) */
typedef enum {
    /* Base address: payment key + stake key */
    ADA_ADDR_BASE_PUBKEY_PUBKEY = 0x00,
    ADA_ADDR_BASE_SCRIPT_PUBKEY = 0x10,
    ADA_ADDR_BASE_PUBKEY_SCRIPT = 0x20,
    ADA_ADDR_BASE_SCRIPT_SCRIPT = 0x30,

    /* Pointer address: payment key + pointer to stake key registration */
    ADA_ADDR_POINTER_PUBKEY     = 0x40,
    ADA_ADDR_POINTER_SCRIPT     = 0x50,

    /* Enterprise address: payment key only (no staking) */
    ADA_ADDR_ENTERPRISE_PUBKEY  = 0x60,
    ADA_ADDR_ENTERPRISE_SCRIPT  = 0x70,

    /* Bootstrap (Byron legacy) address */
    ADA_ADDR_BOOTSTRAP          = 0x80,

    /* Reward/Stake address (for staking rewards) */
    ADA_ADDR_REWARD_PUBKEY      = 0xE0,
    ADA_ADDR_REWARD_SCRIPT      = 0xF0
} ada_addr_type_t;

/* Derivation purpose for Cardano (CIP-1852) */
#define ADA_PURPOSE             1852

/* Account role indices */
#define ADA_ROLE_EXTERNAL       0  /* Receiving addresses */
#define ADA_ROLE_INTERNAL       1  /* Change addresses */
#define ADA_ROLE_STAKING        2  /* Staking key */

/* Transaction input (UTXO reference) */
typedef struct {
    uint8_t tx_hash[ADA_TX_HASH_SIZE];  /* Transaction hash */
    uint32_t tx_index;                   /* Output index */
    uint64_t amount;                     /* Amount in lovelace */
} ada_tx_input_t;

/* Transaction output */
typedef struct {
    char address[ADA_ADDR_BECH32_MAX];  /* Destination address */
    uint64_t amount;                     /* Amount in lovelace */
    /* Native tokens would go here (multi-asset) */
} ada_tx_output_t;

/* Maximum inputs/outputs per transaction */
#define ADA_MAX_TX_INPUTS       256
#define ADA_MAX_TX_OUTPUTS      256

/* Transaction structure */
typedef struct {
    ada_tx_input_t inputs[ADA_MAX_TX_INPUTS];
    size_t input_count;

    ada_tx_output_t outputs[ADA_MAX_TX_OUTPUTS];
    size_t output_count;

    uint64_t fee;                /* Transaction fee in lovelace */
    uint32_t ttl;                /* Time to live (slot number) */

    /* Optional metadata */
    uint8_t *metadata;
    size_t metadata_len;

    ada_network_t network;
} ada_tx_t;

/* Extended key structure for Cardano (Ed25519-BIP32) */
typedef struct {
    uint8_t private_key[32];     /* Ed25519 scalar */
    uint8_t extension[32];       /* Chain code / extension */
    uint8_t public_key[32];      /* Ed25519 public key */
} ada_extended_key_t;

/**
 * Derive Cardano master key from seed (Icarus method)
 * Uses PBKDF2-HMAC-SHA512 for key stretching
 *
 * @param seed BIP-39 seed (64 bytes)
 * @param key Output extended key
 * @return 0 on success, -1 on error
 */
int ada_master_key_from_seed(const uint8_t seed[64], ada_extended_key_t *key);

/**
 * Derive child key (hardened or normal)
 *
 * @param parent Parent extended key
 * @param child Output child key
 * @param index Child index (set bit 31 for hardened)
 * @return 0 on success, -1 on error
 */
int ada_derive_child(const ada_extended_key_t *parent, ada_extended_key_t *child,
                     uint32_t index);

/**
 * Derive account key using CIP-1852 path
 * Path: m/1852'/1815'/account'
 *
 * @param master Master extended key
 * @param account Account index
 * @param account_key Output account key
 * @return 0 on success, -1 on error
 */
int ada_derive_account(const ada_extended_key_t *master, uint32_t account,
                       ada_extended_key_t *account_key);

/**
 * Derive address key from account
 * Path: m/1852'/1815'/account'/role/index
 *
 * @param account_key Account key
 * @param role Role (0=external, 1=internal, 2=staking)
 * @param index Address index
 * @param addr_key Output address key
 * @return 0 on success, -1 on error
 */
int ada_derive_address_key(const ada_extended_key_t *account_key,
                           uint32_t role, uint32_t index,
                           ada_extended_key_t *addr_key);

/**
 * Generate Cardano base address from payment and stake keys
 *
 * @param payment_pubkey Payment public key (32 bytes)
 * @param stake_pubkey Stake public key (32 bytes)
 * @param network Network type
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int ada_create_base_address(const uint8_t payment_pubkey[32],
                            const uint8_t stake_pubkey[32],
                            ada_network_t network,
                            char *address, size_t address_len);

/**
 * Generate Cardano enterprise address (payment key only)
 *
 * @param payment_pubkey Payment public key (32 bytes)
 * @param network Network type
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int ada_create_enterprise_address(const uint8_t payment_pubkey[32],
                                  ada_network_t network,
                                  char *address, size_t address_len);

/**
 * Generate Cardano reward/stake address
 *
 * @param stake_pubkey Stake public key (32 bytes)
 * @param network Network type
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int ada_create_reward_address(const uint8_t stake_pubkey[32],
                              ada_network_t network,
                              char *address, size_t address_len);

/**
 * Validate Cardano address (Bech32)
 *
 * @param address Address string
 * @return 1 if valid, 0 if invalid
 */
int ada_validate_address(const char *address);

/**
 * Decode Cardano address to raw bytes
 *
 * @param address Address string
 * @param raw_addr Output buffer for raw address
 * @param raw_len Size of buffer / bytes written
 * @param network Detected network (can be NULL)
 * @return 0 on success, -1 on error
 */
int ada_decode_address(const char *address, uint8_t *raw_addr, size_t *raw_len,
                       ada_network_t *network);

/**
 * Get address type from raw address
 *
 * @param raw_addr Raw address bytes
 * @param raw_len Length of raw address
 * @return Address type, or -1 on error
 */
int ada_get_address_type(const uint8_t *raw_addr, size_t raw_len);

/**
 * Hash public key to key hash (Blake2b-224)
 *
 * @param pubkey Public key (32 bytes)
 * @param hash Output hash (28 bytes)
 * @return 0 on success, -1 on error
 */
int ada_hash_pubkey(const uint8_t pubkey[32], uint8_t hash[28]);

/**
 * Create simple payment transaction
 *
 * @param tx Output transaction structure
 * @param from From address
 * @param to To address
 * @param amount Amount in lovelace
 * @param fee Fee in lovelace
 * @param ttl Time to live (slot)
 * @return 0 on success, -1 on error
 */
int ada_create_payment_tx(ada_tx_t *tx, const char *from, const char *to,
                          uint64_t amount, uint64_t fee, uint32_t ttl);

/**
 * Add input to transaction
 *
 * @param tx Transaction
 * @param tx_hash Previous transaction hash
 * @param tx_index Output index
 * @param amount Amount in lovelace
 * @return 0 on success, -1 on error
 */
int ada_tx_add_input(ada_tx_t *tx, const uint8_t tx_hash[32],
                     uint32_t tx_index, uint64_t amount);

/**
 * Add output to transaction
 *
 * @param tx Transaction
 * @param address Destination address
 * @param amount Amount in lovelace
 * @return 0 on success, -1 on error
 */
int ada_tx_add_output(ada_tx_t *tx, const char *address, uint64_t amount);

/**
 * Serialize transaction body to CBOR
 *
 * @param tx Transaction
 * @param output Output buffer
 * @param output_len Size of buffer / bytes written
 * @return 0 on success, -1 on error
 */
int ada_serialize_tx_body(const ada_tx_t *tx, uint8_t *output, size_t *output_len);

/**
 * Sign transaction with Ed25519 key
 *
 * @param tx_body Serialized transaction body
 * @param tx_body_len Length of transaction body
 * @param key Extended key for signing
 * @param signature Output signature (64 bytes)
 * @return 0 on success, -1 on error
 */
int ada_sign_tx(const uint8_t *tx_body, size_t tx_body_len,
                const ada_extended_key_t *key, uint8_t signature[64]);

/**
 * Build complete signed transaction
 *
 * @param tx_body Serialized transaction body
 * @param tx_body_len Length of transaction body
 * @param witnesses Array of witness signatures
 * @param witness_count Number of witnesses
 * @param signed_tx Output buffer for signed transaction
 * @param signed_tx_len Size of buffer / bytes written
 * @return 0 on success, -1 on error
 */
int ada_build_signed_tx(const uint8_t *tx_body, size_t tx_body_len,
                        const uint8_t witnesses[][64], size_t witness_count,
                        const ada_extended_key_t *keys[],
                        uint8_t *signed_tx, size_t *signed_tx_len);

/**
 * Calculate transaction hash (for signing)
 *
 * @param tx_body Serialized transaction body
 * @param tx_body_len Length of transaction body
 * @param hash Output hash (32 bytes)
 * @return 0 on success, -1 on error
 */
int ada_tx_hash(const uint8_t *tx_body, size_t tx_body_len, uint8_t hash[32]);

/**
 * Calculate minimum transaction fee
 *
 * @param tx Transaction
 * @param a Linear coefficient (usually 44)
 * @param b Constant (usually 155381)
 * @return Minimum fee in lovelace
 */
uint64_t ada_calculate_min_fee(const ada_tx_t *tx, uint64_t a, uint64_t b);

/**
 * Format lovelace amount as ADA string
 *
 * @param lovelace Amount in lovelace (1 ADA = 1,000,000 lovelace)
 * @param output Output string buffer
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int ada_format_amount(uint64_t lovelace, char *output, size_t output_len);

/**
 * Parse ADA amount string to lovelace
 *
 * @param amount_str Amount string (e.g., "10.5" ADA)
 * @param lovelace Output lovelace value
 * @return 0 on success, -1 on error
 */
int ada_parse_amount(const char *amount_str, uint64_t *lovelace);

/**
 * Get BIP44/CIP-1852 derivation path for Cardano
 * Standard: m/1852'/1815'/account'/role/index
 *
 * @param account Account index
 * @param role Role (0=external, 1=internal, 2=staking)
 * @param index Address index
 * @param path Output buffer for path string
 * @param path_len Size of path buffer
 * @return 0 on success, -1 on error
 */
int ada_get_derivation_path(uint32_t account, uint32_t role, uint32_t index,
                            char *path, size_t path_len);

/**
 * Get network name from network type
 *
 * @param network Network type
 * @return Network name string
 */
const char *ada_network_name(ada_network_t network);

/**
 * Free transaction data
 *
 * @param tx Transaction to free
 */
void ada_tx_free(ada_tx_t *tx);

/**
 * Wipe extended key from memory
 *
 * @param key Key to wipe
 */
void ada_key_wipe(ada_extended_key_t *key);

#endif /* CARDANO_H */

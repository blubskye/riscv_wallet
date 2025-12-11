/*
 * Solana Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Solana uses ed25519 elliptic curve cryptography:
 * - Addresses are base58-encoded 32-byte public keys
 * - BIP44 coin type: 501
 * - Uses SLIP-0010 ed25519 derivation (hardened only)
 */

#ifndef SOLANA_H
#define SOLANA_H

#include <stdint.h>
#include <stddef.h>

/* Key sizes */
#define SOL_PUBKEY_SIZE        32
#define SOL_PRIVKEY_SIZE       64  /* ed25519 expanded private key */
#define SOL_SEED_SIZE          32  /* ed25519 seed (private key seed) */
#define SOL_SIGNATURE_SIZE     64

/* Address sizes */
#define SOL_ADDR_MAX           45  /* Base58-encoded 32 bytes + null */

/* Transaction limits */
#define SOL_MAX_SIGNERS        8
#define SOL_MAX_ACCOUNTS       32
#define SOL_MAX_INSTRUCTIONS   16

/* BIP44 coin type */
#define SOL_COIN_TYPE          501

/* Lamports per SOL (1 SOL = 1,000,000,000 lamports) */
#define SOL_LAMPORTS_PER_SOL   1000000000ULL

/* Network types */
typedef enum {
    SOL_MAINNET = 0,
    SOL_DEVNET,
    SOL_TESTNET
} sol_network_t;

/* ed25519 keypair structure */
typedef struct {
    uint8_t seed[SOL_SEED_SIZE];           /* 32-byte seed */
    uint8_t public_key[SOL_PUBKEY_SIZE];   /* 32-byte public key */
    uint8_t secret_key[SOL_PRIVKEY_SIZE];  /* 64-byte expanded secret key */
} sol_keypair_t;

/* Account metadata for transaction */
typedef struct {
    uint8_t pubkey[SOL_PUBKEY_SIZE];
    int is_signer;
    int is_writable;
} sol_account_meta_t;

/* Instruction for transaction */
typedef struct {
    uint8_t program_id[SOL_PUBKEY_SIZE];
    sol_account_meta_t accounts[SOL_MAX_ACCOUNTS];
    size_t account_count;
    uint8_t *data;
    size_t data_len;
} sol_instruction_t;

/* Unsigned transaction (message) */
typedef struct {
    uint8_t recent_blockhash[SOL_PUBKEY_SIZE];
    uint8_t fee_payer[SOL_PUBKEY_SIZE];
    sol_instruction_t instructions[SOL_MAX_INSTRUCTIONS];
    size_t instruction_count;
    sol_network_t network;
} sol_tx_t;

/**
 * Derive ed25519 keypair from BIP-32 seed
 * Uses SLIP-0010 for ed25519 key derivation
 *
 * @param seed 64-byte BIP-39 seed
 * @param account Account index (hardened)
 * @param change Change index (0 for external) (hardened)
 * @param keypair Output keypair
 * @return 0 on success, -1 on error
 */
int sol_derive_keypair(const uint8_t seed[64], uint32_t account,
                       uint32_t change, sol_keypair_t *keypair);

/**
 * Generate Solana address from public key
 *
 * @param pubkey 32-byte ed25519 public key
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int sol_pubkey_to_address(const uint8_t pubkey[SOL_PUBKEY_SIZE],
                          char *address, size_t address_len);

/**
 * Validate Solana address format
 *
 * @param address Address string
 * @return 0 if valid, -1 if invalid
 */
int sol_validate_address(const char *address);

/**
 * Decode Solana address to public key bytes
 *
 * @param address Address string
 * @param pubkey Output 32-byte public key
 * @return 0 on success, -1 on error
 */
int sol_address_to_pubkey(const char *address, uint8_t pubkey[SOL_PUBKEY_SIZE]);

/**
 * Sign message with ed25519 keypair
 *
 * @param keypair Signing keypair
 * @param message Message to sign
 * @param message_len Length of message
 * @param signature Output signature buffer (64 bytes)
 * @return 0 on success, -1 on error
 */
int sol_sign_message(const sol_keypair_t *keypair,
                     const uint8_t *message, size_t message_len,
                     uint8_t signature[SOL_SIGNATURE_SIZE]);

/**
 * Verify ed25519 signature
 *
 * @param pubkey 32-byte public key
 * @param message Original message
 * @param message_len Length of message
 * @param signature 64-byte signature
 * @return 0 if valid, -1 if invalid
 */
int sol_verify_signature(const uint8_t pubkey[SOL_PUBKEY_SIZE],
                         const uint8_t *message, size_t message_len,
                         const uint8_t signature[SOL_SIGNATURE_SIZE]);

/**
 * Create SOL transfer instruction
 *
 * @param from_pubkey Sender public key
 * @param to_pubkey Recipient public key
 * @param lamports Amount in lamports
 * @param instruction Output instruction
 * @return 0 on success, -1 on error
 */
int sol_transfer_instruction(const uint8_t from_pubkey[SOL_PUBKEY_SIZE],
                             const uint8_t to_pubkey[SOL_PUBKEY_SIZE],
                             uint64_t lamports,
                             sol_instruction_t *instruction);

/**
 * Serialize transaction message for signing
 *
 * @param tx Transaction
 * @param output Output buffer
 * @param output_len Size of buffer / bytes written
 * @return 0 on success, -1 on error
 */
int sol_serialize_message(const sol_tx_t *tx, uint8_t *output, size_t *output_len);

/**
 * Sign transaction
 *
 * @param tx Transaction to sign
 * @param keypairs Array of signing keypairs
 * @param keypair_count Number of keypairs
 * @param signed_tx Output buffer for signed transaction
 * @param signed_tx_len Size of buffer / bytes written
 * @return 0 on success, -1 on error
 */
int sol_sign_tx(sol_tx_t *tx, const sol_keypair_t *keypairs, size_t keypair_count,
                uint8_t *signed_tx, size_t *signed_tx_len);

/**
 * Get BIP44 derivation path for Solana
 *
 * @param account Account index
 * @param change Change index (typically 0)
 * @param path Output buffer for path string
 * @param path_len Size of path buffer
 * @return 0 on success, -1 on error
 */
int sol_get_derivation_path(uint32_t account, uint32_t change,
                            char *path, size_t path_len);

/**
 * Format lamports amount to SOL string
 *
 * @param lamports Amount in lamports
 * @param output Output string buffer
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int sol_format_amount(uint64_t lamports, char *output, size_t output_len);

/**
 * Securely wipe keypair from memory
 *
 * @param keypair Keypair to wipe
 */
void sol_keypair_wipe(sol_keypair_t *keypair);

/* System Program ID (11111111111111111111111111111111) */
extern const uint8_t SOL_SYSTEM_PROGRAM_ID[SOL_PUBKEY_SIZE];

/* Token Program ID */
extern const uint8_t SOL_TOKEN_PROGRAM_ID[SOL_PUBKEY_SIZE];

#endif /* SOLANA_H */

/*
 * XRP/Ripple Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * XRP Ledger (XRPL) is an account-based blockchain with unique features:
 * - Address encoding: Base58Check with prefix 0x00 (r-addresses)
 * - Supports secp256k1 (legacy) or Ed25519 (preferred)
 * - BIP44 coin type: 144
 * - Account requires minimum reserve (currently 10 XRP)
 * - No UTXO model - account-based with sequence numbers
 */

#ifndef RIPPLE_H
#define RIPPLE_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/bip32.h"

/* Address and hash sizes */
#define XRP_ADDR_SIZE       35  /* r... addresses are ~25-35 chars */
#define XRP_ADDR_RAW_SIZE   20  /* 160-bit hash */
#define XRP_HASH_SIZE       32
#define XRP_SIG_SIZE        72  /* DER-encoded secp256k1 or 64 for Ed25519 */
#define XRP_PUBKEY_SIZE     33  /* Compressed secp256k1 or 33 for Ed25519 (prefix + 32) */

/* BIP44 coin type for XRP */
#define XRP_COIN_TYPE       144

/* XRP currency precision: 1 XRP = 1,000,000 drops */
#define XRP_DROPS_PER_XRP   1000000ULL

/* Minimum reserve (in drops) */
#define XRP_MIN_RESERVE     10000000ULL  /* 10 XRP */

/* Maximum memo data size */
#define XRP_MAX_MEMO_SIZE   1024

/* Network types */
typedef enum {
    XRP_MAINNET = 0,
    XRP_TESTNET,
    XRP_DEVNET
} xrp_network_t;

/* Key types */
typedef enum {
    XRP_KEY_SECP256K1 = 0,  /* Legacy key type */
    XRP_KEY_ED25519         /* Preferred for new accounts */
} xrp_key_type_t;

/* Transaction types */
typedef enum {
    XRP_TX_PAYMENT = 0,           /* Simple XRP transfer */
    XRP_TX_TRUST_SET,             /* Set trust line for tokens */
    XRP_TX_OFFER_CREATE,          /* Create DEX offer */
    XRP_TX_OFFER_CANCEL,          /* Cancel DEX offer */
    XRP_TX_ESCROW_CREATE,         /* Create escrow */
    XRP_TX_ESCROW_FINISH,         /* Complete escrow */
    XRP_TX_ESCROW_CANCEL,         /* Cancel escrow */
    XRP_TX_ACCOUNT_SET,           /* Account settings */
    XRP_TX_SET_REGULAR_KEY,       /* Set regular key pair */
    XRP_TX_SIGNER_LIST_SET,       /* Multi-sig setup */
    XRP_TX_NFT_MINT,              /* Mint NFT */
    XRP_TX_NFT_BURN,              /* Burn NFT */
    XRP_TX_NFT_CREATE_OFFER,      /* Create NFT offer */
    XRP_TX_NFT_ACCEPT_OFFER,      /* Accept NFT offer */
    XRP_TX_NFT_CANCEL_OFFER       /* Cancel NFT offer */
} xrp_tx_type_t;

/* Amount structure (for XRP and issued currencies) */
typedef struct {
    int is_xrp;                    /* 1 for XRP, 0 for issued currency */

    /* For XRP: amount in drops */
    uint64_t drops;

    /* For issued currencies */
    char currency[4];              /* 3-letter currency code or 40-hex */
    char issuer[XRP_ADDR_SIZE];    /* Issuer address */
    char value[64];                /* Amount as string (IOU amounts) */
} xrp_amount_t;

/* Memo structure */
typedef struct {
    uint8_t *data;
    size_t data_len;
    char type[64];                 /* Memo type (optional) */
    char format[64];               /* Memo format (optional, e.g., "text/plain") */
} xrp_memo_t;

/* Payment transaction */
typedef struct {
    xrp_tx_type_t type;

    /* Common fields */
    char account[XRP_ADDR_SIZE];   /* Sender address */
    uint32_t sequence;             /* Account sequence number */
    uint64_t fee;                  /* Transaction fee in drops */
    uint32_t last_ledger_seq;      /* Last valid ledger index */

    /* Payment-specific */
    char destination[XRP_ADDR_SIZE];
    xrp_amount_t amount;
    uint32_t destination_tag;      /* Optional destination tag */
    int has_destination_tag;

    /* Memo (optional) */
    xrp_memo_t memo;
    int has_memo;

    /* For display */
    char amount_str[64];
    char fee_str[32];
} xrp_tx_t;

/**
 * Generate XRP address from public key
 *
 * @param pubkey Compressed public key (33 bytes)
 * @param key_type Key type (secp256k1 or ed25519)
 * @param address Output address buffer (XRP_ADDR_SIZE)
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int xrp_pubkey_to_address(const uint8_t pubkey[33], xrp_key_type_t key_type,
                          char *address, size_t address_len);

/**
 * Validate XRP address (r-address format)
 *
 * @param address Address string
 * @return 1 if valid, 0 if invalid
 */
int xrp_validate_address(const char *address);

/**
 * Decode XRP address to account ID (20-byte hash)
 *
 * @param address Address string
 * @param account_id Output buffer for 20-byte account ID
 * @return 0 on success, -1 on error
 */
int xrp_decode_address(const char *address, uint8_t account_id[20]);

/**
 * Encode account ID to XRP address
 *
 * @param account_id 20-byte account ID
 * @param address Output address buffer
 * @param address_len Size of address buffer
 * @return 0 on success, -1 on error
 */
int xrp_encode_address(const uint8_t account_id[20], char *address, size_t address_len);

/**
 * Create XRP payment transaction
 *
 * @param tx Output transaction structure
 * @param from Sender address
 * @param to Recipient address
 * @param amount_drops Amount in drops
 * @param sequence Account sequence number
 * @param fee_drops Fee in drops
 * @return 0 on success, -1 on error
 */
int xrp_create_payment(xrp_tx_t *tx, const char *from, const char *to,
                       uint64_t amount_drops, uint32_t sequence, uint64_t fee_drops);

/**
 * Set destination tag on transaction
 *
 * @param tx Transaction
 * @param tag Destination tag
 * @return 0 on success, -1 on error
 */
int xrp_tx_set_destination_tag(xrp_tx_t *tx, uint32_t tag);

/**
 * Set memo on transaction
 *
 * @param tx Transaction
 * @param data Memo data
 * @param data_len Memo data length
 * @param type Memo type (can be NULL)
 * @return 0 on success, -1 on error
 */
int xrp_tx_set_memo(xrp_tx_t *tx, const uint8_t *data, size_t data_len,
                    const char *type);

/**
 * Serialize transaction for signing
 *
 * @param tx Transaction
 * @param output Output buffer
 * @param output_len Size of buffer / bytes written
 * @return 0 on success, -1 on error
 */
int xrp_serialize_tx(const xrp_tx_t *tx, uint8_t *output, size_t *output_len);

/**
 * Sign XRP transaction (secp256k1)
 *
 * @param tx Transaction to sign
 * @param key Private key for signing
 * @param key_type Key type
 * @param signed_tx Output buffer for signed transaction (binary)
 * @param signed_tx_len Size of buffer / bytes written
 * @return 0 on success, -1 on error
 */
int xrp_sign_tx(xrp_tx_t *tx, const bip32_key_t *key, xrp_key_type_t key_type,
                uint8_t *signed_tx, size_t *signed_tx_len);

/**
 * Convert signed transaction to hex blob for submission
 *
 * @param signed_tx Signed transaction binary
 * @param signed_tx_len Length of signed transaction
 * @param hex_blob Output buffer for hex string
 * @param hex_blob_len Size of hex buffer
 * @return 0 on success, -1 on error
 */
int xrp_tx_to_hex(const uint8_t *signed_tx, size_t signed_tx_len,
                  char *hex_blob, size_t hex_blob_len);

/**
 * Parse XRP transaction from binary blob
 *
 * @param data Binary transaction data
 * @param data_len Length of data
 * @param tx Output transaction structure
 * @return 0 on success, -1 on error
 */
int xrp_parse_tx(const uint8_t *data, size_t data_len, xrp_tx_t *tx);

/**
 * Format drops amount as XRP string
 *
 * @param drops Amount in drops (1 XRP = 1,000,000 drops)
 * @param output Output string buffer
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int xrp_format_amount(uint64_t drops, char *output, size_t output_len);

/**
 * Parse XRP amount string to drops
 *
 * @param amount_str Amount string (e.g., "10.5" XRP)
 * @param drops Output drops value
 * @return 0 on success, -1 on error
 */
int xrp_parse_amount(const char *amount_str, uint64_t *drops);

/**
 * Get BIP44 derivation path for XRP
 * Standard: m/44'/144'/account'/0/index
 *
 * @param account Account index
 * @param index Address index
 * @param path Output buffer for path string
 * @param path_len Size of path buffer
 * @return 0 on success, -1 on error
 */
int xrp_get_derivation_path(uint32_t account, uint32_t index,
                            char *path, size_t path_len);

/**
 * Calculate transaction fee based on current network load
 * Returns a recommended fee in drops
 *
 * @param base_fee Base fee (usually 10 drops)
 * @param load_factor Network load factor (1.0 = normal)
 * @return Recommended fee in drops
 */
uint64_t xrp_calculate_fee(uint64_t base_fee, double load_factor);

/**
 * Get network name from network type
 *
 * @param network Network type
 * @return Network name string
 */
const char *xrp_network_name(xrp_network_t network);

/**
 * Free transaction data
 *
 * @param tx Transaction to free
 */
void xrp_tx_free(xrp_tx_t *tx);

/**
 * Hash public key for account ID (AccountID from public key)
 * This is SHA-256 + RIPEMD-160 (like Bitcoin's hash160)
 *
 * @param pubkey Public key (33 bytes for secp256k1, 33 for ed25519 with prefix)
 * @param pubkey_len Public key length
 * @param account_id Output 20-byte account ID
 * @return 0 on success, -1 on error
 */
int xrp_hash_pubkey(const uint8_t *pubkey, size_t pubkey_len, uint8_t account_id[20]);

/* XRP-specific Base58 alphabet (different from Bitcoin!) */
extern const char *XRP_BASE58_ALPHABET;

#endif /* RIPPLE_H */

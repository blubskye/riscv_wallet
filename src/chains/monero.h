/*
 * Monero Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implements CryptoNote-style key derivation and address generation for Monero.
 * Reference: https://github.com/monero-project/monero/tree/master/src/crypto
 */

#ifndef MONERO_H
#define MONERO_H

#include <stdint.h>
#include <stddef.h>

/* Monero uses ed25519 curve but with different key derivation than SLIP-0010 */
#define XMR_KEY_SIZE           32
#define XMR_PUBKEY_SIZE        32
#define XMR_SECRET_KEY_SIZE    32
#define XMR_ADDRESS_SIZE       95  /* Standard address length (mainnet) */
#define XMR_INTEGRATED_SIZE    106 /* Integrated address with payment ID */
#define XMR_SUBADDRESS_SIZE    95  /* Subaddress length */

/* Network prefixes */
#define XMR_NETWORK_MAINNET    0x12  /* Standard address prefix (18) */
#define XMR_NETWORK_TESTNET    0x35  /* Testnet address prefix (53) */
#define XMR_NETWORK_STAGENET   0x18  /* Stagenet address prefix (24) */

/* Subaddress prefixes */
#define XMR_SUBADDR_MAINNET    0x2A  /* Subaddress prefix mainnet (42) */
#define XMR_SUBADDR_TESTNET    0x3F  /* Subaddress prefix testnet (63) */
#define XMR_SUBADDR_STAGENET   0x24  /* Subaddress prefix stagenet (36) */

/* Integrated address prefixes */
#define XMR_INTEGRATED_MAINNET 0x13  /* Integrated address mainnet (19) */
#define XMR_INTEGRATED_TESTNET 0x36  /* Integrated address testnet (54) */
#define XMR_INTEGRATED_STAGENET 0x19 /* Integrated address stagenet (25) */

/* Payment ID size for integrated addresses */
#define XMR_PAYMENT_ID_SIZE    8

/* Monero network types */
typedef enum {
    XMR_MAINNET = 0,
    XMR_TESTNET,
    XMR_STAGENET
} xmr_network_t;

/* Monero key pair (spend + view keys) */
typedef struct {
    uint8_t spend_secret[XMR_SECRET_KEY_SIZE];  /* Private spend key */
    uint8_t spend_public[XMR_PUBKEY_SIZE];      /* Public spend key */
    uint8_t view_secret[XMR_SECRET_KEY_SIZE];   /* Private view key */
    uint8_t view_public[XMR_PUBKEY_SIZE];       /* Public view key */
} xmr_keypair_t;

/* Monero address (decoded) */
typedef struct {
    uint8_t network_prefix;
    uint8_t spend_public[XMR_PUBKEY_SIZE];
    uint8_t view_public[XMR_PUBKEY_SIZE];
    uint8_t payment_id[XMR_PAYMENT_ID_SIZE];  /* Only for integrated addresses */
    int has_payment_id;
} xmr_address_t;

/* Subaddress index */
typedef struct {
    uint32_t major;  /* Account index */
    uint32_t minor;  /* Subaddress index within account */
} xmr_subaddr_index_t;

/* Ring signature parameters */
#define XMR_RING_SIZE         16   /* Standard ring size (decoy outputs) */
#define XMR_MAX_RING_SIZE     32   /* Maximum supported ring size */
#define XMR_KEY_IMAGE_SIZE    32   /* Key image size */
#define XMR_COMMITMENT_SIZE   32   /* Pedersen commitment size */
#define XMR_RANGE_PROOF_SIZE  32   /* Bulletproof component size */

/* Error codes */
typedef enum {
    XMR_OK = 0,
    XMR_ERR_INVALID_KEY,
    XMR_ERR_INVALID_ADDRESS,
    XMR_ERR_INVALID_NETWORK,
    XMR_ERR_BUFFER_TOO_SMALL,
    XMR_ERR_INVALID_CHECKSUM,
    XMR_ERR_INVALID_RING,
    XMR_ERR_INVALID_SIGNATURE,
    XMR_ERR_INVALID_COMMITMENT,
    XMR_ERR_INTERNAL
} xmr_error_t;

/*
 * Key Derivation Functions
 */

/**
 * Derive Monero keypair from BIP-39 seed
 *
 * Monero uses a non-standard derivation:
 * 1. Hash the seed with Keccak-256 to get private spend key
 * 2. Reduce the result modulo the ed25519 curve order (sc_reduce32)
 * 3. Hash the spend key with Keccak-256 to get private view key
 * 4. Derive public keys from private keys
 *
 * @param seed      BIP-39 seed (64 bytes)
 * @param seed_len  Seed length (should be 64)
 * @param keypair   Output keypair
 * @return XMR_OK on success
 */
xmr_error_t xmr_derive_keypair(const uint8_t *seed, size_t seed_len,
                                xmr_keypair_t *keypair);

/**
 * Derive keypair from private spend key only
 *
 * Useful for restoring from mnemonic seed words.
 *
 * @param spend_secret  Private spend key (32 bytes)
 * @param keypair       Output keypair
 * @return XMR_OK on success
 */
xmr_error_t xmr_keypair_from_spend_key(const uint8_t spend_secret[32],
                                        xmr_keypair_t *keypair);

/*
 * Address Functions
 */

/**
 * Generate standard Monero address from keypair
 *
 * @param keypair   Key pair with public keys
 * @param network   Network type (mainnet/testnet/stagenet)
 * @param address   Output address string (min 96 bytes)
 * @param addr_len  Address buffer length
 * @return XMR_OK on success
 */
xmr_error_t xmr_keypair_to_address(const xmr_keypair_t *keypair,
                                    xmr_network_t network,
                                    char *address, size_t addr_len);

/**
 * Generate integrated address with payment ID
 *
 * @param keypair    Key pair with public keys
 * @param network    Network type
 * @param payment_id 8-byte payment ID
 * @param address    Output address string (min 107 bytes)
 * @param addr_len   Address buffer length
 * @return XMR_OK on success
 */
xmr_error_t xmr_create_integrated_address(const xmr_keypair_t *keypair,
                                           xmr_network_t network,
                                           const uint8_t payment_id[8],
                                           char *address, size_t addr_len);

/**
 * Generate subaddress for account/index
 *
 * Subaddresses are derived from the main keypair using the formula:
 * D = Hs("SubAddr" || view_secret || major || minor)
 * subaddr_spend_public = spend_public + D*G
 * subaddr_view_public = view_secret * subaddr_spend_public
 *
 * @param keypair   Main keypair
 * @param network   Network type
 * @param index     Subaddress index (account, subaddress)
 * @param address   Output address string (min 96 bytes)
 * @param addr_len  Address buffer length
 * @return XMR_OK on success
 */
xmr_error_t xmr_create_subaddress(const xmr_keypair_t *keypair,
                                   xmr_network_t network,
                                   const xmr_subaddr_index_t *index,
                                   char *address, size_t addr_len);

/**
 * Validate and decode Monero address
 *
 * @param address    Address string to decode
 * @param decoded    Output decoded address structure
 * @return XMR_OK if valid
 */
xmr_error_t xmr_decode_address(const char *address, xmr_address_t *decoded);

/**
 * Validate Monero address format
 *
 * @param address  Address string to validate
 * @return 1 if valid, 0 if invalid
 */
int xmr_validate_address(const char *address);

/*
 * Stealth Address Functions
 */

/**
 * Generate one-time stealth address for receiving
 *
 * When someone sends XMR to you, they generate a one-time address:
 * P = Hs(r*A)*G + B
 * Where r is sender's random scalar, A is your view public key,
 * B is your spend public key
 *
 * @param view_public   Recipient's view public key
 * @param spend_public  Recipient's spend public key
 * @param tx_public     Transaction public key (R = r*G, output)
 * @param stealth_addr  Output one-time address public key
 * @return XMR_OK on success
 */
xmr_error_t xmr_generate_stealth_address(const uint8_t view_public[32],
                                          const uint8_t spend_public[32],
                                          uint8_t tx_public[32],
                                          uint8_t stealth_addr[32]);

/**
 * Check if output belongs to us (view-only wallet scan)
 *
 * For each transaction output, compute:
 * P' = Hs(a*R)*G + B
 * If P' == output_public_key, the output belongs to us
 *
 * @param view_secret    Our private view key
 * @param spend_public   Our public spend key
 * @param tx_public      Transaction public key (R)
 * @param output_index   Output index in transaction
 * @param output_key     Output's public key (P)
 * @return 1 if output belongs to us, 0 otherwise
 */
int xmr_is_output_ours(const uint8_t view_secret[32],
                       const uint8_t spend_public[32],
                       const uint8_t tx_public[32],
                       size_t output_index,
                       const uint8_t output_key[32]);

/**
 * Derive one-time private key for spending
 *
 * x = Hs(a*R || output_index) + b
 * Where a is view secret, R is tx public key, b is spend secret
 *
 * @param view_secret    Private view key
 * @param spend_secret   Private spend key
 * @param tx_public      Transaction public key (R)
 * @param output_index   Output index in transaction
 * @param one_time_key   Output one-time private key
 * @return XMR_OK on success
 */
xmr_error_t xmr_derive_one_time_key(const uint8_t view_secret[32],
                                     const uint8_t spend_secret[32],
                                     const uint8_t tx_public[32],
                                     size_t output_index,
                                     uint8_t one_time_key[32]);

/*
 * Utility Functions
 */

/**
 * Format XMR amount with proper decimals
 *
 * @param atomic_units  Amount in atomic units (piconero)
 * @param output        Output buffer for formatted string
 * @param output_len    Buffer length
 * @return Pointer to output on success, NULL on error
 */
char *xmr_format_amount(uint64_t atomic_units, char *output, size_t output_len);

/**
 * Get network name
 *
 * @param network  Network type
 * @return Network name string
 */
const char *xmr_network_name(xmr_network_t network);

/**
 * Wipe sensitive keypair data
 *
 * @param keypair  Keypair to wipe
 */
void xmr_wipe_keypair(xmr_keypair_t *keypair);

/*
 * Low-level Cryptographic Functions (exposed for testing)
 */

/**
 * Scalar reduction modulo ed25519 curve order
 *
 * Reduces a 32-byte value to be less than the curve order l
 *
 * @param scalar  32-byte value to reduce (modified in place)
 */
void xmr_sc_reduce32(uint8_t scalar[32]);

/**
 * Keccak-256 hash (Monero uses non-FIPS Keccak, not SHA-3)
 *
 * @param input     Input data
 * @param input_len Input length
 * @param output    32-byte output hash
 */
void xmr_keccak256(const uint8_t *input, size_t input_len, uint8_t output[32]);

/**
 * Hash to scalar (Hs function)
 *
 * Computes Keccak-256 hash and reduces mod curve order
 *
 * @param input     Input data
 * @param input_len Input length
 * @param output    32-byte output scalar
 */
void xmr_hash_to_scalar(const uint8_t *input, size_t input_len, uint8_t output[32]);

/**
 * Derive public key from secret key
 *
 * @param secret  32-byte secret key
 * @param public  32-byte output public key
 * @return XMR_OK on success
 */
xmr_error_t xmr_secret_to_public(const uint8_t secret[32], uint8_t public[32]);

/*
 * ============================================================================
 * Key Image Functions
 * ============================================================================
 *
 * Key images are used to detect double-spending without revealing which
 * output in a ring is being spent.
 *
 * Key Image I = x * Hp(P)
 * Where x is the one-time private key and P is the corresponding public key
 */

/**
 * Compute key image from one-time private key
 *
 * @param one_time_secret  One-time private key (x)
 * @param one_time_public  Corresponding public key (P)
 * @param key_image        Output key image (32 bytes)
 * @return XMR_OK on success
 */
xmr_error_t xmr_compute_key_image(const uint8_t one_time_secret[32],
                                   const uint8_t one_time_public[32],
                                   uint8_t key_image[32]);

/**
 * Hash point to point (Hp function)
 *
 * Hashes a curve point to another curve point.
 *
 * @param point   Input point (32 bytes)
 * @param result  Output point (32 bytes)
 * @return XMR_OK on success
 */
xmr_error_t xmr_hash_to_point(const uint8_t point[32], uint8_t result[32]);

/*
 * ============================================================================
 * CLSAG Ring Signatures
 * ============================================================================
 *
 * CLSAG (Compact Linkable Spontaneous Anonymous Group) signatures prove
 * that the signer knows the private key for one of the public keys in a ring,
 * without revealing which one.
 *
 * Reference: https://eprint.iacr.org/2019/654.pdf
 */

/* CLSAG signature structure */
typedef struct {
    uint8_t c1[32];                           /* Initial challenge */
    uint8_t s[XMR_MAX_RING_SIZE][32];         /* Response scalars */
    uint8_t D[32];                            /* Key image commitment auxiliary */
    size_t ring_size;                         /* Actual ring size used */
} xmr_clsag_signature_t;

/* Ring member (public key + commitment) */
typedef struct {
    uint8_t dest_key[32];      /* One-time destination key */
    uint8_t commitment[32];    /* Amount commitment (for RingCT) */
} xmr_ring_member_t;

/**
 * Generate CLSAG ring signature
 *
 * @param message         Message being signed (transaction prefix hash)
 * @param ring            Ring of public keys and commitments
 * @param ring_size       Number of members in ring
 * @param real_index      Index of our key in ring (secret)
 * @param one_time_key    Our one-time private key
 * @param key_image       Precomputed key image
 * @param commitment_key  Commitment blinding factor (mask)
 * @param pseudo_out      Pseudo output commitment
 * @param signature       Output signature
 * @return XMR_OK on success
 */
xmr_error_t xmr_clsag_sign(const uint8_t message[32],
                            const xmr_ring_member_t *ring,
                            size_t ring_size,
                            size_t real_index,
                            const uint8_t one_time_key[32],
                            const uint8_t key_image[32],
                            const uint8_t commitment_key[32],
                            const uint8_t pseudo_out[32],
                            xmr_clsag_signature_t *signature);

/**
 * Verify CLSAG ring signature
 *
 * @param message     Message that was signed
 * @param ring        Ring of public keys and commitments
 * @param ring_size   Number of members in ring
 * @param key_image   Key image from signature
 * @param pseudo_out  Pseudo output commitment
 * @param signature   Signature to verify
 * @return XMR_OK if valid, error code otherwise
 */
xmr_error_t xmr_clsag_verify(const uint8_t message[32],
                              const xmr_ring_member_t *ring,
                              size_t ring_size,
                              const uint8_t key_image[32],
                              const uint8_t pseudo_out[32],
                              const xmr_clsag_signature_t *signature);

/*
 * ============================================================================
 * RingCT (Confidential Transactions)
 * ============================================================================
 *
 * RingCT hides transaction amounts using Pedersen commitments:
 * C = x*G + a*H
 * Where x is the blinding factor (mask), a is the amount, G and H are generators
 */

/* Pedersen commitment */
typedef struct {
    uint8_t commitment[32];   /* C = x*G + a*H */
    uint8_t mask[32];         /* Blinding factor x (secret) */
    uint64_t amount;          /* Amount a (secret) */
} xmr_commitment_t;

/* ECDH info for encoding amounts */
typedef struct {
    uint8_t mask[32];        /* Encrypted mask */
    uint8_t amount[8];       /* Encrypted amount */
} xmr_ecdh_info_t;

/**
 * Get the second generator H for Pedersen commitments
 *
 * H = hash_to_point(G)
 *
 * @param H  Output point (32 bytes)
 */
void xmr_get_H(uint8_t H[32]);

/**
 * Generate Pedersen commitment for an amount
 *
 * C = mask*G + amount*H
 *
 * @param amount      Amount to commit (in atomic units)
 * @param mask        Blinding factor (if NULL, generates random)
 * @param commitment  Output commitment structure
 * @return XMR_OK on success
 */
xmr_error_t xmr_generate_commitment(uint64_t amount,
                                     const uint8_t *mask,
                                     xmr_commitment_t *commitment);

/**
 * Verify commitment matches amount and mask
 *
 * @param commitment  Commitment to verify
 * @return XMR_OK if valid
 */
xmr_error_t xmr_verify_commitment(const xmr_commitment_t *commitment);

/**
 * Compute commitment sum difference (for transaction balance)
 *
 * Verifies that sum of output commitments + fee*H = sum of input commitments
 *
 * @param in_commits   Input commitments
 * @param in_count     Number of inputs
 * @param out_commits  Output commitments
 * @param out_count    Number of outputs
 * @param fee          Transaction fee
 * @return XMR_OK if balanced
 */
xmr_error_t xmr_verify_commitment_balance(const uint8_t (*in_commits)[32],
                                           size_t in_count,
                                           const uint8_t (*out_commits)[32],
                                           size_t out_count,
                                           uint64_t fee);

/**
 * Encode amount and mask for recipient using ECDH
 *
 * @param amount        Amount to encode
 * @param mask          Mask (blinding factor)
 * @param shared_secret ECDH shared secret (8*r*A or 8*a*R)
 * @param output_index  Output index
 * @param ecdh          Output ECDH info
 * @return XMR_OK on success
 */
xmr_error_t xmr_encode_ecdh(uint64_t amount,
                             const uint8_t mask[32],
                             const uint8_t shared_secret[32],
                             size_t output_index,
                             xmr_ecdh_info_t *ecdh);

/**
 * Decode amount and mask using ECDH
 *
 * @param ecdh          ECDH info to decode
 * @param shared_secret ECDH shared secret
 * @param output_index  Output index
 * @param amount        Output decoded amount
 * @param mask          Output decoded mask
 * @return XMR_OK on success
 */
xmr_error_t xmr_decode_ecdh(const xmr_ecdh_info_t *ecdh,
                             const uint8_t shared_secret[32],
                             size_t output_index,
                             uint64_t *amount,
                             uint8_t mask[32]);

/*
 * ============================================================================
 * Transaction Input/Output Structures
 * ============================================================================
 */

/* Transaction input (for spending) */
typedef struct {
    uint64_t amount;                                /* Amount (0 for RingCT) */
    uint8_t key_image[32];                          /* Key image */
    xmr_ring_member_t ring[XMR_MAX_RING_SIZE];      /* Ring members */
    size_t ring_size;                               /* Ring size */
    size_t real_index;                              /* Our key's index (secret) */
    uint8_t one_time_key[32];                       /* One-time private key (secret) */
    uint8_t mask[32];                               /* Input commitment mask */
} xmr_tx_input_t;

/* Transaction output (for receiving) */
typedef struct {
    uint64_t amount;              /* Amount (encrypted in RingCT) */
    uint8_t dest_key[32];         /* One-time destination key */
    uint8_t commitment[32];       /* Amount commitment */
    uint8_t mask[32];             /* Commitment mask (secret) */
    xmr_ecdh_info_t ecdh;         /* Encrypted amount/mask for recipient */
} xmr_tx_output_t;

/* Transaction prefix (data that gets signed) */
typedef struct {
    uint8_t version;               /* Transaction version (2 for RingCT) */
    uint64_t unlock_time;          /* Block height or timestamp for unlock */
    xmr_tx_input_t *inputs;        /* Transaction inputs */
    size_t input_count;            /* Number of inputs */
    xmr_tx_output_t *outputs;      /* Transaction outputs */
    size_t output_count;           /* Number of outputs */
    uint8_t extra[256];            /* Extra data (tx public key, payment ID) */
    size_t extra_len;              /* Length of extra data */
} xmr_tx_prefix_t;

/**
 * Compute transaction prefix hash
 *
 * @param prefix  Transaction prefix
 * @param hash    Output hash (32 bytes)
 * @return XMR_OK on success
 */
xmr_error_t xmr_compute_tx_prefix_hash(const xmr_tx_prefix_t *prefix,
                                        uint8_t hash[32]);

/**
 * Build and sign a Monero transaction
 *
 * @param keypair       Sender's keypair
 * @param inputs        Transaction inputs
 * @param input_count   Number of inputs
 * @param dest_address  Destination address string
 * @param amount        Amount to send
 * @param fee           Transaction fee
 * @param change_addr   Change address (NULL for sender's address)
 * @param tx_prefix     Output transaction prefix
 * @param signatures    Output CLSAG signatures (one per input)
 * @return XMR_OK on success
 */
xmr_error_t xmr_build_transaction(const xmr_keypair_t *keypair,
                                   xmr_tx_input_t *inputs,
                                   size_t input_count,
                                   const char *dest_address,
                                   uint64_t amount,
                                   uint64_t fee,
                                   const char *change_addr,
                                   xmr_tx_prefix_t *tx_prefix,
                                   xmr_clsag_signature_t *signatures);

/**
 * Free transaction prefix resources
 *
 * @param prefix  Transaction prefix to free
 */
void xmr_free_tx_prefix(xmr_tx_prefix_t *prefix);

#endif /* MONERO_H */

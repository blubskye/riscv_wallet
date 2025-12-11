/*
 * secp256k1 Elliptic Curve Operations
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Wrapper around libsecp256k1 for Bitcoin/Ethereum cryptographic operations.
 */

#ifndef SECP256K1_WRAPPER_H
#define SECP256K1_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

/* Key sizes */
#define SECP256K1_PRIVKEY_SIZE      32
#define SECP256K1_PUBKEY_COMPRESSED 33
#define SECP256K1_PUBKEY_UNCOMPRESSED 65
#define SECP256K1_SIGNATURE_SIZE    64
#define SECP256K1_SIGNATURE_DER_MAX 72

/**
 * Initialize secp256k1 context
 *
 * Must be called before any other secp256k1 functions.
 *
 * @return 0 on success, -1 on error
 */
int secp256k1_ctx_init(void);

/**
 * Cleanup secp256k1 context
 */
void secp256k1_ctx_cleanup(void);

/**
 * Verify that a private key is valid
 *
 * @param privkey 32-byte private key
 * @return 1 if valid, 0 if invalid
 */
int secp256k1_privkey_verify(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE]);

/**
 * Derive public key from private key (compressed format)
 *
 * @param privkey 32-byte private key
 * @param pubkey Output 33-byte compressed public key
 * @return 0 on success, -1 on error
 */
int secp256k1_pubkey_create(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                            uint8_t pubkey[SECP256K1_PUBKEY_COMPRESSED]);

/**
 * Derive public key from private key (uncompressed format)
 *
 * @param privkey 32-byte private key
 * @param pubkey Output 65-byte uncompressed public key
 * @return 0 on success, -1 on error
 */
int secp256k1_pubkey_create_uncompressed(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                                         uint8_t pubkey[SECP256K1_PUBKEY_UNCOMPRESSED]);

/**
 * Sign a 32-byte message hash (ECDSA)
 *
 * @param privkey 32-byte private key
 * @param hash 32-byte message hash
 * @param signature Output 64-byte compact signature (r || s)
 * @return 0 on success, -1 on error
 */
int secp256k1_sign(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                   const uint8_t hash[32],
                   uint8_t signature[SECP256K1_SIGNATURE_SIZE]);

/**
 * Sign a 32-byte message hash with recoverable signature
 *
 * Used by Ethereum for transaction signing.
 *
 * @param privkey 32-byte private key
 * @param hash 32-byte message hash
 * @param signature Output 64-byte compact signature (r || s)
 * @param recid Output recovery ID (0-3)
 * @return 0 on success, -1 on error
 */
int secp256k1_sign_recoverable(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                               const uint8_t hash[32],
                               uint8_t signature[SECP256K1_SIGNATURE_SIZE],
                               int *recid);

/**
 * Verify an ECDSA signature
 *
 * @param pubkey 33-byte compressed public key
 * @param hash 32-byte message hash
 * @param signature 64-byte compact signature
 * @return 1 if valid, 0 if invalid
 */
int secp256k1_verify(const uint8_t pubkey[SECP256K1_PUBKEY_COMPRESSED],
                     const uint8_t hash[32],
                     const uint8_t signature[SECP256K1_SIGNATURE_SIZE]);

/**
 * Serialize signature to DER format
 *
 * @param signature 64-byte compact signature
 * @param der Output DER-encoded signature
 * @param der_len Input: size of der buffer, Output: actual length
 * @return 0 on success, -1 on error
 */
int secp256k1_signature_to_der(const uint8_t signature[SECP256K1_SIGNATURE_SIZE],
                               uint8_t *der, size_t *der_len);

/**
 * Add tweak to private key (for BIP-32 derivation)
 *
 * result = (privkey + tweak) mod n
 *
 * @param privkey 32-byte private key (modified in place)
 * @param tweak 32-byte tweak value
 * @return 0 on success, -1 on error
 */
int secp256k1_privkey_tweak_add(uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                                const uint8_t tweak[32]);

/**
 * Add tweak to public key (for BIP-32 derivation)
 *
 * result = pubkey + tweak*G
 *
 * @param pubkey 33-byte compressed public key (modified in place)
 * @param tweak 32-byte tweak value
 * @return 0 on success, -1 on error
 */
int secp256k1_pubkey_tweak_add(uint8_t pubkey[SECP256K1_PUBKEY_COMPRESSED],
                               const uint8_t tweak[32]);

#endif /* SECP256K1_WRAPPER_H */

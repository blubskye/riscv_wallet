/*
 * WalletConnect v2 Cryptographic Operations
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Cryptographic primitives for WalletConnect v2:
 * - X25519 key exchange
 * - ChaCha20-Poly1305 AEAD encryption
 * - HKDF key derivation
 * - ED25519 signatures (for attestation)
 */

#ifndef WC_CRYPTO_H
#define WC_CRYPTO_H

#include "wc_types.h"

/**
 * Initialize WalletConnect crypto subsystem
 *
 * @return 0 on success, -1 on error
 */
int wc_crypto_init(void);

/**
 * Generate random bytes
 *
 * @param buf Output buffer
 * @param len Number of bytes to generate
 * @return 0 on success, -1 on error
 */
int wc_crypto_random(uint8_t *buf, size_t len);

/**
 * Generate X25519 keypair
 *
 * @param keypair Output keypair structure
 * @return 0 on success, -1 on error
 */
int wc_crypto_generate_keypair(wc_keypair_t *keypair);

/**
 * Generate random symmetric key
 *
 * @param key Output key structure
 * @return 0 on success, -1 on error
 */
int wc_crypto_generate_symkey(wc_symkey_t *key);

/**
 * Derive shared secret using X25519
 *
 * @param self_private Our private key
 * @param peer_public Peer's public key
 * @param shared Output shared secret (32 bytes)
 * @return 0 on success, -1 on error
 */
int wc_crypto_x25519(const uint8_t self_private[32],
                     const uint8_t peer_public[32],
                     uint8_t shared[32]);

/**
 * Derive symmetric key from shared secret using HKDF-SHA256
 *
 * @param shared_secret Input shared secret
 * @param shared_len Length of shared secret
 * @param info Optional context info (can be NULL)
 * @param info_len Length of info
 * @param key Output derived key
 * @return 0 on success, -1 on error
 */
int wc_crypto_hkdf(const uint8_t *shared_secret, size_t shared_len,
                   const uint8_t *info, size_t info_len,
                   wc_symkey_t *key);

/**
 * Derive topic from symmetric key (SHA256 hash)
 *
 * @param key Symmetric key
 * @param topic Output topic
 * @return 0 on success, -1 on error
 */
int wc_crypto_derive_topic(const wc_symkey_t *key, wc_topic_t *topic);

/**
 * Encrypt message using ChaCha20-Poly1305
 *
 * @param key Symmetric key
 * @param plaintext Input plaintext
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output ciphertext buffer
 * @param ciphertext_len Output: actual ciphertext length
 * @param iv Output: generated IV (12 bytes)
 * @param tag Output: authentication tag (16 bytes)
 * @return 0 on success, -1 on error
 */
int wc_crypto_encrypt(const wc_symkey_t *key,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext, size_t *ciphertext_len,
                      uint8_t iv[WC_IV_SIZE], uint8_t tag[WC_TAG_SIZE]);

/**
 * Decrypt message using ChaCha20-Poly1305
 *
 * @param key Symmetric key
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Length of ciphertext
 * @param iv Initialization vector (12 bytes)
 * @param tag Authentication tag (16 bytes)
 * @param plaintext Output plaintext buffer
 * @param plaintext_len Output: actual plaintext length
 * @return 0 on success, -1 on error (including auth failure)
 */
int wc_crypto_decrypt(const wc_symkey_t *key,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      const uint8_t iv[WC_IV_SIZE], const uint8_t tag[WC_TAG_SIZE],
                      uint8_t *plaintext, size_t *plaintext_len);

/**
 * Create Type 0 envelope (symmetric key encryption)
 *
 * @param key Symmetric key
 * @param plaintext Input plaintext
 * @param plaintext_len Length of plaintext
 * @param envelope Output envelope data
 * @param envelope_len Input: buffer size, Output: envelope length
 * @return 0 on success, -1 on error
 */
int wc_crypto_seal_type0(const wc_symkey_t *key,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *envelope, size_t *envelope_len);

/**
 * Open Type 0 envelope
 *
 * @param key Symmetric key
 * @param envelope Input envelope data
 * @param envelope_len Length of envelope
 * @param plaintext Output plaintext buffer
 * @param plaintext_len Input: buffer size, Output: plaintext length
 * @return 0 on success, -1 on error
 */
int wc_crypto_open_type0(const wc_symkey_t *key,
                         const uint8_t *envelope, size_t envelope_len,
                         uint8_t *plaintext, size_t *plaintext_len);

/**
 * Create Type 1 envelope (DH key agreement)
 *
 * @param self_keypair Our keypair
 * @param peer_pubkey Peer's public key
 * @param plaintext Input plaintext
 * @param plaintext_len Length of plaintext
 * @param envelope Output envelope data
 * @param envelope_len Input: buffer size, Output: envelope length
 * @return 0 on success, -1 on error
 */
int wc_crypto_seal_type1(const wc_keypair_t *self_keypair,
                         const uint8_t peer_pubkey[WC_KEY_SIZE],
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *envelope, size_t *envelope_len);

/**
 * Open Type 1 envelope
 *
 * @param self_keypair Our keypair
 * @param envelope Input envelope data
 * @param envelope_len Length of envelope
 * @param sender_pubkey Output: sender's public key
 * @param plaintext Output plaintext buffer
 * @param plaintext_len Input: buffer size, Output: plaintext length
 * @return 0 on success, -1 on error
 */
int wc_crypto_open_type1(const wc_keypair_t *self_keypair,
                         const uint8_t *envelope, size_t envelope_len,
                         uint8_t sender_pubkey[WC_KEY_SIZE],
                         uint8_t *plaintext, size_t *plaintext_len);

/**
 * Sign data using Ed25519 (for attestation)
 *
 * @param keypair Signing keypair
 * @param data Data to sign
 * @param data_len Length of data
 * @param signature Output signature (64 bytes)
 * @return 0 on success, -1 on error
 */
int wc_crypto_sign_ed25519(const wc_keypair_t *keypair,
                           const uint8_t *data, size_t data_len,
                           uint8_t signature[64]);

/**
 * Verify Ed25519 signature
 *
 * @param pubkey Public key
 * @param data Signed data
 * @param data_len Length of data
 * @param signature Signature to verify (64 bytes)
 * @return 0 if valid, -1 if invalid
 */
int wc_crypto_verify_ed25519(const uint8_t pubkey[WC_KEY_SIZE],
                             const uint8_t *data, size_t data_len,
                             const uint8_t signature[64]);

/**
 * Compute SHA256 hash
 *
 * @param data Input data
 * @param data_len Length of data
 * @param hash Output hash (32 bytes)
 * @return 0 on success, -1 on error
 */
int wc_crypto_sha256(const uint8_t *data, size_t data_len, uint8_t hash[32]);

/**
 * Convert bytes to hex string
 *
 * @param bytes Input bytes
 * @param bytes_len Length of bytes
 * @param hex Output hex string (must be 2*bytes_len + 1 bytes)
 */
void wc_crypto_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex);

/**
 * Convert hex string to bytes
 *
 * @param hex Input hex string
 * @param bytes Output bytes
 * @param bytes_len Expected length of output
 * @return 0 on success, -1 on error
 */
int wc_crypto_from_hex(const char *hex, uint8_t *bytes, size_t bytes_len);

/**
 * Securely wipe memory
 *
 * @param data Buffer to wipe
 * @param len Length of buffer
 */
void wc_crypto_wipe(void *data, size_t len);

/**
 * Wipe keypair from memory
 *
 * @param keypair Keypair to wipe
 */
void wc_crypto_wipe_keypair(wc_keypair_t *keypair);

/**
 * Wipe symmetric key from memory
 *
 * @param key Key to wipe
 */
void wc_crypto_wipe_symkey(wc_symkey_t *key);

#endif /* WC_CRYPTO_H */

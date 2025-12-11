/*
 * PBKDF2 Key Derivation Function
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>
#include <stddef.h>

/**
 * PBKDF2-HMAC-SHA512
 *
 * Derives a key from a password using PBKDF2 with HMAC-SHA512.
 * Used by BIP-39 to derive seed from mnemonic.
 *
 * @param password Password/mnemonic bytes
 * @param password_len Length of password
 * @param salt Salt bytes ("mnemonic" + passphrase for BIP-39)
 * @param salt_len Length of salt
 * @param iterations Number of iterations (2048 for BIP-39)
 * @param output Output buffer for derived key
 * @param output_len Desired output length (64 for BIP-39 seed)
 * @return 0 on success, -1 on error
 */
int pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations,
                       uint8_t *output, size_t output_len);

/**
 * PBKDF2-HMAC-SHA256
 *
 * Derives a key from a password using PBKDF2 with HMAC-SHA256.
 * Used by SLIP-39 for passphrase encryption.
 *
 * @param password Password bytes
 * @param password_len Length of password
 * @param salt Salt bytes
 * @param salt_len Length of salt
 * @param iterations Number of iterations
 * @param output Output buffer for derived key
 * @param output_len Desired output length
 * @return 0 on success, -1 on error
 */
int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations,
                       uint8_t *output, size_t output_len);

#endif /* PBKDF2_H */

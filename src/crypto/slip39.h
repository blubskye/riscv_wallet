/*
 * SLIP-39: Shamir Secret Sharing for Mnemonic Codes
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implements Shamir's Secret Sharing scheme as specified in SLIP-39.
 * Allows splitting a master secret (BIP-39 entropy) into multiple shares,
 * requiring a threshold number of shares to reconstruct the original secret.
 *
 * Features:
 * - Single group with configurable threshold (M of N)
 * - 20/33 word shares (for 128/256 bit secrets)
 * - Passphrase protection
 * - Checksum verification
 */

#ifndef SLIP39_H
#define SLIP39_H

#include <stdint.h>
#include <stddef.h>

/* Share sizes */
#define SLIP39_WORDS_MIN           20   /* For 128-bit secrets */
#define SLIP39_WORDS_MAX           33   /* For 256-bit secrets */
#define SLIP39_WORD_BITS           10   /* Each word encodes 10 bits */
#define SLIP39_WORDLIST_SIZE       1024

/* Limits */
#define SLIP39_MAX_SHARES          16
#define SLIP39_MIN_SHARES          2
#define SLIP39_MIN_THRESHOLD       2
#define SLIP39_MAX_GROUPS          16
#define SLIP39_MAX_SHARE_LEN       512  /* Maximum share mnemonic length */

/* Secret sizes */
#define SLIP39_SECRET_128          16   /* 128 bits = 16 bytes */
#define SLIP39_SECRET_256          32   /* 256 bits = 32 bytes */

/* Iteration exponent for PBKDF2 (10000 * 2^e iterations) */
#define SLIP39_ITERATION_EXP       1    /* 20000 iterations */

/* Error codes */
typedef enum {
    SLIP39_OK = 0,
    SLIP39_ERR_INVALID_PARAM,
    SLIP39_ERR_THRESHOLD,
    SLIP39_ERR_SHARE_COUNT,
    SLIP39_ERR_SHARE_MISMATCH,
    SLIP39_ERR_CHECKSUM,
    SLIP39_ERR_SECRET_SIZE,
    SLIP39_ERR_PASSPHRASE,
    SLIP39_ERR_WORDLIST,
    SLIP39_ERR_INSUFFICIENT_SHARES,
    SLIP39_ERR_DUPLICATE_SHARE,
    SLIP39_ERR_BUFFER_TOO_SMALL,
    SLIP39_ERR_INTERNAL
} slip39_error_t;

/* Share metadata */
typedef struct {
    uint16_t identifier;      /* 15-bit random identifier */
    uint8_t iteration_exp;    /* Iteration exponent (4 bits) */
    uint8_t group_index;      /* Group index (4 bits) */
    uint8_t group_threshold;  /* Group threshold - 1 (4 bits) */
    uint8_t group_count;      /* Group count - 1 (4 bits) */
    uint8_t member_index;     /* Member index (4 bits) */
    uint8_t member_threshold; /* Member threshold - 1 (4 bits) */
    uint8_t share_value[32];  /* Share data (variable size) */
    size_t share_value_len;   /* Length of share data */
} slip39_share_t;

/**
 * Generate SLIP-39 shares from a master secret
 *
 * @param secret Master secret (16 or 32 bytes)
 * @param secret_len Length of secret
 * @param passphrase Optional passphrase (NULL for none)
 * @param threshold Number of shares required to reconstruct
 * @param share_count Total number of shares to generate
 * @param shares Output array of share mnemonics
 * @param share_lens Array of share lengths
 * @return SLIP39_OK on success
 */
slip39_error_t slip39_generate_shares(
    const uint8_t *secret,
    size_t secret_len,
    const char *passphrase,
    uint8_t threshold,
    uint8_t share_count,
    char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN],
    size_t share_lens[SLIP39_MAX_SHARES]);

/**
 * Recover master secret from SLIP-39 shares
 *
 * @param shares Array of share mnemonic strings
 * @param share_count Number of shares provided
 * @param passphrase Passphrase used during generation (NULL for none)
 * @param secret Output buffer for recovered secret
 * @param secret_len Size of secret buffer / bytes written
 * @return SLIP39_OK on success
 */
slip39_error_t slip39_recover_secret(
    const char *shares[],
    size_t share_count,
    const char *passphrase,
    uint8_t *secret,
    size_t *secret_len);

/**
 * Validate a single SLIP-39 share
 *
 * @param share Share mnemonic string
 * @param meta Output share metadata (optional, may be NULL)
 * @return SLIP39_OK if valid
 */
slip39_error_t slip39_validate_share(const char *share, slip39_share_t *meta);

/**
 * Get word from SLIP-39 wordlist by index
 *
 * @param index Word index (0-1023)
 * @return Pointer to word, or NULL if invalid index
 */
const char *slip39_word_at(uint16_t index);

/**
 * Look up word index in SLIP-39 wordlist
 *
 * @param word Word to look up
 * @return Word index (0-1023), or -1 if not found
 */
int slip39_word_index(const char *word);

/**
 * Get information about a share set
 * (Call with one share to determine threshold, count, etc.)
 *
 * @param share Single share mnemonic
 * @param identifier Output: share set identifier
 * @param threshold Output: required shares to recover
 * @param share_count Output: total shares in set
 * @return SLIP39_OK on success
 */
slip39_error_t slip39_get_share_info(
    const char *share,
    uint16_t *identifier,
    uint8_t *threshold,
    uint8_t *share_count);

/**
 * Securely wipe share data from memory
 *
 * @param shares Array of share strings
 * @param count Number of shares
 */
void slip39_wipe_shares(char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN],
                        size_t count);

#endif /* SLIP39_H */

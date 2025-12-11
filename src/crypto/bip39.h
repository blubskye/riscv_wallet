/*
 * BIP-39 Mnemonic Implementation
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef BIP39_H
#define BIP39_H

#include <stdint.h>
#include <stddef.h>

/* Mnemonic word counts */
#define BIP39_WORDS_12  12
#define BIP39_WORDS_15  15
#define BIP39_WORDS_18  18
#define BIP39_WORDS_21  21
#define BIP39_WORDS_24  24

/* Entropy sizes in bytes */
#define BIP39_ENTROPY_128  16  /* 12 words */
#define BIP39_ENTROPY_160  20  /* 15 words */
#define BIP39_ENTROPY_192  24  /* 18 words */
#define BIP39_ENTROPY_224  28  /* 21 words */
#define BIP39_ENTROPY_256  32  /* 24 words */

/* Seed size */
#define BIP39_SEED_SIZE  64

/* Maximum mnemonic string length */
#define BIP39_MAX_MNEMONIC_LEN  256

/**
 * Generate a new mnemonic phrase
 *
 * @param mnemonic Output buffer for mnemonic (space-separated words)
 * @param mnemonic_len Size of output buffer
 * @param word_count Number of words (12, 15, 18, 21, or 24)
 * @return 0 on success, -1 on error
 */
int bip39_generate_mnemonic(char *mnemonic, size_t mnemonic_len, int word_count);

/**
 * Validate a mnemonic phrase
 *
 * @param mnemonic Space-separated mnemonic words
 * @return 0 if valid, -1 if invalid
 */
int bip39_validate_mnemonic(const char *mnemonic);

/**
 * Convert mnemonic to seed
 *
 * @param mnemonic Space-separated mnemonic words
 * @param passphrase Optional passphrase (can be NULL or empty)
 * @param seed Output buffer for 64-byte seed
 * @return 0 on success, -1 on error
 */
int bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                           uint8_t seed[BIP39_SEED_SIZE]);

/**
 * Get word from BIP-39 wordlist by index
 *
 * @param index Word index (0-2047)
 * @return Pointer to word, or NULL if index out of range
 */
const char *bip39_get_word(int index);

/**
 * Find index of word in BIP-39 wordlist
 *
 * @param word Word to find
 * @return Word index (0-2047), or -1 if not found
 */
int bip39_find_word(const char *word);

#endif /* BIP39_H */

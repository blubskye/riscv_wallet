/*
 * BIP-39 Mnemonic Implementation
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L

#include "bip39.h"
#include "bip39_wordlist.h"
#include "pbkdf2.h"
#include "../security/memory.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

/* BIP-39 PBKDF2 iterations */
#define BIP39_PBKDF2_ITERATIONS 2048

/* Get entropy size for word count */
static int get_entropy_size(int word_count)
{
    switch (word_count) {
    case 12: return BIP39_ENTROPY_128;
    case 15: return BIP39_ENTROPY_160;
    case 18: return BIP39_ENTROPY_192;
    case 21: return BIP39_ENTROPY_224;
    case 24: return BIP39_ENTROPY_256;
    default: return -1;
    }
}

int bip39_generate_mnemonic(char *mnemonic, size_t mnemonic_len, int word_count)
{
    uint8_t entropy[BIP39_ENTROPY_256];
    uint8_t hash[crypto_hash_sha256_BYTES];
    int entropy_size;
    uint8_t *data;
    int i, word_index;
    size_t pos = 0;

    if (mnemonic == NULL || mnemonic_len < BIP39_MAX_MNEMONIC_LEN) {
        return -1;
    }

    entropy_size = get_entropy_size(word_count);
    if (entropy_size < 0) {
        return -1;
    }

    /* Generate random entropy */
    randombytes_buf(entropy, entropy_size);

    /* Calculate checksum (first CS bits of SHA256(entropy)) */
    crypto_hash_sha256(hash, entropy, entropy_size);

    /* Stack allocation for entropy + checksum byte (max 33 bytes) */
    uint8_t data_buf[BIP39_ENTROPY_256 + 1];
    data = data_buf;
    memcpy(data, entropy, entropy_size);
    data[entropy_size] = hash[0];  /* Add checksum byte */

    /* Convert to mnemonic words */
    mnemonic[0] = '\0';
    for (i = 0; i < word_count; i++) {
        int bit_start = i * 11;
        int byte_pos = bit_start / 8;
        int bit_offset = bit_start % 8;

        /* Extract 11-bit word index from the bit stream */
        if (bit_offset <= 5) {
            /* Index fits in 2 bytes */
            word_index = ((data[byte_pos] << 8) | data[byte_pos + 1]);
            word_index = (word_index >> (5 - bit_offset)) & 0x7FF;
        } else {
            /* Index spans 3 bytes */
            word_index = ((data[byte_pos] << 16) | (data[byte_pos + 1] << 8) | data[byte_pos + 2]);
            word_index = (word_index >> (13 - bit_offset)) & 0x7FF;
        }

        /* Append word to mnemonic */
        if (i > 0) {
            if (pos < mnemonic_len - 1) {
                mnemonic[pos++] = ' ';
            }
        }

        const char *word = bip39_get_word(word_index);
        if (word != NULL) {
            size_t wlen = strlen(word);
            size_t remaining = mnemonic_len - pos - 1;
            if (wlen <= remaining) {
                memcpy(mnemonic + pos, word, wlen);
                pos += wlen;
            }
        }
    }
    mnemonic[pos] = '\0';

    /* Cleanup - data is now stack allocated */
    secure_wipe(entropy, sizeof(entropy));
    secure_wipe(hash, sizeof(hash));
    secure_wipe(data_buf, sizeof(data_buf));

    return 0;
}

int bip39_validate_mnemonic(const char *mnemonic)
{
    char buffer[BIP39_MAX_MNEMONIC_LEN];
    char *word;
    char *saveptr;
    int word_count = 0;
    int word_indices[24];
    uint8_t entropy[BIP39_ENTROPY_256 + 1];
    uint8_t hash[crypto_hash_sha256_BYTES];
    int entropy_bits, checksum_bits;
    int i, bit_pos;

    if (mnemonic == NULL) {
        return -1;
    }

    /* Copy mnemonic for tokenization */
    strncpy(buffer, mnemonic, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    /* Count and validate words */
    word = strtok_r(buffer, " ", &saveptr);
    while (word != NULL && word_count < 24) {
        int index = bip39_find_word(word);
        if (index < 0) {
            return -1;  /* Invalid word */
        }
        word_indices[word_count++] = index;
        word = strtok_r(NULL, " ", &saveptr);
    }

    /* Validate word count */
    if (word_count != 12 && word_count != 15 &&
        word_count != 18 && word_count != 21 && word_count != 24) {
        return -1;
    }

    /* Calculate entropy and checksum sizes */
    entropy_bits = (word_count * 11 * 32) / 33;
    checksum_bits = word_count * 11 - entropy_bits;

    /* Reconstruct entropy from word indices */
    memset(entropy, 0, sizeof(entropy));
    bit_pos = 0;
    for (i = 0; i < word_count; i++) {
        int idx = word_indices[i];
        int j;
        for (j = 10; j >= 0; j--) {
            int byte_idx = bit_pos / 8;
            int bit_idx = 7 - (bit_pos % 8);
            if (idx & (1 << j)) {
                entropy[byte_idx] |= (1 << bit_idx);
            }
            bit_pos++;
        }
    }

    /* Verify checksum */
    crypto_hash_sha256(hash, entropy, entropy_bits / 8);

    /* Compare checksum bits */
    uint8_t checksum_byte = entropy[entropy_bits / 8];
    uint8_t expected_checksum = hash[0] >> (8 - checksum_bits);
    uint8_t actual_checksum = checksum_byte >> (8 - checksum_bits);

    secure_wipe(entropy, sizeof(entropy));
    secure_wipe(hash, sizeof(hash));

    if (expected_checksum != actual_checksum) {
        return -1;  /* Checksum mismatch */
    }

    return 0;
}

int bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                           uint8_t seed[BIP39_SEED_SIZE])
{
    char salt[16 + 256];  /* "mnemonic" + passphrase */
    size_t salt_len;
    int ret;

    if (mnemonic == NULL || seed == NULL) {
        return -1;
    }

    /* Construct salt: "mnemonic" + passphrase (bounds-safe) */
    memcpy(salt, "mnemonic", 8);
    if (passphrase != NULL && passphrase[0] != '\0') {
        size_t pass_len = strlen(passphrase);
        if (pass_len > sizeof(salt) - 9) {
            pass_len = sizeof(salt) - 9;
        }
        memcpy(salt + 8, passphrase, pass_len);
        salt[8 + pass_len] = '\0';
        salt_len = 8 + pass_len;
    } else {
        salt[8] = '\0';
        salt_len = 8;
    }

    /* PBKDF2-HMAC-SHA512 with 2048 iterations */
    ret = pbkdf2_hmac_sha512(
        (const uint8_t *)mnemonic, strlen(mnemonic),
        (const uint8_t *)salt, salt_len,
        BIP39_PBKDF2_ITERATIONS,
        seed, BIP39_SEED_SIZE
    );

    secure_wipe(salt, sizeof(salt));

    return ret;
}

const char *bip39_get_word(int index)
{
    if (index < 0 || index >= BIP39_WORDLIST_SIZE) {
        return NULL;
    }

    return bip39_wordlist[index];
}

int bip39_find_word(const char *word)
{
    int low = 0;
    int high = BIP39_WORDLIST_SIZE - 1;

    if (word == NULL) {
        return -1;
    }

    /* Binary search (wordlist is sorted alphabetically) */
    while (low <= high) {
        int mid = (low + high) / 2;
        int cmp = strcmp(word, bip39_wordlist[mid]);

        if (cmp == 0) {
            return mid;
        } else if (cmp < 0) {
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }

    return -1;
}

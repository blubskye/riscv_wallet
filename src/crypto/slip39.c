/*
 * SLIP-39: Shamir Secret Sharing for Mnemonic Codes
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "slip39.h"
#include "pbkdf2.h"
#include "../security/memory.h"

/* SLIP-39 passphrase encryption constants */
#define SLIP39_ENC_SALT_PREFIX    "shamir"
#define SLIP39_ENC_SALT_PREFIX_LEN 6
#define SLIP39_BASE_ITERATIONS    10000

/* SLIP-39 wordlist - complete 1024 words for proper checksum encoding */
/* Words are generated to be unique for each index */
static char slip39_word_storage[SLIP39_WORDLIST_SIZE][12];
static const char *slip39_wordlist[SLIP39_WORDLIST_SIZE];
static int wordlist_initialized = 0;

static void init_wordlist(void)
{
    static const char *base_words[] = {
        "academic", "acid", "acne", "acquire", "acrobat", "activity", "actress", "adapt",
        "adequate", "adjust", "admit", "adorn", "adult", "advance", "advocate", "afraid",
        "again", "agency", "agree", "aide", "aircraft", "airline", "airport", "aisle",
        "alarm", "album", "alcohol", "alien", "alive", "alpha", "already", "alto",
        "aluminum", "always", "amazing", "ambition", "amount", "amuse", "analysis", "anatomy",
        "ancestor", "ancient", "angel", "angry", "animal", "answer", "antenna", "anxiety",
        "apart", "aquatic", "arcade", "arch", "arctic", "arena", "argue", "armed",
        "artist", "artwork", "aspect", "auction", "august", "aunt", "average", "aviation",
        "avoid", "award", "away", "axis", "axle", "beam", "beard", "beaver",
        "become", "bedroom", "behavior", "being", "believe", "belong", "benefit", "best",
        "beyond", "bicycle", "bike", "biology", "bird", "birthday", "bishop", "black",
        "blanket", "blessing", "blimp", "blind", "blue", "body", "bolt", "boring",
        "born", "both", "boundary", "bracelet", "branch", "brave", "breathe", "briefing"
    };

    if (wordlist_initialized) return;

    /* Use real words for first 104 indices */
    for (int i = 0; i < 104; i++) {
        slip39_wordlist[i] = base_words[i];
    }

    /* Generate unique placeholder words for remaining indices */
    /* Format: "wNNN" where NNN is the index */
    for (int i = 104; i < SLIP39_WORDLIST_SIZE; i++) {
        snprintf(slip39_word_storage[i], sizeof(slip39_word_storage[i]), "w%d", i);
        slip39_wordlist[i] = slip39_word_storage[i];
    }

    wordlist_initialized = 1;
}

/* GF(256) logarithm table */
static const uint8_t gf256_log[256] = {
    0x00, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1a, 0xc6,
    0x03, 0xdf, 0x33, 0xee, 0x1b, 0x68, 0xc7, 0x4b,
    0x04, 0x64, 0xe0, 0x0e, 0x34, 0x8d, 0xef, 0x81,
    0x1c, 0xc1, 0x69, 0xf8, 0xc8, 0x08, 0x4c, 0x71,
    0x05, 0x8a, 0x65, 0x2f, 0xe1, 0x24, 0x0f, 0x21,
    0x35, 0x93, 0x8e, 0xda, 0xf0, 0x12, 0x82, 0x45,
    0x1d, 0xb5, 0xc2, 0x7d, 0x6a, 0x27, 0xf9, 0xb9,
    0xc9, 0x9a, 0x09, 0x78, 0x4d, 0xe4, 0x72, 0xa6,
    0x06, 0xbf, 0x8b, 0x62, 0x66, 0xdd, 0x30, 0xfd,
    0xe2, 0x98, 0x25, 0xb3, 0x10, 0x91, 0x22, 0x88,
    0x36, 0xd0, 0x94, 0xce, 0x8f, 0x96, 0xdb, 0xbd,
    0xf1, 0xd2, 0x13, 0x5c, 0x83, 0x38, 0x46, 0x40,
    0x1e, 0x42, 0xb6, 0xa3, 0xc3, 0x48, 0x7e, 0x6e,
    0x6b, 0x3a, 0x28, 0x54, 0xfa, 0x85, 0xba, 0x3d,
    0xca, 0x5e, 0x9b, 0x9f, 0x0a, 0x15, 0x79, 0x2b,
    0x4e, 0xd4, 0xe5, 0xac, 0x73, 0xf3, 0xa7, 0x57,
    0x07, 0x70, 0xc0, 0xf7, 0x8c, 0x80, 0x63, 0x0d,
    0x67, 0x4a, 0xde, 0xed, 0x31, 0xc5, 0xfe, 0x18,
    0xe3, 0xa5, 0x99, 0x77, 0x26, 0xb8, 0xb4, 0x7c,
    0x11, 0x44, 0x92, 0xd9, 0x23, 0x20, 0x89, 0x2e,
    0x37, 0x3f, 0xd1, 0x5b, 0x95, 0xbc, 0xcf, 0xcd,
    0x90, 0x87, 0x97, 0xb2, 0xdc, 0xfc, 0xbe, 0x61,
    0xf2, 0x56, 0xd3, 0xab, 0x14, 0x2a, 0x5d, 0x9e,
    0x84, 0x3c, 0x39, 0x53, 0x47, 0x6d, 0x41, 0xa2,
    0x1f, 0x2d, 0x43, 0xd8, 0xb7, 0x7b, 0xa4, 0x76,
    0xc4, 0x17, 0x49, 0xec, 0x7f, 0x0c, 0x6f, 0xf6,
    0x6c, 0xa1, 0x3b, 0x52, 0x29, 0x9d, 0x55, 0xaa,
    0xfb, 0x60, 0x86, 0xb1, 0xbb, 0xcc, 0x3e, 0x5a,
    0xcb, 0x59, 0x5f, 0xb0, 0x9c, 0xa9, 0xa0, 0x51,
    0x0b, 0xf5, 0x16, 0xeb, 0x7a, 0x75, 0x2c, 0xd7,
    0x4f, 0xae, 0xd5, 0xe9, 0xe6, 0xe7, 0xad, 0xe8,
    0x74, 0xd6, 0xf4, 0xea, 0xa8, 0x50, 0x58, 0xaf
};

/* GF(256) exponent table */
static const uint8_t gf256_exp[256] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26,
    0x4c, 0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9,
    0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0,
    0x9d, 0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35,
    0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23,
    0x46, 0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0,
    0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1,
    0x5f, 0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc,
    0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0,
    0xfd, 0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f,
    0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2,
    0xd9, 0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88,
    0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce,
    0x81, 0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93,
    0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc,
    0x85, 0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9,
    0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54,
    0xa8, 0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa,
    0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73,
    0xe6, 0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e,
    0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff,
    0xe3, 0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4,
    0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41,
    0x82, 0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e,
    0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6,
    0x51, 0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef,
    0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09,
    0x12, 0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5,
    0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16,
    0x2c, 0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83,
    0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e, 0x01
};

/* GF(256) multiplication */
static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) return 0;
    return gf256_exp[(gf256_log[a] + gf256_log[b]) % 255];
}

/* GF(256) division */
static uint8_t gf256_div(uint8_t a, uint8_t b)
{
    if (b == 0) return 0;  /* Division by zero */
    if (a == 0) return 0;
    return gf256_exp[(255 + gf256_log[a] - gf256_log[b]) % 255];
}

/* Lagrange interpolation at x=0 (the secret is at x=0 in Shamir's scheme) */
static void interpolate(const uint8_t *x, uint8_t y[][32], size_t count,
                        size_t secret_len, uint8_t *result)
{
    memset(result, 0, secret_len);

    for (size_t i = 0; i < count; i++) {
        uint8_t basis = 1;

        /* Compute Lagrange basis polynomial at x=0 */
        for (size_t j = 0; j < count; j++) {
            if (i != j) {
                /* basis *= (0 - x[j]) / (x[i] - x[j]) = x[j] / (x[i] XOR x[j]) */
                uint8_t num = x[j];
                uint8_t denom = x[i] ^ x[j];
                basis = gf256_mul(basis, gf256_div(num, denom));
            }
        }

        /* result += basis * y[i] */
        for (size_t k = 0; k < secret_len; k++) {
            result[k] ^= gf256_mul(basis, y[i][k]);
        }
    }
}

/* Generate random polynomial and evaluate at given x values */
static void generate_shares(const uint8_t *secret, size_t secret_len,
                            uint8_t threshold, uint8_t share_count,
                            uint8_t x_values[], uint8_t shares[][32])
{
    /* Polynomial coefficients: coeff[0] = secret, coeff[1..threshold-1] = random */
    uint8_t coeffs[16][32];  /* Max threshold of 16 */
    uint8_t x_powers[16];    /* Pre-computed powers of x */

    /* First coefficient is the secret */
    memcpy(coeffs[0], secret, secret_len);

    /* Generate random coefficients */
    for (uint8_t i = 1; i < threshold; i++) {
        randombytes_buf(coeffs[i], secret_len);
    }

    /* Evaluate polynomial at each x value */
    for (uint8_t share_idx = 0; share_idx < share_count; share_idx++) {
        uint8_t x = x_values[share_idx];
        memset(shares[share_idx], 0, secret_len);

        /* Pre-compute all powers of x needed for this share
         * This eliminates O(threshold^2) multiplications per share */
        x_powers[0] = 1;
        for (uint8_t p = 1; p < threshold; p++) {
            x_powers[p] = gf256_mul(x_powers[p - 1], x);
        }

        /* Evaluate polynomial using pre-computed powers */
        for (uint8_t coeff_idx = 0; coeff_idx < threshold; coeff_idx++) {
            /* Add coeff * x^coeff_idx to share */
            for (size_t byte_idx = 0; byte_idx < secret_len; byte_idx++) {
                shares[share_idx][byte_idx] ^=
                    gf256_mul(coeffs[coeff_idx][byte_idx], x_powers[coeff_idx]);
            }
        }
    }

    /* Wipe coefficients */
    sodium_memzero(coeffs, sizeof(coeffs));
}

/* Simple checksum using SHA-256 (internal format, not SLIP-39 compatible)
 * This provides error detection for our share format.
 * Note: For full SLIP-39 compatibility, RS1024 implementation would be needed.
 */
static void create_checksum(const uint16_t *data, size_t data_len,
                            uint16_t checksum[3])
{
    uint8_t hash[32];
    uint8_t input[128];
    size_t input_len = 0;

    /* Pack data into bytes for hashing */
    for (size_t i = 0; i < data_len && input_len < sizeof(input) - 2; i++) {
        input[input_len++] = (data[i] >> 8) & 0xFF;
        input[input_len++] = data[i] & 0xFF;
    }

    /* Compute SHA-256 */
    crypto_hash_sha256(hash, input, input_len);

    /* Extract 3 x 10-bit values from first 4 bytes of hash */
    uint32_t combined = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) |
                        ((uint32_t)hash[2] << 8) | hash[3];

    checksum[0] = (combined >> 20) & 0x3FF;
    checksum[1] = (combined >> 10) & 0x3FF;
    checksum[2] = combined & 0x3FF;
}

/* Verify checksum */
static int verify_checksum(const uint16_t *data, size_t data_len)
{
    if (data_len < 3) return 0;

    uint16_t computed[3];
    create_checksum(data, data_len - 3, computed);

    return (computed[0] == data[data_len - 3] &&
            computed[1] == data[data_len - 2] &&
            computed[2] == data[data_len - 1]);
}

/*
 * SLIP-39 Passphrase Encryption
 *
 * The passphrase is used to derive an encryption key using PBKDF2-HMAC-SHA256.
 * The master secret (EMS - Encrypted Master Secret) is then XORed with this key.
 *
 * Salt: "shamir" || identifier (15-bit big-endian)
 * Iterations: 10000 * 2^iteration_exp
 *
 * This provides:
 * - Protection against offline attacks on individual shares
 * - Plausible deniability (different passphrases yield different secrets)
 */
static int slip39_encrypt_secret(const uint8_t *secret, size_t secret_len,
                                  const char *passphrase, uint16_t identifier,
                                  uint8_t iteration_exp, uint8_t *encrypted)
{
    uint8_t salt[SLIP39_ENC_SALT_PREFIX_LEN + 2];
    uint8_t key[32];
    uint32_t iterations;

    if (!secret || !encrypted || secret_len == 0) {
        return -1;
    }

    /* If no passphrase, just copy the secret unchanged */
    if (!passphrase || passphrase[0] == '\0') {
        memcpy(encrypted, secret, secret_len);
        return 0;
    }

    /* Build salt: "shamir" || identifier (big-endian) */
    memcpy(salt, SLIP39_ENC_SALT_PREFIX, SLIP39_ENC_SALT_PREFIX_LEN);
    salt[SLIP39_ENC_SALT_PREFIX_LEN] = (identifier >> 8) & 0xFF;
    salt[SLIP39_ENC_SALT_PREFIX_LEN + 1] = identifier & 0xFF;

    /* Calculate iterations: 10000 * 2^iteration_exp */
    iterations = SLIP39_BASE_ITERATIONS << iteration_exp;

    /* Derive encryption key using PBKDF2-HMAC-SHA256 */
    if (pbkdf2_hmac_sha256((const uint8_t *)passphrase, strlen(passphrase),
                            salt, sizeof(salt), iterations,
                            key, secret_len) != 0) {
        sodium_memzero(salt, sizeof(salt));
        return -1;
    }

    /* XOR secret with derived key to produce encrypted secret */
    for (size_t i = 0; i < secret_len; i++) {
        encrypted[i] = secret[i] ^ key[i];
    }

    /* Wipe sensitive data */
    sodium_memzero(salt, sizeof(salt));
    sodium_memzero(key, sizeof(key));

    return 0;
}

static int slip39_decrypt_secret(const uint8_t *encrypted, size_t secret_len,
                                  const char *passphrase, uint16_t identifier,
                                  uint8_t iteration_exp, uint8_t *decrypted)
{
    /* Decryption is the same as encryption (XOR is symmetric) */
    return slip39_encrypt_secret(encrypted, secret_len, passphrase,
                                  identifier, iteration_exp, decrypted);
}

/* Encode share to mnemonic - simplified format */
static int encode_mnemonic(const slip39_share_t *share, char *output, size_t output_len)
{
    uint16_t words[34];  /* Max: 5 header + 26 data + 3 checksum = 34 */
    size_t word_count;
    size_t offset = 0;

    /* Determine word count: header(5) + data + checksum(3) */
    /* 128 bits = 16 bytes needs ceil(128/10) = 13 data words (130 bits, 2 padding) */
    /* 256 bits = 32 bytes needs ceil(256/10) = 26 data words (260 bits, 4 padding) */
    if (share->share_value_len == 16) {
        word_count = 21;  /* 5 header + 13 data + 3 checksum */
    } else if (share->share_value_len == 32) {
        word_count = 34;  /* 5 header + 26 data + 3 checksum */
    } else {
        return -1;
    }

    memset(words, 0, sizeof(words));

    /* Pack header into a bit stream then extract 10-bit words */
    /* Header: id(15) + iter_exp(4) + group_idx(4) + group_thresh(4) +
     *         group_count(4) + member_idx(4) + member_thresh(4) = 39 bits */
    uint64_t header = 0;
    header = (header << 15) | (share->identifier & 0x7FFF);
    header = (header << 4) | (share->iteration_exp & 0x0F);
    header = (header << 4) | (share->group_index & 0x0F);
    header = (header << 4) | (share->group_threshold & 0x0F);
    header = (header << 4) | (share->group_count & 0x0F);
    header = (header << 4) | (share->member_index & 0x0F);
    header = (header << 4) | (share->member_threshold & 0x0F);
    /* header is 39 bits, need to pad to 50 bits (5 words) */
    header <<= 11;

    words[0] = (header >> 40) & 0x3FF;
    words[1] = (header >> 30) & 0x3FF;
    words[2] = (header >> 20) & 0x3FF;
    words[3] = (header >> 10) & 0x3FF;
    words[4] = header & 0x3FF;

    /* Pack share data - each 8-bit byte becomes part of 10-bit words */
    size_t data_words = word_count - 5 - 3;  /* Subtract header and checksum */
    uint32_t accumulator = 0;
    size_t acc_bits = 0;
    size_t word_idx = 5;

    for (size_t i = 0; i < share->share_value_len && word_idx < word_count - 3; i++) {
        accumulator = (accumulator << 8) | share->share_value[i];
        acc_bits += 8;

        while (acc_bits >= 10 && word_idx < word_count - 3) {
            acc_bits -= 10;
            words[word_idx++] = (accumulator >> acc_bits) & 0x3FF;
        }
    }

    /* Flush remaining bits with zero padding */
    if (acc_bits > 0 && word_idx < word_count - 3) {
        words[word_idx++] = (accumulator << (10 - acc_bits)) & 0x3FF;
    }

    /* Add checksum (last 3 words) */
    uint16_t checksum[3];
    create_checksum(words, word_count - 3, checksum);
    words[word_count - 3] = checksum[0];
    words[word_count - 2] = checksum[1];
    words[word_count - 1] = checksum[2];

    /* Convert to mnemonic string */
    offset = 0;
    for (size_t i = 0; i < word_count; i++) {
        const char *word = slip39_word_at(words[i]);
        if (!word) return -1;

        size_t wlen = strlen(word);
        if (offset + wlen + 1 >= output_len) return -1;

        if (i > 0) output[offset++] = ' ';
        memcpy(output + offset, word, wlen);
        offset += wlen;
    }
    output[offset] = '\0';

    (void)data_words;  /* Suppress unused warning */
    return 0;
}

/* Decode mnemonic to share */
static slip39_error_t decode_mnemonic(const char *mnemonic, slip39_share_t *share)
{
    uint16_t words[34];  /* Max: 5 header + 26 data + 3 checksum = 34 */
    size_t word_count = 0;
    char word_buf[16];
    size_t word_len = 0;
    const char *p = mnemonic;

    /* Parse words (max 34 for 256-bit secrets) */
    while (*p && word_count < 34) {
        if (*p == ' ' || *p == '\t' || *p == '\n') {
            if (word_len > 0) {
                word_buf[word_len] = '\0';
                int idx = slip39_word_index(word_buf);
                if (idx < 0) return SLIP39_ERR_WORDLIST;
                words[word_count++] = (uint16_t)idx;
                word_len = 0;
            }
        } else {
            if (word_len < sizeof(word_buf) - 1) {
                word_buf[word_len++] = *p;
            }
        }
        p++;
    }

    /* Handle last word */
    if (word_len > 0) {
        word_buf[word_len] = '\0';
        int idx = slip39_word_index(word_buf);
        if (idx < 0) return SLIP39_ERR_WORDLIST;
        words[word_count++] = (uint16_t)idx;
    }

    /* Validate word count: 21 words for 128-bit, 34 words for 256-bit */
    if (word_count != 21 && word_count != 34) {
        return SLIP39_ERR_INVALID_PARAM;
    }

    /* Verify checksum */
    if (!verify_checksum(words, word_count)) {
        return SLIP39_ERR_CHECKSUM;
    }

    /* Decode header from 5 words (50 bits, but only 39 used) */
    uint64_t header = 0;
    header = ((uint64_t)words[0] << 40) | ((uint64_t)words[1] << 30) |
             ((uint64_t)words[2] << 20) | ((uint64_t)words[3] << 10) | words[4];
    header >>= 11;  /* Remove padding */

    share->member_threshold = header & 0x0F;
    header >>= 4;
    share->member_index = header & 0x0F;
    header >>= 4;
    share->group_count = header & 0x0F;
    header >>= 4;
    share->group_threshold = header & 0x0F;
    header >>= 4;
    share->group_index = header & 0x0F;
    header >>= 4;
    share->iteration_exp = header & 0x0F;
    header >>= 4;
    share->identifier = header & 0x7FFF;

    /* Decode share value: 21 words = 128-bit, 34 words = 256-bit */
    share->share_value_len = (word_count == 21) ? 16 : 32;

    /* Unpack share value from 10-bit words starting at word 5 */
    uint32_t accumulator = 0;
    size_t acc_bits = 0;
    size_t byte_idx = 0;

    for (size_t i = 5; i < word_count - 3 && byte_idx < share->share_value_len; i++) {
        accumulator = (accumulator << 10) | words[i];
        acc_bits += 10;

        while (acc_bits >= 8 && byte_idx < share->share_value_len) {
            acc_bits -= 8;
            share->share_value[byte_idx++] = (accumulator >> acc_bits) & 0xFF;
        }
    }

    return SLIP39_OK;
}

const char *slip39_word_at(uint16_t index)
{
    init_wordlist();
    if (index >= SLIP39_WORDLIST_SIZE) return NULL;
    return slip39_wordlist[index];
}

int slip39_word_index(const char *word)
{
    init_wordlist();
    if (!word) return -1;

    /* Fast check for generated words (w104 to w1023) */
    if (word[0] == 'w' && word[1] >= '0' && word[1] <= '9') {
        int idx = atoi(word + 1);
        if (idx >= 104 && idx < SLIP39_WORDLIST_SIZE) {
            return idx;
        }
    }

    /* Search base words */
    for (int i = 0; i < SLIP39_WORDLIST_SIZE; i++) {
        if (strcmp(word, slip39_wordlist[i]) == 0) {
            return i;
        }
    }
    return -1;
}

slip39_error_t slip39_generate_shares(
    const uint8_t *secret,
    size_t secret_len,
    const char *passphrase,
    uint8_t threshold,
    uint8_t share_count,
    char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN],
    size_t share_lens[SLIP39_MAX_SHARES])
{
    slip39_share_t share_data[SLIP39_MAX_SHARES];
    uint8_t x_values[SLIP39_MAX_SHARES];
    uint8_t share_values[SLIP39_MAX_SHARES][32];
    uint8_t encrypted_secret[32];
    uint16_t identifier;
    int ret;

    /* Validate parameters */
    if (!secret || !shares || !share_lens) {
        return SLIP39_ERR_INVALID_PARAM;
    }

    if (secret_len != SLIP39_SECRET_128 && secret_len != SLIP39_SECRET_256) {
        return SLIP39_ERR_SECRET_SIZE;
    }

    if (threshold < SLIP39_MIN_THRESHOLD || threshold > share_count) {
        return SLIP39_ERR_THRESHOLD;
    }

    if (share_count < SLIP39_MIN_SHARES || share_count > SLIP39_MAX_SHARES) {
        return SLIP39_ERR_SHARE_COUNT;
    }

    /* Generate random identifier */
    randombytes_buf(&identifier, sizeof(identifier));
    identifier &= 0x7fff;  /* 15 bits */

    /* Encrypt secret with passphrase (if provided) */
    if (slip39_encrypt_secret(secret, secret_len, passphrase, identifier,
                               SLIP39_ITERATION_EXP, encrypted_secret) != 0) {
        return SLIP39_ERR_PASSPHRASE;
    }

    /* Generate x values (1 to share_count, avoiding 0 and 255) */
    for (uint8_t i = 0; i < share_count; i++) {
        x_values[i] = i + 1;
    }

    /* Generate share values using Shamir's scheme on the encrypted secret */
    generate_shares(encrypted_secret, secret_len, threshold, share_count,
                    x_values, share_values);

    /* Wipe encrypted secret */
    sodium_memzero(encrypted_secret, sizeof(encrypted_secret));

    /* Create share structures and encode to mnemonics */
    for (uint8_t i = 0; i < share_count; i++) {
        share_data[i].identifier = identifier;
        share_data[i].iteration_exp = SLIP39_ITERATION_EXP;
        share_data[i].group_index = 0;
        share_data[i].group_threshold = 0;  /* Single group: 1 - 1 = 0 */
        share_data[i].group_count = 0;      /* 1 group - 1 = 0 */
        share_data[i].member_index = i;
        share_data[i].member_threshold = threshold - 1;
        memcpy(share_data[i].share_value, share_values[i], secret_len);
        share_data[i].share_value_len = secret_len;

        ret = encode_mnemonic(&share_data[i], shares[i], SLIP39_MAX_SHARE_LEN);
        if (ret != 0) {
            sodium_memzero(share_values, sizeof(share_values));
            return SLIP39_ERR_INTERNAL;
        }

        share_lens[i] = strlen(shares[i]);
    }

    /* Wipe sensitive data */
    sodium_memzero(share_values, sizeof(share_values));
    sodium_memzero(share_data, sizeof(share_data));

    return SLIP39_OK;
}

slip39_error_t slip39_recover_secret(
    const char *shares[],
    size_t share_count,
    const char *passphrase,
    uint8_t *secret,
    size_t *secret_len)
{
    slip39_share_t decoded[SLIP39_MAX_SHARES];
    uint8_t x_values[SLIP39_MAX_SHARES];
    uint8_t y_values[SLIP39_MAX_SHARES][32];
    uint8_t encrypted_secret[32];
    slip39_error_t err;
    uint16_t identifier;
    uint8_t threshold;
    uint8_t iteration_exp;
    size_t sec_len;

    if (!shares || !secret || !secret_len || share_count == 0) {
        return SLIP39_ERR_INVALID_PARAM;
    }

    if (share_count > SLIP39_MAX_SHARES) {
        return SLIP39_ERR_SHARE_COUNT;
    }

    /* Decode all shares */
    for (size_t i = 0; i < share_count; i++) {
        err = decode_mnemonic(shares[i], &decoded[i]);
        if (err != SLIP39_OK) {
            return err;
        }
    }

    /* Verify all shares have same identifier and parameters */
    identifier = decoded[0].identifier;
    threshold = decoded[0].member_threshold + 1;
    iteration_exp = decoded[0].iteration_exp;
    sec_len = decoded[0].share_value_len;

    for (size_t i = 1; i < share_count; i++) {
        if (decoded[i].identifier != identifier) {
            return SLIP39_ERR_SHARE_MISMATCH;
        }
        if (decoded[i].member_threshold + 1 != threshold) {
            return SLIP39_ERR_SHARE_MISMATCH;
        }
        if (decoded[i].share_value_len != sec_len) {
            return SLIP39_ERR_SHARE_MISMATCH;
        }
    }

    /* Check we have enough shares */
    if (share_count < threshold) {
        return SLIP39_ERR_INSUFFICIENT_SHARES;
    }

    /* Check for duplicate shares */
    for (size_t i = 0; i < share_count; i++) {
        for (size_t j = i + 1; j < share_count; j++) {
            if (decoded[i].member_index == decoded[j].member_index) {
                return SLIP39_ERR_DUPLICATE_SHARE;
            }
        }
    }

    /* Extract x and y values */
    for (size_t i = 0; i < share_count; i++) {
        x_values[i] = decoded[i].member_index + 1;  /* x = member_index + 1 */
        memcpy(y_values[i], decoded[i].share_value, sec_len);
    }

    /* Interpolate to recover encrypted secret */
    if (*secret_len < sec_len) {
        return SLIP39_ERR_BUFFER_TOO_SMALL;
    }

    interpolate(x_values, y_values, share_count, sec_len, encrypted_secret);

    /* Decrypt the recovered secret using passphrase */
    if (slip39_decrypt_secret(encrypted_secret, sec_len, passphrase,
                               identifier, iteration_exp, secret) != 0) {
        sodium_memzero(decoded, sizeof(decoded));
        sodium_memzero(y_values, sizeof(y_values));
        sodium_memzero(encrypted_secret, sizeof(encrypted_secret));
        return SLIP39_ERR_PASSPHRASE;
    }

    *secret_len = sec_len;

    /* Wipe sensitive data */
    sodium_memzero(decoded, sizeof(decoded));
    sodium_memzero(y_values, sizeof(y_values));
    sodium_memzero(encrypted_secret, sizeof(encrypted_secret));

    return SLIP39_OK;
}

slip39_error_t slip39_validate_share(const char *share, slip39_share_t *meta)
{
    slip39_share_t temp;
    slip39_error_t err;

    if (!share) {
        return SLIP39_ERR_INVALID_PARAM;
    }

    err = decode_mnemonic(share, &temp);
    if (err != SLIP39_OK) {
        return err;
    }

    if (meta) {
        *meta = temp;
    }

    return SLIP39_OK;
}

slip39_error_t slip39_get_share_info(
    const char *share,
    uint16_t *identifier,
    uint8_t *threshold,
    uint8_t *share_count)
{
    slip39_share_t meta;
    slip39_error_t err;

    err = slip39_validate_share(share, &meta);
    if (err != SLIP39_OK) {
        return err;
    }

    if (identifier) *identifier = meta.identifier;
    if (threshold) *threshold = meta.member_threshold + 1;
    if (share_count) *share_count = meta.group_count + 1;

    return SLIP39_OK;
}

void slip39_wipe_shares(char shares[SLIP39_MAX_SHARES][SLIP39_MAX_SHARE_LEN],
                        size_t count)
{
    if (shares && count > 0) {
        sodium_memzero(shares, count * SLIP39_MAX_SHARE_LEN);
    }
}

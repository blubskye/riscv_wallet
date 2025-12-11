/*
 * Bech32/Bech32m Encoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implementation of BIP-173 (Bech32) and BIP-350 (Bech32m) encoding.
 */

#include "bech32.h"
#include <string.h>
#include <ctype.h>

/* Bech32 character set */
static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/* Reverse lookup table */
static const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

/* Generator polynomial constants */
static const uint32_t GENERATOR[5] = {
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
};

/* Checksum constants */
#define BECH32_CONST  1
#define BECH32M_CONST 0x2bc830a3

/**
 * Polymod checksum computation
 */
static uint32_t polymod(const uint8_t *values, size_t len)
{
    uint32_t chk = 1;
    size_t i;

    for (i = 0; i < len; i++) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];

        if (top & 1)  chk ^= GENERATOR[0];
        if (top & 2)  chk ^= GENERATOR[1];
        if (top & 4)  chk ^= GENERATOR[2];
        if (top & 8)  chk ^= GENERATOR[3];
        if (top & 16) chk ^= GENERATOR[4];
    }

    return chk;
}

/**
 * Expand HRP for checksum computation
 */
static size_t hrp_expand(const char *hrp, uint8_t *output)
{
    size_t len = strlen(hrp);
    size_t i;

    for (i = 0; i < len; i++) {
        output[i] = hrp[i] >> 5;
    }
    output[len] = 0;
    for (i = 0; i < len; i++) {
        output[len + 1 + i] = hrp[i] & 31;
    }

    return len * 2 + 1;
}

/**
 * Create checksum
 */
static void create_checksum(const char *hrp, const uint8_t *data, size_t data_len,
                            bech32_encoding_t encoding, uint8_t *checksum)
{
    uint8_t values[BECH32_MAX_HRP_LEN * 2 + 1 + BECH32_MAX_DATA_LEN + 6];
    size_t hrp_len;
    uint32_t polymod_val;
    uint32_t target = (encoding == BECH32_ENCODING_BECH32M) ? BECH32M_CONST : BECH32_CONST;
    int i;

    hrp_len = hrp_expand(hrp, values);
    memcpy(values + hrp_len, data, data_len);
    memset(values + hrp_len + data_len, 0, 6);

    polymod_val = polymod(values, hrp_len + data_len + 6) ^ target;

    for (i = 0; i < 6; i++) {
        checksum[i] = (polymod_val >> (5 * (5 - i))) & 31;
    }
}

/**
 * Verify checksum
 */
static bech32_encoding_t verify_checksum(const char *hrp, const uint8_t *data,
                                         size_t data_len)
{
    uint8_t values[BECH32_MAX_HRP_LEN * 2 + 1 + BECH32_MAX_DATA_LEN + 6];
    size_t hrp_len;
    uint32_t check;

    hrp_len = hrp_expand(hrp, values);
    memcpy(values + hrp_len, data, data_len);

    check = polymod(values, hrp_len + data_len);

    if (check == BECH32_CONST) {
        return BECH32_ENCODING_BECH32;
    }
    if (check == BECH32M_CONST) {
        return BECH32_ENCODING_BECH32M;
    }

    return (bech32_encoding_t)-1;  /* Invalid */
}

int bech32_encode(const char *hrp, const uint8_t *data, size_t data_len,
                  char *output, size_t output_len, bech32_encoding_t encoding)
{
    uint8_t checksum[6];
    size_t hrp_len;
    size_t i;
    size_t pos = 0;

    if (hrp == NULL || data == NULL || output == NULL) {
        return -1;
    }

    hrp_len = strlen(hrp);
    if (hrp_len < 1 || hrp_len > BECH32_MAX_HRP_LEN) {
        return -1;
    }

    /* Check output buffer size */
    if (output_len < hrp_len + 1 + data_len + 6 + 1) {
        return -1;
    }

    /* Validate HRP characters */
    for (i = 0; i < hrp_len; i++) {
        if (hrp[i] < 33 || hrp[i] > 126) {
            return -1;
        }
    }

    /* Validate data values */
    for (i = 0; i < data_len; i++) {
        if (data[i] > 31) {
            return -1;
        }
    }

    /* Create checksum */
    create_checksum(hrp, data, data_len, encoding, checksum);

    /* Build output string */
    for (i = 0; i < hrp_len; i++) {
        output[pos++] = tolower((unsigned char)hrp[i]);
    }
    output[pos++] = '1';  /* Separator */

    for (i = 0; i < data_len; i++) {
        output[pos++] = CHARSET[data[i]];
    }

    for (i = 0; i < 6; i++) {
        output[pos++] = CHARSET[checksum[i]];
    }

    output[pos] = '\0';

    return (int)pos;
}

int bech32_decode(const char *input, char *hrp, size_t hrp_len,
                  uint8_t *data, size_t *data_len, bech32_encoding_t *encoding)
{
    size_t input_len;
    size_t sep_pos = 0;
    size_t i;
    int have_lower = 0, have_upper = 0;

    if (input == NULL || hrp == NULL || data == NULL || data_len == NULL) {
        return -1;
    }

    input_len = strlen(input);
    /* Allow up to 128 chars for Cardano and other chains with longer addresses */
    if (input_len < 8 || input_len > 128) {
        return -1;
    }

    /* Find separator */
    for (i = input_len - 1; i > 0; i--) {
        if (input[i] == '1') {
            sep_pos = i;
            break;
        }
    }

    if (sep_pos < 1 || sep_pos + 7 > input_len) {
        return -1;
    }

    /* Check HRP length */
    if (sep_pos > hrp_len - 1) {
        return -1;
    }

    /* Check data buffer size */
    if (input_len - sep_pos - 1 > *data_len) {
        return -1;
    }

    /* Check for mixed case and copy HRP */
    for (i = 0; i < sep_pos; i++) {
        char c = input[i];
        if (c >= 'a' && c <= 'z') have_lower = 1;
        if (c >= 'A' && c <= 'Z') have_upper = 1;
        if (c < 33 || c > 126) return -1;
        hrp[i] = tolower((unsigned char)c);
    }
    hrp[sep_pos] = '\0';

    if (have_lower && have_upper) {
        return -1;  /* Mixed case */
    }

    /* Decode data */
    *data_len = input_len - sep_pos - 1;
    for (i = 0; i < *data_len; i++) {
        unsigned char c = input[sep_pos + 1 + i];
        if (c >= 128 || CHARSET_REV[c] == -1) {
            return -1;
        }
        data[i] = CHARSET_REV[c];
    }

    /* Verify checksum */
    *encoding = verify_checksum(hrp, data, *data_len);
    if ((int)*encoding < 0) {
        return -1;
    }

    /* Remove checksum from data length */
    *data_len -= 6;

    return 0;
}

int bech32_convert_bits_8to5(const uint8_t *data, size_t data_len,
                             uint8_t *output, size_t *output_len, int pad)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t out_idx = 0;
    size_t max_out = *output_len;
    size_t i;

    for (i = 0; i < data_len; i++) {
        acc = (acc << 8) | data[i];
        bits += 8;

        while (bits >= 5) {
            bits -= 5;
            if (out_idx >= max_out) {
                return -1;
            }
            output[out_idx++] = (acc >> bits) & 31;
        }
    }

    if (pad && bits > 0) {
        if (out_idx >= max_out) {
            return -1;
        }
        output[out_idx++] = (acc << (5 - bits)) & 31;
    } else if (!pad && bits >= 5) {
        return -1;
    }

    *output_len = out_idx;
    return 0;
}

int bech32_convert_bits_5to8(const uint8_t *data, size_t data_len,
                             uint8_t *output, size_t *output_len, int pad)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t out_idx = 0;
    size_t max_out = *output_len;
    size_t i;

    for (i = 0; i < data_len; i++) {
        if (data[i] > 31) {
            return -1;
        }
        acc = (acc << 5) | data[i];
        bits += 5;

        while (bits >= 8) {
            bits -= 8;
            if (out_idx >= max_out) {
                return -1;
            }
            output[out_idx++] = (acc >> bits) & 255;
        }
    }

    if (!pad && bits > 0) {
        /* Check that remaining bits are zero */
        if ((acc << (8 - bits)) & 255) {
            return -1;
        }
    }

    *output_len = out_idx;
    return 0;
}

int bech32_encode_segwit(const char *hrp, int witness_version,
                         const uint8_t *witness_program, size_t witness_len,
                         char *output, size_t output_len)
{
    uint8_t data[65];  /* 1 + 32*8/5 + 1 */
    size_t data_len = sizeof(data);
    bech32_encoding_t encoding;

    if (hrp == NULL || witness_program == NULL || output == NULL) {
        return -1;
    }

    /* Validate witness version */
    if (witness_version < 0 || witness_version > 16) {
        return -1;
    }

    /* Validate witness program length */
    if (witness_len < 2 || witness_len > 40) {
        return -1;
    }

    /* v0 must be 20 or 32 bytes */
    if (witness_version == 0 && witness_len != 20 && witness_len != 32) {
        return -1;
    }

    /* Convert witness program to 5-bit groups */
    if (bech32_convert_bits_8to5(witness_program, witness_len,
                                  data + 1, &data_len, 1) != 0) {
        return -1;
    }

    /* Prepend witness version */
    data[0] = witness_version;
    data_len++;

    /* Choose encoding based on witness version */
    encoding = (witness_version == 0) ? BECH32_ENCODING_BECH32 : BECH32_ENCODING_BECH32M;

    return bech32_encode(hrp, data, data_len, output, output_len, encoding);
}

int bech32_decode_segwit(const char *address, char *hrp_out, size_t hrp_out_len,
                         int *witness_version, uint8_t *witness_program,
                         size_t *witness_len)
{
    char hrp[BECH32_MAX_HRP_LEN + 1];
    uint8_t data[65];
    size_t data_len = sizeof(data);
    bech32_encoding_t encoding;
    size_t prog_len;

    if (address == NULL || witness_version == NULL ||
        witness_program == NULL || witness_len == NULL) {
        return -1;
    }

    /* Decode bech32 */
    if (bech32_decode(address, hrp, sizeof(hrp), data, &data_len, &encoding) != 0) {
        return -1;
    }

    if (data_len < 1) {
        return -1;
    }

    /* Extract witness version */
    *witness_version = data[0];
    if (*witness_version > 16) {
        return -1;
    }

    /* Check encoding matches version */
    if (*witness_version == 0 && encoding != BECH32_ENCODING_BECH32) {
        return -1;
    }
    if (*witness_version != 0 && encoding != BECH32_ENCODING_BECH32M) {
        return -1;
    }

    /* Convert data to 8-bit */
    prog_len = *witness_len;
    if (bech32_convert_bits_5to8(data + 1, data_len - 1,
                                  witness_program, &prog_len, 0) != 0) {
        return -1;
    }

    /* Validate length */
    if (prog_len < 2 || prog_len > 40) {
        return -1;
    }
    if (*witness_version == 0 && prog_len != 20 && prog_len != 32) {
        return -1;
    }

    *witness_len = prog_len;

    /* Copy HRP if requested */
    if (hrp_out != NULL && hrp_out_len > 0) {
        strncpy(hrp_out, hrp, hrp_out_len - 1);
        hrp_out[hrp_out_len - 1] = '\0';
    }

    return 0;
}

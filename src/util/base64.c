/*
 * Base64 Encoding/Decoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "base64.h"
#include <string.h>

/* Base64 alphabet */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Decoding table: maps ASCII to base64 value (-1 = invalid, -2 = padding) */
static const int8_t base64_decode_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x00-0x0F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x10-0x1F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 0x20-0x2F: +, / */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,  /* 0x30-0x3F: 0-9, = */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 0x40-0x4F: A-O */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 0x50-0x5F: P-Z */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 0x60-0x6F: a-o */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 0x70-0x7F: p-z */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x80-0x8F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0x90-0x9F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xA0-0xAF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xB0-0xBF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xC0-0xCF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xD0-0xDF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 0xE0-0xEF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* 0xF0-0xFF */
};

int base64_decoded_len(const char *input, size_t input_len)
{
    size_t len;
    int padding = 0;

    if (input == NULL) {
        return -1;
    }

    if (input_len == 0) {
        input_len = strlen(input);
    }

    /* Skip whitespace at end */
    while (input_len > 0 && (input[input_len - 1] == '\n' ||
                             input[input_len - 1] == '\r' ||
                             input[input_len - 1] == ' ')) {
        input_len--;
    }

    if (input_len == 0) {
        return 0;
    }

    /* Count padding */
    if (input_len >= 1 && input[input_len - 1] == '=') {
        padding++;
        if (input_len >= 2 && input[input_len - 2] == '=') {
            padding++;
        }
    }

    /* Base64 encodes 3 bytes as 4 characters */
    len = (input_len * 3) / 4 - padding;

    return (int)len;
}

int base64_decode(const char *input, size_t input_len,
                  uint8_t *output, size_t *output_len)
{
    size_t out_pos = 0;
    size_t max_out;
    uint32_t accum = 0;
    int bits = 0;

    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    if (input_len == 0) {
        input_len = strlen(input);
    }

    max_out = *output_len;

    for (size_t i = 0; i < input_len; i++) {
        unsigned char c = (unsigned char)input[i];

        /* Skip whitespace */
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            continue;
        }

        int8_t val = base64_decode_table[c];

        /* Padding */
        if (val == -2) {
            break;
        }

        /* Invalid character */
        if (val < 0) {
            return -1;
        }

        accum = (accum << 6) | (uint32_t)val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (out_pos >= max_out) {
                return -1;  /* Output buffer too small */
            }
            output[out_pos++] = (uint8_t)(accum >> bits);
            accum &= (1u << bits) - 1;
        }
    }

    *output_len = out_pos;
    return 0;
}

int base64_encode(const uint8_t *input, size_t input_len,
                  char *output, size_t output_len)
{
    size_t out_pos = 0;
    size_t needed_len = ((input_len + 2) / 3) * 4 + 1;

    if (input == NULL || output == NULL) {
        return -1;
    }

    if (output_len < needed_len) {
        return -1;
    }

    for (size_t i = 0; i < input_len; i += 3) {
        uint32_t triple = ((uint32_t)input[i]) << 16;

        if (i + 1 < input_len) {
            triple |= ((uint32_t)input[i + 1]) << 8;
        }
        if (i + 2 < input_len) {
            triple |= (uint32_t)input[i + 2];
        }

        output[out_pos++] = base64_chars[(triple >> 18) & 0x3F];
        output[out_pos++] = base64_chars[(triple >> 12) & 0x3F];

        if (i + 1 < input_len) {
            output[out_pos++] = base64_chars[(triple >> 6) & 0x3F];
        } else {
            output[out_pos++] = '=';
        }

        if (i + 2 < input_len) {
            output[out_pos++] = base64_chars[triple & 0x3F];
        } else {
            output[out_pos++] = '=';
        }
    }

    output[out_pos] = '\0';
    return 0;
}

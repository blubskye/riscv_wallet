/*
 * Hexadecimal Utilities
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "hex.h"
#include <string.h>
#include <ctype.h>

static const char hex_lower[] = "0123456789abcdef";
static const char hex_upper[] = "0123456789ABCDEF";

int hex_encode(const uint8_t *data, size_t data_len, char *output, int lowercase)
{
    size_t i;
    const char *hex_chars = lowercase ? hex_lower : hex_upper;

    if (data == NULL || output == NULL) {
        return -1;
    }

    for (i = 0; i < data_len; i++) {
        output[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    output[data_len * 2] = '\0';

    return 0;
}

static int hex_char_to_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int hex_decode(const char *input, uint8_t *output, size_t *output_len)
{
    size_t input_len;
    size_t i;
    int high, low;

    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    /* Skip optional 0x prefix */
    if (input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        input += 2;
    }

    input_len = strlen(input);

    /* Must be even length */
    if (input_len % 2 != 0) {
        return -1;
    }

    if (input_len / 2 > *output_len) {
        return -1;
    }

    for (i = 0; i < input_len; i += 2) {
        high = hex_char_to_value(input[i]);
        low = hex_char_to_value(input[i + 1]);

        if (high < 0 || low < 0) {
            return -1;  /* Invalid hex character */
        }

        output[i / 2] = (high << 4) | low;
    }

    *output_len = input_len / 2;
    return 0;
}

int hex_is_valid(const char *input)
{
    size_t i;

    if (input == NULL) {
        return 0;
    }

    /* Skip optional 0x prefix */
    if (input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        input += 2;
    }

    for (i = 0; input[i] != '\0'; i++) {
        if (!isxdigit((unsigned char)input[i])) {
            return 0;
        }
    }

    /* Must be even length */
    return (i % 2 == 0) ? 1 : 0;
}

/*
 * RLP (Recursive Length Prefix) Encoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implementation of Ethereum's RLP encoding/decoding.
 */

#include "rlp.h"
#include <string.h>

/**
 * Encode length prefix for string or list
 */
static int encode_length(size_t len, int is_list, uint8_t *output, size_t output_len)
{
    uint8_t base = is_list ? 0xC0 : 0x80;

    if (len <= 55) {
        if (output_len < 1) return -1;
        output[0] = base + len;
        return 1;
    }

    /* Calculate number of bytes needed for length */
    size_t len_bytes = 0;
    size_t temp = len;
    while (temp > 0) {
        len_bytes++;
        temp >>= 8;
    }

    if (output_len < 1 + len_bytes) return -1;

    output[0] = base + 55 + len_bytes;

    /* Write length in big-endian */
    for (size_t i = 0; i < len_bytes; i++) {
        output[1 + len_bytes - 1 - i] = (len >> (i * 8)) & 0xFF;
    }

    return 1 + len_bytes;
}

/**
 * Decode length prefix
 */
static int decode_length(const uint8_t *input, size_t input_len,
                         size_t *data_len, size_t *prefix_len, rlp_type_t *type)
{
    if (input_len < 1) return -1;

    uint8_t first = input[0];

    if (first < 0x80) {
        /* Single byte */
        *type = RLP_TYPE_STRING;
        *data_len = 1;
        *prefix_len = 0;
        return 0;
    }

    if (first <= 0xB7) {
        /* Short string (0-55 bytes) */
        *type = RLP_TYPE_STRING;
        *data_len = first - 0x80;
        *prefix_len = 1;
        return 0;
    }

    if (first <= 0xBF) {
        /* Long string */
        size_t len_bytes = first - 0xB7;
        if (input_len < 1 + len_bytes) return -1;

        *type = RLP_TYPE_STRING;
        *prefix_len = 1 + len_bytes;

        *data_len = 0;
        for (size_t i = 0; i < len_bytes; i++) {
            *data_len = (*data_len << 8) | input[1 + i];
        }
        return 0;
    }

    if (first <= 0xF7) {
        /* Short list (0-55 bytes total) */
        *type = RLP_TYPE_LIST;
        *data_len = first - 0xC0;
        *prefix_len = 1;
        return 0;
    }

    /* Long list */
    size_t len_bytes = first - 0xF7;
    if (input_len < 1 + len_bytes) return -1;

    *type = RLP_TYPE_LIST;
    *prefix_len = 1 + len_bytes;

    *data_len = 0;
    for (size_t i = 0; i < len_bytes; i++) {
        *data_len = (*data_len << 8) | input[1 + i];
    }

    return 0;
}

size_t rlp_encoded_string_len(size_t data_len)
{
    if (data_len == 1) {
        /* Could be single byte (no prefix) or short string */
        return 2;  /* Worst case: prefix + data */
    }
    if (data_len <= 55) {
        return 1 + data_len;
    }

    /* Count bytes needed for length */
    size_t len_bytes = 0;
    size_t temp = data_len;
    while (temp > 0) {
        len_bytes++;
        temp >>= 8;
    }

    return 1 + len_bytes + data_len;
}

size_t rlp_encoded_list_len(size_t content_len)
{
    if (content_len <= 55) {
        return 1 + content_len;
    }

    size_t len_bytes = 0;
    size_t temp = content_len;
    while (temp > 0) {
        len_bytes++;
        temp >>= 8;
    }

    return 1 + len_bytes + content_len;
}

int rlp_encode_string(const uint8_t *data, size_t data_len,
                      uint8_t *output, size_t output_len)
{
    /* Empty string */
    if (data_len == 0) {
        if (output_len < 1) return -1;
        output[0] = 0x80;
        return 1;
    }

    /* Single byte < 0x80: no prefix needed */
    if (data_len == 1 && data[0] < 0x80) {
        if (output_len < 1) return -1;
        output[0] = data[0];
        return 1;
    }

    /* Encode with length prefix */
    int prefix_len = encode_length(data_len, 0, output, output_len);
    if (prefix_len < 0) return -1;

    if (output_len < (size_t)prefix_len + data_len) return -1;

    memcpy(output + prefix_len, data, data_len);
    return prefix_len + data_len;
}

int rlp_encode_list(const uint8_t **items, const size_t *item_lens,
                    size_t item_count, uint8_t *output, size_t output_len)
{
    /* Calculate total content length */
    size_t content_len = 0;
    for (size_t i = 0; i < item_count; i++) {
        content_len += item_lens[i];
    }

    /* Encode list prefix */
    int prefix_len = encode_length(content_len, 1, output, output_len);
    if (prefix_len < 0) return -1;

    if (output_len < (size_t)prefix_len + content_len) return -1;

    /* Copy items */
    size_t offset = prefix_len;
    for (size_t i = 0; i < item_count; i++) {
        memcpy(output + offset, items[i], item_lens[i]);
        offset += item_lens[i];
    }

    return offset;
}

int rlp_encode_uint64(uint64_t value, uint8_t *output, size_t output_len)
{
    /* Zero encodes as empty string */
    if (value == 0) {
        if (output_len < 1) return -1;
        output[0] = 0x80;
        return 1;
    }

    /* Convert to big-endian bytes, skipping leading zeros */
    uint8_t bytes[8];
    int len = 0;

    for (int i = 7; i >= 0; i--) {
        uint8_t b = (value >> (i * 8)) & 0xFF;
        if (len > 0 || b != 0) {
            bytes[len++] = b;
        }
    }

    return rlp_encode_string(bytes, len, output, output_len);
}

int rlp_encode_bigint(const uint8_t *data, size_t data_len,
                      uint8_t *output, size_t output_len)
{
    /* Skip leading zeros */
    while (data_len > 0 && data[0] == 0) {
        data++;
        data_len--;
    }

    /* Zero value */
    if (data_len == 0) {
        if (output_len < 1) return -1;
        output[0] = 0x80;
        return 1;
    }

    return rlp_encode_string(data, data_len, output, output_len);
}

int rlp_decode_item(const uint8_t *input, size_t input_len, rlp_item_t *item)
{
    size_t data_len, prefix_len;
    rlp_type_t type;

    if (input_len < 1 || item == NULL) return -1;

    /* Handle single byte case */
    if (input[0] < 0x80) {
        item->type = RLP_TYPE_STRING;
        item->data = input;
        item->length = 1;
        return 1;
    }

    if (decode_length(input, input_len, &data_len, &prefix_len, &type) != 0) {
        return -1;
    }

    if (input_len < prefix_len + data_len) {
        return -1;
    }

    item->type = type;
    item->data = input + prefix_len;
    item->length = data_len;

    return prefix_len + data_len;
}

int rlp_decode_list(const uint8_t *input, size_t input_len,
                    rlp_item_t *items, size_t max_items)
{
    size_t offset = 0;
    size_t count = 0;

    while (offset < input_len && count < max_items) {
        int consumed = rlp_decode_item(input + offset, input_len - offset,
                                        &items[count]);
        if (consumed < 0) {
            return -1;
        }

        offset += consumed;
        count++;
    }

    /* Check we consumed everything */
    if (offset != input_len) {
        return -1;
    }

    return count;
}

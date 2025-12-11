/*
 * RLP (Recursive Length Prefix) Encoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implementation of Ethereum's RLP encoding/decoding.
 * See: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
 */

#ifndef RLP_H
#define RLP_H

#include <stdint.h>
#include <stddef.h>

/* RLP item types */
typedef enum {
    RLP_TYPE_STRING,
    RLP_TYPE_LIST
} rlp_type_t;

/* RLP decoded item */
typedef struct {
    rlp_type_t type;
    const uint8_t *data;
    size_t length;
} rlp_item_t;

/**
 * Encode a byte string as RLP
 *
 * @param data Input data (can be NULL for empty string)
 * @param data_len Length of input data
 * @param output Output buffer
 * @param output_len Size of output buffer
 * @return Number of bytes written, or -1 on error
 */
int rlp_encode_string(const uint8_t *data, size_t data_len,
                      uint8_t *output, size_t output_len);

/**
 * Encode a list of pre-encoded RLP items
 *
 * @param items Array of pre-encoded RLP item buffers
 * @param item_lens Array of item lengths
 * @param item_count Number of items
 * @param output Output buffer
 * @param output_len Size of output buffer
 * @return Number of bytes written, or -1 on error
 */
int rlp_encode_list(const uint8_t **items, const size_t *item_lens,
                    size_t item_count, uint8_t *output, size_t output_len);

/**
 * Encode a uint64 as RLP
 *
 * @param value Value to encode
 * @param output Output buffer
 * @param output_len Size of output buffer
 * @return Number of bytes written, or -1 on error
 */
int rlp_encode_uint64(uint64_t value, uint8_t *output, size_t output_len);

/**
 * Encode a big integer (big-endian byte array) as RLP
 *
 * @param data Big-endian byte array
 * @param data_len Length of byte array
 * @param output Output buffer
 * @param output_len Size of output buffer
 * @return Number of bytes written, or -1 on error
 */
int rlp_encode_bigint(const uint8_t *data, size_t data_len,
                      uint8_t *output, size_t output_len);

/**
 * Decode an RLP item
 *
 * @param input RLP-encoded data
 * @param input_len Length of input data
 * @param item Output decoded item info
 * @return Number of bytes consumed, or -1 on error
 */
int rlp_decode_item(const uint8_t *input, size_t input_len, rlp_item_t *item);

/**
 * Decode an RLP list into individual items
 *
 * @param input RLP-encoded list data (the content, not including list prefix)
 * @param input_len Length of list data
 * @param items Output array of decoded items
 * @param max_items Maximum number of items to decode
 * @return Number of items decoded, or -1 on error
 */
int rlp_decode_list(const uint8_t *input, size_t input_len,
                    rlp_item_t *items, size_t max_items);

/**
 * Get the encoded length of a string
 *
 * @param data_len Length of string data
 * @return Total encoded length including prefix
 */
size_t rlp_encoded_string_len(size_t data_len);

/**
 * Get the encoded length of a list
 *
 * @param content_len Total length of encoded list contents
 * @return Total encoded length including list prefix
 */
size_t rlp_encoded_list_len(size_t content_len);

#endif /* RLP_H */

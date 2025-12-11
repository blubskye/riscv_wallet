/*
 * Base64 Encoding/Decoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>
#include <stddef.h>

/**
 * Decode base64-encoded data
 *
 * @param input Base64-encoded string
 * @param input_len Length of input (0 to use strlen)
 * @param output Output buffer for decoded data
 * @param output_len Size of output buffer / bytes written
 * @return 0 on success, -1 on error
 */
int base64_decode(const char *input, size_t input_len,
                  uint8_t *output, size_t *output_len);

/**
 * Encode data as base64
 *
 * @param input Binary data to encode
 * @param input_len Length of input data
 * @param output Output buffer for base64 string
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int base64_encode(const uint8_t *input, size_t input_len,
                  char *output, size_t output_len);

/**
 * Calculate decoded length from base64 string
 *
 * @param input Base64-encoded string
 * @param input_len Length of input
 * @return Decoded length, or -1 on error
 */
int base64_decoded_len(const char *input, size_t input_len);

#endif /* BASE64_H */

/*
 * Base58 Encoding/Decoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef BASE58_H
#define BASE58_H

#include <stdint.h>
#include <stddef.h>

/**
 * Encode binary data to Base58
 *
 * @param data Input binary data
 * @param data_len Length of input data
 * @param output Output buffer for Base58 string
 * @param output_len Size of output buffer
 * @return Length of encoded string, or -1 on error
 */
int base58_encode(const uint8_t *data, size_t data_len,
                  char *output, size_t output_len);

/**
 * Decode Base58 string to binary
 *
 * @param input Base58 string
 * @param output Output buffer for binary data
 * @param output_len Size of output buffer / bytes written
 * @return 0 on success, -1 on error
 */
int base58_decode(const char *input, uint8_t *output, size_t *output_len);

/**
 * Encode binary data to Base58Check (with checksum)
 *
 * @param data Input binary data
 * @param data_len Length of input data
 * @param output Output buffer for Base58Check string
 * @param output_len Size of output buffer
 * @return Length of encoded string, or -1 on error
 */
int base58check_encode(const uint8_t *data, size_t data_len,
                       char *output, size_t output_len);

/**
 * Decode Base58Check string to binary (with checksum verification)
 *
 * @param input Base58Check string
 * @param output Output buffer for binary data
 * @param output_len Size of output buffer / bytes written
 * @return 0 on success, -1 on error (including checksum failure)
 */
int base58check_decode(const char *input, uint8_t *output, size_t *output_len);

#endif /* BASE58_H */

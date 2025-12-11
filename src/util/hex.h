/*
 * Hexadecimal Utilities
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef HEX_H
#define HEX_H

#include <stdint.h>
#include <stddef.h>

/**
 * Convert binary data to hex string
 *
 * @param data Input binary data
 * @param data_len Length of input data
 * @param output Output buffer (must be at least data_len * 2 + 1)
 * @param lowercase Use lowercase hex characters
 * @return 0 on success, -1 on error
 */
int hex_encode(const uint8_t *data, size_t data_len, char *output, int lowercase);

/**
 * Convert hex string to binary data
 *
 * @param input Hex string (may start with "0x")
 * @param output Output buffer
 * @param output_len Size of output buffer / bytes written
 * @return 0 on success, -1 on error
 */
int hex_decode(const char *input, uint8_t *output, size_t *output_len);

/**
 * Check if string is valid hex
 *
 * @param input String to check
 * @return 1 if valid hex, 0 if not
 */
int hex_is_valid(const char *input);

#endif /* HEX_H */

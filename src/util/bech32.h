/*
 * Bech32/Bech32m Encoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implementation of BIP-173 (Bech32) and BIP-350 (Bech32m) encoding
 * for Bitcoin SegWit addresses.
 */

#ifndef BECH32_H
#define BECH32_H

#include <stdint.h>
#include <stddef.h>

/* Maximum lengths - extended for Cardano (addresses can be ~103 chars) */
#define BECH32_MAX_HRP_LEN    83
#define BECH32_MAX_DATA_LEN   (128 - 8)  /* 128 max - separator - checksum */

/* Encoding variants */
typedef enum {
    BECH32_ENCODING_BECH32,   /* BIP-173: witness v0 */
    BECH32_ENCODING_BECH32M   /* BIP-350: witness v1+ (taproot) */
} bech32_encoding_t;

/**
 * Encode data as Bech32/Bech32m
 *
 * @param hrp Human-readable part (e.g., "bc" for mainnet, "tb" for testnet)
 * @param data 5-bit data values to encode
 * @param data_len Number of 5-bit values
 * @param output Output buffer for encoded string
 * @param output_len Size of output buffer
 * @param encoding BECH32_ENCODING_BECH32 or BECH32_ENCODING_BECH32M
 * @return Length of encoded string, or -1 on error
 */
int bech32_encode(const char *hrp, const uint8_t *data, size_t data_len,
                  char *output, size_t output_len, bech32_encoding_t encoding);

/**
 * Decode Bech32/Bech32m string
 *
 * @param input Bech32-encoded string
 * @param hrp Output buffer for human-readable part
 * @param hrp_len Size of hrp buffer
 * @param data Output buffer for 5-bit data values
 * @param data_len Input: size of data buffer, Output: number of values
 * @param encoding Output: detected encoding variant
 * @return 0 on success, -1 on error
 */
int bech32_decode(const char *input, char *hrp, size_t hrp_len,
                  uint8_t *data, size_t *data_len, bech32_encoding_t *encoding);

/**
 * Convert 8-bit data to 5-bit groups
 *
 * @param data Input 8-bit data
 * @param data_len Length of input data
 * @param output Output buffer for 5-bit values
 * @param output_len Input: size of output buffer, Output: number of values
 * @param pad Add padding if needed
 * @return 0 on success, -1 on error
 */
int bech32_convert_bits_8to5(const uint8_t *data, size_t data_len,
                             uint8_t *output, size_t *output_len, int pad);

/**
 * Convert 5-bit groups to 8-bit data
 *
 * @param data Input 5-bit values
 * @param data_len Number of input values
 * @param output Output buffer for 8-bit data
 * @param output_len Input: size of output buffer, Output: bytes written
 * @param pad Expect padding
 * @return 0 on success, -1 on error
 */
int bech32_convert_bits_5to8(const uint8_t *data, size_t data_len,
                             uint8_t *output, size_t *output_len, int pad);

/**
 * Encode SegWit address
 *
 * @param hrp Human-readable part ("bc" or "tb")
 * @param witness_version Witness program version (0-16)
 * @param witness_program Witness program data (20 or 32 bytes)
 * @param witness_len Length of witness program
 * @param output Output buffer for address
 * @param output_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int bech32_encode_segwit(const char *hrp, int witness_version,
                         const uint8_t *witness_program, size_t witness_len,
                         char *output, size_t output_len);

/**
 * Decode SegWit address
 *
 * @param address Bech32/Bech32m address string
 * @param hrp_out Output buffer for HRP (can be NULL)
 * @param hrp_out_len Size of HRP buffer
 * @param witness_version Output witness version
 * @param witness_program Output witness program
 * @param witness_len Input: size of buffer, Output: program length
 * @return 0 on success, -1 on error
 */
int bech32_decode_segwit(const char *address, char *hrp_out, size_t hrp_out_len,
                         int *witness_version, uint8_t *witness_program,
                         size_t *witness_len);

#endif /* BECH32_H */

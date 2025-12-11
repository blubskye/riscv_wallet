/*
 * AFL Fuzzing Harness - Bech32/Bech32m Encoding/Decoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util/bech32.h"

int main(void)
{
    char input[4096];
    char hrp[128];
    uint8_t data[4096];
    char encoded[8192];
    bech32_encoding_t encoding;

    ssize_t len = read(0, input, sizeof(input) - 1);
    if (len <= 0) return 0;
    input[len] = '\0';

    size_t data_len = sizeof(data);

    /* Try bech32 decode */
    if (bech32_decode(input, hrp, sizeof(hrp), data, &data_len, &encoding) == 0) {
        /* Round-trip encode */
        (void)bech32_encode(hrp, data, data_len, encoded, sizeof(encoded), encoding);
    }

    /* Try bit conversion on raw input */
    uint8_t bits5[4096];
    size_t bits5_len = sizeof(bits5);
    (void)bech32_convert_bits_8to5((uint8_t *)input, (size_t)len, bits5, &bits5_len, 1);

    return 0;
}

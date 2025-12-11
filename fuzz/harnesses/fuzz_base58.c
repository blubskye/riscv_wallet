/*
 * AFL Fuzzing Harness - Base58 Encoding/Decoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util/base58.h"

int main(void)
{
    char input[4096];
    uint8_t decoded[4096];
    char encoded[8192];

    ssize_t len = read(0, input, sizeof(input) - 1);
    if (len <= 0) return 0;
    input[len] = '\0';

    size_t decoded_len = sizeof(decoded);

    /* Try base58 decode */
    if (base58_decode(input, decoded, &decoded_len) == 0) {
        /* Round-trip: encode the decoded data */
        (void)base58_encode(decoded, decoded_len, encoded, sizeof(encoded));
    }

    /* Try base58check decode */
    decoded_len = sizeof(decoded);
    (void)base58check_decode(input, decoded, &decoded_len);

    /* Try encoding raw bytes (interpret input as binary) */
    (void)base58_encode((uint8_t *)input, (size_t)len, encoded, sizeof(encoded));

    return 0;
}

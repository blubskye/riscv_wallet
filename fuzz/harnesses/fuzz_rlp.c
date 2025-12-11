/*
 * AFL Fuzzing Harness - RLP (Recursive Length Prefix) Decoding
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util/rlp.h"

int main(void)
{
    uint8_t input[4096];
    uint8_t output[8192];

    ssize_t len = read(0, input, sizeof(input));
    if (len <= 0) return 0;

    rlp_item_t item;

    /* Try to decode RLP item */
    (void)rlp_decode_item(input, (size_t)len, &item);

    /* Try decoding as list */
    rlp_item_t items[16];
    size_t item_count = 16;
    (void)rlp_decode_list(input, (size_t)len, items, item_count);

    /* Try encoding various data sizes */
    (void)rlp_encode_string(input, (size_t)len, output, sizeof(output));

    /* Try encoding as integer if small enough */
    if (len <= 8) {
        uint64_t val = 0;
        for (ssize_t i = 0; i < len && i < 8; i++) {
            val = (val << 8) | input[i];
        }
        (void)rlp_encode_uint64(val, output, sizeof(output));
    }

    return 0;
}

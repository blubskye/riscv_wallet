/*
 * AFL Fuzzing Harness - BIP-39 Mnemonic Parsing
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto/bip39.h"

int main(void)
{
    char input[4096];
    uint8_t seed[64];

    ssize_t len = read(0, input, sizeof(input) - 1);
    if (len <= 0) return 0;
    input[len] = '\0';

    /* Target: mnemonic validation and seed derivation */
    (void)bip39_validate_mnemonic(input);
    (void)bip39_mnemonic_to_seed(input, "", seed);
    (void)bip39_mnemonic_to_seed(input, "testpassphrase", seed);

    return 0;
}

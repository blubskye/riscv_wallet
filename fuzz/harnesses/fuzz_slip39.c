/*
 * AFL Fuzzing Harness - SLIP-39 Shamir Secret Sharing
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto/slip39.h"

int main(void)
{
    char input[4096];

    ssize_t len = read(0, input, sizeof(input) - 1);
    if (len <= 0) return 0;
    input[len] = '\0';

    slip39_share_t share;

    /* Try to validate/parse as SLIP-39 share mnemonic */
    (void)slip39_validate_share(input, &share);

    /* Try to recover with single share (will fail but tests parsing) */
    uint8_t secret[32];
    size_t secret_len = sizeof(secret);
    const char *shares[1] = { input };
    (void)slip39_recover_secret(shares, 1, "", secret, &secret_len);

    return 0;
}

/*
 * Hardware RNG Integration
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Provides random number generation with optional hardware RNG support.
 * When hardware RNG is available (/dev/hwrng), uses it to seed or
 * supplement libsodium's RNG for added entropy.
 */

#ifndef CRYPTO_RANDOM_H
#define CRYPTO_RANDOM_H

#include <stddef.h>
#include <stdint.h>

/* Random source type */
typedef enum {
    RANDOM_SOURCE_SOFTWARE = 0,  /* libsodium only */
    RANDOM_SOURCE_HARDWARE,      /* Hardware RNG available */
    RANDOM_SOURCE_MIXED          /* Hardware + software combined */
} random_source_t;

/**
 * Initialize random subsystem
 *
 * Attempts to open hardware RNG if available, configures libsodium.
 * Uses hardware config settings for RNG device path.
 *
 * @return 0 on success, -1 on error
 */
int random_init(void);

/**
 * Cleanup random subsystem
 */
void random_cleanup(void);

/**
 * Get cryptographically secure random bytes
 *
 * @param buf Output buffer
 * @param len Number of bytes to generate
 */
void random_bytes(void *buf, size_t len);

/**
 * Get random bytes with explicit hardware RNG usage
 *
 * If hardware RNG is available, reads from it directly.
 * Falls back to software RNG if hardware unavailable.
 *
 * @param buf Output buffer
 * @param len Number of bytes to generate
 * @return Number of bytes from hardware RNG (may be less than len)
 */
size_t random_bytes_hwrng(void *buf, size_t len);

/**
 * Get current random source type
 *
 * @return Current random source being used
 */
random_source_t random_get_source(void);

/**
 * Get hardware RNG device path (if available)
 *
 * @return Device path or NULL if not available
 */
const char *random_get_hwrng_device(void);

/**
 * Test hardware RNG quality (simple entropy check)
 *
 * @return 0 if passes basic tests, -1 if fails or unavailable
 */
int random_test_hwrng(void);

/**
 * Reseed from hardware RNG
 *
 * Reads additional entropy from hardware RNG if available
 * and uses it to reseed the software RNG.
 *
 * @return 0 on success, -1 if hardware RNG unavailable
 */
int random_reseed(void);

#endif /* CRYPTO_RANDOM_H */

/*
 * Secure Memory Handling
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>

/**
 * Initialize secure memory subsystem
 *
 * This sets up memory locking and other protections
 * to prevent sensitive data from being swapped to disk.
 *
 * @return 0 on success, -1 on error
 */
int secure_memory_init(void);

/**
 * Cleanup secure memory subsystem
 */
void secure_memory_cleanup(void);

/**
 * Allocate secure memory
 *
 * Memory allocated with this function:
 * - Is locked to prevent swapping
 * - Will be automatically wiped on free
 * - Is guard-page protected where possible
 *
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL on failure
 */
void *secure_malloc(size_t size);

/**
 * Free secure memory
 *
 * This will securely wipe the memory before freeing.
 *
 * @param ptr Pointer to memory (can be NULL)
 * @param size Size of allocation (for secure wiping)
 */
void secure_free(void *ptr, size_t size);

/**
 * Securely wipe memory
 *
 * Uses volatile pointer to prevent compiler optimization.
 *
 * @param ptr Pointer to memory
 * @param size Number of bytes to wipe
 */
void secure_wipe(void *ptr, size_t size);

/**
 * Wipe all tracked secure allocations
 *
 * Called during shutdown to ensure no sensitive data remains.
 */
void secure_memory_wipe_all(void);

/**
 * Constant-time memory comparison
 *
 * @param a First buffer
 * @param b Second buffer
 * @param size Number of bytes to compare
 * @return 0 if equal, non-zero if different
 */
int secure_memcmp(const void *a, const void *b, size_t size);

#endif /* MEMORY_H */

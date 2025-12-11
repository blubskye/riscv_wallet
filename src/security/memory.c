/*
 * Secure Memory Handling
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "memory.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sodium.h>

/* Track secure allocations for wipe-on-exit */
#define MAX_TRACKED_ALLOCS 256

typedef struct {
    void *ptr;
    size_t size;
} tracked_alloc_t;

static tracked_alloc_t g_tracked[MAX_TRACKED_ALLOCS];
static size_t g_tracked_count = 0;
static int g_initialized = 0;

int secure_memory_init(void)
{
    if (g_initialized) {
        return 0;
    }

    /* Initialize libsodium */
    if (sodium_init() < 0) {
        return -1;
    }

    memset(g_tracked, 0, sizeof(g_tracked));
    g_tracked_count = 0;
    g_initialized = 1;

    return 0;
}

void secure_memory_cleanup(void)
{
    secure_memory_wipe_all();
    g_initialized = 0;
}

void *secure_malloc(size_t size)
{
    void *ptr;

    if (!g_initialized || size == 0) {
        return NULL;
    }

    /* Use libsodium's secure memory allocation */
    ptr = sodium_malloc(size);
    if (ptr == NULL) {
        return NULL;
    }

    /* Lock memory to prevent swapping */
    sodium_mlock(ptr, size);

    /* Track allocation */
    if (g_tracked_count < MAX_TRACKED_ALLOCS) {
        g_tracked[g_tracked_count].ptr = ptr;
        g_tracked[g_tracked_count].size = size;
        g_tracked_count++;
    }

    return ptr;
}

void secure_free(void *ptr, size_t size)
{
    size_t i;

    if (ptr == NULL) {
        return;
    }

    /* Wipe memory before freeing */
    sodium_memzero(ptr, size);

    /* Remove from tracking */
    for (i = 0; i < g_tracked_count; i++) {
        if (g_tracked[i].ptr == ptr) {
            g_tracked[i] = g_tracked[g_tracked_count - 1];
            g_tracked_count--;
            break;
        }
    }

    /* Free using libsodium */
    sodium_free(ptr);
}

void secure_wipe(void *ptr, size_t size)
{
    if (ptr == NULL || size == 0) {
        return;
    }

    /* Use libsodium's secure zeroing (prevents optimization) */
    sodium_memzero(ptr, size);
}

void secure_memory_wipe_all(void)
{
    size_t i;

    for (i = 0; i < g_tracked_count; i++) {
        if (g_tracked[i].ptr != NULL) {
            sodium_memzero(g_tracked[i].ptr, g_tracked[i].size);
            sodium_free(g_tracked[i].ptr);
        }
    }

    memset(g_tracked, 0, sizeof(g_tracked));
    g_tracked_count = 0;
}

int secure_memcmp(const void *a, const void *b, size_t size)
{
    /* Use libsodium's constant-time comparison */
    return sodium_memcmp(a, b, size);
}

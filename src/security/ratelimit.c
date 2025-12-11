/*
 * Rate Limiting for Authentication Attempts
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "ratelimit.h"
#include "memory.h"
#include "storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* State file format magic */
#define RATELIMIT_MAGIC  0x52415445  /* "RATE" */

/* State file name */
#define RATELIMIT_FILE   "ratelimit.bin"

/* Global state */
static ratelimit_state_t g_state;
static int g_initialized = 0;

/* Calculate simple checksum for integrity verification */
static uint32_t calculate_checksum(const ratelimit_state_t *state)
{
    const uint8_t *data = (const uint8_t *)state;
    size_t len = offsetof(ratelimit_state_t, checksum);
    uint32_t sum = 0;

    for (size_t i = 0; i < len; i++) {
        sum = (sum << 1) | (sum >> 31);  /* Rotate left */
        sum ^= data[i];
    }

    return sum;
}

/* Load state from storage */
static int load_state(void)
{
    char path[512];
    FILE *fp;
    ratelimit_state_t loaded;

    snprintf(path, sizeof(path), "%s/%s", storage_get_path(), RATELIMIT_FILE);

    fp = fopen(path, "rb");
    if (fp == NULL) {
        /* No state file - initialize fresh */
        memset(&g_state, 0, sizeof(g_state));
        g_state.magic = RATELIMIT_MAGIC;
        return RATELIMIT_OK;
    }

    if (fread(&loaded, sizeof(loaded), 1, fp) != 1) {
        fclose(fp);
        memset(&g_state, 0, sizeof(g_state));
        g_state.magic = RATELIMIT_MAGIC;
        return RATELIMIT_OK;
    }
    fclose(fp);

    /* Verify magic and checksum */
    if (loaded.magic != RATELIMIT_MAGIC ||
        loaded.checksum != calculate_checksum(&loaded)) {
        fprintf(stderr, "[ratelimit] Corrupt state file, resetting\n");
        memset(&g_state, 0, sizeof(g_state));
        g_state.magic = RATELIMIT_MAGIC;
        return RATELIMIT_OK;
    }

    memcpy(&g_state, &loaded, sizeof(g_state));
    return RATELIMIT_OK;
}

/* Save state to storage */
static int save_state(void)
{
    char path[512];
    FILE *fp;

    g_state.checksum = calculate_checksum(&g_state);

    snprintf(path, sizeof(path), "%s/%s", storage_get_path(), RATELIMIT_FILE);

    fp = fopen(path, "wb");
    if (fp == NULL) {
        return RATELIMIT_ERR_IO;
    }

    if (fwrite(&g_state, sizeof(g_state), 1, fp) != 1) {
        fclose(fp);
        return RATELIMIT_ERR_IO;
    }

    fclose(fp);
    return RATELIMIT_OK;
}

/* Get current time as Unix timestamp */
static int64_t get_current_time(void)
{
    return (int64_t)time(NULL);
}

/* Calculate lockout duration based on level (exponential backoff) */
static uint32_t calculate_lockout_duration(uint32_t level)
{
    /* Base: 30s, doubles each level: 30, 60, 120, 240, 480, 960, 1920, 3600 max */
    uint32_t duration = RATELIMIT_BASE_LOCKOUT_SEC;

    for (uint32_t i = 0; i < level && duration < RATELIMIT_MAX_LOCKOUT_SEC; i++) {
        duration *= 2;
    }

    if (duration > RATELIMIT_MAX_LOCKOUT_SEC) {
        duration = RATELIMIT_MAX_LOCKOUT_SEC;
    }

    return duration;
}

int ratelimit_init(void)
{
    if (g_initialized) {
        return RATELIMIT_OK;
    }

    /* Storage must be initialized first */
    if (storage_get_path()[0] == '\0') {
        return RATELIMIT_ERR_INIT;
    }

    if (load_state() != RATELIMIT_OK) {
        return RATELIMIT_ERR_INIT;
    }

    g_initialized = 1;
    printf("[ratelimit] Initialized (PIN fails: %u, FP fails: %u, lockout level: %u)\n",
           g_state.pin_fail_count, g_state.fp_fail_count, g_state.lockout_level);

    return RATELIMIT_OK;
}

void ratelimit_cleanup(void)
{
    if (g_initialized) {
        save_state();
        secure_wipe(&g_state, sizeof(g_state));
        g_initialized = 0;
    }
}

int ratelimit_check(auth_type_t auth_type, uint32_t *remaining_sec)
{
    int64_t now;
    int64_t remaining;

    (void)auth_type;  /* Currently lockout applies to all auth types */

    if (!g_initialized) {
        return RATELIMIT_ERR_INIT;
    }

    now = get_current_time();

    if (g_state.lockout_until > now) {
        remaining = g_state.lockout_until - now;
        if (remaining_sec != NULL) {
            *remaining_sec = (uint32_t)remaining;
        }
        return RATELIMIT_LOCKED;
    }

    if (remaining_sec != NULL) {
        *remaining_sec = 0;
    }

    return RATELIMIT_OK;
}

int ratelimit_record_failure(auth_type_t auth_type)
{
    uint32_t *fail_count;
    uint32_t *total_count;
    uint32_t threshold;
    int64_t now;
    uint32_t lockout_duration;

    if (!g_initialized) {
        return RATELIMIT_ERR_INIT;
    }

    /* Select counters based on auth type */
    if (auth_type == AUTH_TYPE_PIN) {
        fail_count = &g_state.pin_fail_count;
        total_count = &g_state.total_pin_failures;
    } else {
        fail_count = &g_state.fp_fail_count;
        total_count = &g_state.total_fp_failures;
    }

    /* Increment counters */
    (*fail_count)++;
    (*total_count)++;

    /* Check for wallet wipe threshold */
    threshold = g_state.total_pin_failures + g_state.total_fp_failures;
    if (threshold >= RATELIMIT_WIPE_THRESHOLD) {
        printf("\n[SECURITY] Too many failed attempts (%u). Wiping wallet!\n", threshold);
        storage_wipe_wallet();
        ratelimit_reset();
        save_state();
        return RATELIMIT_WIPED;
    }

    /* Check for lockout trigger */
    if (*fail_count >= RATELIMIT_MAX_ATTEMPTS) {
        now = get_current_time();
        lockout_duration = calculate_lockout_duration(g_state.lockout_level);
        g_state.lockout_until = now + lockout_duration;
        g_state.lockout_level++;

        printf("\n[SECURITY] Too many failures. Locked for %u seconds.\n", lockout_duration);
        printf("           Lockout level: %u\n", g_state.lockout_level);

        /* Reset consecutive counter but keep total */
        *fail_count = 0;

        save_state();
        return RATELIMIT_LOCKED;
    }

    save_state();
    return RATELIMIT_OK;
}

void ratelimit_record_success(auth_type_t auth_type)
{
    if (!g_initialized) {
        return;
    }

    /* Reset consecutive failure counter for this auth type */
    if (auth_type == AUTH_TYPE_PIN) {
        g_state.pin_fail_count = 0;
    } else {
        g_state.fp_fail_count = 0;
    }

    /* On successful auth, also reset lockout state */
    g_state.lockout_until = 0;
    g_state.lockout_level = 0;

    save_state();
}

void ratelimit_get_stats(uint32_t *pin_fails, uint32_t *fp_fails,
                         uint32_t *total_pin, uint32_t *total_fp)
{
    if (!g_initialized) {
        return;
    }

    if (pin_fails != NULL) {
        *pin_fails = g_state.pin_fail_count;
    }
    if (fp_fails != NULL) {
        *fp_fails = g_state.fp_fail_count;
    }
    if (total_pin != NULL) {
        *total_pin = g_state.total_pin_failures;
    }
    if (total_fp != NULL) {
        *total_fp = g_state.total_fp_failures;
    }
}

int ratelimit_is_locked(uint32_t *remaining_sec, uint32_t *lockout_level)
{
    int64_t now;
    int64_t remaining;

    if (!g_initialized) {
        if (remaining_sec != NULL) *remaining_sec = 0;
        if (lockout_level != NULL) *lockout_level = 0;
        return 0;
    }

    now = get_current_time();

    if (g_state.lockout_until > now) {
        remaining = g_state.lockout_until - now;
        if (remaining_sec != NULL) {
            *remaining_sec = (uint32_t)remaining;
        }
        if (lockout_level != NULL) {
            *lockout_level = g_state.lockout_level;
        }
        return 1;
    }

    if (remaining_sec != NULL) *remaining_sec = 0;
    if (lockout_level != NULL) *lockout_level = g_state.lockout_level;
    return 0;
}

void ratelimit_reset(void)
{
    if (!g_initialized) {
        return;
    }

    g_state.pin_fail_count = 0;
    g_state.fp_fail_count = 0;
    g_state.total_pin_failures = 0;
    g_state.total_fp_failures = 0;
    g_state.lockout_until = 0;
    g_state.lockout_level = 0;

    save_state();
}

int ratelimit_save_state(void)
{
    if (!g_initialized) {
        return RATELIMIT_ERR_INIT;
    }

    return save_state();
}

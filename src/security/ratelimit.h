/*
 * Rate Limiting for Authentication Attempts
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implements exponential backoff lockout after failed PIN/fingerprint attempts.
 * State is persisted to storage to survive reboots.
 */

#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <stdint.h>
#include <time.h>

/* Rate limit error codes */
#define RATELIMIT_OK            0
#define RATELIMIT_LOCKED       -1   /* Currently locked out */
#define RATELIMIT_ERR_INIT     -2
#define RATELIMIT_ERR_IO       -3
#define RATELIMIT_WIPED        -4   /* Wallet wiped after too many attempts */

/* Default configuration */
#define RATELIMIT_MAX_ATTEMPTS      5    /* Attempts before lockout */
#define RATELIMIT_BASE_LOCKOUT_SEC  30   /* Initial lockout: 30 seconds */
#define RATELIMIT_MAX_LOCKOUT_SEC   3600 /* Maximum lockout: 1 hour */
#define RATELIMIT_WIPE_THRESHOLD    20   /* Wipe wallet after this many total failures */

/* Authentication types */
typedef enum {
    AUTH_TYPE_PIN,
    AUTH_TYPE_FINGERPRINT
} auth_type_t;

/* Rate limit state (persisted) */
typedef struct {
    uint32_t magic;                /* Validation magic number */
    uint32_t pin_fail_count;       /* Consecutive PIN failures */
    uint32_t fp_fail_count;        /* Consecutive fingerprint failures */
    uint32_t total_pin_failures;   /* Total PIN failures (never resets) */
    uint32_t total_fp_failures;    /* Total fingerprint failures (never resets) */
    int64_t  lockout_until;        /* Unix timestamp when lockout ends */
    uint32_t lockout_level;        /* Current exponential backoff level */
    uint32_t checksum;             /* Simple checksum for integrity */
} ratelimit_state_t;

/**
 * Initialize rate limiting subsystem
 * Loads persisted state from storage if available
 *
 * @return RATELIMIT_OK on success, error code on failure
 */
int ratelimit_init(void);

/**
 * Cleanup rate limiting subsystem
 * Saves current state to storage
 */
void ratelimit_cleanup(void);

/**
 * Check if authentication is allowed
 * Call this BEFORE attempting PIN or fingerprint verification
 *
 * @param auth_type Type of authentication being attempted
 * @param remaining_sec Output: seconds remaining if locked (can be NULL)
 * @return RATELIMIT_OK if allowed, RATELIMIT_LOCKED if locked out
 */
int ratelimit_check(auth_type_t auth_type, uint32_t *remaining_sec);

/**
 * Record a failed authentication attempt
 * Updates counters and may trigger lockout
 *
 * @param auth_type Type of authentication that failed
 * @return RATELIMIT_OK, RATELIMIT_LOCKED, or RATELIMIT_WIPED
 */
int ratelimit_record_failure(auth_type_t auth_type);

/**
 * Record a successful authentication
 * Resets consecutive failure counter for that type
 *
 * @param auth_type Type of authentication that succeeded
 */
void ratelimit_record_success(auth_type_t auth_type);

/**
 * Get current failure counts
 *
 * @param pin_fails Output: consecutive PIN failures (can be NULL)
 * @param fp_fails Output: consecutive fingerprint failures (can be NULL)
 * @param total_pin Output: total PIN failures (can be NULL)
 * @param total_fp Output: total fingerprint failures (can be NULL)
 */
void ratelimit_get_stats(uint32_t *pin_fails, uint32_t *fp_fails,
                         uint32_t *total_pin, uint32_t *total_fp);

/**
 * Get lockout status
 *
 * @param remaining_sec Output: seconds remaining in lockout (0 if not locked)
 * @param lockout_level Output: current exponential backoff level
 * @return 1 if currently locked, 0 if not
 */
int ratelimit_is_locked(uint32_t *remaining_sec, uint32_t *lockout_level);

/**
 * Reset rate limiting state (admin function)
 * WARNING: This should only be called after successful authentication
 */
void ratelimit_reset(void);

/**
 * Force save state to storage
 *
 * @return RATELIMIT_OK on success, error code on failure
 */
int ratelimit_save_state(void);

#endif /* RATELIMIT_H */

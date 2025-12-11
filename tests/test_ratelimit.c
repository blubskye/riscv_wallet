/*
 * Rate Limiting Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../src/security/ratelimit.h"
#include "../src/security/storage.h"

/* External test report function */
extern void test_report(const char *name, int result);

static int test_ratelimit_init(void)
{
    /* Initialize storage first (required for rate limiting) */
    if (storage_init() != STORAGE_OK) {
        printf("    Storage init failed\n");
        return -1;
    }

    /* Initialize rate limiting */
    if (ratelimit_init() != RATELIMIT_OK) {
        printf("    Rate limit init failed\n");
        return -1;
    }

    /* Reset to clean state */
    ratelimit_reset();

    return 0;
}

static int test_ratelimit_check_unlocked(void)
{
    uint32_t remaining;

    /* After reset, should not be locked */
    if (ratelimit_check(AUTH_TYPE_PIN, &remaining) == RATELIMIT_LOCKED) {
        printf("    Should not be locked after reset\n");
        return -1;
    }

    if (remaining != 0) {
        printf("    Remaining should be 0, got %u\n", remaining);
        return -1;
    }

    return 0;
}

static int test_ratelimit_record_failure(void)
{
    uint32_t pin_fails, total_fails;

    /* Reset to clean state */
    ratelimit_reset();

    /* Record one failure */
    int ret = ratelimit_record_failure(AUTH_TYPE_PIN);
    if (ret != RATELIMIT_OK) {
        printf("    First failure should return OK\n");
        return -1;
    }

    /* Check counters */
    ratelimit_get_stats(&pin_fails, NULL, &total_fails, NULL);
    if (pin_fails != 1) {
        printf("    Expected 1 PIN failure, got %u\n", pin_fails);
        return -1;
    }

    return 0;
}

static int test_ratelimit_record_success(void)
{
    uint32_t pin_fails;

    /* Reset to clean state */
    ratelimit_reset();

    /* Record some failures */
    ratelimit_record_failure(AUTH_TYPE_PIN);
    ratelimit_record_failure(AUTH_TYPE_PIN);

    ratelimit_get_stats(&pin_fails, NULL, NULL, NULL);
    if (pin_fails != 2) {
        printf("    Expected 2 failures, got %u\n", pin_fails);
        return -1;
    }

    /* Record success - should reset consecutive counter */
    ratelimit_record_success(AUTH_TYPE_PIN);

    ratelimit_get_stats(&pin_fails, NULL, NULL, NULL);
    if (pin_fails != 0) {
        printf("    Consecutive failures should be 0 after success, got %u\n", pin_fails);
        return -1;
    }

    return 0;
}

static int test_ratelimit_lockout_trigger(void)
{
    uint32_t remaining;
    int ret;

    /* Reset to clean state */
    ratelimit_reset();

    /* Record failures up to limit */
    for (int i = 0; i < RATELIMIT_MAX_ATTEMPTS - 1; i++) {
        ret = ratelimit_record_failure(AUTH_TYPE_PIN);
        if (ret != RATELIMIT_OK) {
            printf("    Failure %d should return OK\n", i + 1);
            return -1;
        }
    }

    /* Next failure should trigger lockout */
    ret = ratelimit_record_failure(AUTH_TYPE_PIN);
    if (ret != RATELIMIT_LOCKED) {
        printf("    Should return LOCKED after max attempts\n");
        return -1;
    }

    /* Check that we're locked */
    if (ratelimit_is_locked(&remaining, NULL) != 1) {
        printf("    Should be locked\n");
        return -1;
    }

    if (remaining == 0 || remaining > RATELIMIT_BASE_LOCKOUT_SEC) {
        printf("    Lockout duration unexpected: %u (expected ~%d)\n",
               remaining, RATELIMIT_BASE_LOCKOUT_SEC);
        return -1;
    }

    return 0;
}

static int test_ratelimit_separate_counters(void)
{
    uint32_t pin_fails, fp_fails;

    /* Reset to clean state */
    ratelimit_reset();

    /* Record PIN failures */
    ratelimit_record_failure(AUTH_TYPE_PIN);
    ratelimit_record_failure(AUTH_TYPE_PIN);

    /* Record fingerprint failures */
    ratelimit_record_failure(AUTH_TYPE_FINGERPRINT);

    /* Check counters are separate */
    ratelimit_get_stats(&pin_fails, &fp_fails, NULL, NULL);

    if (pin_fails != 2) {
        printf("    Expected 2 PIN failures, got %u\n", pin_fails);
        return -1;
    }

    if (fp_fails != 1) {
        printf("    Expected 1 FP failure, got %u\n", fp_fails);
        return -1;
    }

    return 0;
}

int test_ratelimit(void)
{
    int result = 0;

    test_report("Rate limit init", test_ratelimit_init());
    test_report("Check unlocked state", test_ratelimit_check_unlocked());
    test_report("Record failure", test_ratelimit_record_failure());
    test_report("Record success resets counter", test_ratelimit_record_success());
    test_report("Lockout trigger", test_ratelimit_lockout_trigger());
    test_report("Separate PIN/FP counters", test_ratelimit_separate_counters());

    /* Cleanup */
    ratelimit_reset();
    ratelimit_cleanup();

    return result;
}

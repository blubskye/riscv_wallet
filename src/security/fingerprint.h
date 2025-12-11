/*
 * Fingerprint Authentication
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <stdint.h>
#include <stddef.h>

/* Maximum fingerprint slots */
#define FP_MAX_SLOTS      5

/* Fingerprint error codes */
#define FP_OK             0
#define FP_ERR_INIT      -1
#define FP_ERR_NO_DEVICE -2
#define FP_ERR_ENROLL    -3
#define FP_ERR_VERIFY    -4
#define FP_ERR_NO_MATCH  -5
#define FP_ERR_IO        -6
#define FP_ERR_SLOT      -7
#define FP_ERR_TIMEOUT   -8

/* Enrollment stages callback */
typedef void (*fp_enroll_callback_t)(int stage, int total_stages, void *user_data);

/* Verify progress callback */
typedef void (*fp_verify_callback_t)(int retry_count, void *user_data);

/**
 * Initialize fingerprint subsystem
 *
 * @return FP_OK on success, error code on failure
 */
int fingerprint_init(void);

/**
 * Cleanup fingerprint subsystem
 */
void fingerprint_cleanup(void);

/**
 * Check if fingerprint reader is available
 *
 * @return 1 if available, 0 if not
 */
int fingerprint_is_available(void);

/**
 * Get device name/description
 *
 * @return Device name string, or NULL if not available
 */
const char *fingerprint_get_device_name(void);

/**
 * Enroll a new fingerprint
 *
 * @param slot Fingerprint slot (0-4)
 * @param callback Optional callback for enrollment progress
 * @param user_data User data for callback
 * @return FP_OK on success, error code on failure
 */
int fingerprint_enroll(int slot, fp_enroll_callback_t callback, void *user_data);

/**
 * Verify fingerprint against enrolled prints
 *
 * @param callback Optional callback for retry progress
 * @param user_data User data for callback
 * @return FP_OK on successful match, error code on failure
 */
int fingerprint_verify(fp_verify_callback_t callback, void *user_data);

/**
 * Verify fingerprint and return matched slot
 *
 * @param matched_slot Output: which slot matched (-1 if no match)
 * @return FP_OK on successful match, error code on failure
 */
int fingerprint_identify(int *matched_slot);

/**
 * Delete enrolled fingerprint
 *
 * @param slot Fingerprint slot to delete
 * @return FP_OK on success, error code on failure
 */
int fingerprint_delete(int slot);

/**
 * Delete all enrolled fingerprints
 *
 * @return FP_OK on success, error code on failure
 */
int fingerprint_delete_all(void);

/**
 * Get number of enrolled fingerprints
 *
 * @return Number of enrolled fingerprints
 */
int fingerprint_get_enrolled_count(void);

/**
 * Check if a slot has an enrolled fingerprint
 *
 * @param slot Slot to check
 * @return 1 if enrolled, 0 if empty
 */
int fingerprint_slot_enrolled(int slot);

/**
 * Set enrollment timeout in seconds
 *
 * @param timeout Timeout in seconds (0 = no timeout)
 */
void fingerprint_set_timeout(int timeout);

#endif /* FINGERPRINT_H */

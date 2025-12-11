/*
 * Secure Boot Chain Verification
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Implements verification of firmware images using Ed25519 signatures.
 * Provides a chain of trust from bootloader to application.
 */

#ifndef SECUREBOOT_H
#define SECUREBOOT_H

#include <stdint.h>
#include <stddef.h>

/* Signature algorithm identifiers */
#define SECBOOT_ALG_ED25519      0x01
#define SECBOOT_ALG_ED25519PH    0x02  /* Pre-hashed */
#define SECBOOT_ALG_ECDSA_P256   0x03  /* Future expansion */

/* Image types */
#define SECBOOT_IMAGE_BOOTLOADER 0x01
#define SECBOOT_IMAGE_FIRMWARE   0x02
#define SECBOOT_IMAGE_RECOVERY   0x03
#define SECBOOT_IMAGE_DATA       0x04

/* Boot status flags */
#define SECBOOT_FLAG_VERIFIED    (1 << 0)  /* Image signature verified */
#define SECBOOT_FLAG_ROLLBACK_OK (1 << 1)  /* Rollback protection passed */
#define SECBOOT_FLAG_DEBUG_MODE  (1 << 2)  /* Debug/development mode */
#define SECBOOT_FLAG_RECOVERY    (1 << 3)  /* Running in recovery mode */

/* Error codes */
#define SECBOOT_OK               0
#define SECBOOT_ERR_INVALID_SIG  -1
#define SECBOOT_ERR_INVALID_HDR  -2
#define SECBOOT_ERR_ROLLBACK     -3
#define SECBOOT_ERR_KEY_REVOKED  -4
#define SECBOOT_ERR_HASH_FAIL    -5
#define SECBOOT_ERR_NO_IMAGE     -6
#define SECBOOT_ERR_INTERNAL     -7

/* Version structure */
typedef struct {
    uint8_t major;
    uint8_t minor;
    uint16_t patch;
    uint32_t build;          /* Build number for rollback protection */
} secboot_version_t;

/* Image header (prepended to firmware images) */
#define SECBOOT_MAGIC   0x52564257  /* "RVBW" - RISC-V Bitcoin Wallet */
#define SECBOOT_HDR_VERSION  1

typedef struct __attribute__((packed)) {
    uint32_t magic;              /* SECBOOT_MAGIC */
    uint32_t header_version;     /* Header format version */
    uint32_t image_size;         /* Size of image (excluding header) */
    uint32_t image_type;         /* SECBOOT_IMAGE_* */
    uint32_t algorithm;          /* SECBOOT_ALG_* */
    uint8_t  version[8];         /* secboot_version_t */
    uint8_t  image_hash[32];     /* SHA-256 of image */
    uint8_t  pubkey_hash[32];    /* SHA-256 of signing public key */
    uint8_t  signature[64];      /* Ed25519 signature */
    uint8_t  reserved[60];       /* Reserved for future use */
    uint32_t header_crc;         /* CRC32 of header (excluding this field) */
} secboot_header_t;

/* Public key slot (stored in secure memory) */
#define SECBOOT_MAX_KEYS         4
#define SECBOOT_KEY_VALID        (1 << 0)
#define SECBOOT_KEY_PRODUCTION   (1 << 1)
#define SECBOOT_KEY_REVOKED      (1 << 2)

typedef struct {
    uint8_t  pubkey[32];         /* Ed25519 public key */
    uint8_t  pubkey_hash[32];    /* SHA-256 of public key (for matching) */
    uint32_t flags;              /* Key flags */
    uint32_t key_id;             /* Key identifier */
} secboot_pubkey_t;

/* Boot state (persisted across boots) */
typedef struct {
    uint32_t boot_count;         /* Total boot count */
    uint32_t last_verified_build;/* Highest verified build number */
    uint32_t rollback_version;   /* Minimum allowed version (for rollback protection) */
    uint32_t flags;              /* Boot status flags */
    uint8_t  last_image_hash[32];/* Hash of last verified image */
} secboot_state_t;

/* ============================================================================
 * Initialization
 * ============================================================================ */

/**
 * Initialize secure boot subsystem
 *
 * @return SECBOOT_OK on success, error code on failure
 */
int secboot_init(void);

/**
 * Check if secure boot is enabled
 *
 * @return 1 if enabled, 0 if disabled (development mode)
 */
int secboot_is_enabled(void);

/**
 * Get current boot status flags
 *
 * @return Boot status flags (SECBOOT_FLAG_*)
 */
uint32_t secboot_get_flags(void);

/* ============================================================================
 * Key Management
 * ============================================================================ */

/**
 * Load public key from slot
 *
 * @param slot Key slot number (0 to SECBOOT_MAX_KEYS-1)
 * @param key Output key structure
 * @return SECBOOT_OK on success, error code on failure
 */
int secboot_load_pubkey(unsigned int slot, secboot_pubkey_t *key);

/**
 * Store public key in slot (only allowed in provisioning mode)
 *
 * @param slot Key slot number
 * @param pubkey Ed25519 public key (32 bytes)
 * @param flags Key flags
 * @return SECBOOT_OK on success, error code on failure
 */
int secboot_store_pubkey(unsigned int slot, const uint8_t pubkey[32], uint32_t flags);

/**
 * Revoke public key (permanent)
 *
 * @param slot Key slot number
 * @return SECBOOT_OK on success, error code on failure
 */
int secboot_revoke_key(unsigned int slot);

/**
 * Find key by hash
 *
 * @param pubkey_hash SHA-256 hash of public key
 * @param key Output key structure
 * @return Key slot number if found, -1 if not found
 */
int secboot_find_key(const uint8_t pubkey_hash[32], secboot_pubkey_t *key);

/* ============================================================================
 * Image Verification
 * ============================================================================ */

/**
 * Parse image header
 *
 * @param data Image data (starting with header)
 * @param data_len Length of image data
 * @param header Output header structure
 * @return SECBOOT_OK on success, error code on failure
 */
int secboot_parse_header(const uint8_t *data, size_t data_len,
                         secboot_header_t *header);

/**
 * Verify image signature
 *
 * @param header Parsed image header
 * @param image Image data (after header)
 * @return SECBOOT_OK if valid, error code on failure
 */
int secboot_verify_image(const secboot_header_t *header, const uint8_t *image);

/**
 * Verify complete image (header + data) from buffer
 *
 * @param data Complete image data
 * @param data_len Length of image data
 * @return SECBOOT_OK if valid, error code on failure
 */
int secboot_verify_buffer(const uint8_t *data, size_t data_len);

/**
 * Verify image file
 *
 * @param path Path to image file
 * @return SECBOOT_OK if valid, error code on failure
 */
int secboot_verify_file(const char *path);

/* ============================================================================
 * Rollback Protection
 * ============================================================================ */

/**
 * Check if version is allowed (rollback protection)
 *
 * @param version Version to check
 * @return 1 if allowed, 0 if rollback detected
 */
int secboot_check_version(const secboot_version_t *version);

/**
 * Update minimum version (commit to new version)
 *
 * @param version New minimum version
 * @return SECBOOT_OK on success, error code on failure
 */
int secboot_update_rollback(const secboot_version_t *version);

/**
 * Get current rollback counter
 *
 * @return Current rollback counter value
 */
uint32_t secboot_get_rollback_counter(void);

/* ============================================================================
 * Boot State
 * ============================================================================ */

/**
 * Load boot state from persistent storage
 *
 * @param state Output state structure
 * @return SECBOOT_OK on success, error code on failure
 */
int secboot_load_state(secboot_state_t *state);

/**
 * Save boot state to persistent storage
 *
 * @param state State to save
 * @return SECBOOT_OK on success, error code on failure
 */
int secboot_save_state(const secboot_state_t *state);

/**
 * Record successful boot
 *
 * @param header Verified image header
 * @return SECBOOT_OK on success, error code on failure
 */
int secboot_record_boot(const secboot_header_t *header);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Get error message for error code
 *
 * @param err Error code
 * @return Human-readable error message
 */
const char *secboot_error_string(int err);

/**
 * Format version to string
 *
 * @param version Version structure
 * @param str Output string buffer
 * @param str_len Size of string buffer
 * @return 0 on success, -1 on error
 */
int secboot_format_version(const secboot_version_t *version, char *str, size_t str_len);

/**
 * Parse version from header bytes
 *
 * @param data 8-byte version data from header
 * @param version Output version structure
 */
void secboot_parse_version(const uint8_t data[8], secboot_version_t *version);

/**
 * Compare versions
 *
 * @param a First version
 * @param b Second version
 * @return <0 if a<b, 0 if a==b, >0 if a>b
 */
int secboot_compare_version(const secboot_version_t *a, const secboot_version_t *b);

#endif /* SECUREBOOT_H */

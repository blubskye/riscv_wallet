/*
 * Firmware Update Mechanism
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Secure over-the-air (OTA) firmware update with verification.
 * Supports incremental updates and rollback recovery.
 */

#ifndef FIRMWARE_H
#define FIRMWARE_H

#include <stdint.h>
#include <stddef.h>
#include "secureboot.h"

/* Firmware update status codes */
#define FW_UPDATE_OK             0
#define FW_UPDATE_ERR_VERIFY     -1   /* Signature verification failed */
#define FW_UPDATE_ERR_ROLLBACK   -2   /* Version rollback detected */
#define FW_UPDATE_ERR_DOWNLOAD   -3   /* Download/transfer error */
#define FW_UPDATE_ERR_STORAGE    -4   /* Insufficient storage */
#define FW_UPDATE_ERR_CORRUPT    -5   /* Image corruption detected */
#define FW_UPDATE_ERR_BUSY       -6   /* Update already in progress */
#define FW_UPDATE_ERR_ABORTED    -7   /* Update aborted by user */
#define FW_UPDATE_ERR_INTERNAL   -8   /* Internal error */

/* Update state */
typedef enum {
    FW_STATE_IDLE = 0,           /* No update in progress */
    FW_STATE_DOWNLOADING,        /* Receiving firmware chunks */
    FW_STATE_VERIFYING,          /* Verifying signature */
    FW_STATE_STAGING,            /* Staged for install */
    FW_STATE_INSTALLING,         /* Writing to flash */
    FW_STATE_COMPLETE,           /* Update complete, reboot pending */
    FW_STATE_FAILED              /* Update failed */
} fw_update_state_t;

/* Update source types */
typedef enum {
    FW_SOURCE_USB,               /* USB mass storage or companion app */
    FW_SOURCE_SDCARD,            /* SD card */
    FW_SOURCE_SERIAL,            /* UART/serial transfer */
    FW_SOURCE_NETWORK            /* Network (if available) */
} fw_source_t;

/* Chunk transfer protocol */
#define FW_CHUNK_SIZE            4096   /* Chunk size for transfers */
#define FW_CHUNK_MAGIC           0x464B  /* "FK" - Firmware chunk */

typedef struct __attribute__((packed)) {
    uint16_t magic;              /* FW_CHUNK_MAGIC */
    uint16_t flags;              /* Chunk flags */
    uint32_t chunk_num;          /* Chunk sequence number */
    uint32_t total_chunks;       /* Total chunks in image */
    uint32_t chunk_size;         /* Size of this chunk */
    uint32_t chunk_crc;          /* CRC32 of chunk data */
    uint8_t  data[];             /* Chunk data (variable length) */
} fw_chunk_t;

/* Chunk flags */
#define FW_CHUNK_FLAG_FIRST      (1 << 0)   /* First chunk (contains header) */
#define FW_CHUNK_FLAG_LAST       (1 << 1)   /* Last chunk */
#define FW_CHUNK_FLAG_COMPRESSED (1 << 2)   /* Data is compressed */

/* Update progress information */
typedef struct {
    fw_update_state_t state;
    uint32_t total_size;         /* Total firmware size */
    uint32_t received_size;      /* Bytes received so far */
    uint32_t total_chunks;       /* Total chunks expected */
    uint32_t received_chunks;    /* Chunks received */
    uint8_t  percent_complete;   /* Progress percentage */
    int      last_error;         /* Last error code */
    char     version_str[32];    /* New version string */
} fw_progress_t;

/* Staged update information */
typedef struct {
    secboot_header_t header;     /* Verified image header */
    uint32_t staged_size;        /* Size of staged image */
    uint32_t stage_time;         /* Timestamp when staged */
    uint8_t  image_hash[32];     /* SHA-256 of staged image */
    int      verified;           /* 1 if signature verified */
} fw_staged_t;

/* ============================================================================
 * Update Control
 * ============================================================================ */

/**
 * Initialize firmware update subsystem
 *
 * @return FW_UPDATE_OK on success, error code on failure
 */
int fw_update_init(void);

/**
 * Start firmware update process
 *
 * @param source Update source type
 * @param expected_size Expected firmware size (0 if unknown)
 * @return FW_UPDATE_OK on success, error code on failure
 */
int fw_update_start(fw_source_t source, uint32_t expected_size);

/**
 * Abort firmware update
 *
 * @return FW_UPDATE_OK on success
 */
int fw_update_abort(void);

/**
 * Get current update state
 *
 * @return Current update state
 */
fw_update_state_t fw_update_get_state(void);

/**
 * Get update progress information
 *
 * @param progress Output progress structure
 * @return FW_UPDATE_OK on success
 */
int fw_update_get_progress(fw_progress_t *progress);

/* ============================================================================
 * Data Transfer
 * ============================================================================ */

/**
 * Receive firmware chunk
 *
 * @param chunk Chunk data
 * @param chunk_len Length of chunk (including header)
 * @return FW_UPDATE_OK on success, error code on failure
 */
int fw_update_receive_chunk(const fw_chunk_t *chunk, size_t chunk_len);

/**
 * Receive raw firmware data (streaming mode)
 *
 * @param data Data buffer
 * @param len Length of data
 * @param offset Offset in firmware image
 * @return FW_UPDATE_OK on success, error code on failure
 */
int fw_update_receive_data(const uint8_t *data, size_t len, uint32_t offset);

/**
 * Signal end of transfer
 *
 * @return FW_UPDATE_OK on success, error code on failure
 */
int fw_update_end_transfer(void);

/* ============================================================================
 * Verification and Installation
 * ============================================================================ */

/**
 * Verify staged firmware
 *
 * @return FW_UPDATE_OK if verified, error code on failure
 */
int fw_update_verify(void);

/**
 * Install verified firmware
 *
 * @return FW_UPDATE_OK on success, error code on failure
 */
int fw_update_install(void);

/**
 * Check if update is staged and ready
 *
 * @param staged Output staged update info (can be NULL)
 * @return 1 if staged, 0 if not
 */
int fw_update_is_staged(fw_staged_t *staged);

/**
 * Clear staged update
 *
 * @return FW_UPDATE_OK on success
 */
int fw_update_clear_staged(void);

/* ============================================================================
 * Recovery
 * ============================================================================ */

/**
 * Check if recovery mode is needed
 *
 * @return 1 if recovery needed, 0 if not
 */
int fw_recovery_needed(void);

/**
 * Enter recovery mode
 *
 * @return Does not return on success
 */
int fw_enter_recovery(void);

/**
 * Restore from backup (if available)
 *
 * @return FW_UPDATE_OK on success, error code on failure
 */
int fw_restore_backup(void);

/* ============================================================================
 * Version Information
 * ============================================================================ */

/**
 * Get current firmware version
 *
 * @param version Output version structure
 * @return FW_UPDATE_OK on success
 */
int fw_get_current_version(secboot_version_t *version);

/**
 * Get staged firmware version
 *
 * @param version Output version structure
 * @return FW_UPDATE_OK if staged, error code if not
 */
int fw_get_staged_version(secboot_version_t *version);

/**
 * Check if version is newer than current
 *
 * @param version Version to check
 * @return 1 if newer, 0 if same or older
 */
int fw_is_newer_version(const secboot_version_t *version);

/* ============================================================================
 * File-Based Updates
 * ============================================================================ */

/**
 * Load firmware from file
 *
 * @param path Path to firmware file
 * @return FW_UPDATE_OK on success, error code on failure
 */
int fw_update_load_file(const char *path);

/**
 * Scan for firmware files in directory
 *
 * @param dir Directory to scan
 * @param files Output array of firmware file paths
 * @param max_files Maximum files to return
 * @return Number of firmware files found
 */
int fw_scan_directory(const char *dir, char files[][256], int max_files);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Get error message for error code
 *
 * @param err Error code
 * @return Human-readable error message
 */
const char *fw_update_error_string(int err);

/**
 * Get state name string
 *
 * @param state Update state
 * @return State name string
 */
const char *fw_update_state_string(fw_update_state_t state);

/**
 * Calculate CRC32 for chunk verification
 *
 * @param data Data buffer
 * @param len Length of data
 * @return CRC32 checksum
 */
uint32_t fw_chunk_crc32(const uint8_t *data, size_t len);

#endif /* FIRMWARE_H */

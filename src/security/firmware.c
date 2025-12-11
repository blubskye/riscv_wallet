/*
 * Firmware Update Mechanism
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L

#include "firmware.h"
#include "storage.h"
#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sodium.h>

/* Staging file names */
#define FW_STAGING_FILE    "firmware_staging.bin"
#define FW_STAGING_META    "firmware_staging.meta"
#define FW_BACKUP_FILE     "firmware_backup.bin"

/* Maximum firmware size (16 MB) */
#define FW_MAX_SIZE        (16 * 1024 * 1024)

/* Current firmware version (compiled in) */
static const secboot_version_t current_version = {
    .major = 1,
    .minor = 0,
    .patch = 0,
    .build = 1
};

/* Update state */
static struct {
    fw_update_state_t state;
    fw_source_t source;
    uint32_t expected_size;
    uint32_t received_size;
    uint32_t total_chunks;
    uint32_t received_chunks;
    int last_error;
    FILE *staging_file;
    uint8_t *chunk_bitmap;       /* Track received chunks */
    secboot_header_t header;
    int header_received;
} g_update;

/* Error messages */
static const char *error_messages[] = {
    [0]  = "Success",
    [1]  = "Signature verification failed",
    [2]  = "Version rollback detected",
    [3]  = "Download/transfer error",
    [4]  = "Insufficient storage",
    [5]  = "Image corruption detected",
    [6]  = "Update already in progress",
    [7]  = "Update aborted",
    [8]  = "Internal error",
};

/* State names */
static const char *state_names[] = {
    [FW_STATE_IDLE]         = "Idle",
    [FW_STATE_DOWNLOADING]  = "Downloading",
    [FW_STATE_VERIFYING]    = "Verifying",
    [FW_STATE_STAGING]      = "Staged",
    [FW_STATE_INSTALLING]   = "Installing",
    [FW_STATE_COMPLETE]     = "Complete",
    [FW_STATE_FAILED]       = "Failed",
};

/* CRC32 calculation */
uint32_t fw_chunk_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

/* ============================================================================
 * Update Control
 * ============================================================================ */

int fw_update_init(void)
{
    memset(&g_update, 0, sizeof(g_update));
    g_update.state = FW_STATE_IDLE;
    return FW_UPDATE_OK;
}

int fw_update_start(fw_source_t source, uint32_t expected_size)
{
    if (g_update.state != FW_STATE_IDLE) {
        return FW_UPDATE_ERR_BUSY;
    }

    if (expected_size > FW_MAX_SIZE) {
        return FW_UPDATE_ERR_STORAGE;
    }

    /* Open staging file */
    char staging_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(staging_path, sizeof(staging_path), "%s/%s", storage_dir, FW_STAGING_FILE);

    g_update.staging_file = fopen(staging_path, "wb");
    if (!g_update.staging_file) {
        return FW_UPDATE_ERR_STORAGE;
    }

    g_update.state = FW_STATE_DOWNLOADING;
    g_update.source = source;
    g_update.expected_size = expected_size;
    g_update.received_size = 0;
    g_update.total_chunks = 0;
    g_update.received_chunks = 0;
    g_update.last_error = 0;
    g_update.header_received = 0;

    /* Allocate chunk bitmap if chunked transfer */
    if (expected_size > 0) {
        size_t num_chunks = (expected_size + FW_CHUNK_SIZE - 1) / FW_CHUNK_SIZE;
        g_update.chunk_bitmap = calloc((num_chunks + 7) / 8, 1);
        g_update.total_chunks = (uint32_t)num_chunks;
    }

    return FW_UPDATE_OK;
}

int fw_update_abort(void)
{
    if (g_update.staging_file) {
        fclose(g_update.staging_file);
        g_update.staging_file = NULL;
    }

    if (g_update.chunk_bitmap) {
        free(g_update.chunk_bitmap);
        g_update.chunk_bitmap = NULL;
    }

    /* Remove staging file */
    char staging_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(staging_path, sizeof(staging_path), "%s/%s", storage_dir, FW_STAGING_FILE);
    remove(staging_path);

    g_update.state = FW_STATE_IDLE;
    g_update.last_error = FW_UPDATE_ERR_ABORTED;

    return FW_UPDATE_OK;
}

fw_update_state_t fw_update_get_state(void)
{
    return g_update.state;
}

int fw_update_get_progress(fw_progress_t *progress)
{
    if (progress == NULL) {
        return FW_UPDATE_ERR_INTERNAL;
    }

    progress->state = g_update.state;
    progress->total_size = g_update.expected_size;
    progress->received_size = g_update.received_size;
    progress->total_chunks = g_update.total_chunks;
    progress->received_chunks = g_update.received_chunks;
    progress->last_error = g_update.last_error;

    if (g_update.expected_size > 0) {
        progress->percent_complete = (uint8_t)(
            (g_update.received_size * 100) / g_update.expected_size);
    } else {
        progress->percent_complete = 0;
    }

    if (g_update.header_received) {
        secboot_version_t version;
        secboot_parse_version(g_update.header.version, &version);
        secboot_format_version(&version, progress->version_str,
                               sizeof(progress->version_str));
    } else {
        progress->version_str[0] = '\0';
    }

    return FW_UPDATE_OK;
}

/* ============================================================================
 * Data Transfer
 * ============================================================================ */

int fw_update_receive_chunk(const fw_chunk_t *chunk, size_t chunk_len)
{
    if (g_update.state != FW_STATE_DOWNLOADING) {
        return FW_UPDATE_ERR_BUSY;
    }

    if (chunk == NULL || chunk_len < sizeof(fw_chunk_t)) {
        return FW_UPDATE_ERR_CORRUPT;
    }

    /* Verify chunk magic */
    if (chunk->magic != FW_CHUNK_MAGIC) {
        return FW_UPDATE_ERR_CORRUPT;
    }

    /* Verify chunk CRC */
    if (chunk->chunk_size > 0) {
        uint32_t computed_crc = fw_chunk_crc32(chunk->data, chunk->chunk_size);
        if (computed_crc != chunk->chunk_crc) {
            return FW_UPDATE_ERR_CORRUPT;
        }
    }

    /* Update total chunks if this is the first chunk */
    if (chunk->flags & FW_CHUNK_FLAG_FIRST) {
        g_update.total_chunks = chunk->total_chunks;

        /* Parse header from first chunk */
        if (chunk->chunk_size >= sizeof(secboot_header_t)) {
            int ret = secboot_parse_header(chunk->data, chunk->chunk_size,
                                          &g_update.header);
            if (ret != SECBOOT_OK) {
                g_update.state = FW_STATE_FAILED;
                g_update.last_error = FW_UPDATE_ERR_VERIFY;
                return FW_UPDATE_ERR_VERIFY;
            }
            g_update.header_received = 1;
            g_update.expected_size = g_update.header.image_size +
                                    (uint32_t)sizeof(secboot_header_t);
        }
    }

    /* Write chunk data */
    uint32_t offset = chunk->chunk_num * FW_CHUNK_SIZE;
    if (g_update.staging_file) {
        fseek(g_update.staging_file, (long)offset, SEEK_SET);
        if (fwrite(chunk->data, 1, chunk->chunk_size,
                   g_update.staging_file) != chunk->chunk_size) {
            g_update.state = FW_STATE_FAILED;
            g_update.last_error = FW_UPDATE_ERR_STORAGE;
            return FW_UPDATE_ERR_STORAGE;
        }
    }

    /* Mark chunk as received */
    if (g_update.chunk_bitmap) {
        g_update.chunk_bitmap[chunk->chunk_num / 8] |= (1 << (chunk->chunk_num % 8));
    }

    g_update.received_chunks++;
    g_update.received_size += chunk->chunk_size;

    /* Check if all chunks received */
    if (chunk->flags & FW_CHUNK_FLAG_LAST ||
        g_update.received_chunks >= g_update.total_chunks) {
        return fw_update_end_transfer();
    }

    return FW_UPDATE_OK;
}

int fw_update_receive_data(const uint8_t *data, size_t len, uint32_t offset)
{
    if (g_update.state != FW_STATE_DOWNLOADING) {
        return FW_UPDATE_ERR_BUSY;
    }

    if (data == NULL || len == 0) {
        return FW_UPDATE_ERR_CORRUPT;
    }

    /* Write data at offset */
    if (g_update.staging_file) {
        fseek(g_update.staging_file, (long)offset, SEEK_SET);
        if (fwrite(data, 1, len, g_update.staging_file) != len) {
            g_update.state = FW_STATE_FAILED;
            g_update.last_error = FW_UPDATE_ERR_STORAGE;
            return FW_UPDATE_ERR_STORAGE;
        }
    }

    /* Parse header if this is the beginning */
    if (offset == 0 && len >= sizeof(secboot_header_t) && !g_update.header_received) {
        int ret = secboot_parse_header(data, len, &g_update.header);
        if (ret == SECBOOT_OK) {
            g_update.header_received = 1;
            g_update.expected_size = g_update.header.image_size +
                                    (uint32_t)sizeof(secboot_header_t);
        }
    }

    g_update.received_size = offset + (uint32_t)len;

    return FW_UPDATE_OK;
}

int fw_update_end_transfer(void)
{
    if (g_update.staging_file) {
        fclose(g_update.staging_file);
        g_update.staging_file = NULL;
    }

    if (g_update.chunk_bitmap) {
        free(g_update.chunk_bitmap);
        g_update.chunk_bitmap = NULL;
    }

    g_update.state = FW_STATE_VERIFYING;

    /* Verify the staged firmware */
    return fw_update_verify();
}

/* ============================================================================
 * Verification and Installation
 * ============================================================================ */

int fw_update_verify(void)
{
    char staging_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(staging_path, sizeof(staging_path), "%s/%s", storage_dir, FW_STAGING_FILE);

    /* Use secure boot verification */
    int ret = secboot_verify_file(staging_path);
    if (ret != SECBOOT_OK) {
        g_update.state = FW_STATE_FAILED;
        g_update.last_error = FW_UPDATE_ERR_VERIFY;
        return FW_UPDATE_ERR_VERIFY;
    }

    /* Check version (rollback protection) */
    if (g_update.header_received) {
        secboot_version_t staged_version;
        secboot_parse_version(g_update.header.version, &staged_version);

        if (!fw_is_newer_version(&staged_version)) {
            g_update.state = FW_STATE_FAILED;
            g_update.last_error = FW_UPDATE_ERR_ROLLBACK;
            return FW_UPDATE_ERR_ROLLBACK;
        }
    }

    g_update.state = FW_STATE_STAGING;

    /* Save staging metadata */
    char meta_path[256];
    snprintf(meta_path, sizeof(meta_path), "%s/%s", storage_dir, FW_STAGING_META);

    FILE *f = fopen(meta_path, "wb");
    if (f) {
        fw_staged_t staged = {0};
        memcpy(&staged.header, &g_update.header, sizeof(secboot_header_t));
        staged.staged_size = g_update.received_size;
        staged.stage_time = (uint32_t)time(NULL);
        memcpy(staged.image_hash, g_update.header.image_hash, 32);
        staged.verified = 1;

        fwrite(&staged, sizeof(staged), 1, f);
        fclose(f);
    }

    return FW_UPDATE_OK;
}

int fw_update_install(void)
{
    if (g_update.state != FW_STATE_STAGING) {
        fw_staged_t staged;
        if (!fw_update_is_staged(&staged)) {
            return FW_UPDATE_ERR_INTERNAL;
        }
    }

    g_update.state = FW_STATE_INSTALLING;

    /*
     * In a real firmware update, this would:
     * 1. Backup current firmware
     * 2. Write new firmware to flash
     * 3. Update boot configuration
     * 4. Trigger reboot
     *
     * For this simulation, we just mark it complete
     */

    /* Create backup */
    const char *storage_dir = storage_get_path();
    char backup_path[256];
    snprintf(backup_path, sizeof(backup_path), "%s/%s", storage_dir, FW_BACKUP_FILE);

    /* Simulated: copy staging to backup (in real impl, copy current firmware) */
    char staging_path[256];
    snprintf(staging_path, sizeof(staging_path), "%s/%s", storage_dir, FW_STAGING_FILE);

    FILE *src = fopen(staging_path, "rb");
    FILE *dst = fopen(backup_path, "wb");
    if (src && dst) {
        uint8_t buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
            fwrite(buf, 1, n, dst);
        }
    }
    if (src) fclose(src);
    if (dst) fclose(dst);

    /* Update rollback counter */
    if (g_update.header_received) {
        secboot_version_t version;
        secboot_parse_version(g_update.header.version, &version);
        secboot_update_rollback(&version);
    }

    g_update.state = FW_STATE_COMPLETE;

    /* Clear staging files */
    fw_update_clear_staged();

    return FW_UPDATE_OK;
}

int fw_update_is_staged(fw_staged_t *staged)
{
    char meta_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(meta_path, sizeof(meta_path), "%s/%s", storage_dir, FW_STAGING_META);

    FILE *f = fopen(meta_path, "rb");
    if (!f) {
        return 0;
    }

    fw_staged_t tmp;
    if (fread(&tmp, sizeof(tmp), 1, f) != 1) {
        fclose(f);
        return 0;
    }
    fclose(f);

    if (staged) {
        memcpy(staged, &tmp, sizeof(fw_staged_t));
    }

    return tmp.verified;
}

int fw_update_clear_staged(void)
{
    const char *storage_dir = storage_get_path();
    char path[256];

    snprintf(path, sizeof(path), "%s/%s", storage_dir, FW_STAGING_FILE);
    remove(path);

    snprintf(path, sizeof(path), "%s/%s", storage_dir, FW_STAGING_META);
    remove(path);

    g_update.state = FW_STATE_IDLE;

    return FW_UPDATE_OK;
}

/* ============================================================================
 * Recovery
 * ============================================================================ */

int fw_recovery_needed(void)
{
    /* Check for boot failure flags */
    secboot_state_t state;
    if (secboot_load_state(&state) == SECBOOT_OK) {
        /* If verified flag is not set, recovery may be needed */
        if (!(state.flags & SECBOOT_FLAG_VERIFIED)) {
            return 1;
        }
    }
    return 0;
}

int fw_enter_recovery(void)
{
    /* In a real implementation, this would:
     * 1. Set recovery boot flag
     * 2. Trigger system reboot into recovery partition
     */
    printf("[FW] Entering recovery mode...\n");
    return FW_UPDATE_OK;
}

int fw_restore_backup(void)
{
    const char *storage_dir = storage_get_path();
    char backup_path[256];
    snprintf(backup_path, sizeof(backup_path), "%s/%s", storage_dir, FW_BACKUP_FILE);

    /* Check if backup exists */
    FILE *f = fopen(backup_path, "rb");
    if (!f) {
        return FW_UPDATE_ERR_INTERNAL;
    }
    fclose(f);

    /* Verify backup */
    int ret = secboot_verify_file(backup_path);
    if (ret != SECBOOT_OK) {
        return FW_UPDATE_ERR_VERIFY;
    }

    /*
     * In a real implementation, restore backup to active partition
     */

    return FW_UPDATE_OK;
}

/* ============================================================================
 * Version Information
 * ============================================================================ */

int fw_get_current_version(secboot_version_t *version)
{
    if (version == NULL) {
        return FW_UPDATE_ERR_INTERNAL;
    }

    memcpy(version, &current_version, sizeof(secboot_version_t));
    return FW_UPDATE_OK;
}

int fw_get_staged_version(secboot_version_t *version)
{
    if (version == NULL) {
        return FW_UPDATE_ERR_INTERNAL;
    }

    fw_staged_t staged;
    if (!fw_update_is_staged(&staged)) {
        return FW_UPDATE_ERR_INTERNAL;
    }

    secboot_parse_version(staged.header.version, version);
    return FW_UPDATE_OK;
}

int fw_is_newer_version(const secboot_version_t *version)
{
    if (version == NULL) {
        return 0;
    }

    return secboot_compare_version(version, &current_version) > 0;
}

/* ============================================================================
 * File-Based Updates
 * ============================================================================ */

int fw_update_load_file(const char *path)
{
    if (path == NULL) {
        return FW_UPDATE_ERR_INTERNAL;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        return FW_UPDATE_ERR_DOWNLOAD;
    }

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || (size_t)size > FW_MAX_SIZE) {
        fclose(f);
        return FW_UPDATE_ERR_STORAGE;
    }

    /* Start update */
    int ret = fw_update_start(FW_SOURCE_SDCARD, (uint32_t)size);
    if (ret != FW_UPDATE_OK) {
        fclose(f);
        return ret;
    }

    /* Read and transfer data */
    uint8_t buf[4096];
    uint32_t offset = 0;
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        ret = fw_update_receive_data(buf, n, offset);
        if (ret != FW_UPDATE_OK) {
            fclose(f);
            fw_update_abort();
            return ret;
        }
        offset += (uint32_t)n;
    }

    fclose(f);

    return fw_update_end_transfer();
}

int fw_scan_directory(const char *dir, char files[][256], int max_files)
{
    if (dir == NULL || files == NULL || max_files <= 0) {
        return 0;
    }

    DIR *d = opendir(dir);
    if (!d) {
        return 0;
    }

    int count = 0;
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL && count < max_files) {
        /* Look for .bin or .fw files */
        const char *ext = strrchr(ent->d_name, '.');
        if (ext && (strcmp(ext, ".bin") == 0 || strcmp(ext, ".fw") == 0)) {
            /* Limit path lengths to prevent truncation */
            size_t dir_len = strlen(dir);
            size_t name_len = strnlen(ent->d_name, 255);
            if (dir_len + name_len + 2 < 256) {
                int ret = snprintf(files[count], 256, "%s/%.*s",
                                   dir, (int)name_len, ent->d_name);
                if (ret > 0 && ret < 256) {
                    count++;
                }
            }
        }
    }

    closedir(d);
    return count;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char *fw_update_error_string(int err)
{
    if (err < 0) {
        err = -err;
    }
    if (err < (int)(sizeof(error_messages) / sizeof(error_messages[0]))) {
        return error_messages[err];
    }
    return "Unknown error";
}

const char *fw_update_state_string(fw_update_state_t state)
{
    if (state < sizeof(state_names) / sizeof(state_names[0])) {
        return state_names[state];
    }
    return "Unknown";
}

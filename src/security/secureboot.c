/*
 * Secure Boot Chain Verification
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L

#include "secureboot.h"
#include "storage.h"
#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

/* State file names */
#define SECBOOT_STATE_FILE   "secboot.dat"
#define SECBOOT_KEYS_FILE    "secboot_keys.dat"

/* State magic */
#define SECBOOT_STATE_MAGIC  0x53425354  /* "SBST" */
#define SECBOOT_KEYS_MAGIC   0x53424B59  /* "SBKY" */

/* Internal state */
static secboot_state_t g_state;
static secboot_pubkey_t g_keys[SECBOOT_MAX_KEYS];
static int g_initialized = 0;
static uint32_t g_boot_flags = 0;

/* CRC32 for header integrity */
static uint32_t secboot_crc32(const uint8_t *data, size_t len)
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

/* Error messages */
static const char *error_messages[] = {
    [0]  = "Success",
    [1]  = "Invalid signature",
    [2]  = "Invalid header",
    [3]  = "Rollback detected",
    [4]  = "Key revoked",
    [5]  = "Hash verification failed",
    [6]  = "No image found",
    [7]  = "Internal error",
};

/* ============================================================================
 * Initialization
 * ============================================================================ */

int secboot_init(void)
{
    if (g_initialized) {
        return SECBOOT_OK;
    }

    /* Initialize state */
    memset(&g_state, 0, sizeof(g_state));
    memset(g_keys, 0, sizeof(g_keys));
    g_boot_flags = 0;

    /* Try to load existing state */
    if (secboot_load_state(&g_state) != SECBOOT_OK) {
        /* No existing state - initialize defaults */
        g_state.boot_count = 0;
        g_state.last_verified_build = 0;
        g_state.rollback_version = 0;
        g_state.flags = 0;
        memset(g_state.last_image_hash, 0, sizeof(g_state.last_image_hash));
    }

    /* Load keys */
    char keys_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(keys_path, sizeof(keys_path), "%s/%s", storage_dir, SECBOOT_KEYS_FILE);

    FILE *f = fopen(keys_path, "rb");
    if (f) {
        uint32_t magic;
        if (fread(&magic, sizeof(magic), 1, f) == 1 && magic == SECBOOT_KEYS_MAGIC) {
            size_t num_keys;
            if (fread(&num_keys, sizeof(num_keys), 1, f) == 1) {
                for (size_t i = 0; i < num_keys && i < SECBOOT_MAX_KEYS; i++) {
                    if (fread(&g_keys[i], sizeof(secboot_pubkey_t), 1, f) != 1) {
                        break;
                    }
                }
            }
        }
        fclose(f);
    }

    g_initialized = 1;
    return SECBOOT_OK;
}

int secboot_is_enabled(void)
{
    /* Check if any valid production keys are loaded */
    for (int i = 0; i < SECBOOT_MAX_KEYS; i++) {
        if ((g_keys[i].flags & SECBOOT_KEY_VALID) &&
            (g_keys[i].flags & SECBOOT_KEY_PRODUCTION) &&
            !(g_keys[i].flags & SECBOOT_KEY_REVOKED)) {
            return 1;
        }
    }
    return 0;
}

uint32_t secboot_get_flags(void)
{
    return g_boot_flags;
}

/* ============================================================================
 * Key Management
 * ============================================================================ */

int secboot_load_pubkey(unsigned int slot, secboot_pubkey_t *key)
{
    if (!g_initialized) {
        secboot_init();
    }

    if (slot >= SECBOOT_MAX_KEYS || key == NULL) {
        return SECBOOT_ERR_INTERNAL;
    }

    if (!(g_keys[slot].flags & SECBOOT_KEY_VALID)) {
        return SECBOOT_ERR_NO_IMAGE;
    }

    memcpy(key, &g_keys[slot], sizeof(secboot_pubkey_t));
    return SECBOOT_OK;
}

int secboot_store_pubkey(unsigned int slot, const uint8_t pubkey[32], uint32_t flags)
{
    if (!g_initialized) {
        secboot_init();
    }

    if (slot >= SECBOOT_MAX_KEYS || pubkey == NULL) {
        return SECBOOT_ERR_INTERNAL;
    }

    /* Store key */
    memcpy(g_keys[slot].pubkey, pubkey, 32);
    g_keys[slot].flags = flags | SECBOOT_KEY_VALID;
    g_keys[slot].key_id = slot;

    /* Compute public key hash */
    crypto_hash_sha256(g_keys[slot].pubkey_hash, pubkey, 32);

    /* Save keys to storage */
    char keys_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(keys_path, sizeof(keys_path), "%s/%s", storage_dir, SECBOOT_KEYS_FILE);

    FILE *f = fopen(keys_path, "wb");
    if (!f) {
        return SECBOOT_ERR_INTERNAL;
    }

    uint32_t magic = SECBOOT_KEYS_MAGIC;
    fwrite(&magic, sizeof(magic), 1, f);

    size_t num_keys = SECBOOT_MAX_KEYS;
    fwrite(&num_keys, sizeof(num_keys), 1, f);

    for (int i = 0; i < SECBOOT_MAX_KEYS; i++) {
        fwrite(&g_keys[i], sizeof(secboot_pubkey_t), 1, f);
    }

    fclose(f);
    return SECBOOT_OK;
}

int secboot_revoke_key(unsigned int slot)
{
    if (!g_initialized) {
        secboot_init();
    }

    if (slot >= SECBOOT_MAX_KEYS) {
        return SECBOOT_ERR_INTERNAL;
    }

    if (!(g_keys[slot].flags & SECBOOT_KEY_VALID)) {
        return SECBOOT_ERR_NO_IMAGE;
    }

    g_keys[slot].flags |= SECBOOT_KEY_REVOKED;

    /* Save updated keys */
    char keys_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(keys_path, sizeof(keys_path), "%s/%s", storage_dir, SECBOOT_KEYS_FILE);

    FILE *f = fopen(keys_path, "wb");
    if (!f) {
        return SECBOOT_ERR_INTERNAL;
    }

    uint32_t magic = SECBOOT_KEYS_MAGIC;
    fwrite(&magic, sizeof(magic), 1, f);

    size_t num_keys = SECBOOT_MAX_KEYS;
    fwrite(&num_keys, sizeof(num_keys), 1, f);

    for (int i = 0; i < SECBOOT_MAX_KEYS; i++) {
        fwrite(&g_keys[i], sizeof(secboot_pubkey_t), 1, f);
    }

    fclose(f);
    return SECBOOT_OK;
}

int secboot_find_key(const uint8_t pubkey_hash[32], secboot_pubkey_t *key)
{
    if (!g_initialized) {
        secboot_init();
    }

    for (int i = 0; i < SECBOOT_MAX_KEYS; i++) {
        if ((g_keys[i].flags & SECBOOT_KEY_VALID) &&
            sodium_memcmp(g_keys[i].pubkey_hash, pubkey_hash, 32) == 0) {
            if (key != NULL) {
                memcpy(key, &g_keys[i], sizeof(secboot_pubkey_t));
            }
            return i;
        }
    }
    return -1;
}

/* ============================================================================
 * Image Verification
 * ============================================================================ */

int secboot_parse_header(const uint8_t *data, size_t data_len,
                         secboot_header_t *header)
{
    if (data == NULL || header == NULL) {
        return SECBOOT_ERR_INTERNAL;
    }

    if (data_len < sizeof(secboot_header_t)) {
        return SECBOOT_ERR_INVALID_HDR;
    }

    memcpy(header, data, sizeof(secboot_header_t));

    /* Verify magic */
    if (header->magic != SECBOOT_MAGIC) {
        return SECBOOT_ERR_INVALID_HDR;
    }

    /* Verify header version */
    if (header->header_version != SECBOOT_HDR_VERSION) {
        return SECBOOT_ERR_INVALID_HDR;
    }

    /* Verify header CRC */
    uint32_t computed_crc = secboot_crc32(data, sizeof(secboot_header_t) - 4);
    if (computed_crc != header->header_crc) {
        return SECBOOT_ERR_INVALID_HDR;
    }

    /* Verify image fits in buffer */
    if (data_len < sizeof(secboot_header_t) + header->image_size) {
        return SECBOOT_ERR_INVALID_HDR;
    }

    return SECBOOT_OK;
}

int secboot_verify_image(const secboot_header_t *header, const uint8_t *image)
{
    if (!g_initialized) {
        secboot_init();
    }

    if (header == NULL || image == NULL) {
        return SECBOOT_ERR_INTERNAL;
    }

    /* Find signing key */
    secboot_pubkey_t key;
    int slot = secboot_find_key(header->pubkey_hash, &key);
    if (slot < 0) {
        return SECBOOT_ERR_KEY_REVOKED;
    }

    /* Check if key is revoked */
    if (key.flags & SECBOOT_KEY_REVOKED) {
        return SECBOOT_ERR_KEY_REVOKED;
    }

    /* Verify image hash */
    uint8_t computed_hash[32];
    crypto_hash_sha256(computed_hash, image, header->image_size);

    if (sodium_memcmp(computed_hash, header->image_hash, 32) != 0) {
        return SECBOOT_ERR_HASH_FAIL;
    }

    /* Verify Ed25519 signature */
    if (header->algorithm == SECBOOT_ALG_ED25519) {
        /* Signature is over the header (minus signature and CRC) + image hash */
        uint8_t sign_data[sizeof(secboot_header_t) - 64 - 4];
        memcpy(sign_data, header, sizeof(sign_data));

        if (crypto_sign_ed25519_verify_detached(
                header->signature,
                sign_data, sizeof(sign_data),
                key.pubkey) != 0) {
            return SECBOOT_ERR_INVALID_SIG;
        }
    } else if (header->algorithm == SECBOOT_ALG_ED25519PH) {
        /* Pre-hashed: signature is over SHA-256 of header */
        uint8_t header_hash[32];
        crypto_hash_sha256(header_hash,
                          (const uint8_t *)header,
                          sizeof(secboot_header_t) - 64 - 4);

        if (crypto_sign_ed25519_verify_detached(
                header->signature,
                header_hash, 32,
                key.pubkey) != 0) {
            return SECBOOT_ERR_INVALID_SIG;
        }
    } else {
        return SECBOOT_ERR_INVALID_HDR;
    }

    /* Check rollback protection */
    secboot_version_t version = {0};
    secboot_parse_version(header->version, &version);

    if (!secboot_check_version(&version)) {
        return SECBOOT_ERR_ROLLBACK;
    }

    /* Mark as verified */
    g_boot_flags |= SECBOOT_FLAG_VERIFIED | SECBOOT_FLAG_ROLLBACK_OK;

    return SECBOOT_OK;
}

int secboot_verify_buffer(const uint8_t *data, size_t data_len)
{
    secboot_header_t header;
    int ret;

    ret = secboot_parse_header(data, data_len, &header);
    if (ret != SECBOOT_OK) {
        return ret;
    }

    return secboot_verify_image(&header, data + sizeof(secboot_header_t));
}

int secboot_verify_file(const char *path)
{
    if (path == NULL) {
        return SECBOOT_ERR_INTERNAL;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        return SECBOOT_ERR_NO_IMAGE;
    }

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < (long)sizeof(secboot_header_t)) {
        fclose(f);
        return SECBOOT_ERR_INVALID_HDR;
    }

    /* Read file */
    uint8_t *data = malloc((size_t)size);
    if (!data) {
        fclose(f);
        return SECBOOT_ERR_INTERNAL;
    }

    if (fread(data, 1, (size_t)size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return SECBOOT_ERR_INTERNAL;
    }
    fclose(f);

    int ret = secboot_verify_buffer(data, (size_t)size);

    secure_wipe(data, (size_t)size);
    free(data);

    return ret;
}

/* ============================================================================
 * Rollback Protection
 * ============================================================================ */

int secboot_check_version(const secboot_version_t *version)
{
    if (version == NULL) {
        return 0;
    }

    /* Compare build number against rollback counter */
    if (version->build < g_state.rollback_version) {
        return 0;  /* Rollback detected */
    }

    return 1;
}

int secboot_update_rollback(const secboot_version_t *version)
{
    if (version == NULL) {
        return SECBOOT_ERR_INTERNAL;
    }

    /* Only update if new version is higher */
    if (version->build > g_state.rollback_version) {
        g_state.rollback_version = version->build;
        g_state.last_verified_build = version->build;
        return secboot_save_state(&g_state);
    }

    return SECBOOT_OK;
}

uint32_t secboot_get_rollback_counter(void)
{
    return g_state.rollback_version;
}

/* ============================================================================
 * Boot State
 * ============================================================================ */

int secboot_load_state(secboot_state_t *state)
{
    if (state == NULL) {
        return SECBOOT_ERR_INTERNAL;
    }

    char state_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(state_path, sizeof(state_path), "%s/%s", storage_dir, SECBOOT_STATE_FILE);

    FILE *f = fopen(state_path, "rb");
    if (!f) {
        return SECBOOT_ERR_NO_IMAGE;
    }

    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, f) != 1 || magic != SECBOOT_STATE_MAGIC) {
        fclose(f);
        return SECBOOT_ERR_INVALID_HDR;
    }

    if (fread(state, sizeof(secboot_state_t), 1, f) != 1) {
        fclose(f);
        return SECBOOT_ERR_INTERNAL;
    }

    fclose(f);
    return SECBOOT_OK;
}

int secboot_save_state(const secboot_state_t *state)
{
    if (state == NULL) {
        return SECBOOT_ERR_INTERNAL;
    }

    char state_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(state_path, sizeof(state_path), "%s/%s", storage_dir, SECBOOT_STATE_FILE);

    FILE *f = fopen(state_path, "wb");
    if (!f) {
        return SECBOOT_ERR_INTERNAL;
    }

    uint32_t magic = SECBOOT_STATE_MAGIC;
    fwrite(&magic, sizeof(magic), 1, f);
    fwrite(state, sizeof(secboot_state_t), 1, f);

    fclose(f);
    return SECBOOT_OK;
}

int secboot_record_boot(const secboot_header_t *header)
{
    if (header == NULL) {
        return SECBOOT_ERR_INTERNAL;
    }

    g_state.boot_count++;
    memcpy(g_state.last_image_hash, header->image_hash, 32);

    secboot_version_t version = {0};
    secboot_parse_version(header->version, &version);
    g_state.last_verified_build = version.build;

    return secboot_save_state(&g_state);
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char *secboot_error_string(int err)
{
    if (err < 0) {
        err = -err;
    }
    if (err < (int)(sizeof(error_messages) / sizeof(error_messages[0]))) {
        return error_messages[err];
    }
    return "Unknown error";
}

int secboot_format_version(const secboot_version_t *version, char *str, size_t str_len)
{
    if (version == NULL || str == NULL || str_len == 0) {
        return -1;
    }

    int ret = snprintf(str, str_len, "%u.%u.%u (build %u)",
                       version->major, version->minor, version->patch,
                       version->build);

    return (ret > 0 && (size_t)ret < str_len) ? 0 : -1;
}

void secboot_parse_version(const uint8_t data[8], secboot_version_t *version)
{
    if (data == NULL || version == NULL) {
        return;
    }

    version->major = data[0];
    version->minor = data[1];
    version->patch = ((uint16_t)data[2] << 8) | data[3];
    version->build = ((uint32_t)data[4] << 24) |
                     ((uint32_t)data[5] << 16) |
                     ((uint32_t)data[6] << 8) |
                     data[7];
}

int secboot_compare_version(const secboot_version_t *a, const secboot_version_t *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    /* Compare major.minor.patch.build */
    if (a->major != b->major) return (int)a->major - (int)b->major;
    if (a->minor != b->minor) return (int)a->minor - (int)b->minor;
    if (a->patch != b->patch) return (int)a->patch - (int)b->patch;
    if (a->build != b->build) {
        return (a->build > b->build) ? 1 : -1;
    }
    return 0;
}

/*
 * Secure Encrypted Storage
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "storage.h"
#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sodium.h>

/* Storage paths */
#define STORAGE_DIR      ".riscv_wallet"
#define WALLET_FILE      "wallet.enc"

/* Encrypted file format:
 * [16 bytes] salt
 * [24 bytes] nonce
 * [N bytes]  ciphertext (includes 16-byte auth tag)
 */
#define SALT_SIZE     crypto_pwhash_SALTBYTES
#define NONCE_SIZE    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define KEY_SIZE      crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define TAG_SIZE      crypto_aead_xchacha20poly1305_ietf_ABYTES

static char g_storage_path[256];
static int g_initialized = 0;

static int ensure_directory(const char *path)
{
    struct stat st;

    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }

    return mkdir(path, 0700);
}

static int derive_key(const char *pin, size_t pin_len,
                      const uint8_t salt[SALT_SIZE],
                      uint8_t key[KEY_SIZE])
{
    /* Use Argon2id for key derivation */
    if (crypto_pwhash(key, KEY_SIZE,
                      pin, pin_len,
                      salt,
                      STORAGE_ARGON2_TIME,
                      STORAGE_ARGON2_MEM,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return STORAGE_ERR_INIT;
    }

    return STORAGE_OK;
}

int storage_init(void)
{
    const char *home;

    if (g_initialized) {
        return STORAGE_OK;
    }

    home = getenv("HOME");
    if (home == NULL) {
        home = "/tmp";
    }

    snprintf(g_storage_path, sizeof(g_storage_path), "%s/%s", home, STORAGE_DIR);

    if (ensure_directory(g_storage_path) != 0) {
        fprintf(stderr, "Failed to create storage directory: %s\n", g_storage_path);
        return STORAGE_ERR_INIT;
    }

    printf("[storage] Initialized at %s\n", g_storage_path);
    g_initialized = 1;

    return STORAGE_OK;
}

void storage_cleanup(void)
{
    g_initialized = 0;
}

int storage_wallet_exists(void)
{
    char path[512];
    struct stat st;

    snprintf(path, sizeof(path), "%s/%s", g_storage_path, WALLET_FILE);
    return stat(path, &st) == 0;
}

int storage_save_wallet(const uint8_t *data, size_t data_len,
                        const char *pin, size_t pin_len)
{
    char path[512];
    FILE *fp = NULL;
    uint8_t salt[SALT_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t key[KEY_SIZE];
    uint8_t *ciphertext = NULL;
    unsigned long long ciphertext_len;
    int ret = STORAGE_ERR_IO;

    if (!g_initialized) {
        return STORAGE_ERR_INIT;
    }

    /* Generate random salt and nonce */
    randombytes_buf(salt, sizeof(salt));
    randombytes_buf(nonce, sizeof(nonce));

    /* Derive encryption key from PIN */
    if (derive_key(pin, pin_len, salt, key) != STORAGE_OK) {
        return STORAGE_ERR_INIT;
    }

    /* Allocate ciphertext buffer */
    ciphertext = malloc(data_len + TAG_SIZE);
    if (ciphertext == NULL) {
        secure_wipe(key, sizeof(key));
        return STORAGE_ERR_IO;
    }

    /* Encrypt data */
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &ciphertext_len,
            data, data_len,
            NULL, 0,  /* No additional data */
            NULL,
            nonce, key) != 0) {
        ret = STORAGE_ERR_IO;
        goto cleanup;
    }

    /* Write to file */
    snprintf(path, sizeof(path), "%s/%s", g_storage_path, WALLET_FILE);
    fp = fopen(path, "wb");
    if (fp == NULL) {
        goto cleanup;
    }

    if (fwrite(salt, 1, sizeof(salt), fp) != sizeof(salt) ||
        fwrite(nonce, 1, sizeof(nonce), fp) != sizeof(nonce) ||
        fwrite(ciphertext, 1, ciphertext_len, fp) != ciphertext_len) {
        goto cleanup;
    }

    ret = STORAGE_OK;

cleanup:
    secure_wipe(key, sizeof(key));
    if (ciphertext != NULL) {
        secure_wipe(ciphertext, data_len + TAG_SIZE);
        free(ciphertext);
    }
    if (fp != NULL) {
        fclose(fp);
    }

    return ret;
}

int storage_load_wallet(uint8_t *data, size_t *data_len,
                        const char *pin, size_t pin_len)
{
    char path[512];
    FILE *fp = NULL;
    struct stat st;
    uint8_t salt[SALT_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t key[KEY_SIZE];
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len;
    unsigned long long plaintext_len;
    int ret = STORAGE_ERR_IO;

    if (!g_initialized) {
        return STORAGE_ERR_INIT;
    }

    snprintf(path, sizeof(path), "%s/%s", g_storage_path, WALLET_FILE);

    if (stat(path, &st) != 0) {
        return STORAGE_ERR_NOT_FOUND;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return STORAGE_ERR_IO;
    }

    /* Read salt and nonce */
    if (fread(salt, 1, sizeof(salt), fp) != sizeof(salt) ||
        fread(nonce, 1, sizeof(nonce), fp) != sizeof(nonce)) {
        goto cleanup;
    }

    /* Calculate and read ciphertext */
    ciphertext_len = st.st_size - sizeof(salt) - sizeof(nonce);
    ciphertext = malloc(ciphertext_len);
    if (ciphertext == NULL) {
        goto cleanup;
    }

    if (fread(ciphertext, 1, ciphertext_len, fp) != ciphertext_len) {
        goto cleanup;
    }

    /* Derive decryption key from PIN */
    if (derive_key(pin, pin_len, salt, key) != STORAGE_OK) {
        ret = STORAGE_ERR_INIT;
        goto cleanup;
    }

    /* Decrypt data */
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            data, &plaintext_len,
            NULL,
            ciphertext, ciphertext_len,
            NULL, 0,  /* No additional data */
            nonce, key) != 0) {
        ret = STORAGE_ERR_DECRYPT;
        goto cleanup;
    }

    *data_len = (size_t)plaintext_len;
    ret = STORAGE_OK;

cleanup:
    secure_wipe(key, sizeof(key));
    if (ciphertext != NULL) {
        secure_wipe(ciphertext, ciphertext_len);
        free(ciphertext);
    }
    if (fp != NULL) {
        fclose(fp);
    }

    return ret;
}

int storage_wipe_wallet(void)
{
    char path[512];
    FILE *fp;
    struct stat st;
    uint8_t *zeros;

    if (!g_initialized) {
        return STORAGE_ERR_INIT;
    }

    snprintf(path, sizeof(path), "%s/%s", g_storage_path, WALLET_FILE);

    if (stat(path, &st) != 0) {
        return STORAGE_OK;  /* Nothing to wipe */
    }

    /* Overwrite with zeros before deleting */
    zeros = calloc(1, st.st_size);
    if (zeros != NULL) {
        fp = fopen(path, "wb");
        if (fp != NULL) {
            fwrite(zeros, 1, st.st_size, fp);
            fclose(fp);
        }
        free(zeros);
    }

    /* Delete file */
    remove(path);

    return STORAGE_OK;
}

const char *storage_get_path(void)
{
    return g_storage_path;
}

/* ============================================================================
 * Settings Storage
 * ============================================================================ */

#define SETTINGS_FILE    "settings.dat"
#define SETTINGS_VERSION 1
#define SETTINGS_MAGIC   0x53455453  /* "SETS" */

/* Settings file format:
 * [4 bytes] magic
 * [4 bytes] version
 * [N bytes] wallet_settings_t data
 * [4 bytes] CRC32
 */

/* Simple CRC32 for settings integrity */
static uint32_t settings_crc32(const uint8_t *data, size_t len)
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

void storage_init_default_settings(wallet_settings_t *settings)
{
    if (!settings) return;

    memset(settings, 0, sizeof(*settings));
    settings->version = SETTINGS_VERSION;
    settings->flags = SETTINGS_DEFAULT_FLAGS;
    settings->auto_lock_timeout = SETTINGS_DEFAULT_TIMEOUT;
    settings->default_network = SETTINGS_DEFAULT_NETWORK;
    settings->address_format = 0;  /* Lowercase */
    settings->fp_slots_enabled = 0x1F;  /* All 5 slots enabled by default */
}

int storage_load_settings(wallet_settings_t *settings)
{
    char path[512];
    FILE *fp;
    uint32_t magic, version, stored_crc, calc_crc;

    if (!g_initialized || !settings) {
        return STORAGE_ERR_INIT;
    }

    snprintf(path, sizeof(path), "%s/%s", g_storage_path, SETTINGS_FILE);

    fp = fopen(path, "rb");
    if (fp == NULL) {
        /* No settings file - use defaults */
        storage_init_default_settings(settings);
        return STORAGE_OK;
    }

    /* Read magic */
    if (fread(&magic, sizeof(magic), 1, fp) != 1 || magic != SETTINGS_MAGIC) {
        fclose(fp);
        storage_init_default_settings(settings);
        return STORAGE_OK;  /* Corrupt - use defaults */
    }

    /* Read version */
    if (fread(&version, sizeof(version), 1, fp) != 1) {
        fclose(fp);
        storage_init_default_settings(settings);
        return STORAGE_OK;
    }

    /* Read settings */
    if (fread(settings, sizeof(*settings), 1, fp) != 1) {
        fclose(fp);
        storage_init_default_settings(settings);
        return STORAGE_OK;
    }

    /* Read and verify CRC */
    if (fread(&stored_crc, sizeof(stored_crc), 1, fp) != 1) {
        fclose(fp);
        storage_init_default_settings(settings);
        return STORAGE_OK;
    }

    calc_crc = settings_crc32((const uint8_t *)settings, sizeof(*settings));
    if (stored_crc != calc_crc) {
        fclose(fp);
        storage_init_default_settings(settings);
        return STORAGE_OK;  /* CRC mismatch - use defaults */
    }

    fclose(fp);

    /* Handle version upgrades if needed */
    if (settings->version < SETTINGS_VERSION) {
        /* Future: handle migrations here */
        settings->version = SETTINGS_VERSION;
    }

    return STORAGE_OK;
}

int storage_save_settings(const wallet_settings_t *settings)
{
    char path[512];
    FILE *fp;
    uint32_t magic = SETTINGS_MAGIC;
    uint32_t version = SETTINGS_VERSION;
    uint32_t crc;

    if (!g_initialized || !settings) {
        return STORAGE_ERR_INIT;
    }

    snprintf(path, sizeof(path), "%s/%s", g_storage_path, SETTINGS_FILE);

    fp = fopen(path, "wb");
    if (fp == NULL) {
        return STORAGE_ERR_IO;
    }

    /* Write magic */
    if (fwrite(&magic, sizeof(magic), 1, fp) != 1) {
        fclose(fp);
        return STORAGE_ERR_IO;
    }

    /* Write version */
    if (fwrite(&version, sizeof(version), 1, fp) != 1) {
        fclose(fp);
        return STORAGE_ERR_IO;
    }

    /* Write settings */
    if (fwrite(settings, sizeof(*settings), 1, fp) != 1) {
        fclose(fp);
        return STORAGE_ERR_IO;
    }

    /* Write CRC */
    crc = settings_crc32((const uint8_t *)settings, sizeof(*settings));
    if (fwrite(&crc, sizeof(crc), 1, fp) != 1) {
        fclose(fp);
        return STORAGE_ERR_IO;
    }

    fclose(fp);
    return STORAGE_OK;
}

int storage_setting_enabled(const wallet_settings_t *settings, uint32_t flag)
{
    if (!settings) return 0;
    return (settings->flags & flag) != 0;
}

void storage_setting_set(wallet_settings_t *settings, uint32_t flag, int enabled)
{
    if (!settings) return;

    if (enabled) {
        settings->flags |= flag;
    } else {
        settings->flags &= ~flag;
    }
}

/*
 * Secure Encrypted Storage
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <stddef.h>

/* Storage error codes */
#define STORAGE_OK              0
#define STORAGE_ERR_INIT       -1
#define STORAGE_ERR_IO         -2
#define STORAGE_ERR_DECRYPT    -3
#define STORAGE_ERR_CORRUPT    -4
#define STORAGE_ERR_NOT_FOUND  -5

/* Key derivation parameters for Argon2id */
#define STORAGE_ARGON2_TIME    3
#define STORAGE_ARGON2_MEM     (64 * 1024)  /* 64 MB */
#define STORAGE_ARGON2_LANES   4

/**
 * Initialize storage subsystem
 *
 * @return STORAGE_OK on success, error code on failure
 */
int storage_init(void);

/**
 * Cleanup storage subsystem
 */
void storage_cleanup(void);

/**
 * Check if wallet data exists
 *
 * @return 1 if exists, 0 if not
 */
int storage_wallet_exists(void);

/**
 * Save encrypted wallet data
 *
 * @param data Wallet data to encrypt and save
 * @param data_len Length of data
 * @param pin User PIN for key derivation
 * @param pin_len Length of PIN
 * @return STORAGE_OK on success, error code on failure
 */
int storage_save_wallet(const uint8_t *data, size_t data_len,
                        const char *pin, size_t pin_len);

/**
 * Load and decrypt wallet data
 *
 * @param data Output buffer for decrypted data
 * @param data_len Size of output buffer / bytes read
 * @param pin User PIN for key derivation
 * @param pin_len Length of PIN
 * @return STORAGE_OK on success, error code on failure
 */
int storage_load_wallet(uint8_t *data, size_t *data_len,
                        const char *pin, size_t pin_len);

/**
 * Securely delete all wallet data
 *
 * @return STORAGE_OK on success, error code on failure
 */
int storage_wipe_wallet(void);

/**
 * Get storage path
 *
 * @return Path to storage directory
 */
const char *storage_get_path(void);

/* ============================================================================
 * Settings Storage (unencrypted configuration)
 * ============================================================================ */

/* Security settings flags */
#define SETTINGS_PIN_REQUIRED       (1 << 0)   /* PIN required for wallet access */
#define SETTINGS_FP_REQUIRED        (1 << 1)   /* Fingerprint required for wallet access */
#define SETTINGS_FP_FOR_SIGN        (1 << 2)   /* Fingerprint required for signing */
#define SETTINGS_PIN_FOR_SIGN       (1 << 3)   /* PIN required for signing */
#define SETTINGS_AUTO_LOCK          (1 << 4)   /* Auto-lock after timeout */
#define SETTINGS_PARANOID_MODE      (1 << 5)   /* Extra security warnings */

/* Default settings */
#define SETTINGS_DEFAULT_FLAGS      (SETTINGS_PIN_REQUIRED)
#define SETTINGS_DEFAULT_TIMEOUT    300        /* 5 minutes auto-lock */
#define SETTINGS_DEFAULT_NETWORK    0          /* Mainnet */

/* Settings structure */
typedef struct {
    uint32_t version;           /* Settings file version */
    uint32_t flags;             /* Security flags (SETTINGS_*) */
    uint32_t auto_lock_timeout; /* Auto-lock timeout in seconds (0=disabled) */
    uint8_t default_network;    /* 0=mainnet, 1=testnet */
    uint8_t address_format;     /* 0=lowercase, 1=uppercase, 2=mixed */
    uint8_t reserved[2];        /* Reserved for future use */
    uint8_t fp_slots_enabled;   /* Bitmask of enabled fingerprint slots */
} wallet_settings_t;

/**
 * Load wallet settings
 *
 * @param settings Output settings structure
 * @return STORAGE_OK on success, error code on failure
 */
int storage_load_settings(wallet_settings_t *settings);

/**
 * Save wallet settings
 *
 * @param settings Settings to save
 * @return STORAGE_OK on success, error code on failure
 */
int storage_save_settings(const wallet_settings_t *settings);

/**
 * Initialize settings to defaults
 *
 * @param settings Settings structure to initialize
 */
void storage_init_default_settings(wallet_settings_t *settings);

/**
 * Check if a specific security flag is enabled
 *
 * @param settings Settings structure
 * @param flag Flag to check (SETTINGS_*)
 * @return 1 if enabled, 0 if disabled
 */
int storage_setting_enabled(const wallet_settings_t *settings, uint32_t flag);

/**
 * Enable or disable a security flag
 *
 * @param settings Settings structure
 * @param flag Flag to modify (SETTINGS_*)
 * @param enabled 1 to enable, 0 to disable
 */
void storage_setting_set(wallet_settings_t *settings, uint32_t flag, int enabled);

#endif /* STORAGE_H */

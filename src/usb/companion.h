/*
 * USB HID Companion App Protocol
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Protocol for communication between hardware wallet and companion apps.
 * Supports wallet management, address generation, and transaction signing.
 */

#ifndef COMPANION_H
#define COMPANION_H

#include <stdint.h>
#include <stddef.h>
#include "hid.h"
#include "../wallet/wallet.h"

/* Protocol version */
#define COMPANION_PROTOCOL_VERSION  0x0100  /* 1.0 */

/* Message types */
#define COMP_MSG_PING               0x00
#define COMP_MSG_GET_INFO           0x01
#define COMP_MSG_GET_PUBKEY         0x02
#define COMP_MSG_GET_ADDRESS        0x03
#define COMP_MSG_SIGN_TX            0x04
#define COMP_MSG_SIGN_MESSAGE       0x05
#define COMP_MSG_VERIFY_ADDRESS     0x06
#define COMP_MSG_GET_XPUB           0x07
#define COMP_MSG_LIST_ACCOUNTS      0x08
#define COMP_MSG_SET_ACCOUNT        0x09

/* Extended message types for advanced features */
#define COMP_MSG_SIGN_PSBT          0x10  /* Bitcoin PSBT signing */
#define COMP_MSG_SIGN_TYPED_DATA    0x11  /* EIP-712 typed data */
#define COMP_MSG_GET_ENTROPY        0x12  /* Request entropy from device */
#define COMP_MSG_ATTESTATION        0x13  /* Device attestation */

/* Response status codes */
#define COMP_STATUS_OK              0x00
#define COMP_STATUS_ERROR           0x01
#define COMP_STATUS_USER_REJECTED   0x02
#define COMP_STATUS_BUSY            0x03
#define COMP_STATUS_LOCKED          0x04
#define COMP_STATUS_INVALID_CMD     0x05
#define COMP_STATUS_INVALID_DATA    0x06
#define COMP_STATUS_NOT_SUPPORTED   0x07
#define COMP_STATUS_TIMEOUT         0x08

/* Display flags for address/key verification */
#define COMP_DISPLAY_NONE           0x00  /* Silent operation */
#define COMP_DISPLAY_VERIFY         0x01  /* Show and require confirmation */
#define COMP_DISPLAY_SHOW           0x02  /* Show but no confirmation needed */

/* Signing flags */
#define COMP_SIGN_CONFIRM_AMOUNT    0x01  /* Confirm transaction amount */
#define COMP_SIGN_CONFIRM_RECIPIENT 0x02  /* Confirm recipient address */
#define COMP_SIGN_SHOW_FEE          0x04  /* Show fee before signing */
#define COMP_SIGN_CONFIRM_ALL       0x07  /* All confirmations */

/* Maximum sizes */
#define COMP_MAX_PATH_DEPTH         10    /* Maximum BIP32 path depth */
#define COMP_MAX_MESSAGE_SIZE       1024  /* Maximum message to sign */
#define COMP_MAX_TX_SIZE            4096  /* Maximum transaction size */
#define COMP_MAX_ADDRESS_SIZE       128   /* Maximum address string length */
#define COMP_MAX_XPUB_SIZE          128   /* Maximum xpub string length */

/* Device information structure */
typedef struct {
    uint16_t protocol_version;
    uint8_t  firmware_major;
    uint8_t  firmware_minor;
    uint8_t  firmware_patch;
    uint8_t  device_id[16];             /* Unique device identifier */
    uint8_t  supported_chains;          /* Bitmask of supported chains */
    uint8_t  flags;                     /* Device capability flags */
    char     model_name[32];            /* Human-readable model name */
} companion_device_info_t;

/* Device capability flags */
#define COMP_CAP_BITCOIN            (1 << 0)
#define COMP_CAP_ETHEREUM           (1 << 1)
#define COMP_CAP_LITECOIN           (1 << 2)
#define COMP_CAP_SOLANA             (1 << 3)
#define COMP_CAP_MONERO             (1 << 4)
#define COMP_CAP_FINGERPRINT        (1 << 5)
#define COMP_CAP_SECURE_ELEMENT     (1 << 6)
#define COMP_CAP_PASSPHRASE         (1 << 7)

/* BIP32 path structure */
typedef struct {
    uint32_t path[COMP_MAX_PATH_DEPTH];
    size_t   depth;
} companion_path_t;

/* Public key response */
typedef struct {
    uint8_t pubkey[65];         /* Uncompressed public key */
    size_t  pubkey_len;         /* Actual length (33 or 65) */
    char    chain_code[64];     /* Chain code (hex) */
} companion_pubkey_t;

/* Address response */
typedef struct {
    char    address[COMP_MAX_ADDRESS_SIZE];
    uint8_t pubkey[33];         /* Compressed public key */
} companion_address_t;

/* Transaction signing request */
typedef struct {
    chain_type_t    chain;
    uint8_t        *tx_data;
    size_t          tx_len;
    companion_path_t path;
    uint8_t         flags;
} companion_sign_request_t;

/* Transaction signature response */
typedef struct {
    uint8_t signature[73];      /* DER-encoded signature (max size) */
    size_t  sig_len;
    uint8_t v;                  /* Recovery ID (for Ethereum) */
} companion_signature_t;

/* Message signing request */
typedef struct {
    chain_type_t     chain;
    uint8_t         *message;
    size_t           msg_len;
    companion_path_t path;
    uint8_t          flags;
} companion_message_request_t;

/* Account information */
typedef struct {
    uint32_t        index;
    chain_type_t    chain;
    address_type_t  addr_type;
    char            label[WALLET_LABEL_MAX_LEN];
    uint32_t        flags;      /* Watch-only, etc. */
} companion_account_info_t;

/* Companion session context */
typedef struct {
    usb_hid_device_t        *device;
    companion_device_info_t  info;
    int                      authenticated;
    uint32_t                 current_account;
    uint8_t                  session_key[32];
} companion_session_t;

/* ============================================================================
 * Session Management
 * ============================================================================ */

/**
 * Initialize companion session
 *
 * @param device USB HID device handle
 * @param session Output session structure
 * @return 0 on success, -1 on error
 */
int companion_init_session(usb_hid_device_t *device, companion_session_t *session);

/**
 * Close companion session
 *
 * @param session Session to close
 */
void companion_close_session(companion_session_t *session);

/**
 * Ping device to check connectivity
 *
 * @param session Active session
 * @return 0 if device responds, -1 on error
 */
int companion_ping(companion_session_t *session);

/**
 * Get device information
 *
 * @param session Active session
 * @param info Output device info structure
 * @return 0 on success, -1 on error
 */
int companion_get_info(companion_session_t *session, companion_device_info_t *info);

/* ============================================================================
 * Key and Address Operations
 * ============================================================================ */

/**
 * Get public key for derivation path
 *
 * @param session Active session
 * @param path BIP32 derivation path
 * @param display Display flags
 * @param pubkey Output public key structure
 * @return 0 on success, -1 on error
 */
int companion_get_pubkey(companion_session_t *session,
                         const companion_path_t *path,
                         uint8_t display,
                         companion_pubkey_t *pubkey);

/**
 * Get address for derivation path
 *
 * @param session Active session
 * @param chain Blockchain type
 * @param path BIP32 derivation path
 * @param addr_type Address type
 * @param display Display flags
 * @param address Output address structure
 * @return 0 on success, -1 on error
 */
int companion_get_address(companion_session_t *session,
                          chain_type_t chain,
                          const companion_path_t *path,
                          address_type_t addr_type,
                          uint8_t display,
                          companion_address_t *address);

/**
 * Verify address on device display
 *
 * @param session Active session
 * @param chain Blockchain type
 * @param path BIP32 derivation path
 * @param address Address to verify
 * @return 0 if verified, -1 on error or rejection
 */
int companion_verify_address(companion_session_t *session,
                             chain_type_t chain,
                             const companion_path_t *path,
                             const char *address);

/**
 * Get extended public key (xpub/ypub/zpub)
 *
 * @param session Active session
 * @param chain Blockchain type
 * @param path BIP32 derivation path
 * @param addr_type Address type (determines xpub prefix)
 * @param xpub Output xpub string
 * @param xpub_len Size of xpub buffer
 * @return 0 on success, -1 on error
 */
int companion_get_xpub(companion_session_t *session,
                       chain_type_t chain,
                       const companion_path_t *path,
                       address_type_t addr_type,
                       char *xpub, size_t xpub_len);

/* ============================================================================
 * Transaction Signing
 * ============================================================================ */

/**
 * Sign transaction
 *
 * @param session Active session
 * @param request Signing request
 * @param signature Output signature
 * @return 0 on success, -1 on error/rejection
 */
int companion_sign_transaction(companion_session_t *session,
                               const companion_sign_request_t *request,
                               companion_signature_t *signature);

/**
 * Sign PSBT (Bitcoin)
 *
 * @param session Active session
 * @param psbt_data PSBT binary data
 * @param psbt_len Length of PSBT data
 * @param flags Signing flags
 * @param signed_psbt Output signed PSBT
 * @param signed_len Output length / buffer size
 * @return 0 on success, -1 on error/rejection
 */
int companion_sign_psbt(companion_session_t *session,
                        const uint8_t *psbt_data, size_t psbt_len,
                        uint8_t flags,
                        uint8_t *signed_psbt, size_t *signed_len);

/**
 * Sign message
 *
 * @param session Active session
 * @param request Message signing request
 * @param signature Output signature
 * @return 0 on success, -1 on error/rejection
 */
int companion_sign_message(companion_session_t *session,
                           const companion_message_request_t *request,
                           companion_signature_t *signature);

/**
 * Sign EIP-712 typed data (Ethereum)
 *
 * @param session Active session
 * @param domain_hash 32-byte domain separator hash
 * @param message_hash 32-byte structured data hash
 * @param path BIP32 derivation path
 * @param signature Output signature
 * @return 0 on success, -1 on error/rejection
 */
int companion_sign_typed_data(companion_session_t *session,
                              const uint8_t domain_hash[32],
                              const uint8_t message_hash[32],
                              const companion_path_t *path,
                              companion_signature_t *signature);

/* ============================================================================
 * Account Management
 * ============================================================================ */

/**
 * List accounts on device
 *
 * @param session Active session
 * @param accounts Output array
 * @param max_accounts Maximum number to retrieve
 * @return Number of accounts, or -1 on error
 */
int companion_list_accounts(companion_session_t *session,
                            companion_account_info_t *accounts,
                            size_t max_accounts);

/**
 * Set active account
 *
 * @param session Active session
 * @param account_index Account index to activate
 * @return 0 on success, -1 on error
 */
int companion_set_account(companion_session_t *session, uint32_t account_index);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Parse BIP32 path string to path structure
 *
 * @param path_str Path string (e.g., "m/44'/0'/0'/0/0")
 * @param path Output path structure
 * @return 0 on success, -1 on error
 */
int companion_parse_path(const char *path_str, companion_path_t *path);

/**
 * Format path structure to string
 *
 * @param path Path structure
 * @param str Output string buffer
 * @param str_len Size of string buffer
 * @return 0 on success, -1 on error
 */
int companion_format_path(const companion_path_t *path, char *str, size_t str_len);

/**
 * Get status message for response code
 *
 * @param status Status code
 * @return Human-readable status message
 */
const char *companion_status_string(uint8_t status);

/**
 * Check if device supports a specific chain
 *
 * @param info Device info
 * @param chain Chain type to check
 * @return 1 if supported, 0 if not
 */
int companion_supports_chain(const companion_device_info_t *info, chain_type_t chain);

/* ============================================================================
 * Device-Side Handler (for firmware)
 * ============================================================================ */

/**
 * Process incoming companion protocol message
 * This is called by the firmware to handle incoming requests.
 *
 * @param request Request data
 * @param request_len Request length
 * @param response Output response buffer
 * @param response_len Output response length / buffer size
 * @param wallet Active wallet context
 * @return 0 on success, -1 on error
 */
int companion_handle_request(const uint8_t *request, size_t request_len,
                             uint8_t *response, size_t *response_len,
                             wallet_t *wallet);

#endif /* COMPANION_H */

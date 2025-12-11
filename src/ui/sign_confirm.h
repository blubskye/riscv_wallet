/*
 * Transaction Signing Confirmation UI
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Provides user confirmation flows for transaction signing requests.
 * Supports multiple input methods (buttons, fingerprint) and various
 * transaction types (ETH, BTC, etc.).
 */

#ifndef SIGN_CONFIRM_H
#define SIGN_CONFIRM_H

#include <stdint.h>
#include <stddef.h>
#include "../wallet/wallet.h"

/* Confirmation result */
typedef enum {
    SIGN_RESULT_PENDING = 0,    /* Awaiting user action */
    SIGN_RESULT_APPROVED,       /* User approved the transaction */
    SIGN_RESULT_REJECTED,       /* User rejected the transaction */
    SIGN_RESULT_TIMEOUT,        /* Confirmation timed out */
    SIGN_RESULT_ERROR           /* Error during confirmation */
} sign_result_t;

/* Transaction type for display purposes */
typedef enum {
    SIGN_TX_TYPE_UNKNOWN = 0,
    SIGN_TX_TYPE_TRANSFER,      /* Simple value transfer */
    SIGN_TX_TYPE_CONTRACT,      /* Contract interaction */
    SIGN_TX_TYPE_TOKEN,         /* Token transfer (ERC-20, etc.) */
    SIGN_TX_TYPE_NFT,           /* NFT transfer */
    SIGN_TX_TYPE_SWAP,          /* DEX swap */
    SIGN_TX_TYPE_APPROVE        /* Token approval */
} sign_tx_type_t;

/* Confirmation method */
typedef enum {
    SIGN_CONFIRM_BUTTONS = 0,   /* Hardware buttons */
    SIGN_CONFIRM_FINGERPRINT,   /* Fingerprint authentication */
    SIGN_CONFIRM_PIN,           /* PIN entry */
    SIGN_CONFIRM_ALL            /* Require multiple methods */
} sign_confirm_method_t;

/* Transaction details for confirmation */
typedef struct {
    chain_type_t chain;
    sign_tx_type_t tx_type;

    /* Recipient info */
    char to_address[128];
    char to_label[64];          /* Optional label (address book) */

    /* Amount info */
    char amount[32];            /* Human-readable amount string */
    char amount_fiat[32];       /* Optional fiat equivalent */
    char symbol[16];            /* Currency symbol (BTC, ETH, etc.) */

    /* Fee info */
    char fee[32];               /* Fee in native currency */
    char fee_fiat[32];          /* Optional fiat equivalent */
    char total[32];             /* Total (amount + fee) */

    /* Contract info (for contract interactions) */
    char contract_name[64];     /* e.g., "Uniswap V3" */
    char function_name[64];     /* e.g., "swap" */

    /* Raw data (for advanced users) */
    const uint8_t *raw_data;
    size_t raw_data_len;

    /* Source info */
    char source[64];            /* "WalletConnect", "USB", etc. */
    char dapp_name[64];         /* dApp name if available */
    char dapp_url[128];         /* dApp URL if available */
} sign_tx_details_t;

/* Message signing request */
typedef struct {
    chain_type_t chain;
    char address[128];          /* Signing address */
    const char *message;        /* Message to sign */
    size_t message_len;
    int is_typed;               /* EIP-712 typed data */

    /* Source info */
    char source[64];
    char dapp_name[64];
    char dapp_url[128];
} sign_message_details_t;

/* Confirmation options */
typedef struct {
    sign_confirm_method_t method;
    uint32_t timeout_ms;        /* Confirmation timeout (0 = no timeout) */
    int show_raw_data;          /* Show raw transaction data option */
    int require_fingerprint;    /* Require fingerprint for high-value tx */
    uint64_t fingerprint_threshold; /* Satoshi threshold for fingerprint */
} sign_confirm_options_t;

/* Default options */
#define SIGN_CONFIRM_DEFAULT_TIMEOUT    120000  /* 2 minutes */
#define SIGN_CONFIRM_DEFAULT_OPTIONS    { \
    .method = SIGN_CONFIRM_BUTTONS, \
    .timeout_ms = SIGN_CONFIRM_DEFAULT_TIMEOUT, \
    .show_raw_data = 0, \
    .require_fingerprint = 0, \
    .fingerprint_threshold = 0 \
}

/* ============================================================================
 * Transaction Confirmation
 * ============================================================================ */

/**
 * Request user confirmation for a transaction
 *
 * Displays transaction details on screen and waits for user
 * to confirm (SELECT/CONFIRM button) or reject (BACK/CANCEL button).
 *
 * @param details Transaction details to display
 * @param options Confirmation options (NULL for defaults)
 * @return SIGN_RESULT_APPROVED if user confirms, SIGN_RESULT_REJECTED otherwise
 */
sign_result_t sign_confirm_transaction(const sign_tx_details_t *details,
                                       const sign_confirm_options_t *options);

/**
 * Request user confirmation for message signing
 *
 * @param details Message signing details
 * @param options Confirmation options (NULL for defaults)
 * @return SIGN_RESULT_APPROVED if user confirms, SIGN_RESULT_REJECTED otherwise
 */
sign_result_t sign_confirm_message(const sign_message_details_t *details,
                                   const sign_confirm_options_t *options);

/**
 * Request user confirmation for address verification
 *
 * Displays address on screen for user to verify it matches
 * what they expect.
 *
 * @param address Address string to display
 * @param chain Chain type
 * @param path Derivation path (for display)
 * @return SIGN_RESULT_APPROVED if user confirms
 */
sign_result_t sign_confirm_address(const char *address,
                                   chain_type_t chain,
                                   const char *path);

/* ============================================================================
 * Multi-step Confirmation (for high-value transactions)
 * ============================================================================ */

/**
 * Begin multi-step confirmation flow
 *
 * For high-value transactions, this shows multiple screens
 * that the user must review and confirm:
 * 1. Overview (recipient, amount)
 * 2. Fee details
 * 3. Raw data (optional)
 * 4. Final confirmation
 *
 * @param details Transaction details
 * @return SIGN_RESULT_APPROVED if user confirms all steps
 */
sign_result_t sign_confirm_multistep(const sign_tx_details_t *details);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Format transaction amount for display
 *
 * @param satoshis Amount in smallest unit
 * @param chain Chain type
 * @param output Output buffer
 * @param output_len Buffer size
 * @return 0 on success, -1 on error
 */
int sign_format_amount(uint64_t satoshis, chain_type_t chain,
                       char *output, size_t output_len);

/**
 * Detect transaction type from contract data
 *
 * @param data Contract call data
 * @param data_len Data length
 * @return Detected transaction type
 */
sign_tx_type_t sign_detect_tx_type(const uint8_t *data, size_t data_len);

/**
 * Get transaction type display name
 *
 * @param type Transaction type
 * @return Human-readable type name
 */
const char *sign_tx_type_name(sign_tx_type_t type);

/**
 * Check if transaction should require fingerprint
 *
 * Based on amount, destination (unknown address), or contract type.
 *
 * @param details Transaction details
 * @param options Confirmation options
 * @return 1 if fingerprint required, 0 otherwise
 */
int sign_requires_fingerprint(const sign_tx_details_t *details,
                              const sign_confirm_options_t *options);

#endif /* SIGN_CONFIRM_H */

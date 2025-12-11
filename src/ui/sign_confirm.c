/*
 * Transaction Signing Confirmation UI
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "sign_confirm.h"
#include "display.h"
#include "input.h"
#include "../security/fingerprint.h"
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Internal State
 * ============================================================================ */

/* Chain decimal places for amount formatting */
static const int chain_decimals[] = {
    [CHAIN_BITCOIN] = 8,        /* Satoshis */
    [CHAIN_BITCOIN_TESTNET] = 8,
    [CHAIN_ETHEREUM] = 18,      /* Wei */
    [CHAIN_LITECOIN] = 8,       /* Litoshis */
    [CHAIN_SOLANA] = 9,         /* Lamports */
    [CHAIN_DOGECOIN] = 8,       /* Koinus */
    [CHAIN_XRP] = 6,            /* Drops */
    [CHAIN_CARDANO] = 6,        /* Lovelace */
};

/* Chain symbols */
static const char *chain_symbols[] = {
    [CHAIN_BITCOIN] = "BTC",
    [CHAIN_BITCOIN_TESTNET] = "tBTC",
    [CHAIN_ETHEREUM] = "ETH",
    [CHAIN_LITECOIN] = "LTC",
    [CHAIN_SOLANA] = "SOL",
    [CHAIN_DOGECOIN] = "DOGE",
    [CHAIN_XRP] = "XRP",
    [CHAIN_CARDANO] = "ADA",
};

/* Transaction type names */
static const char *tx_type_names[] = {
    [SIGN_TX_TYPE_UNKNOWN] = "Transaction",
    [SIGN_TX_TYPE_TRANSFER] = "Transfer",
    [SIGN_TX_TYPE_CONTRACT] = "Contract Call",
    [SIGN_TX_TYPE_TOKEN] = "Token Transfer",
    [SIGN_TX_TYPE_NFT] = "NFT Transfer",
    [SIGN_TX_TYPE_SWAP] = "Swap",
    [SIGN_TX_TYPE_APPROVE] = "Approval",
};

/* ERC-20 transfer function selector */
static const uint8_t ERC20_TRANSFER_SELECTOR[] = {0xa9, 0x05, 0x9c, 0xbb};
/* ERC-20 approve function selector */
static const uint8_t ERC20_APPROVE_SELECTOR[] = {0x09, 0x5e, 0xa7, 0xb3};
/* ERC-721 transferFrom function selector */
static const uint8_t ERC721_TRANSFER_SELECTOR[] = {0x23, 0xb8, 0x72, 0xdd};
/* Uniswap V3 swap selectors */
static const uint8_t UNISWAP_EXACT_INPUT[] = {0xc0, 0x4b, 0x8d, 0x59};
static const uint8_t UNISWAP_EXACT_OUTPUT[] = {0xf2, 0x8c, 0x05, 0x98};

/* ============================================================================
 * Display Helpers
 * ============================================================================ */

/**
 * Truncate address for display (first 10...last 8)
 */
static void truncate_address(const char *address, char *output, size_t output_len)
{
    size_t addr_len = strlen(address);
    if (addr_len <= 20 || output_len < 22) {
        strncpy(output, address, output_len - 1);
        output[output_len - 1] = '\0';
        return;
    }

    snprintf(output, output_len, "%.10s...%.8s",
             address, address + addr_len - 8);
}

/**
 * Show transaction overview screen
 */
static void show_tx_overview(const sign_tx_details_t *details)
{
    display_clear(COLOR_BLACK);

    /* Header with transaction type */
    display_fill_rect(0, 0, DISPLAY_WIDTH, 24, COLOR_ORANGE);
    display_draw_text_centered(4, sign_tx_type_name(details->tx_type),
                               COLOR_BLACK, COLOR_ORANGE);

    /* Source/dApp info */
    if (details->dapp_name[0]) {
        char source_line[80];
        snprintf(source_line, sizeof(source_line), "From: %.70s", details->dapp_name);
        display_draw_text(10, 30, source_line, COLOR_LIGHTGRAY, COLOR_BLACK);
    }

    /* Recipient */
    char truncated_addr[32];
    truncate_address(details->to_address, truncated_addr, sizeof(truncated_addr));
    display_draw_text(10, 55, "To:", COLOR_WHITE, COLOR_BLACK);
    display_draw_text(40, 55, truncated_addr, COLOR_CYAN, COLOR_BLACK);

    /* Amount */
    char amount_line[96];
    if (details->amount_fiat[0]) {
        snprintf(amount_line, sizeof(amount_line), "%.24s %.12s (~%.24s)",
                 details->amount, details->symbol, details->amount_fiat);
    } else {
        snprintf(amount_line, sizeof(amount_line), "%.24s %.12s",
                 details->amount, details->symbol);
    }
    display_draw_text(10, 85, "Amount:", COLOR_WHITE, COLOR_BLACK);
    display_draw_text(80, 85, amount_line, COLOR_GREEN, COLOR_BLACK);

    /* Fee */
    char fee_line[96];
    if (details->fee_fiat[0]) {
        snprintf(fee_line, sizeof(fee_line), "%s (~%s)",
                 details->fee, details->fee_fiat);
    } else {
        snprintf(fee_line, sizeof(fee_line), "%s", details->fee);
    }
    display_draw_text(10, 110, "Fee:", COLOR_WHITE, COLOR_BLACK);
    display_draw_text(60, 110, fee_line, COLOR_YELLOW, COLOR_BLACK);

    /* Total (if available) */
    if (details->total[0]) {
        display_draw_text(10, 135, "Total:", COLOR_WHITE, COLOR_BLACK);
        display_draw_text(70, 135, details->total, COLOR_WHITE, COLOR_BLACK);
    }

    /* Contract info (if applicable) */
    if (details->contract_name[0]) {
        display_draw_text(10, 165, "Contract:", COLOR_LIGHTGRAY, COLOR_BLACK);
        display_draw_text(90, 165, details->contract_name, COLOR_CYAN, COLOR_BLACK);
    }

    /* Instructions */
    display_fill_rect(0, DISPLAY_HEIGHT - 30, DISPLAY_WIDTH, 30, COLOR_DARKGRAY);
    display_draw_text(10, DISPLAY_HEIGHT - 22, "[CONFIRM] Sign", COLOR_GREEN, COLOR_DARKGRAY);
    display_draw_text(160, DISPLAY_HEIGHT - 22, "[CANCEL] Reject", COLOR_RED, COLOR_DARKGRAY);

    display_update();
}

/**
 * Show message signing screen
 */
static void show_message_overview(const sign_message_details_t *details)
{
    display_clear(COLOR_BLACK);

    /* Header */
    const char *title = details->is_typed ? "Sign Typed Data" : "Sign Message";
    display_fill_rect(0, 0, DISPLAY_WIDTH, 24, COLOR_BLUE);
    display_draw_text_centered(4, title, COLOR_WHITE, COLOR_BLUE);

    /* Source/dApp info */
    if (details->dapp_name[0]) {
        char source_line[80];
        snprintf(source_line, sizeof(source_line), "From: %.70s", details->dapp_name);
        display_draw_text(10, 30, source_line, COLOR_LIGHTGRAY, COLOR_BLACK);
    }

    /* Signing address */
    char truncated_addr[32];
    truncate_address(details->address, truncated_addr, sizeof(truncated_addr));
    display_draw_text(10, 55, "Signer:", COLOR_WHITE, COLOR_BLACK);
    display_draw_text(80, 55, truncated_addr, COLOR_CYAN, COLOR_BLACK);

    /* Message preview (first ~100 chars) */
    display_draw_text(10, 85, "Message:", COLOR_WHITE, COLOR_BLACK);

    if (details->message && details->message_len > 0) {
        char preview[100];
        size_t preview_len = details->message_len < 96 ? details->message_len : 96;
        memcpy(preview, details->message, preview_len);
        preview[preview_len] = '\0';

        /* Replace newlines with spaces for display */
        for (size_t i = 0; i < preview_len; i++) {
            if (preview[i] == '\n' || preview[i] == '\r') {
                preview[i] = ' ';
            }
        }

        /* Multi-line display */
        display_draw_text(10, 105, preview, COLOR_LIGHTGRAY, COLOR_BLACK);

        if (details->message_len > 96) {
            display_draw_text(10, 145, "... (message truncated)", COLOR_GRAY, COLOR_BLACK);
        }
    }

    /* Instructions */
    display_fill_rect(0, DISPLAY_HEIGHT - 30, DISPLAY_WIDTH, 30, COLOR_DARKGRAY);
    display_draw_text(10, DISPLAY_HEIGHT - 22, "[CONFIRM] Sign", COLOR_GREEN, COLOR_DARKGRAY);
    display_draw_text(160, DISPLAY_HEIGHT - 22, "[CANCEL] Reject", COLOR_RED, COLOR_DARKGRAY);

    display_update();
}

/**
 * Show address verification screen
 */
static void show_address_verification(const char *address, chain_type_t chain,
                                      const char *path)
{
    display_clear(COLOR_BLACK);

    /* Header */
    display_fill_rect(0, 0, DISPLAY_WIDTH, 24, COLOR_GREEN);
    display_draw_text_centered(4, "Verify Address", COLOR_BLACK, COLOR_GREEN);

    /* Chain name */
    display_draw_text(10, 35, "Chain:", COLOR_WHITE, COLOR_BLACK);
    display_draw_text(80, 35, wallet_chain_name(chain), COLOR_CYAN, COLOR_BLACK);

    /* Derivation path */
    if (path && path[0]) {
        display_draw_text(10, 55, "Path:", COLOR_WHITE, COLOR_BLACK);
        display_draw_text(60, 55, path, COLOR_LIGHTGRAY, COLOR_BLACK);
    }

    /* Full address (may need scrolling for long addresses) */
    display_draw_text(10, 85, "Address:", COLOR_WHITE, COLOR_BLACK);

    /* Display address in chunks if too long */
    size_t addr_len = strlen(address);
    int y = 105;
    for (size_t i = 0; i < addr_len && y < DISPLAY_HEIGHT - 50; i += 30) {
        char chunk[32];
        strncpy(chunk, address + i, 30);
        chunk[30] = '\0';
        display_draw_text(10, y, chunk, COLOR_CYAN, COLOR_BLACK);
        y += 16;
    }

    /* QR code (if space permits) */
    display_draw_qr(address, DISPLAY_WIDTH - 80, 100, 2);

    /* Instructions */
    display_fill_rect(0, DISPLAY_HEIGHT - 30, DISPLAY_WIDTH, 30, COLOR_DARKGRAY);
    display_draw_text(10, DISPLAY_HEIGHT - 22, "[CONFIRM] Verified", COLOR_GREEN, COLOR_DARKGRAY);
    display_draw_text(160, DISPLAY_HEIGHT - 22, "[CANCEL] Wrong", COLOR_RED, COLOR_DARKGRAY);

    display_update();
}

/**
 * Wait for user confirmation
 */
static sign_result_t wait_for_confirmation(uint32_t timeout_ms)
{
    input_event_t event;
    uint32_t start_time = input_get_time_ms();

    while (1) {
        /* Check timeout */
        if (timeout_ms > 0) {
            uint32_t elapsed = input_get_time_ms() - start_time;
            if (elapsed >= timeout_ms) {
                return SIGN_RESULT_TIMEOUT;
            }
        }

        /* Wait for input */
        int result = input_wait(&event, 100);

        if (result > 0 && event.pressed) {
            switch (event.button) {
                case BTN_CONFIRM:
                case BTN_SELECT:
                    return SIGN_RESULT_APPROVED;

                case BTN_CANCEL:
                case BTN_BACK:
                    return SIGN_RESULT_REJECTED;

                default:
                    break;
            }
        }
    }
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

sign_result_t sign_confirm_transaction(const sign_tx_details_t *details,
                                       const sign_confirm_options_t *options)
{
    if (details == NULL) {
        return SIGN_RESULT_ERROR;
    }

    sign_confirm_options_t opts = SIGN_CONFIRM_DEFAULT_OPTIONS;
    if (options != NULL) {
        opts = *options;
    }

    /* Check if fingerprint is required */
    if (sign_requires_fingerprint(details, &opts)) {
#ifdef HAVE_LIBFPRINT
        /* Show fingerprint prompt */
        display_clear(COLOR_BLACK);
        display_draw_text_centered(80, "Place finger on sensor", COLOR_WHITE, COLOR_BLACK);
        display_draw_text_centered(100, "to authorize transaction", COLOR_WHITE, COLOR_BLACK);
        display_update();

        fingerprint_set_timeout((int)(opts.timeout_ms / 1000));
        int matched_slot = -1;
        if (fingerprint_identify(&matched_slot) != 0 || matched_slot < 0) {
            return SIGN_RESULT_REJECTED;
        }
#endif
    }

    /* Show transaction overview */
    show_tx_overview(details);

    /* Wait for user confirmation */
    return wait_for_confirmation(opts.timeout_ms);
}

sign_result_t sign_confirm_message(const sign_message_details_t *details,
                                   const sign_confirm_options_t *options)
{
    if (details == NULL) {
        return SIGN_RESULT_ERROR;
    }

    sign_confirm_options_t opts = SIGN_CONFIRM_DEFAULT_OPTIONS;
    if (options != NULL) {
        opts = *options;
    }

    /* Show message overview */
    show_message_overview(details);

    /* Wait for user confirmation */
    return wait_for_confirmation(opts.timeout_ms);
}

sign_result_t sign_confirm_address(const char *address,
                                   chain_type_t chain,
                                   const char *path)
{
    if (address == NULL) {
        return SIGN_RESULT_ERROR;
    }

    /* Show address verification screen */
    show_address_verification(address, chain, path);

    /* Wait for user confirmation */
    return wait_for_confirmation(SIGN_CONFIRM_DEFAULT_TIMEOUT);
}

sign_result_t sign_confirm_multistep(const sign_tx_details_t *details)
{
    if (details == NULL) {
        return SIGN_RESULT_ERROR;
    }

    input_event_t event;
    int step = 0;
    const int total_steps = 3;

    while (step < total_steps) {
        display_clear(COLOR_BLACK);

        /* Progress indicator */
        char progress[32];
        snprintf(progress, sizeof(progress), "Step %d of %d", step + 1, total_steps);
        display_draw_text(10, 5, progress, COLOR_LIGHTGRAY, COLOR_BLACK);

        switch (step) {
            case 0:
                /* Step 1: Recipient and amount */
                display_fill_rect(0, 20, DISPLAY_WIDTH, 24, COLOR_ORANGE);
                display_draw_text_centered(24, "Verify Recipient", COLOR_BLACK, COLOR_ORANGE);

                {
                    char truncated[32];
                    truncate_address(details->to_address, truncated, sizeof(truncated));
                    display_draw_text(10, 60, "To:", COLOR_WHITE, COLOR_BLACK);
                    display_draw_text(40, 60, truncated, COLOR_CYAN, COLOR_BLACK);
                }

                display_draw_text(10, 90, "Amount:", COLOR_WHITE, COLOR_BLACK);
                {
                    char amount_str[64];
                    snprintf(amount_str, sizeof(amount_str), "%s %s",
                             details->amount, details->symbol);
                    display_draw_text(80, 90, amount_str, COLOR_GREEN, COLOR_BLACK);
                }
                break;

            case 1:
                /* Step 2: Fee details */
                display_fill_rect(0, 20, DISPLAY_WIDTH, 24, COLOR_YELLOW);
                display_draw_text_centered(24, "Verify Fee", COLOR_BLACK, COLOR_YELLOW);

                display_draw_text(10, 60, "Network Fee:", COLOR_WHITE, COLOR_BLACK);
                display_draw_text(110, 60, details->fee, COLOR_YELLOW, COLOR_BLACK);

                if (details->total[0]) {
                    display_draw_text(10, 90, "Total Cost:", COLOR_WHITE, COLOR_BLACK);
                    display_draw_text(110, 90, details->total, COLOR_WHITE, COLOR_BLACK);
                }
                break;

            case 2:
                /* Step 3: Final confirmation */
                display_fill_rect(0, 20, DISPLAY_WIDTH, 24, COLOR_RED);
                display_draw_text_centered(24, "Final Confirmation", COLOR_WHITE, COLOR_RED);

                display_draw_text_centered(60, "You are about to sign", COLOR_WHITE, COLOR_BLACK);
                display_draw_text_centered(80, "this transaction.", COLOR_WHITE, COLOR_BLACK);

                display_draw_text_centered(120, "This cannot be undone.", COLOR_YELLOW, COLOR_BLACK);
                break;
        }

        /* Navigation instructions */
        display_fill_rect(0, DISPLAY_HEIGHT - 30, DISPLAY_WIDTH, 30, COLOR_DARKGRAY);
        if (step < total_steps - 1) {
            display_draw_text(10, DISPLAY_HEIGHT - 22, "[OK] Next", COLOR_GREEN, COLOR_DARKGRAY);
        } else {
            display_draw_text(10, DISPLAY_HEIGHT - 22, "[OK] SIGN", COLOR_GREEN, COLOR_DARKGRAY);
        }
        display_draw_text(180, DISPLAY_HEIGHT - 22, "[X] Cancel", COLOR_RED, COLOR_DARKGRAY);

        display_update();

        /* Wait for input */
        while (1) {
            if (input_wait(&event, 100) > 0 && event.pressed) {
                if (event.button == BTN_CONFIRM || event.button == BTN_SELECT) {
                    step++;
                    break;
                } else if (event.button == BTN_CANCEL || event.button == BTN_BACK) {
                    return SIGN_RESULT_REJECTED;
                } else if (event.button == BTN_LEFT && step > 0) {
                    step--;
                    break;
                }
            }
        }
    }

    return SIGN_RESULT_APPROVED;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

int sign_format_amount(uint64_t units, chain_type_t chain,
                       char *output, size_t output_len)
{
    if (output == NULL || output_len == 0) {
        return -1;
    }

    int decimals = 8;  /* Default */
    if ((size_t)chain < sizeof(chain_decimals) / sizeof(chain_decimals[0])) {
        decimals = chain_decimals[chain];
    }

    const char *symbol = "???";
    if ((size_t)chain < sizeof(chain_symbols) / sizeof(chain_symbols[0])) {
        symbol = chain_symbols[chain];
    }

    /* Convert to decimal string */
    uint64_t whole = units;
    for (int i = 0; i < decimals; i++) {
        whole /= 10;
    }

    uint64_t frac = units;
    for (int i = 0; i < decimals; i++) {
        frac %= 10;
        frac *= 10;
    }
    frac /= 10;

    snprintf(output, output_len, "%lu.%0*lu %s",
             (unsigned long)whole, decimals, (unsigned long)frac, symbol);

    return 0;
}

sign_tx_type_t sign_detect_tx_type(const uint8_t *data, size_t data_len)
{
    if (data == NULL || data_len < 4) {
        return SIGN_TX_TYPE_TRANSFER;  /* No data = simple transfer */
    }

    /* Check function selector (first 4 bytes) */
    if (memcmp(data, ERC20_TRANSFER_SELECTOR, 4) == 0) {
        return SIGN_TX_TYPE_TOKEN;
    }
    if (memcmp(data, ERC20_APPROVE_SELECTOR, 4) == 0) {
        return SIGN_TX_TYPE_APPROVE;
    }
    if (memcmp(data, ERC721_TRANSFER_SELECTOR, 4) == 0) {
        return SIGN_TX_TYPE_NFT;
    }
    if (memcmp(data, UNISWAP_EXACT_INPUT, 4) == 0 ||
        memcmp(data, UNISWAP_EXACT_OUTPUT, 4) == 0) {
        return SIGN_TX_TYPE_SWAP;
    }

    return SIGN_TX_TYPE_CONTRACT;
}

const char *sign_tx_type_name(sign_tx_type_t type)
{
    if ((size_t)type < sizeof(tx_type_names) / sizeof(tx_type_names[0])) {
        return tx_type_names[type];
    }
    return "Unknown";
}

int sign_requires_fingerprint(const sign_tx_details_t *details,
                              const sign_confirm_options_t *options)
{
    if (!options->require_fingerprint) {
        return 0;
    }

#ifdef HAVE_LIBFPRINT
    if (!fingerprint_is_available()) {
        return 0;
    }

    /* Check if transaction exceeds threshold */
    /* This is a simplified check - real implementation would parse amount */
    if (options->fingerprint_threshold > 0) {
        /* For now, always require fingerprint for contract interactions */
        if (details->tx_type == SIGN_TX_TYPE_CONTRACT ||
            details->tx_type == SIGN_TX_TYPE_APPROVE) {
            return 1;
        }
    }

    return 0;
#else
    (void)details;
    return 0;
#endif
}

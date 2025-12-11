/*
 * Command Line Interface
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef CLI_H
#define CLI_H

#include <stdint.h>
#include <stddef.h>
#include "../wallet/wallet.h"

/* CLI return codes */
#define CLI_OK          0
#define CLI_ERROR      -1
#define CLI_EXIT       -2
#define CLI_CANCEL     -3

/* Maximum input lengths */
#define CLI_MAX_INPUT   256
#define CLI_MAX_PATH    256

/**
 * Initialize CLI subsystem
 * @return 0 on success, -1 on error
 */
int cli_init(void);

/**
 * Cleanup CLI subsystem
 */
void cli_cleanup(void);

/**
 * Run the main CLI loop
 * @return Exit code
 */
int cli_run(void);

/**
 * Display the main menu and get user choice
 * @return Selected menu option (1-based) or CLI_EXIT/CLI_ERROR
 */
int cli_main_menu(void);

/**
 * Wallet creation wizard
 * @param wallet Wallet to initialize
 * @return 0 on success, -1 on error
 */
int cli_create_wallet(wallet_t *wallet);

/**
 * Wallet restore wizard
 * @param wallet Wallet to restore
 * @return 0 on success, -1 on error
 */
int cli_restore_wallet(wallet_t *wallet);

/**
 * Account management menu
 * @param wallet Active wallet
 * @return 0 on success, -1 on error
 */
int cli_account_menu(wallet_t *wallet);

/**
 * Generate and display new address
 * @param wallet Active wallet
 * @return 0 on success, -1 on error
 */
int cli_generate_address(wallet_t *wallet);

/**
 * Sign transaction interface
 * @param wallet Active wallet
 * @return 0 on success, -1 on error
 */
int cli_sign_transaction(wallet_t *wallet);

/**
 * Display wallet info
 * @param wallet Active wallet
 */
void cli_show_wallet_info(const wallet_t *wallet);

/**
 * Prompt user for confirmation
 * @param prompt Prompt message
 * @return 1 if confirmed, 0 if denied
 */
int cli_confirm(const char *prompt);

/**
 * Read a line of input from user
 * @param prompt Prompt message
 * @param buffer Output buffer
 * @param buffer_len Size of output buffer
 * @param hide_input Hide input (for passwords/mnemonics)
 * @return Number of characters read, or -1 on error
 */
int cli_read_line(const char *prompt, char *buffer, size_t buffer_len, int hide_input);

/**
 * Display mnemonic words for backup
 * @param mnemonic Space-separated mnemonic words
 */
void cli_display_mnemonic(const char *mnemonic);

/**
 * Verify user has written down mnemonic
 * @param mnemonic Original mnemonic to verify against
 * @return 0 if verified correctly, -1 on mismatch
 */
int cli_verify_mnemonic(const char *mnemonic);

/**
 * Clear the screen
 */
void cli_clear_screen(void);

/**
 * Print a horizontal separator
 */
void cli_print_separator(void);

/**
 * Print centered text
 * @param text Text to center
 * @param width Width to center within
 */
void cli_print_centered(const char *text, int width);

#endif /* CLI_H */

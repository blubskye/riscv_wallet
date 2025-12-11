/*
 * Command Line Interface
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L

#include "cli.h"
#include "../crypto/bip39.h"
#include "../crypto/bip32.h"
#include "../crypto/secp256k1.h"
#include "../crypto/random.h"
#include "../chains/bitcoin.h"
#include "../chains/ethereum.h"
#include "../security/memory.h"
#include "../security/storage.h"
#include "../security/fingerprint.h"
#include "../security/ratelimit.h"
#include "../util/hex.h"
#include "../util/base64.h"
#include "qr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>

/* Terminal width for formatting */
#define TERM_WIDTH 60

/* Menu options */
typedef enum {
    MENU_CREATE_WALLET = 1,
    MENU_RESTORE_WALLET,
    MENU_OPEN_WALLET,
    MENU_GENERATE_ADDRESS,
    MENU_SHOW_ADDRESSES,
    MENU_SIGN_TX,
    MENU_WALLET_INFO,
    MENU_SETTINGS,
    MENU_EXIT
} main_menu_t;

/* Global wallet state */
static wallet_t g_wallet;
static int g_wallet_loaded = 0;
static char g_current_pin[16] = "";  /* Current PIN for re-encryption */
static wallet_settings_t g_settings;  /* Global settings */
static int g_settings_loaded = 0;

int cli_init(void)
{
    /* Initialize libsodium */
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return -1;
    }

    /* Initialize secp256k1 context */
    if (secp256k1_ctx_init() != 0) {
        fprintf(stderr, "Failed to initialize secp256k1\n");
        return -1;
    }

    /* Initialize fingerprint subsystem (optional - doesn't fail if no device) */
    int fp_ret = fingerprint_init();
    if (fp_ret == FP_OK) {
        printf("[cli] Fingerprint reader available: %s\n",
               fingerprint_get_device_name());
    } else if (fp_ret == FP_ERR_NO_DEVICE) {
        /* No device - that's OK for systems without fingerprint readers */
    } else {
        fprintf(stderr, "[cli] Warning: Fingerprint init failed (code %d)\n", fp_ret);
    }

    /* Initialize storage for rate limiting persistence */
    if (storage_init() == STORAGE_OK) {
        /* Initialize rate limiting (must be after storage_init) */
        if (ratelimit_init() != RATELIMIT_OK) {
            fprintf(stderr, "[cli] Warning: Rate limiting init failed\n");
        }

        /* Load settings */
        if (storage_load_settings(&g_settings) == STORAGE_OK) {
            g_settings_loaded = 1;
        } else {
            storage_init_default_settings(&g_settings);
            g_settings_loaded = 1;
        }
    } else {
        storage_init_default_settings(&g_settings);
        g_settings_loaded = 1;
    }

    memset(&g_wallet, 0, sizeof(g_wallet));
    g_wallet_loaded = 0;

    return 0;
}

void cli_cleanup(void)
{
    if (g_wallet_loaded) {
        wallet_wipe(&g_wallet);
        g_wallet_loaded = 0;
    }

    /* Securely wipe stored PIN */
    secure_wipe(g_current_pin, sizeof(g_current_pin));

    ratelimit_cleanup();
    fingerprint_cleanup();
    secp256k1_ctx_cleanup();
}

void cli_clear_screen(void)
{
    printf("\033[2J\033[H");
    fflush(stdout);
}

void cli_print_separator(void)
{
    for (int i = 0; i < TERM_WIDTH; i++) {
        putchar('=');
    }
    putchar('\n');
}

void cli_print_centered(const char *text, int width)
{
    int len = (int)strlen(text);
    int padding = (width - len) / 2;
    if (padding < 0) padding = 0;

    for (int i = 0; i < padding; i++) {
        putchar(' ');
    }
    printf("%s\n", text);
}

static void print_header(const char *title)
{
    printf("\n");
    cli_print_separator();
    cli_print_centered(title, TERM_WIDTH);
    cli_print_separator();
    printf("\n");
}

static void print_menu_option(int num, const char *text)
{
    printf("  [%d] %s\n", num, text);
}

static void wait_for_enter(void)
{
    printf("\nPress Enter to continue...");
    fflush(stdout);
    getchar();
}

int cli_read_line(const char *prompt, char *buffer, size_t buffer_len, int hide_input)
{
    struct termios old_term, new_term;
    int hide_ok = 0;

    if (prompt) {
        printf("%s", prompt);
        fflush(stdout);
    }

    /* Hide input if requested */
    if (hide_input) {
        if (tcgetattr(STDIN_FILENO, &old_term) == 0) {
            new_term = old_term;
            new_term.c_lflag &= ~(ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
            hide_ok = 1;
        }
    }

    if (fgets(buffer, (int)buffer_len, stdin) == NULL) {
        if (hide_ok) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
            printf("\n");
        }
        return -1;
    }

    /* Restore terminal */
    if (hide_ok) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        printf("\n");
    }

    /* Remove trailing newline */
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
        len--;
    }

    return (int)len;
}

int cli_confirm(const char *prompt)
{
    char response[16];

    printf("%s (y/n): ", prompt);
    fflush(stdout);

    if (fgets(response, sizeof(response), stdin) == NULL) {
        return 0;
    }

    return (response[0] == 'y' || response[0] == 'Y');
}

void cli_display_mnemonic(const char *mnemonic)
{
    char buffer[BIP39_MAX_MNEMONIC_LEN];
    char *word;
    char *saveptr;
    int word_num = 1;

    strncpy(buffer, mnemonic, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    print_header("RECOVERY PHRASE - WRITE THIS DOWN!");

    printf("  Your recovery phrase contains %d words.\n",
           (strchr(mnemonic, ' ') != NULL) ? 12 +
           (int)(strlen(mnemonic) - strlen(strrchr(mnemonic, ' '))) / 7 : 1);
    printf("  Write them down in order and store securely.\n\n");

    printf("  ┌─────────────────────────────────────────────┐\n");

    word = strtok_r(buffer, " ", &saveptr);
    while (word != NULL) {
        printf("  │  %2d. %-12s", word_num, word);
        word_num++;

        word = strtok_r(NULL, " ", &saveptr);
        if (word != NULL) {
            printf("  %2d. %-12s │\n", word_num, word);
            word_num++;
        } else {
            printf("                    │\n");
        }

        word = strtok_r(NULL, " ", &saveptr);
    }

    printf("  └─────────────────────────────────────────────┘\n\n");

    printf("  WARNING: Never share your recovery phrase!\n");
    printf("  Anyone with these words can steal your funds.\n\n");
}

int cli_verify_mnemonic(const char *mnemonic)
{
    char buffer[BIP39_MAX_MNEMONIC_LEN];
    char original[BIP39_MAX_MNEMONIC_LEN];
    char *words[24];
    int word_count = 0;
    char *word, *saveptr;
    int verify_indices[3];
    char verify_word[32];

    /* Parse original mnemonic into words */
    strncpy(original, mnemonic, sizeof(original) - 1);
    original[sizeof(original) - 1] = '\0';

    word = strtok_r(original, " ", &saveptr);
    while (word != NULL && word_count < 24) {
        words[word_count++] = word;
        word = strtok_r(NULL, " ", &saveptr);
    }

    /* Select 3 random words to verify */
    randombytes_buf(verify_indices, sizeof(verify_indices));
    for (int i = 0; i < 3; i++) {
        verify_indices[i] = (verify_indices[i] % word_count);
        /* Avoid duplicates */
        for (int j = 0; j < i; j++) {
            if (verify_indices[i] == verify_indices[j]) {
                verify_indices[i] = (verify_indices[i] + 1) % word_count;
                j = -1; /* Restart check */
            }
        }
    }

    print_header("VERIFY RECOVERY PHRASE");
    printf("  Please enter the following words to confirm\n");
    printf("  you have written down your recovery phrase.\n\n");

    for (int i = 0; i < 3; i++) {
        snprintf(buffer, sizeof(buffer), "  Enter word #%d: ", verify_indices[i] + 1);
        cli_read_line(buffer, verify_word, sizeof(verify_word), 0);

        /* Trim whitespace */
        char *trimmed = verify_word;
        while (isspace((unsigned char)*trimmed)) trimmed++;
        char *end = trimmed + strlen(trimmed) - 1;
        while (end > trimmed && isspace((unsigned char)*end)) *end-- = '\0';

        if (strcmp(trimmed, words[verify_indices[i]]) != 0) {
            printf("\n  Incorrect! Word #%d should be '%s'\n",
                   verify_indices[i] + 1, words[verify_indices[i]]);
            return -1;
        }
    }

    printf("\n  All words verified correctly!\n");
    return 0;
}

int cli_create_wallet(wallet_t *wallet)
{
    char mnemonic[BIP39_MAX_MNEMONIC_LEN];
    char passphrase[128] = {0};
    char passphrase_confirm[128] = {0};
    int word_count;

    print_header("CREATE NEW WALLET");

    /* Ask for mnemonic length */
    printf("  Select recovery phrase length:\n\n");
    printf("    [1] 12 words (128-bit security)\n");
    printf("    [2] 24 words (256-bit security, recommended)\n\n");

    char choice[8];
    cli_read_line("  Choice: ", choice, sizeof(choice), 0);

    if (choice[0] == '1') {
        word_count = 12;
    } else {
        word_count = 24;
    }

    /* Ask for optional passphrase (BIP-39 "25th word") */
    printf("\n  Optional: Add a passphrase for extra security?\n");
    printf("  (This creates a 'hidden wallet' - different passphrase = different wallet)\n");
    printf("  WARNING: If you forget this passphrase, your funds are UNRECOVERABLE!\n\n");
    printf("  Enter passphrase (or press Enter for none): ");
    cli_read_line(NULL, passphrase, sizeof(passphrase), 1);

    if (passphrase[0] != '\0') {
        /* Confirm passphrase */
        printf("  Confirm passphrase: ");
        cli_read_line(NULL, passphrase_confirm, sizeof(passphrase_confirm), 1);

        if (strcmp(passphrase, passphrase_confirm) != 0) {
            printf("\n  ERROR: Passphrases do not match!\n");
            secure_wipe(passphrase, sizeof(passphrase));
            secure_wipe(passphrase_confirm, sizeof(passphrase_confirm));
            return -1;
        }
        secure_wipe(passphrase_confirm, sizeof(passphrase_confirm));
        printf("\n  Passphrase set. Remember: mnemonic + passphrase = your wallet.\n");
    }

    printf("\n  Generating secure random mnemonic...\n");

    /* Generate wallet with mnemonic and optional passphrase */
    const char *pp = passphrase[0] ? passphrase : NULL;
    if (wallet_create(wallet, word_count, pp, mnemonic, sizeof(mnemonic)) != 0) {
        printf("  ERROR: Failed to create wallet\n");
        secure_wipe(passphrase, sizeof(passphrase));
        return -1;
    }

    secure_wipe(passphrase, sizeof(passphrase));

    /* Display mnemonic */
    cli_display_mnemonic(mnemonic);
    wait_for_enter();

    /* Verify user has written it down */
    cli_clear_screen();
    if (cli_verify_mnemonic(mnemonic) != 0) {
        printf("  Verification failed. Please try again.\n");
        secure_wipe(mnemonic, sizeof(mnemonic));
        wallet_wipe(wallet);
        return -1;
    }

    /* Wipe sensitive data */
    secure_wipe(mnemonic, sizeof(mnemonic));

    printf("\n  Wallet created successfully!\n");
    return 0;
}

int cli_restore_wallet(wallet_t *wallet)
{
    char mnemonic[BIP39_MAX_MNEMONIC_LEN];
    char passphrase[128] = {0};

    print_header("RESTORE WALLET");

    printf("  Enter your recovery phrase (12 or 24 words):\n\n");

    if (cli_read_line("  > ", mnemonic, sizeof(mnemonic), 0) < 0) {
        return -1;
    }

    /* Normalize: lowercase, single spaces */
    char *src = mnemonic, *dst = mnemonic;
    int last_space = 1;
    while (*src) {
        if (isspace((unsigned char)*src)) {
            if (!last_space) {
                *dst++ = ' ';
                last_space = 1;
            }
        } else {
            *dst++ = tolower((unsigned char)*src);
            last_space = 0;
        }
        src++;
    }
    if (dst > mnemonic && *(dst - 1) == ' ') dst--;
    *dst = '\0';

    printf("\n  Validating mnemonic...\n");

    if (bip39_validate_mnemonic(mnemonic) != 0) {
        printf("  ERROR: Invalid mnemonic phrase!\n");
        printf("  Check spelling and word order.\n");
        secure_wipe(mnemonic, sizeof(mnemonic));
        return -1;
    }

    printf("  Mnemonic is valid!\n\n");

    /* Ask for passphrase */
    printf("  Enter passphrase (or press Enter if none): ");
    cli_read_line(NULL, passphrase, sizeof(passphrase), 1);

    /* Restore wallet */
    printf("  Deriving wallet keys...\n");
    if (wallet_restore(wallet, mnemonic, passphrase[0] ? passphrase : NULL) != 0) {
        printf("  ERROR: Failed to restore wallet\n");
        secure_wipe(mnemonic, sizeof(mnemonic));
        secure_wipe(passphrase, sizeof(passphrase));
        return -1;
    }

    secure_wipe(mnemonic, sizeof(mnemonic));
    secure_wipe(passphrase, sizeof(passphrase));

    printf("\n  Wallet restored successfully!\n");
    return 0;
}

int cli_load_wallet(wallet_t *wallet)
{
    char pin[16];
    uint32_t remaining_sec;
    uint32_t pin_fails, total_fails;
    int rl_ret;

    print_header("UNLOCK SAVED WALLET");

    /* Initialize storage */
    if (storage_init() != STORAGE_OK) {
        printf("  ERROR: Failed to initialize storage\n");
        return -1;
    }

    if (!storage_wallet_exists()) {
        printf("  No saved wallet found.\n");
        printf("  Create or restore a wallet first.\n");
        return -1;
    }

    printf("  Encrypted wallet found at: %s\n\n", storage_get_path());

    /* Check rate limiting lockout */
    rl_ret = ratelimit_check(AUTH_TYPE_PIN, &remaining_sec);
    if (rl_ret == RATELIMIT_LOCKED) {
        printf("  ╔═══════════════════════════════════════════════════╗\n");
        printf("  ║             SECURITY LOCKOUT ACTIVE               ║\n");
        printf("  ╚═══════════════════════════════════════════════════╝\n\n");
        printf("  Too many failed PIN attempts.\n");
        printf("  Please wait %u seconds before trying again.\n", remaining_sec);

        /* Show failure stats */
        ratelimit_get_stats(&pin_fails, NULL, &total_fails, NULL);
        printf("\n  Total failed attempts: %u / %u (wipe threshold)\n",
               total_fails, RATELIMIT_WIPE_THRESHOLD);

        return -1;
    }

    /* Get current failure stats */
    ratelimit_get_stats(&pin_fails, NULL, &total_fails, NULL);
    int attempts_remaining = RATELIMIT_MAX_ATTEMPTS - (int)pin_fails;
    if (attempts_remaining < 1) attempts_remaining = 1;

    while (attempts_remaining > 0) {
        printf("  Enter PIN to unlock (%d attempt%s before lockout): ",
               attempts_remaining, attempts_remaining == 1 ? "" : "s");
        cli_read_line(NULL, pin, sizeof(pin), 1);

        /* Check lockout again (in case of long delay) */
        if (ratelimit_check(AUTH_TYPE_PIN, &remaining_sec) == RATELIMIT_LOCKED) {
            printf("\n  Lockout activated. Wait %u seconds.\n", remaining_sec);
            secure_wipe(pin, sizeof(pin));
            return -1;
        }

        printf("\n  Decrypting wallet (this may take a moment)...\n");

        int ret = wallet_load(wallet, pin);

        if (ret == 0) {
            /* SUCCESS - reset rate limit counters */
            ratelimit_record_success(AUTH_TYPE_PIN);

            /* Save PIN for potential re-encryption (PIN change) */
            strncpy(g_current_pin, pin, sizeof(g_current_pin) - 1);
            g_current_pin[sizeof(g_current_pin) - 1] = '\0';
            secure_wipe(pin, sizeof(pin));
            printf("\n  Wallet unlocked successfully!\n");
            printf("  Accounts loaded: %zu\n", wallet->account_count);
            return 0;
        }

        if (ret == -2) {
            /* Wrong PIN - record failure */
            rl_ret = ratelimit_record_failure(AUTH_TYPE_PIN);

            if (rl_ret == RATELIMIT_WIPED) {
                printf("\n  ╔═══════════════════════════════════════════════════╗\n");
                printf("  ║         WALLET WIPED - SECURITY BREACH            ║\n");
                printf("  ╚═══════════════════════════════════════════════════╝\n\n");
                printf("  Too many total failed attempts.\n");
                printf("  Wallet data has been securely erased.\n");
                secure_wipe(pin, sizeof(pin));
                return -1;
            }

            if (rl_ret == RATELIMIT_LOCKED) {
                ratelimit_is_locked(&remaining_sec, NULL);
                printf("\n  Lockout activated! Wait %u seconds.\n", remaining_sec);
                secure_wipe(pin, sizeof(pin));
                return -1;
            }

            /* Update attempts remaining */
            ratelimit_get_stats(&pin_fails, NULL, &total_fails, NULL);
            attempts_remaining = RATELIMIT_MAX_ATTEMPTS - (int)pin_fails;

            if (attempts_remaining > 0) {
                printf("  ERROR: Wrong PIN.\n");
                printf("  WARNING: %u total failures. Wallet wipes at %u.\n\n",
                       total_fails, RATELIMIT_WIPE_THRESHOLD);
            } else {
                printf("  ERROR: Too many failed attempts.\n");
            }
        } else {
            printf("  ERROR: Failed to load wallet\n");
            secure_wipe(pin, sizeof(pin));
            return -1;
        }
    }

    secure_wipe(pin, sizeof(pin));
    return -1;
}

int cli_save_wallet(wallet_t *wallet)
{
    char pin[16];
    char confirm_pin[16];

    print_header("SAVE WALLET");

    if (wallet == NULL || !wallet->is_initialized) {
        printf("  ERROR: No wallet to save\n");
        return -1;
    }

    /* Initialize storage */
    if (storage_init() != STORAGE_OK) {
        printf("  ERROR: Failed to initialize storage\n");
        return -1;
    }

    printf("  Set a PIN to encrypt your wallet.\n");
    printf("  (4-8 digits, DO NOT FORGET THIS PIN!)\n\n");

    printf("  Enter PIN: ");
    cli_read_line(NULL, pin, sizeof(pin), 1);

    /* Validate PIN */
    size_t len = strlen(pin);
    if (len < 4 || len > 8) {
        printf("  ERROR: PIN must be 4-8 digits\n");
        secure_wipe(pin, sizeof(pin));
        return -1;
    }

    int valid = 1;
    for (size_t i = 0; i < len; i++) {
        if (pin[i] < '0' || pin[i] > '9') {
            valid = 0;
            break;
        }
    }

    if (!valid) {
        printf("  ERROR: PIN must contain only digits\n");
        secure_wipe(pin, sizeof(pin));
        return -1;
    }

    printf("  Confirm PIN: ");
    cli_read_line(NULL, confirm_pin, sizeof(confirm_pin), 1);

    if (strcmp(pin, confirm_pin) != 0) {
        printf("  ERROR: PINs do not match\n");
        secure_wipe(pin, sizeof(pin));
        secure_wipe(confirm_pin, sizeof(confirm_pin));
        return -1;
    }

    secure_wipe(confirm_pin, sizeof(confirm_pin));

    printf("\n  Encrypting and saving wallet...\n");
    printf("  (Key derivation may take a moment)\n");

    if (wallet_save(wallet, pin) != 0) {
        printf("  ERROR: Failed to save wallet\n");
        secure_wipe(pin, sizeof(pin));
        return -1;
    }

    /* Save PIN for potential re-encryption (PIN change) */
    strncpy(g_current_pin, pin, sizeof(g_current_pin) - 1);
    g_current_pin[sizeof(g_current_pin) - 1] = '\0';
    secure_wipe(pin, sizeof(pin));

    printf("\n  Wallet saved successfully!\n");
    printf("  Location: %s\n", storage_get_path());
    printf("\n  IMPORTANT: Remember your PIN!\n");
    printf("  If you forget it, you'll need your recovery phrase.\n");

    return 0;
}

static const char *chain_name(chain_type_t chain)
{
    switch (chain) {
    case CHAIN_BITCOIN: return "Bitcoin (Mainnet)";
    case CHAIN_BITCOIN_TESTNET: return "Bitcoin (Testnet)";
    case CHAIN_ETHEREUM: return "Ethereum";
    case CHAIN_LITECOIN: return "Litecoin";
    case CHAIN_SOLANA: return "Solana";
    default: return "Unknown";
    }
}

static const char *addr_type_name(address_type_t type)
{
    switch (type) {
    case ADDR_TYPE_LEGACY: return "Legacy (P2PKH)";
    case ADDR_TYPE_SEGWIT_COMPAT: return "SegWit Compat (P2SH-P2WPKH)";
    case ADDR_TYPE_SEGWIT_NATIVE: return "SegWit (P2WPKH)";
    case ADDR_TYPE_TAPROOT: return "Taproot (P2TR)";
    default: return "Unknown";
    }
}

int cli_generate_address(wallet_t *wallet)
{
    char address[128];
    int chain_choice, type_choice;
    chain_type_t chain;
    address_type_t addr_type;

    print_header("GENERATE NEW ADDRESS");

    printf("  Select blockchain:\n\n");
    printf("    [1] Bitcoin (Mainnet)\n");
    printf("    [2] Bitcoin (Testnet)\n");
    printf("    [3] Ethereum\n\n");

    char choice[8];
    cli_read_line("  Choice: ", choice, sizeof(choice), 0);
    chain_choice = atoi(choice);

    switch (chain_choice) {
    case 1: chain = CHAIN_BITCOIN; break;
    case 2: chain = CHAIN_BITCOIN_TESTNET; break;
    case 3: chain = CHAIN_ETHEREUM; break;
    default:
        printf("  Invalid choice\n");
        return -1;
    }

    /* For Bitcoin, ask address type */
    if (chain == CHAIN_BITCOIN || chain == CHAIN_BITCOIN_TESTNET) {
        printf("\n  Select address type:\n\n");
        printf("    [1] Native SegWit (bc1q... - recommended)\n");
        printf("    [2] Taproot (bc1p...)\n");
        printf("    [3] Legacy (1...)\n\n");

        cli_read_line("  Choice: ", choice, sizeof(choice), 0);
        type_choice = atoi(choice);

        switch (type_choice) {
        case 1: addr_type = ADDR_TYPE_SEGWIT_NATIVE; break;
        case 2: addr_type = ADDR_TYPE_TAPROOT; break;
        case 3: addr_type = ADDR_TYPE_LEGACY; break;
        default:
            printf("  Invalid choice\n");
            return -1;
        }
    } else {
        addr_type = ADDR_TYPE_LEGACY; /* Ethereum only has one format */
    }

    /* Find existing account for this chain or create new one */
    wallet_account_t *account = NULL;
    for (size_t i = 0; i < wallet->account_count; i++) {
        if (wallet->accounts[i].chain == chain) {
            account = &wallet->accounts[i];
            break;
        }
    }

    if (account == NULL) {
        int idx = wallet_add_account(wallet, chain, addr_type, NULL);
        if (idx < 0) {
            printf("  ERROR: Failed to create account\n");
            return -1;
        }
        account = wallet_get_account(wallet, (size_t)idx);
    }

    if (account == NULL) {
        printf("  ERROR: Account not found\n");
        return -1;
    }

    /* Generate address */
    if (wallet_get_new_address(account, address, sizeof(address)) != 0) {
        printf("  ERROR: Failed to generate address\n");
        return -1;
    }

    printf("\n");
    cli_print_separator();
    printf("\n  New %s Address:\n\n", chain_name(chain));
    printf("  %s\n\n", address);
    cli_print_separator();

    /* Show QR code option */
    printf("\n  Display QR code? [y/n]: ");
    char qr_choice[8];
    cli_read_line(NULL, qr_choice, sizeof(qr_choice), 0);

    if (qr_choice[0] == 'y' || qr_choice[0] == 'Y') {
        qr_code_t qr;

        /* For Bitcoin addresses, use bitcoin: URI scheme */
        char qr_data[256];
        if (chain == CHAIN_BITCOIN || chain == CHAIN_BITCOIN_TESTNET) {
            snprintf(qr_data, sizeof(qr_data), "bitcoin:%s", address);
        } else if (chain == CHAIN_ETHEREUM) {
            snprintf(qr_data, sizeof(qr_data), "ethereum:%s", address);
        } else {
            strncpy(qr_data, address, sizeof(qr_data) - 1);
            qr_data[sizeof(qr_data) - 1] = '\0';
        }

        if (qr_encode(qr_data, &qr) == 0) {
            printf("\n");
            qr_print_terminal_compact(&qr, 2);
            printf("\n  (Scan with any wallet app)\n");
            qr_free(&qr);
        } else {
            printf("  ERROR: Failed to generate QR code\n");
        }
    }

    return 0;
}

void cli_show_wallet_info(const wallet_t *wallet)
{
    print_header("WALLET INFORMATION");

    if (wallet == NULL || wallet->account_count == 0) {
        printf("  No wallet loaded or no accounts created.\n");
        return;
    }

    printf("  Accounts: %zu\n\n", wallet->account_count);

    for (size_t i = 0; i < wallet->account_count; i++) {
        const wallet_account_t *acc = &wallet->accounts[i];
        printf("  Account %zu:\n", i + 1);
        printf("    Chain: %s\n", chain_name(acc->chain));
        printf("    Type:  %s\n", addr_type_name(acc->addr_type));
        printf("    Addresses generated: %u\n\n", acc->next_external_index);
    }
}

static void cli_show_addresses(wallet_t *wallet)
{
    char address[128];

    print_header("ADDRESS LIST");

    if (wallet == NULL || wallet->account_count == 0) {
        printf("  No accounts found. Generate an address first.\n");
        return;
    }

    for (size_t i = 0; i < wallet->account_count; i++) {
        wallet_account_t *acc = &wallet->accounts[i];

        printf("  %s (%s)\n", chain_name(acc->chain), addr_type_name(acc->addr_type));
        cli_print_separator();

        if (acc->next_external_index == 0) {
            printf("    No addresses generated yet.\n\n");
            continue;
        }

        /* Regenerate addresses for display */
        /* Note: We need to derive from the account key */
        bip32_key_t addr_key;

        for (uint32_t idx = 0; idx < acc->next_external_index && idx < 10; idx++) {
            /* Derive external chain key (m/0) then address key */
            bip32_key_t external_chain;
            if (bip32_derive_child(&acc->account_key, &external_chain, 0) != 0) {
                continue;
            }

            if (bip32_derive_child(&external_chain, &addr_key, idx) != 0) {
                bip32_key_wipe(&external_chain);
                continue;
            }

            bip32_key_wipe(&external_chain);

            /* Generate address based on chain */
            int result = -1;
            if (acc->chain == CHAIN_BITCOIN || acc->chain == CHAIN_BITCOIN_TESTNET) {
                btc_network_t net = (acc->chain == CHAIN_BITCOIN) ? BTC_MAINNET : BTC_TESTNET;
                btc_addr_type_t btc_type;

                switch (acc->addr_type) {
                case ADDR_TYPE_LEGACY: btc_type = BTC_ADDR_P2PKH; break;
                case ADDR_TYPE_SEGWIT_COMPAT: btc_type = BTC_ADDR_P2SH; break;
                case ADDR_TYPE_SEGWIT_NATIVE: btc_type = BTC_ADDR_P2WPKH; break;
                case ADDR_TYPE_TAPROOT: btc_type = BTC_ADDR_P2TR; break;
                default: btc_type = BTC_ADDR_P2WPKH; break;
                }

                result = btc_pubkey_to_address(addr_key.public_key, btc_type,
                                                net, address, sizeof(address));
            } else if (acc->chain == CHAIN_ETHEREUM) {
                /* Need uncompressed pubkey for Ethereum */
                uint8_t uncompressed[65];
                if (secp256k1_pubkey_create_uncompressed(addr_key.private_key, uncompressed) == 0) {
                    result = eth_pubkey_to_address(uncompressed, address);
                }
            }

            bip32_key_wipe(&addr_key);

            if (result == 0) {
                printf("    [%u] %s\n", idx, address);
            }
        }

        if (acc->next_external_index > 10) {
            printf("    ... and %u more addresses\n", acc->next_external_index - 10);
        }

        printf("\n");
    }
}

int cli_account_menu(wallet_t *wallet)
{
    print_header("ACCOUNT MANAGEMENT");

    printf("  [1] Add Bitcoin account\n");
    printf("  [2] Add Ethereum account\n");
    printf("  [3] View accounts\n");
    printf("  [4] Back to main menu\n\n");

    char choice[8];
    cli_read_line("  Choice: ", choice, sizeof(choice), 0);

    switch (atoi(choice)) {
    case 1:
        if (wallet_add_account(wallet, CHAIN_BITCOIN, ADDR_TYPE_SEGWIT_NATIVE, NULL) >= 0) {
            printf("  Bitcoin account added.\n");
        }
        break;
    case 2:
        if (wallet_add_account(wallet, CHAIN_ETHEREUM, ADDR_TYPE_LEGACY, NULL) >= 0) {
            printf("  Ethereum account added.\n");
        }
        break;
    case 3:
        cli_show_wallet_info(wallet);
        break;
    case 4:
        return 0;
    }

    return 0;
}

/**
 * Display PSBT transaction details for user review
 */
static void display_btc_tx(const btc_tx_t *tx)
{
    char amount_str[32];
    char address[BTC_ADDR_BECH32_MAX];

    printf("\n");
    printf("  ╔═══════════════════════════════════════════════════════════════╗\n");
    printf("  ║               TRANSACTION VERIFICATION                        ║\n");
    printf("  ╚═══════════════════════════════════════════════════════════════╝\n");

    /* Warning banner */
    printf("\n  ⚠  REVIEW CAREFULLY BEFORE SIGNING  ⚠\n\n");

    /* Show inputs */
    printf("  ┌─ INPUTS (%zu) ───────────────────────────────────────────────┐\n",
           tx->input_count);
    uint64_t total_in = 0;
    for (size_t i = 0; i < tx->input_count; i++) {
        btc_format_amount(tx->inputs[i].amount, amount_str, sizeof(amount_str));
        printf("  │  [%zu] %s\n", i, amount_str);

        /* Show txid:vout */
        printf("  │      From: ");
        for (int j = 0; j < 8; j++) {
            printf("%02x", tx->inputs[i].prev_txid[j]);
        }
        printf("...:%u\n", tx->inputs[i].prev_index);

        total_in += tx->inputs[i].amount;
    }
    printf("  └──────────────────────────────────────────────────────────────┘\n");

    /* Show outputs with decoded addresses */
    printf("\n  ┌─ OUTPUTS (%zu) ──────────────────────────────────────────────┐\n",
           tx->output_count);
    uint64_t total_out = 0;
    for (size_t i = 0; i < tx->output_count; i++) {
        btc_format_amount(tx->outputs[i].amount, amount_str, sizeof(amount_str));
        printf("  │  [%zu] %s\n", i, amount_str);

        /* Try to decode address from script */
        if (tx->outputs[i].script_pubkey_len > 0) {
            if (btc_script_to_address(tx->outputs[i].script_pubkey,
                                      tx->outputs[i].script_pubkey_len,
                                      tx->network, address, sizeof(address)) == 0) {
                printf("  │      To: %s\n", address);
            } else {
                /* Fallback to hex if we can't decode */
                printf("  │      Script: ");
                for (size_t j = 0; j < tx->outputs[i].script_pubkey_len && j < 12; j++) {
                    printf("%02x", tx->outputs[i].script_pubkey[j]);
                }
                if (tx->outputs[i].script_pubkey_len > 12) {
                    printf("...");
                }
                printf("\n");
            }
        }

        total_out += tx->outputs[i].amount;
    }
    printf("  └──────────────────────────────────────────────────────────────┘\n");

    /* Fee and summary */
    uint64_t fee = btc_calculate_fee(tx);

    printf("\n  ┌─ SUMMARY ────────────────────────────────────────────────────┐\n");
    btc_format_amount(total_in, amount_str, sizeof(amount_str));
    printf("  │  Total Input:   %s\n", amount_str);
    btc_format_amount(total_out, amount_str, sizeof(amount_str));
    printf("  │  Total Output:  %s\n", amount_str);
    printf("  │  ─────────────────────────────────────\n");
    btc_format_amount(fee, amount_str, sizeof(amount_str));
    printf("  │  Network Fee:   %s\n", amount_str);

    /* Fee rate estimation */
    size_t est_vbytes = 10 + tx->input_count * 68 + tx->output_count * 31;
    if (est_vbytes > 0 && fee > 0) {
        uint64_t fee_rate = fee / est_vbytes;
        printf("  │  Fee Rate:      ~%lu sat/vB\n", (unsigned long)fee_rate);

        /* Fee warnings */
        if (fee_rate > 500) {
            printf("  │  ⚠ HIGH FEE RATE - verify this is intended\n");
        } else if (fee_rate < 1) {
            printf("  │  ⚠ LOW FEE - transaction may not confirm\n");
        }
    }

    /* Check for unusually high fee */
    if (total_in > 0 && (fee * 100 / total_in) > 10) {
        printf("  │  ⚠ WARNING: Fee is >10%% of input value!\n");
    }

    printf("  └──────────────────────────────────────────────────────────────┘\n\n");
}

/**
 * Display Ethereum transaction details for user review
 */
static void display_eth_tx(const eth_tx_t *tx)
{
    char value_str[64];
    char max_fee_str[64];

    printf("\n");
    printf("  ╔═══════════════════════════════════════════════════════════════╗\n");
    printf("  ║               TRANSACTION VERIFICATION                        ║\n");
    printf("  ╚═══════════════════════════════════════════════════════════════╝\n");

    /* Warning banner */
    printf("\n  ⚠  REVIEW CAREFULLY BEFORE SIGNING  ⚠\n\n");

    /* Network info */
    printf("  ┌─ NETWORK ─────────────────────────────────────────────────────┐\n");
    printf("  │  Chain: %s (ID: %lu)\n", eth_chain_name(tx->chain_id),
           (unsigned long)tx->chain_id);
    printf("  │  Type:  %s\n",
           tx->type == ETH_TX_EIP1559 ? "EIP-1559 (Base + Priority Fee)" :
           tx->type == ETH_TX_ACCESS_LIST ? "EIP-2930 (Access List)" : "Legacy");
    printf("  └──────────────────────────────────────────────────────────────┘\n");

    /* Transaction details */
    printf("\n  ┌─ TRANSACTION ────────────────────────────────────────────────┐\n");
    printf("  │  Nonce: %lu\n", (unsigned long)tx->nonce);
    printf("  │  To:    %s\n", tx->to_str);

    eth_format_amount(tx->value, value_str, sizeof(value_str), 18);
    printf("  │  Value: %s\n", value_str);

    if (tx->data_len > 0) {
        printf("  │  Data:  %zu bytes", tx->data_len);
        if (tx->data_len >= 4) {
            printf(" (selector: 0x%02x%02x%02x%02x)",
                   tx->data[0], tx->data[1], tx->data[2], tx->data[3]);
        }
        printf("\n");

        /* Common function selectors */
        if (tx->data_len >= 4) {
            uint32_t selector = ((uint32_t)tx->data[0] << 24) |
                               ((uint32_t)tx->data[1] << 16) |
                               ((uint32_t)tx->data[2] << 8) |
                               (uint32_t)tx->data[3];
            const char *fn_name = NULL;

            switch (selector) {
            case 0xa9059cbb: fn_name = "ERC-20 transfer()"; break;
            case 0x23b872dd: fn_name = "ERC-20 transferFrom()"; break;
            case 0x095ea7b3: fn_name = "ERC-20 approve()"; break;
            case 0x42842e0e: fn_name = "ERC-721 safeTransferFrom()"; break;
            case 0xf242432a: fn_name = "ERC-1155 safeTransferFrom()"; break;
            case 0x7ff36ab5: fn_name = "Uniswap swapExactETH...()"; break;
            }

            if (fn_name) {
                printf("  │         ↳ Likely: %s\n", fn_name);
            }
        }
    }
    printf("  └──────────────────────────────────────────────────────────────┘\n");

    /* Gas / Fee details */
    printf("\n  ┌─ GAS & FEES ─────────────────────────────────────────────────┐\n");
    printf("  │  Gas Limit: %lu\n", (unsigned long)tx->gas_limit);

    if (tx->type == ETH_TX_EIP1559) {
        eth_format_amount(tx->max_priority_fee, value_str, sizeof(value_str), 9);
        printf("  │  Priority Fee: %s Gwei\n", value_str);
        eth_format_amount(tx->max_fee, max_fee_str, sizeof(max_fee_str), 9);
        printf("  │  Max Fee:      %s Gwei\n", max_fee_str);
    } else {
        eth_format_amount(tx->gas_price, value_str, sizeof(value_str), 9);
        printf("  │  Gas Price: %s Gwei\n", value_str);
    }
    printf("  └──────────────────────────────────────────────────────────────┘\n\n");
}

/**
 * Collect signing keys from wallet accounts
 */
static int collect_btc_keys(wallet_t *wallet, bip32_key_t *keys, size_t *key_count,
                            size_t max_keys)
{
    size_t count = 0;

    for (size_t i = 0; i < wallet->account_count && count < max_keys; i++) {
        wallet_account_t *acc = &wallet->accounts[i];

        if (acc->chain != CHAIN_BITCOIN && acc->chain != CHAIN_BITCOIN_TESTNET) {
            continue;
        }

        /* Derive external chain keys */
        bip32_key_t external_chain;
        if (bip32_derive_child(&acc->account_key, &external_chain, 0) != 0) {
            continue;
        }

        /* Derive address keys (up to 20 for signing) */
        for (uint32_t idx = 0; idx < acc->next_external_index && idx < 20 && count < max_keys; idx++) {
            if (bip32_derive_child(&external_chain, &keys[count], idx) == 0) {
                count++;
            }
        }

        bip32_key_wipe(&external_chain);
    }

    *key_count = count;
    return (count > 0) ? 0 : -1;
}

/**
 * Get Ethereum key from wallet
 */
static int get_eth_key(wallet_t *wallet, bip32_key_t *key)
{
    for (size_t i = 0; i < wallet->account_count; i++) {
        wallet_account_t *acc = &wallet->accounts[i];

        if (acc->chain != CHAIN_ETHEREUM) {
            continue;
        }

        /* Derive external chain key then first address */
        bip32_key_t external_chain;
        if (bip32_derive_child(&acc->account_key, &external_chain, 0) != 0) {
            continue;
        }

        if (bip32_derive_child(&external_chain, key, 0) == 0) {
            bip32_key_wipe(&external_chain);
            return 0;
        }

        bip32_key_wipe(&external_chain);
    }

    return -1;
}

/**
 * Sign Bitcoin PSBT
 */
static int cli_sign_psbt(wallet_t *wallet)
{
    char psbt_base64[8192];
    uint8_t psbt_data[4096];
    size_t psbt_len;
    btc_tx_t tx;
    bip32_key_t keys[64];
    size_t key_count = 0;
    uint8_t signed_tx[4096];
    size_t signed_tx_len;

    printf("\n  Paste PSBT (base64 encoded, then press Enter):\n\n");
    printf("  > ");
    fflush(stdout);

    if (fgets(psbt_base64, sizeof(psbt_base64), stdin) == NULL) {
        printf("  ERROR: Failed to read input\n");
        return -1;
    }

    /* Trim whitespace */
    size_t len = strlen(psbt_base64);
    while (len > 0 && (psbt_base64[len-1] == '\n' || psbt_base64[len-1] == '\r' ||
                       psbt_base64[len-1] == ' ')) {
        psbt_base64[--len] = '\0';
    }

    if (len == 0) {
        printf("  ERROR: Empty input\n");
        return -1;
    }

    /* Decode base64 */
    psbt_len = sizeof(psbt_data);
    if (base64_decode(psbt_base64, len, psbt_data, &psbt_len) != 0) {
        printf("  ERROR: Invalid base64 encoding\n");
        return -1;
    }

    printf("\n  Decoding PSBT (%zu bytes)...\n", psbt_len);

    /* Parse PSBT */
    if (btc_parse_psbt(psbt_data, psbt_len, &tx) != 0) {
        printf("  ERROR: Failed to parse PSBT\n");
        printf("  Make sure this is a valid PSBT format.\n");
        return -1;
    }

    /* Display transaction for review */
    display_btc_tx(&tx);

    /* Confirm signing */
    if (!cli_confirm("  Do you want to sign this transaction?")) {
        printf("  Signing cancelled.\n");
        return 0;
    }

    /* Collect keys */
    printf("\n  Collecting signing keys...\n");
    if (collect_btc_keys(wallet, keys, &key_count, 64) != 0 || key_count == 0) {
        printf("  ERROR: No Bitcoin keys found in wallet.\n");
        printf("  Generate a Bitcoin address first.\n");
        return -1;
    }

    printf("  Found %zu keys for signing.\n", key_count);

    /* Sign transaction */
    printf("  Signing transaction...\n");
    signed_tx_len = sizeof(signed_tx);
    if (btc_sign_tx(&tx, keys, key_count, signed_tx, &signed_tx_len) != 0) {
        printf("  ERROR: Failed to sign transaction\n");

        /* Wipe keys */
        for (size_t i = 0; i < key_count; i++) {
            bip32_key_wipe(&keys[i]);
        }
        return -1;
    }

    /* Wipe keys */
    for (size_t i = 0; i < key_count; i++) {
        bip32_key_wipe(&keys[i]);
    }

    printf("\n  Transaction signed successfully!\n\n");

    /* Display signed transaction (hex) */
    printf("  Signed Transaction (hex):\n");
    cli_print_separator();
    printf("\n  ");
    for (size_t i = 0; i < signed_tx_len; i++) {
        printf("%02x", signed_tx[i]);
        if ((i + 1) % 32 == 0) {
            printf("\n  ");
        }
    }
    printf("\n");
    cli_print_separator();

    printf("\n  Transaction size: %zu bytes\n", signed_tx_len);
    printf("  Copy the hex above and broadcast via your preferred method.\n");

    return 0;
}

/**
 * Sign Ethereum transaction
 */
static int cli_sign_eth_tx(wallet_t *wallet)
{
    char tx_hex[4096];
    uint8_t tx_data[2048];
    size_t tx_len;
    eth_tx_t tx;
    bip32_key_t key;
    uint8_t signed_tx[2048];
    size_t signed_tx_len;
    char signed_hex[4096];

    printf("\n  Paste unsigned transaction (hex encoded, then press Enter):\n\n");
    printf("  > ");
    fflush(stdout);

    if (fgets(tx_hex, sizeof(tx_hex), stdin) == NULL) {
        printf("  ERROR: Failed to read input\n");
        return -1;
    }

    /* Trim whitespace and 0x prefix */
    char *hex = tx_hex;
    while (*hex == ' ' || *hex == '\t') hex++;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }

    size_t len = strlen(hex);
    while (len > 0 && (hex[len-1] == '\n' || hex[len-1] == '\r' || hex[len-1] == ' ')) {
        hex[--len] = '\0';
    }

    if (len == 0) {
        printf("  ERROR: Empty input\n");
        return -1;
    }

    /* Decode hex */
    tx_len = sizeof(tx_data);
    if (hex_decode(hex, tx_data, &tx_len) != 0) {
        printf("  ERROR: Invalid hex encoding\n");
        return -1;
    }

    printf("\n  Decoding transaction (%zu bytes)...\n", tx_len);

    /* Parse transaction */
    if (eth_parse_tx(tx_data, tx_len, &tx) != 0) {
        printf("  ERROR: Failed to parse transaction\n");
        printf("  Make sure this is a valid RLP-encoded transaction.\n");
        return -1;
    }

    /* Display transaction for review */
    display_eth_tx(&tx);

    /* Confirm signing */
    if (!cli_confirm("  Do you want to sign this transaction?")) {
        printf("  Signing cancelled.\n");
        eth_tx_free(&tx);
        return 0;
    }

    /* Get Ethereum key */
    printf("\n  Looking for Ethereum key...\n");
    if (get_eth_key(wallet, &key) != 0) {
        printf("  ERROR: No Ethereum keys found in wallet.\n");
        printf("  Generate an Ethereum address first.\n");
        eth_tx_free(&tx);
        return -1;
    }

    /* Sign transaction */
    printf("  Signing transaction...\n");
    signed_tx_len = sizeof(signed_tx);
    if (eth_sign_tx(&tx, &key, signed_tx, &signed_tx_len) != 0) {
        printf("  ERROR: Failed to sign transaction\n");
        bip32_key_wipe(&key);
        eth_tx_free(&tx);
        return -1;
    }

    bip32_key_wipe(&key);
    eth_tx_free(&tx);

    printf("\n  Transaction signed successfully!\n\n");

    /* Display signed transaction (hex) */
    hex_encode(signed_tx, signed_tx_len, signed_hex, 1);

    printf("  Signed Transaction (hex):\n");
    cli_print_separator();
    printf("\n  0x");
    for (size_t i = 0; i < signed_tx_len * 2; i++) {
        printf("%c", signed_hex[i]);
        if ((i + 1) % 64 == 0) {
            printf("\n  ");
        }
    }
    printf("\n");
    cli_print_separator();

    printf("\n  Transaction size: %zu bytes\n", signed_tx_len);
    printf("  Copy the hex above and broadcast via your preferred method.\n");

    return 0;
}

/**
 * Sign message (Ethereum or Bitcoin)
 */
static int cli_sign_message(wallet_t *wallet)
{
    char message[2048];
    char choice[8];
    bip32_key_t key;

    printf("\n  Select message format:\n\n");
    printf("    [1] Ethereum personal_sign (EIP-191)\n");
    printf("    [2] Bitcoin message (legacy format)\n");
    printf("    [3] Back\n\n");

    cli_read_line("  Choice: ", choice, sizeof(choice), 0);

    int format = atoi(choice);
    if (format == 3) {
        return 0;
    }

    printf("\n  Enter message to sign (then press Enter):\n\n");
    printf("  > ");
    fflush(stdout);

    if (fgets(message, sizeof(message), stdin) == NULL) {
        printf("  ERROR: Failed to read input\n");
        return -1;
    }

    /* Trim trailing newline */
    size_t len = strlen(message);
    while (len > 0 && (message[len-1] == '\n' || message[len-1] == '\r')) {
        message[--len] = '\0';
    }

    if (len == 0) {
        printf("  ERROR: Empty message\n");
        return -1;
    }

    printf("\n  Message to sign:\n");
    cli_print_separator();
    printf("  \"%s\"\n", message);
    cli_print_separator();
    printf("  Length: %zu characters\n\n", len);

    if (!cli_confirm("  Do you want to sign this message?")) {
        printf("  Signing cancelled.\n");
        return 0;
    }

    if (format == 1) {
        /* Ethereum message signing */
        uint8_t signature[ETH_SIG_SIZE];
        char sig_hex[ETH_SIG_SIZE * 2 + 3];

        if (get_eth_key(wallet, &key) != 0) {
            printf("  ERROR: No Ethereum keys found in wallet.\n");
            printf("  Generate an Ethereum address first.\n");
            return -1;
        }

        printf("\n  Signing with Ethereum key...\n");

        if (eth_sign_message((const uint8_t *)message, len, &key, signature) != 0) {
            printf("  ERROR: Failed to sign message\n");
            bip32_key_wipe(&key);
            return -1;
        }

        bip32_key_wipe(&key);

        /* Format signature as 0x... */
        sig_hex[0] = '0';
        sig_hex[1] = 'x';
        hex_encode(signature, ETH_SIG_SIZE, sig_hex + 2, 1);

        printf("\n  Message signed successfully!\n\n");
        printf("  Signature (EIP-191 / personal_sign):\n");
        cli_print_separator();
        printf("\n  %s\n\n", sig_hex);
        cli_print_separator();

        printf("\n  r: 0x");
        hex_encode(signature, 32, sig_hex, 1);
        printf("%s\n", sig_hex);

        printf("  s: 0x");
        hex_encode(signature + 32, 32, sig_hex, 1);
        printf("%s\n", sig_hex);

        printf("  v: %d\n", signature[64]);

    } else if (format == 2) {
        /* Bitcoin message signing */
        uint8_t msg_hash[32];
        uint8_t signature[SECP256K1_SIGNATURE_SIZE];
        char sig_b64[128];

        /* Get first Bitcoin key */
        bip32_key_t btc_keys[1];
        size_t key_count = 0;
        if (collect_btc_keys(wallet, btc_keys, &key_count, 1) != 0 || key_count == 0) {
            printf("  ERROR: No Bitcoin keys found in wallet.\n");
            printf("  Generate a Bitcoin address first.\n");
            return -1;
        }

        printf("\n  Signing with Bitcoin key...\n");

        /* Bitcoin message signing format:
         * hash = SHA256(SHA256("\x18Bitcoin Signed Message:\n" + varint(len) + message))
         */
        const char *magic = "\x18" "Bitcoin Signed Message:\n";
        size_t magic_len = 25;

        /* Build preimage */
        size_t preimage_len = magic_len + 1 + len;  /* +1 for length varint (assuming < 253) */
        uint8_t *preimage = malloc(preimage_len + 10);
        if (preimage == NULL) {
            bip32_key_wipe(&btc_keys[0]);
            printf("  ERROR: Memory allocation failed\n");
            return -1;
        }

        memcpy(preimage, magic, magic_len);
        size_t offset = magic_len;

        /* Encode message length as varint */
        if (len < 253) {
            preimage[offset++] = (uint8_t)len;
        } else {
            preimage[offset++] = 0xFD;
            preimage[offset++] = len & 0xFF;
            preimage[offset++] = (len >> 8) & 0xFF;
        }

        memcpy(preimage + offset, message, len);
        offset += len;

        /* Double SHA256 */
        uint8_t hash1[32];
        crypto_hash_sha256(hash1, preimage, offset);
        crypto_hash_sha256(msg_hash, hash1, 32);

        secure_wipe(preimage, offset);
        free(preimage);

        /* Sign */
        if (secp256k1_sign(btc_keys[0].private_key, msg_hash, signature) != 0) {
            printf("  ERROR: Failed to sign message\n");
            bip32_key_wipe(&btc_keys[0]);
            return -1;
        }

        bip32_key_wipe(&btc_keys[0]);

        /* Format as base64 (Bitcoin message signature format) */
        /* Header byte encodes recovery and compression info */
        uint8_t full_sig[65];
        full_sig[0] = 31;  /* Compressed key, recovery param 0 (simplified) */
        memcpy(full_sig + 1, signature, 64);

        if (base64_encode(full_sig, 65, sig_b64, sizeof(sig_b64)) != 0) {
            printf("  ERROR: Failed to encode signature\n");
            return -1;
        }

        printf("\n  Message signed successfully!\n\n");
        printf("  Signature (Bitcoin Message):\n");
        cli_print_separator();
        printf("\n  %s\n\n", sig_b64);
        cli_print_separator();
    }

    return 0;
}

int cli_sign_transaction(wallet_t *wallet)
{
    print_header("SIGN TRANSACTION");

    if (wallet == NULL || wallet->account_count == 0) {
        printf("  No wallet loaded. Create or restore a wallet first.\n");
        return -1;
    }

    printf("  Transaction signing modes:\n\n");
    printf("    [1] Sign Bitcoin PSBT (Partially Signed Bitcoin Transaction)\n");
    printf("    [2] Sign Ethereum transaction\n");
    printf("    [3] Sign message (Ethereum/Bitcoin)\n");
    printf("    [4] Back\n\n");

    char choice[8];
    cli_read_line("  Choice: ", choice, sizeof(choice), 0);

    switch (atoi(choice)) {
    case 1:
        return cli_sign_psbt(wallet);
    case 2:
        return cli_sign_eth_tx(wallet);
    case 3:
        return cli_sign_message(wallet);
    case 4:
        return 0;
    }

    return 0;
}

/* Forward declaration for fingerprint menu */
static void cli_fingerprint_menu(void);

/**
 * Security settings menu
 */
static void cli_security_settings_menu(void)
{
    print_header("SECURITY SETTINGS");

    printf("  Current Security Configuration:\n\n");

    /* Display current settings */
    printf("  Authentication:\n");
    printf("    [1] PIN for wallet unlock:      %s\n",
           storage_setting_enabled(&g_settings, SETTINGS_PIN_REQUIRED) ? "ENABLED" : "disabled");
    printf("    [2] Fingerprint for unlock:     %s\n",
           storage_setting_enabled(&g_settings, SETTINGS_FP_REQUIRED) ? "ENABLED" : "disabled");

    printf("\n  Transaction Signing:\n");
    printf("    [3] PIN for signing:            %s\n",
           storage_setting_enabled(&g_settings, SETTINGS_PIN_FOR_SIGN) ? "ENABLED" : "disabled");
    printf("    [4] Fingerprint for signing:    %s\n",
           storage_setting_enabled(&g_settings, SETTINGS_FP_FOR_SIGN) ? "ENABLED" : "disabled");

    printf("\n  Additional Security:\n");
    printf("    [5] Auto-lock timeout:          ");
    if (storage_setting_enabled(&g_settings, SETTINGS_AUTO_LOCK) && g_settings.auto_lock_timeout > 0) {
        printf("%u seconds\n", g_settings.auto_lock_timeout);
    } else {
        printf("disabled\n");
    }
    printf("    [6] Paranoid mode:              %s\n",
           storage_setting_enabled(&g_settings, SETTINGS_PARANOID_MODE) ? "ENABLED" : "disabled");

    printf("\n    [7] Fingerprint management\n");
    printf("    [8] Back to settings\n\n");

    char choice[8];
    cli_read_line("  Toggle setting (1-8): ", choice, sizeof(choice), 0);

    int changed = 0;

    switch (atoi(choice)) {
    case 1: {
        /* Toggle PIN for unlock */
        int current = storage_setting_enabled(&g_settings, SETTINGS_PIN_REQUIRED);
        if (current) {
            /* Disabling PIN - require confirmation */
            if (cli_confirm("\n  WARNING: Disabling PIN removes a security layer.\n"
                            "  Are you sure?")) {
                storage_setting_set(&g_settings, SETTINGS_PIN_REQUIRED, 0);
                printf("  PIN for unlock DISABLED.\n");
                changed = 1;
            }
        } else {
            storage_setting_set(&g_settings, SETTINGS_PIN_REQUIRED, 1);
            printf("  PIN for unlock ENABLED.\n");
            changed = 1;
        }
        break;
    }

    case 2: {
        /* Toggle fingerprint for unlock */
        if (!fingerprint_is_available()) {
            printf("\n  Fingerprint reader not available.\n");
            break;
        }
        if (fingerprint_get_enrolled_count() == 0) {
            printf("\n  No fingerprints enrolled. Enroll a fingerprint first.\n");
            break;
        }

        int current = storage_setting_enabled(&g_settings, SETTINGS_FP_REQUIRED);
        storage_setting_set(&g_settings, SETTINGS_FP_REQUIRED, !current);
        printf("  Fingerprint for unlock %s.\n", !current ? "ENABLED" : "DISABLED");
        changed = 1;
        break;
    }

    case 3: {
        /* Toggle PIN for signing */
        int current = storage_setting_enabled(&g_settings, SETTINGS_PIN_FOR_SIGN);
        storage_setting_set(&g_settings, SETTINGS_PIN_FOR_SIGN, !current);
        printf("  PIN for signing %s.\n", !current ? "ENABLED" : "DISABLED");
        changed = 1;
        break;
    }

    case 4: {
        /* Toggle fingerprint for signing */
        if (!fingerprint_is_available()) {
            printf("\n  Fingerprint reader not available.\n");
            break;
        }
        if (fingerprint_get_enrolled_count() == 0) {
            printf("\n  No fingerprints enrolled. Enroll a fingerprint first.\n");
            break;
        }

        int current = storage_setting_enabled(&g_settings, SETTINGS_FP_FOR_SIGN);
        storage_setting_set(&g_settings, SETTINGS_FP_FOR_SIGN, !current);
        printf("  Fingerprint for signing %s.\n", !current ? "ENABLED" : "DISABLED");
        changed = 1;
        break;
    }

    case 5: {
        /* Configure auto-lock timeout */
        char timeout_str[16];
        printf("\n  Enter auto-lock timeout in seconds (0 to disable): ");
        cli_read_line(NULL, timeout_str, sizeof(timeout_str), 0);

        int timeout = atoi(timeout_str);
        if (timeout < 0) timeout = 0;
        if (timeout > 3600) timeout = 3600;  /* Max 1 hour */

        g_settings.auto_lock_timeout = (uint32_t)timeout;
        if (timeout > 0) {
            storage_setting_set(&g_settings, SETTINGS_AUTO_LOCK, 1);
            printf("  Auto-lock set to %d seconds.\n", timeout);
        } else {
            storage_setting_set(&g_settings, SETTINGS_AUTO_LOCK, 0);
            printf("  Auto-lock disabled.\n");
        }
        changed = 1;
        break;
    }

    case 6: {
        /* Toggle paranoid mode */
        int current = storage_setting_enabled(&g_settings, SETTINGS_PARANOID_MODE);
        storage_setting_set(&g_settings, SETTINGS_PARANOID_MODE, !current);
        if (!current) {
            printf("  Paranoid mode ENABLED.\n");
            printf("  Extra confirmations will be shown for sensitive operations.\n");
        } else {
            printf("  Paranoid mode DISABLED.\n");
        }
        changed = 1;
        break;
    }

    case 7:
        /* Fingerprint management */
        cli_fingerprint_menu();
        break;

    case 8:
    default:
        break;
    }

    /* Save settings if changed */
    if (changed) {
        if (storage_save_settings(&g_settings) == STORAGE_OK) {
            printf("  Settings saved.\n");
        } else {
            printf("  WARNING: Failed to save settings.\n");
        }
    }

    printf("\n  Press Enter to continue...");
    getchar();
}

/**
 * Fingerprint settings menu
 */
static void cli_fingerprint_menu(void)
{
    int fp_result;

    print_header("FINGERPRINT SETTINGS");

    /* Check if fingerprint is available */
    if (!fingerprint_is_available()) {
        printf("  Fingerprint authentication is not available.\n");
        const char *dev_name = fingerprint_get_device_name();
        if (dev_name == NULL) {
            printf("  No fingerprint reader detected.\n");
        }
        printf("\n  Press Enter to continue...");
        getchar();
        return;
    }

    printf("  Device: %s\n", fingerprint_get_device_name());
    printf("  Enrolled: %d fingerprint(s)\n\n", fingerprint_get_enrolled_count());

    printf("  Enrolled slots:\n");
    for (int i = 0; i < FP_MAX_SLOTS; i++) {
        printf("    [%d] %s\n", i, fingerprint_slot_enrolled(i) ? "ENROLLED" : "empty");
    }

    printf("\n  Options:\n");
    printf("    [E] Enroll new fingerprint\n");
    printf("    [V] Verify fingerprint\n");
    printf("    [D] Delete fingerprint\n");
    printf("    [X] Delete all fingerprints\n");
    printf("    [B] Back to settings\n\n");

    char choice[8];
    cli_read_line("  Choice: ", choice, sizeof(choice), 0);

    switch (toupper(choice[0])) {
    case 'E': {
        /* Enroll */
        printf("\n  Available slots:\n");
        for (int i = 0; i < FP_MAX_SLOTS; i++) {
            if (!fingerprint_slot_enrolled(i)) {
                printf("    [%d] empty\n", i);
            }
        }

        char slot_str[8];
        cli_read_line("\n  Select slot (0-4): ", slot_str, sizeof(slot_str), 0);
        int slot = atoi(slot_str);

        if (slot < 0 || slot >= FP_MAX_SLOTS) {
            printf("  Invalid slot.\n");
            break;
        }

        if (fingerprint_slot_enrolled(slot)) {
            if (!cli_confirm("  This slot already has a fingerprint. Overwrite?")) {
                break;
            }
        }

        printf("\n  Starting enrollment...\n");
        printf("  Place your finger on the sensor when prompted.\n");
        printf("  You may need to place your finger multiple times.\n\n");

        fp_result = fingerprint_enroll(slot, NULL, NULL);
        if (fp_result == FP_OK) {
            printf("\n  Fingerprint enrolled successfully!\n");
        } else {
            printf("\n  Enrollment failed (error %d)\n", fp_result);
        }
        break;
    }

    case 'V': {
        /* Verify */
        if (fingerprint_get_enrolled_count() == 0) {
            printf("\n  No fingerprints enrolled.\n");
            break;
        }

        printf("\n  Place your finger on the sensor...\n");
        fp_result = fingerprint_verify(NULL, NULL);
        if (fp_result == FP_OK) {
            printf("  Fingerprint verified!\n");
        } else if (fp_result == FP_ERR_NO_MATCH) {
            printf("  Fingerprint not recognized.\n");
        } else {
            printf("  Verification error (%d)\n", fp_result);
        }
        break;
    }

    case 'D': {
        /* Delete single */
        char slot_str[8];
        cli_read_line("\n  Select slot to delete (0-4): ", slot_str, sizeof(slot_str), 0);
        int slot = atoi(slot_str);

        if (slot < 0 || slot >= FP_MAX_SLOTS) {
            printf("  Invalid slot.\n");
            break;
        }

        if (!fingerprint_slot_enrolled(slot)) {
            printf("  Slot %d is already empty.\n", slot);
            break;
        }

        if (cli_confirm("  Delete fingerprint from slot?")) {
            fp_result = fingerprint_delete(slot);
            if (fp_result == FP_OK) {
                printf("  Fingerprint deleted.\n");
            } else {
                printf("  Delete failed (error %d)\n", fp_result);
            }
        }
        break;
    }

    case 'X':
        /* Delete all */
        if (fingerprint_get_enrolled_count() == 0) {
            printf("\n  No fingerprints to delete.\n");
            break;
        }

        if (cli_confirm("\n  Delete ALL enrolled fingerprints?")) {
            fp_result = fingerprint_delete_all();
            if (fp_result == FP_OK) {
                printf("  All fingerprints deleted.\n");
            } else {
                printf("  Delete failed (error %d)\n", fp_result);
            }
        }
        break;

    case 'B':
    default:
        break;
    }

    printf("\n  Press Enter to continue...");
    getchar();
}

static int cli_settings_menu(void)
{
    print_header("SETTINGS");

    printf("  Wallet Settings:\n\n");
    printf("    [1] Change PIN\n");
    printf("    [2] Export public keys (xpub/zpub)\n");
    printf("    [3] Verify recovery phrase backup\n");
    printf("    [4] Wipe wallet from device\n");
    printf("\n  Display Settings:\n\n");
    printf("    [5] Toggle address format (uppercase/lowercase)\n");
    printf("    [6] Set default network (mainnet/testnet)\n");
    printf("\n  Security:\n\n");
    printf("    [7] Security & MFA settings\n");
    printf("    [8] Show device information\n");
    printf("    [9] Back to main menu\n\n");

    char choice[8];
    cli_read_line("  Choice: ", choice, sizeof(choice), 0);

    switch (atoi(choice)) {
    case 1: {
        /* Change PIN */
        char current_pin[16];
        char new_pin[16];
        char confirm_pin[16];

        if (!g_wallet_loaded) {
            printf("\n  ERROR: No wallet loaded. Load wallet first.\n");
            break;
        }

        if (strlen(g_current_pin) == 0) {
            printf("\n  ERROR: Current PIN not available. Reload wallet first.\n");
            break;
        }

        printf("\n  Enter current PIN: ");
        cli_read_line(NULL, current_pin, sizeof(current_pin), 1);

        /* Verify current PIN matches */
        if (strcmp(current_pin, g_current_pin) != 0) {
            printf("  ERROR: Current PIN is incorrect\n");
            secure_wipe(current_pin, sizeof(current_pin));
            break;
        }

        printf("  Enter new PIN (4-8 digits): ");
        cli_read_line(NULL, new_pin, sizeof(new_pin), 1);

        /* Validate PIN */
        size_t len = strlen(new_pin);
        if (len < 4 || len > 8) {
            printf("  ERROR: PIN must be 4-8 digits\n");
            secure_wipe(current_pin, sizeof(current_pin));
            break;
        }

        int valid = 1;
        for (size_t i = 0; i < len; i++) {
            if (new_pin[i] < '0' || new_pin[i] > '9') {
                valid = 0;
                break;
            }
        }

        if (!valid) {
            printf("  ERROR: PIN must contain only digits\n");
            secure_wipe(current_pin, sizeof(current_pin));
            secure_wipe(new_pin, sizeof(new_pin));
            break;
        }

        printf("  Confirm new PIN: ");
        cli_read_line(NULL, confirm_pin, sizeof(confirm_pin), 1);

        if (strcmp(new_pin, confirm_pin) != 0) {
            printf("  ERROR: PINs do not match\n");
            secure_wipe(current_pin, sizeof(current_pin));
            secure_wipe(new_pin, sizeof(new_pin));
            secure_wipe(confirm_pin, sizeof(confirm_pin));
            break;
        }

        printf("\n  Re-encrypting wallet with new PIN...\n");
        printf("  (Key derivation may take a moment)\n");

        /* Re-save wallet with new PIN */
        if (wallet_save(&g_wallet, new_pin) != 0) {
            printf("  ERROR: Failed to re-encrypt wallet\n");
            secure_wipe(current_pin, sizeof(current_pin));
            secure_wipe(new_pin, sizeof(new_pin));
            secure_wipe(confirm_pin, sizeof(confirm_pin));
            break;
        }

        /* Update stored PIN */
        strncpy(g_current_pin, new_pin, sizeof(g_current_pin) - 1);
        g_current_pin[sizeof(g_current_pin) - 1] = '\0';

        printf("\n  PIN changed successfully!\n");

        secure_wipe(current_pin, sizeof(current_pin));
        secure_wipe(new_pin, sizeof(new_pin));
        secure_wipe(confirm_pin, sizeof(confirm_pin));
        break;
    }

    case 2:
        /* Export public keys */
        printf("\n  Public key export not yet implemented.\n");
        printf("  This would show xpub/ypub/zpub for watch-only wallets.\n");
        break;

    case 3:
        /* Verify recovery phrase */
        printf("\n  Recovery phrase verification not available.\n");
        printf("  (The seed is derived from mnemonic and not stored.)\n");
        break;

    case 4:
        /* Wipe wallet */
        if (cli_confirm("\n  WARNING: This will permanently delete the wallet.\n"
                        "  Are you absolutely sure?")) {
            if (cli_confirm("  Type 'y' again to confirm wallet deletion")) {
                printf("\n  Wiping wallet from memory...\n");
                /* The actual wallet wipe happens in the main loop */
                return -2;  /* Special return code for wipe */
            }
        }
        printf("  Wallet wipe cancelled.\n");
        break;

    case 5:
        printf("\n  Address format setting not yet implemented.\n");
        break;

    case 6:
        printf("\n  Default network setting not yet implemented.\n");
        break;

    case 7:
        /* Security & MFA settings */
        cli_security_settings_menu();
        break;

    case 8:
        /* Device info */
        print_header("DEVICE INFORMATION");
        printf("  RISC-V Cold Wallet\n");
        printf("  Version: 0.1.0\n");
        printf("  Build:   %s %s\n", __DATE__, __TIME__);
        printf("  License: AGPL-3.0-or-later\n");
        printf("  Source:  https://github.com/blubskye/riscv_wallet\n");
        printf("\n  Cryptography:\n");
        printf("    - libsodium (SHA256/512, HMAC, RNG)\n");
        printf("    - libsecp256k1 (ECDSA)\n");
        printf("\n  Random Number Generator:\n");
        {
            random_source_t rng_source = random_get_source();
            const char *hwrng_dev = random_get_hwrng_device();
            if (rng_source == RANDOM_SOURCE_MIXED && hwrng_dev) {
                printf("    - Hardware RNG: %s\n", hwrng_dev);
                printf("    - Mode: Mixed (hardware + software)\n");
            } else if (rng_source == RANDOM_SOURCE_HARDWARE && hwrng_dev) {
                printf("    - Hardware RNG: %s\n", hwrng_dev);
            } else {
                printf("    - Software RNG only (libsodium)\n");
            }
        }
        printf("\n  Supported Chains:\n");
        printf("    - Bitcoin (P2PKH, P2SH, P2WPKH, P2TR)\n");
        printf("    - Ethereum (Legacy, EIP-1559)\n");
        printf("    - Litecoin (P2PKH, P2SH, P2WPKH)\n");
        printf("    - Solana (Ed25519)\n");
        printf("    - Monero (CryptoNote)\n");
        printf("\n  Security Features:\n");
        printf("    - Memory wiping (secure_wipe)\n");
        printf("    - Stack protector\n");
        printf("    - PIE/RELRO hardening\n");
#ifdef HAVE_LIBFPRINT
        printf("    - Fingerprint authentication enabled\n");
#endif
#ifdef ACCEL_HOTLOAD
        printf("    - Hotloadable acceleration enabled\n");
#endif
#ifdef USE_HIDAPI
        printf("    - USB HID support enabled\n");
#endif
        break;

    case 9:
        return 0;

    default:
        printf("  Invalid choice.\n");
        break;
    }

    return 1;  /* Stay in settings menu */
}

int cli_main_menu(void)
{
    int saved_wallet_exists = 0;

    print_header("RISC-V COLD WALLET");

    /* Check if saved wallet exists */
    if (storage_init() == STORAGE_OK) {
        saved_wallet_exists = storage_wallet_exists();
    }

    if (g_wallet_loaded) {
        printf("  Wallet Status: LOADED (%zu accounts)\n\n", g_wallet.account_count);
    } else if (saved_wallet_exists) {
        printf("  Wallet Status: SAVED (locked)\n\n");
    } else {
        printf("  Wallet Status: NOT LOADED\n\n");
    }

    if (!g_wallet_loaded && saved_wallet_exists) {
        print_menu_option(0, "Unlock saved wallet");
    }
    print_menu_option(1, "Create new wallet");
    print_menu_option(2, "Restore wallet from mnemonic");
    printf("\n");

    if (g_wallet_loaded) {
        print_menu_option(3, "Generate new address");
        print_menu_option(4, "Show all addresses");
        print_menu_option(5, "Sign transaction");
        print_menu_option(6, "Wallet info");
        print_menu_option(7, "Account management");
        print_menu_option(8, "Settings");
        printf("\n");
    } else {
        print_menu_option(8, "Settings");
    }

    print_menu_option(9, "Exit");
    printf("\n");

    char choice[8];
    cli_read_line("  Enter choice: ", choice, sizeof(choice), 0);

    int c = atoi(choice);
    if (c == 9) return CLI_EXIT;
    return c;
}

int cli_run(void)
{
    int running = 1;

    cli_clear_screen();

    printf("\n");
    cli_print_separator();
    cli_print_centered("RISC-V COLD WALLET v0.1.0", TERM_WIDTH);
    cli_print_centered("Copyright (C) 2025 blubskye", TERM_WIDTH);
    cli_print_centered("License: AGPL-3.0-or-later", TERM_WIDTH);
    cli_print_centered("Source: github.com/blubskye/riscv_wallet", TERM_WIDTH);
    cli_print_separator();
    printf("\n");

    while (running) {
        int choice = cli_main_menu();

        switch (choice) {
        case CLI_EXIT:
            if (cli_confirm("Are you sure you want to exit?")) {
                running = 0;
            }
            break;

        case 0: /* Unlock saved wallet */
            if (!g_wallet_loaded) {
                if (cli_load_wallet(&g_wallet) == 0) {
                    g_wallet_loaded = 1;
                }
                wait_for_enter();
            }
            break;

        case 1: /* Create wallet */
            if (g_wallet_loaded) {
                if (!cli_confirm("This will replace current wallet. Continue?")) {
                    break;
                }
                wallet_wipe(&g_wallet);
                g_wallet_loaded = 0;
            }
            if (cli_create_wallet(&g_wallet) == 0) {
                g_wallet_loaded = 1;
                /* Offer to save */
                printf("\n");
                if (cli_confirm("  Save wallet to encrypted storage?")) {
                    cli_save_wallet(&g_wallet);
                }
            }
            wait_for_enter();
            break;

        case 2: /* Restore wallet */
            if (g_wallet_loaded) {
                if (!cli_confirm("This will replace current wallet. Continue?")) {
                    break;
                }
                wallet_wipe(&g_wallet);
                g_wallet_loaded = 0;
            }
            if (cli_restore_wallet(&g_wallet) == 0) {
                g_wallet_loaded = 1;
                /* Offer to save */
                printf("\n");
                if (cli_confirm("  Save wallet to encrypted storage?")) {
                    cli_save_wallet(&g_wallet);
                }
            }
            wait_for_enter();
            break;

        case 3: /* Generate address */
            if (g_wallet_loaded) {
                cli_generate_address(&g_wallet);
                wait_for_enter();
            }
            break;

        case 4: /* Show addresses */
            if (g_wallet_loaded) {
                cli_show_addresses(&g_wallet);
                wait_for_enter();
            }
            break;

        case 5: /* Sign transaction */
            if (g_wallet_loaded) {
                cli_sign_transaction(&g_wallet);
                wait_for_enter();
            }
            break;

        case 6: /* Wallet info */
            if (g_wallet_loaded) {
                cli_show_wallet_info(&g_wallet);
                wait_for_enter();
            }
            break;

        case 7: /* Account management */
            if (g_wallet_loaded) {
                cli_account_menu(&g_wallet);
                wait_for_enter();
            }
            break;

        case 8: /* Settings */
            {
                int settings_result;
                do {
                    settings_result = cli_settings_menu();
                    if (settings_result == -2) {
                        /* Wallet wipe requested */
                        if (g_wallet_loaded) {
                            wallet_wipe(&g_wallet);
                            g_wallet_loaded = 0;
                            printf("  Wallet wiped from memory.\n");
                        }
                        settings_result = 0;  /* Exit settings menu */
                    }
                    if (settings_result != 0) {
                        wait_for_enter();
                    }
                } while (settings_result != 0);
            }
            break;

        default:
            /* Invalid choice, just redraw menu */
            break;
        }

        cli_clear_screen();
    }

    printf("\nGoodbye!\n");
    return 0;
}

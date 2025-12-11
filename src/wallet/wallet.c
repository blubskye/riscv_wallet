/*
 * Wallet Management
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "wallet.h"
#include "../crypto/bip39.h"
#include "../crypto/bip32.h"
#include "../crypto/secp256k1.h"
#include "../security/memory.h"
#include "../security/storage.h"
#include "../chains/bitcoin.h"
#include "../chains/ethereum.h"
#include "../chains/dogecoin.h"
#include "../chains/ripple.h"
#include "../chains/cardano.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Wallet file format version */
#define WALLET_FORMAT_VERSION 1

/* Maximum serialized wallet size */
#define WALLET_MAX_SERIALIZED_SIZE (64 + 78 + 256 * 256)

static const char *chain_names[] = {
    "Bitcoin",
    "Bitcoin Testnet",
    "Ethereum",
    "Litecoin",
    "Solana",
    "Dogecoin",
    "XRP",
    "Cardano"
};

int wallet_create(wallet_t *wallet, int word_count, const char *passphrase,
                  char *mnemonic, size_t mnemonic_len)
{
    if (wallet == NULL || mnemonic == NULL) {
        return -1;
    }

    /* Clear wallet structure */
    memset(wallet, 0, sizeof(wallet_t));

    /* Generate mnemonic */
    if (bip39_generate_mnemonic(mnemonic, mnemonic_len, word_count) != 0) {
        return -1;
    }

    /* Derive seed from mnemonic with optional passphrase */
    if (bip39_mnemonic_to_seed(mnemonic, passphrase, wallet->seed) != 0) {
        secure_wipe(mnemonic, mnemonic_len);
        return -1;
    }

    /* Derive master key */
    if (bip32_master_key_from_seed(wallet->seed, &wallet->master_key) != 0) {
        secure_wipe(wallet->seed, sizeof(wallet->seed));
        secure_wipe(mnemonic, mnemonic_len);
        return -1;
    }

    wallet->account_count = 0;
    wallet->flags = 0;

    /* Mark if passphrase was used */
    if (passphrase != NULL && passphrase[0] != '\0') {
        wallet->flags |= WALLET_FLAG_HAS_PASSPHRASE;
    }

    wallet->is_initialized = 1;

    return 0;
}

int wallet_has_passphrase(const wallet_t *wallet)
{
    if (wallet == NULL) return 0;
    return (wallet->flags & WALLET_FLAG_HAS_PASSPHRASE) != 0;
}

int wallet_restore(wallet_t *wallet, const char *mnemonic,
                   const char *passphrase)
{
    if (wallet == NULL || mnemonic == NULL) {
        return -1;
    }

    /* Validate mnemonic */
    if (bip39_validate_mnemonic(mnemonic) != 0) {
        return -1;
    }

    /* Clear wallet structure */
    memset(wallet, 0, sizeof(wallet_t));

    /* Derive seed from mnemonic */
    if (bip39_mnemonic_to_seed(mnemonic, passphrase, wallet->seed) != 0) {
        return -1;
    }

    /* Derive master key */
    if (bip32_master_key_from_seed(wallet->seed, &wallet->master_key) != 0) {
        secure_wipe(wallet->seed, sizeof(wallet->seed));
        return -1;
    }

    wallet->account_count = 0;
    wallet->flags = 0;

    /* Mark if passphrase was used */
    if (passphrase != NULL && passphrase[0] != '\0') {
        wallet->flags |= WALLET_FLAG_HAS_PASSPHRASE;
    }

    wallet->is_initialized = 1;

    return 0;
}

int wallet_add_account(wallet_t *wallet, chain_type_t chain,
                       address_type_t addr_type, const char *label)
{
    wallet_account_t *account;
    char path[64];
    int purpose;
    int coin_type;

    if (wallet == NULL || !wallet->is_initialized) {
        return -1;
    }

    if (wallet->account_count >= WALLET_MAX_ACCOUNTS) {
        return -1;
    }

    account = &wallet->accounts[wallet->account_count];
    account->index = (uint32_t)wallet->account_count;
    account->chain = chain;
    account->addr_type = addr_type;
    account->flags = 0;  /* Not watch-only */

    if (label != NULL) {
        strncpy(account->label, label, sizeof(account->label) - 1);
        account->label[sizeof(account->label) - 1] = '\0';
    }

    /* Determine derivation path based on chain and address type */
    switch (addr_type) {
    case ADDR_TYPE_LEGACY:
        purpose = 44;
        break;
    case ADDR_TYPE_SEGWIT_COMPAT:
        purpose = 49;
        break;
    case ADDR_TYPE_SEGWIT_NATIVE:
    case ADDR_TYPE_TAPROOT:
        purpose = 84;
        break;
    default:
        purpose = 44;
    }

    switch (chain) {
    case CHAIN_BITCOIN:
        coin_type = 0;
        break;
    case CHAIN_BITCOIN_TESTNET:
        coin_type = 1;
        break;
    case CHAIN_ETHEREUM:
        coin_type = 60;
        purpose = 44;  /* ETH always uses BIP-44 */
        break;
    case CHAIN_LITECOIN:
        coin_type = 2;
        break;
    case CHAIN_SOLANA:
        coin_type = 501;
        purpose = 44;
        break;
    case CHAIN_DOGECOIN:
        coin_type = 3;
        purpose = 44;  /* DOGE uses BIP-44 (no SegWit) */
        break;
    case CHAIN_XRP:
        coin_type = 144;
        purpose = 44;  /* XRP uses BIP-44 */
        break;
    case CHAIN_CARDANO:
        coin_type = 1815;
        purpose = 1852;  /* Cardano uses CIP-1852 */
        break;
    default:
        coin_type = 0;
    }

    /* Build derivation path: m/purpose'/coin_type'/account' */
    snprintf(path, sizeof(path), "m/%d'/%d'/%u'",
             purpose, coin_type, account->index);

    /* Derive account key */
    if (bip32_derive_path(&wallet->master_key, path, &account->account_key) != 0) {
        return -1;
    }

    account->next_external_index = 0;
    account->next_internal_index = 0;

    wallet->account_count++;

    return (int)(wallet->account_count - 1);
}

wallet_account_t *wallet_get_account(wallet_t *wallet, size_t index)
{
    if (wallet == NULL || !wallet->is_initialized) {
        return NULL;
    }

    if (index >= wallet->account_count) {
        return NULL;
    }

    return &wallet->accounts[index];
}

int wallet_get_new_address(wallet_account_t *account,
                           char *address, size_t address_len)
{
    bip32_key_t external_key;
    bip32_key_t addr_key;

    if (account == NULL || address == NULL) {
        return -1;
    }

    /* Derive external chain key (m/.../0) */
    if (bip32_derive_child(&account->account_key, &external_key, 0) != 0) {
        return -1;
    }

    /* Derive address key (m/.../0/index) */
    if (bip32_derive_child(&external_key, &addr_key,
                           account->next_external_index) != 0) {
        bip32_key_wipe(&external_key);
        return -1;
    }

    bip32_key_wipe(&external_key);

    /* Generate address based on chain type */
    switch (account->chain) {
    case CHAIN_BITCOIN:
    case CHAIN_BITCOIN_TESTNET:
        {
            btc_network_t network = (account->chain == CHAIN_BITCOIN)
                                    ? BTC_MAINNET : BTC_TESTNET;
            btc_addr_type_t btc_type;

            switch (account->addr_type) {
            case ADDR_TYPE_LEGACY:
                btc_type = BTC_ADDR_P2PKH;
                break;
            case ADDR_TYPE_SEGWIT_COMPAT:
                btc_type = BTC_ADDR_P2SH;
                break;
            case ADDR_TYPE_SEGWIT_NATIVE:
                btc_type = BTC_ADDR_P2WPKH;
                break;
            case ADDR_TYPE_TAPROOT:
                btc_type = BTC_ADDR_P2TR;
                break;
            default:
                btc_type = BTC_ADDR_P2WPKH;
            }

            if (btc_pubkey_to_address(addr_key.public_key, btc_type,
                                      network, address, address_len) != 0) {
                bip32_key_wipe(&addr_key);
                return -1;
            }
        }
        break;

    case CHAIN_ETHEREUM:
        {
            /* ETH needs uncompressed public key (65 bytes) */
            uint8_t uncompressed_pubkey[65];

            if (secp256k1_pubkey_create_uncompressed(addr_key.private_key,
                                                      uncompressed_pubkey) != 0) {
                bip32_key_wipe(&addr_key);
                return -1;
            }

            if (eth_pubkey_to_address(uncompressed_pubkey, address) != 0) {
                secure_wipe(uncompressed_pubkey, sizeof(uncompressed_pubkey));
                bip32_key_wipe(&addr_key);
                return -1;
            }

            secure_wipe(uncompressed_pubkey, sizeof(uncompressed_pubkey));
        }
        break;

    case CHAIN_DOGECOIN:
        {
            /* Dogecoin only supports P2PKH (legacy) addresses */
            if (doge_pubkey_to_address(addr_key.public_key, DOGE_ADDR_P2PKH,
                                       DOGE_MAINNET, address, address_len) != 0) {
                bip32_key_wipe(&addr_key);
                return -1;
            }
        }
        break;

    case CHAIN_XRP:
        {
            /* XRP uses secp256k1 by default (same as BTC) */
            if (xrp_pubkey_to_address(addr_key.public_key, XRP_KEY_SECP256K1,
                                      address, address_len) != 0) {
                bip32_key_wipe(&addr_key);
                return -1;
            }
        }
        break;

    case CHAIN_CARDANO:
        {
            /* Cardano uses Ed25519 and different key derivation
             * For enterprise addresses (no staking), we just need payment key
             * Note: Full Cardano support needs ada_master_key_from_seed
             * and proper Ed25519 derivation. This is a simplified version
             * that creates an enterprise address from the BIP32 pubkey hash. */

            /* Create enterprise address (no staking) using public key hash */
            /* addr_key.public_key is 33 bytes (compressed), skip prefix byte */
            if (ada_create_enterprise_address(addr_key.public_key + 1,
                                              ADA_MAINNET, address, address_len) != 0) {
                bip32_key_wipe(&addr_key);
                return -1;
            }
        }
        break;

    default:
        snprintf(address, address_len, "[Unsupported chain]");
        break;
    }

    bip32_key_wipe(&addr_key);
    account->next_external_index++;

    return 0;
}

void wallet_wipe(wallet_t *wallet)
{
    size_t i;

    if (wallet == NULL) {
        return;
    }

    /* Wipe seed */
    secure_wipe(wallet->seed, sizeof(wallet->seed));

    /* Wipe master key */
    bip32_key_wipe(&wallet->master_key);

    /* Wipe all account keys */
    for (i = 0; i < wallet->account_count; i++) {
        bip32_key_wipe(&wallet->accounts[i].account_key);
    }

    /* Clear structure */
    secure_wipe(wallet, sizeof(wallet_t));
}

const char *wallet_chain_name(chain_type_t chain)
{
    if (chain >= CHAIN_COUNT) {
        return "Unknown";
    }
    return chain_names[chain];
}

/**
 * Write uint32 in little-endian
 */
static void write_u32(uint8_t *buf, uint32_t val)
{
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

/**
 * Read uint32 in little-endian
 */
static uint32_t read_u32(const uint8_t *buf)
{
    return buf[0] | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

int wallet_serialize(const wallet_t *wallet, uint8_t *output, size_t *output_len)
{
    size_t offset = 0;
    size_t max_len;

    if (wallet == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    if (!wallet->is_initialized) {
        return -1;
    }

    max_len = *output_len;

    /* Format:
     * [4 bytes]  version
     * [4 bytes]  wallet_flags (passphrase, etc)
     * [64 bytes] seed
     * [4 bytes]  account_count
     * For each account:
     *   [4 bytes]  index
     *   [4 bytes]  chain
     *   [4 bytes]  addr_type
     *   [4 bytes]  account_flags (watch-only, etc)
     *   [64 bytes] label
     *   [4 bytes]  next_external_index
     *   [4 bytes]  next_internal_index
     *   [78 bytes] account_key (for watch-only accounts)
     *   Note: for non-watch-only accounts, account_key is re-derived from seed
     */

    /* Check buffer size (approximate) */
    size_t needed = 4 + 4 + 64 + 4 + wallet->account_count * (4 + 4 + 4 + 4 + 64 + 4 + 4 + 78);
    if (max_len < needed) {
        return -1;
    }

    /* Version */
    write_u32(output + offset, WALLET_FORMAT_VERSION);
    offset += 4;

    /* Wallet flags (passphrase, etc) */
    write_u32(output + offset, wallet->flags);
    offset += 4;

    /* Seed */
    memcpy(output + offset, wallet->seed, 64);
    offset += 64;

    /* Account count */
    write_u32(output + offset, (uint32_t)wallet->account_count);
    offset += 4;

    /* Accounts */
    for (size_t i = 0; i < wallet->account_count; i++) {
        const wallet_account_t *acc = &wallet->accounts[i];

        write_u32(output + offset, acc->index);
        offset += 4;

        write_u32(output + offset, (uint32_t)acc->chain);
        offset += 4;

        write_u32(output + offset, (uint32_t)acc->addr_type);
        offset += 4;

        write_u32(output + offset, acc->flags);
        offset += 4;

        memcpy(output + offset, acc->label, 64);
        offset += 64;

        write_u32(output + offset, acc->next_external_index);
        offset += 4;

        write_u32(output + offset, acc->next_internal_index);
        offset += 4;

        /* For watch-only accounts, store the account key */
        if (acc->flags & ACCOUNT_FLAG_WATCH_ONLY) {
            /* Serialize public key data: chain_code + public_key */
            memcpy(output + offset, acc->account_key.chain_code, 32);
            offset += 32;
            memcpy(output + offset, acc->account_key.public_key, 33);
            offset += 33;
            /* Padding to 78 bytes */
            memset(output + offset, 0, 13);
            offset += 13;
        } else {
            /* Placeholder for non-watch-only (key is re-derived) */
            memset(output + offset, 0, 78);
            offset += 78;
        }
    }

    *output_len = offset;
    return 0;
}

int wallet_deserialize(const uint8_t *data, size_t data_len, wallet_t *wallet)
{
    size_t offset = 0;
    uint32_t version;
    uint32_t account_count;

    if (data == NULL || wallet == NULL) {
        return -1;
    }

    /* Minimum size check */
    if (data_len < 4 + 4 + 64 + 4) {
        return -1;
    }

    /* Clear wallet */
    memset(wallet, 0, sizeof(wallet_t));

    /* Version */
    version = read_u32(data + offset);
    offset += 4;

    if (version != WALLET_FORMAT_VERSION) {
        return -1;  /* Unsupported version */
    }

    /* Wallet flags */
    wallet->flags = read_u32(data + offset);
    offset += 4;

    /* Seed */
    memcpy(wallet->seed, data + offset, 64);
    offset += 64;

    /* Derive master key from seed */
    if (bip32_master_key_from_seed(wallet->seed, &wallet->master_key) != 0) {
        secure_wipe(wallet->seed, sizeof(wallet->seed));
        return -1;
    }

    /* Account count */
    account_count = read_u32(data + offset);
    offset += 4;

    if (account_count > WALLET_MAX_ACCOUNTS) {
        wallet_wipe(wallet);
        return -1;
    }

    /* Accounts */
    for (uint32_t i = 0; i < account_count; i++) {
        if (offset + (4 + 4 + 4 + 4 + 64 + 4 + 4 + 78) > data_len) {
            wallet_wipe(wallet);
            return -1;
        }

        wallet_account_t acc_info;
        memset(&acc_info, 0, sizeof(acc_info));

        acc_info.index = read_u32(data + offset);
        offset += 4;

        acc_info.chain = (chain_type_t)read_u32(data + offset);
        offset += 4;

        acc_info.addr_type = (address_type_t)read_u32(data + offset);
        offset += 4;

        acc_info.flags = read_u32(data + offset);
        offset += 4;

        memcpy(acc_info.label, data + offset, 64);
        acc_info.label[63] = '\0';  /* Ensure null termination */
        offset += 64;

        acc_info.next_external_index = read_u32(data + offset);
        offset += 4;

        acc_info.next_internal_index = read_u32(data + offset);
        offset += 4;

        /* Read account key data (78 bytes) */
        uint8_t key_data[78];
        memcpy(key_data, data + offset, 78);
        offset += 78;

        int idx;
        if (acc_info.flags & ACCOUNT_FLAG_WATCH_ONLY) {
            /* Watch-only account: restore from stored key data */
            wallet_account_t *account = &wallet->accounts[wallet->account_count];
            memset(account, 0, sizeof(*account));

            account->index = (uint32_t)wallet->account_count;
            account->chain = acc_info.chain;
            account->addr_type = acc_info.addr_type;
            account->flags = acc_info.flags;
            memcpy(account->label, acc_info.label, sizeof(account->label) - 1);
            account->label[sizeof(account->label) - 1] = '\0';

            /* Restore key data */
            memcpy(account->account_key.chain_code, key_data, 32);
            memcpy(account->account_key.public_key, key_data + 32, 33);
            memset(account->account_key.private_key, 0, 32);

            account->next_external_index = acc_info.next_external_index;
            account->next_internal_index = acc_info.next_internal_index;

            wallet->account_count++;
            idx = (int)(wallet->account_count - 1);
        } else {
            /* Normal account: re-derive from seed */
            idx = wallet_add_account(wallet, acc_info.chain, acc_info.addr_type,
                                      acc_info.label[0] ? acc_info.label : NULL);
            if (idx < 0) {
                wallet_wipe(wallet);
                return -1;
            }

            /* Restore address indices */
            wallet->accounts[idx].next_external_index = acc_info.next_external_index;
            wallet->accounts[idx].next_internal_index = acc_info.next_internal_index;
        }
    }

    wallet->is_initialized = 1;
    return 0;
}

int wallet_save(const wallet_t *wallet, const char *pin)
{
    uint8_t *buffer = NULL;
    size_t buffer_len = WALLET_MAX_SERIALIZED_SIZE;
    int ret = -1;

    if (wallet == NULL || pin == NULL) {
        return -1;
    }

    /* Initialize storage if needed */
    if (storage_init() != STORAGE_OK) {
        return -1;
    }

    /* Allocate serialization buffer */
    buffer = malloc(buffer_len);
    if (buffer == NULL) {
        return -1;
    }

    /* Serialize wallet */
    if (wallet_serialize(wallet, buffer, &buffer_len) != 0) {
        goto cleanup;
    }

    /* Save to encrypted storage */
    if (storage_save_wallet(buffer, buffer_len, pin, strlen(pin)) != STORAGE_OK) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (buffer != NULL) {
        secure_wipe(buffer, WALLET_MAX_SERIALIZED_SIZE);
        free(buffer);
    }
    return ret;
}

int wallet_load(wallet_t *wallet, const char *pin)
{
    uint8_t *buffer = NULL;
    size_t buffer_len = WALLET_MAX_SERIALIZED_SIZE;
    int ret = -1;

    if (wallet == NULL || pin == NULL) {
        return -1;
    }

    /* Initialize storage if needed */
    if (storage_init() != STORAGE_OK) {
        return -1;
    }

    /* Check if wallet exists */
    if (!storage_wallet_exists()) {
        return -1;
    }

    /* Allocate buffer */
    buffer = malloc(buffer_len);
    if (buffer == NULL) {
        return -1;
    }

    /* Load from encrypted storage */
    int storage_ret = storage_load_wallet(buffer, &buffer_len, pin, strlen(pin));
    if (storage_ret != STORAGE_OK) {
        if (storage_ret == STORAGE_ERR_DECRYPT) {
            /* Wrong PIN */
            ret = -2;
        }
        goto cleanup;
    }

    /* Deserialize wallet */
    if (wallet_deserialize(buffer, buffer_len, wallet) != 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (buffer != NULL) {
        secure_wipe(buffer, WALLET_MAX_SERIALIZED_SIZE);
        free(buffer);
    }
    return ret;
}

/* ============================================================================
 * Watch-Only Account Support
 * ============================================================================ */

/* Extended public key version bytes */
#define XPUB_VERSION_MAINNET   0x0488B21E  /* xpub */
#define XPUB_VERSION_TESTNET   0x043587CF  /* tpub */
#define YPUB_VERSION_MAINNET   0x049D7CB2  /* ypub (P2SH-P2WPKH) */
#define YPUB_VERSION_TESTNET   0x044A5262  /* upub */
#define ZPUB_VERSION_MAINNET   0x04B24746  /* zpub (P2WPKH) */
#define ZPUB_VERSION_TESTNET   0x045F1CF6  /* vpub */

uint32_t wallet_get_xpub_version(chain_type_t chain, address_type_t addr_type)
{
    int is_testnet = (chain == CHAIN_BITCOIN_TESTNET);

    switch (addr_type) {
    case ADDR_TYPE_LEGACY:
        return is_testnet ? XPUB_VERSION_TESTNET : XPUB_VERSION_MAINNET;
    case ADDR_TYPE_SEGWIT_COMPAT:
        return is_testnet ? YPUB_VERSION_TESTNET : YPUB_VERSION_MAINNET;
    case ADDR_TYPE_SEGWIT_NATIVE:
    case ADDR_TYPE_TAPROOT:
        return is_testnet ? ZPUB_VERSION_TESTNET : ZPUB_VERSION_MAINNET;
    default:
        return XPUB_VERSION_MAINNET;
    }
}

int wallet_account_is_watch_only(const wallet_account_t *account)
{
    if (account == NULL) return 0;
    return (account->flags & ACCOUNT_FLAG_WATCH_ONLY) != 0;
}

int wallet_export_xpub(const wallet_account_t *account,
                       char *xpub, size_t xpub_len)
{
    if (account == NULL || xpub == NULL || xpub_len < 112) {
        return -1;
    }

    /* Get appropriate version for the account type */
    uint32_t version = wallet_get_xpub_version(account->chain, account->addr_type);

    /* Serialize the extended public key */
    if (bip32_serialize_key(&account->account_key, 0, version, xpub, xpub_len) != 0) {
        return -1;
    }

    return 0;
}

int wallet_add_watch_only(wallet_t *wallet, const char *xpub,
                          chain_type_t chain, const char *label)
{
    wallet_account_t *account;
    bip32_key_t key;

    if (wallet == NULL || xpub == NULL) {
        return -1;
    }

    if (wallet->account_count >= WALLET_MAX_ACCOUNTS) {
        return -1;
    }

    /* Parse the extended public key */
    uint32_t version;
    if (bip32_deserialize_key(xpub, &key, &version) != 0) {
        return -1;
    }

    /* Verify it's a public key (not private) */
    if (key.private_key[0] != 0 || key.private_key[31] != 0) {
        /* Check if any byte is non-zero - this is a private key */
        int is_private = 0;
        for (int i = 0; i < 32; i++) {
            if (key.private_key[i] != 0) {
                is_private = 1;
                break;
            }
        }
        if (is_private) {
            /* Wipe the private key data and fail */
            secure_wipe(&key, sizeof(key));
            return -1;
        }
    }

    /* Determine address type from version */
    address_type_t addr_type;
    switch (version) {
    case XPUB_VERSION_MAINNET:
    case XPUB_VERSION_TESTNET:
        addr_type = ADDR_TYPE_LEGACY;
        break;
    case YPUB_VERSION_MAINNET:
    case YPUB_VERSION_TESTNET:
        addr_type = ADDR_TYPE_SEGWIT_COMPAT;
        break;
    case ZPUB_VERSION_MAINNET:
    case ZPUB_VERSION_TESTNET:
        addr_type = ADDR_TYPE_SEGWIT_NATIVE;
        break;
    default:
        addr_type = ADDR_TYPE_LEGACY;
    }

    /* Create the account */
    account = &wallet->accounts[wallet->account_count];
    memset(account, 0, sizeof(*account));

    account->index = (uint32_t)wallet->account_count;
    account->chain = chain;
    account->addr_type = addr_type;
    account->flags = ACCOUNT_FLAG_WATCH_ONLY;

    if (label != NULL) {
        strncpy(account->label, label, sizeof(account->label) - 1);
        account->label[sizeof(account->label) - 1] = '\0';
    } else {
        snprintf(account->label, sizeof(account->label), "Watch-Only #%u", account->index);
    }

    /* Copy the key (only public key data is valid) */
    memcpy(&account->account_key, &key, sizeof(key));

    account->next_external_index = 0;
    account->next_internal_index = 0;

    wallet->account_count++;

    return (int)(wallet->account_count - 1);
}

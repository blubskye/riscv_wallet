/*
 * Solana Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "solana.h"
#include "../util/base58.h"
#include "../security/memory.h"

/* System Program ID: 11111111111111111111111111111111 */
const uint8_t SOL_SYSTEM_PROGRAM_ID[SOL_PUBKEY_SIZE] = {0};

/* Token Program ID: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA */
const uint8_t SOL_TOKEN_PROGRAM_ID[SOL_PUBKEY_SIZE] = {
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9
};

/* SLIP-0010 ed25519 master key derivation */
static int slip10_derive_master(const uint8_t *seed, size_t seed_len,
                                 uint8_t key[32], uint8_t chain_code[32])
{
    uint8_t hmac_out[64];

    /* HMAC-SHA512("ed25519 seed", seed) */
    crypto_auth_hmacsha512_state state;
    crypto_auth_hmacsha512_init(&state, (const uint8_t *)"ed25519 seed", 12);
    crypto_auth_hmacsha512_update(&state, seed, seed_len);
    crypto_auth_hmacsha512_final(&state, hmac_out);

    memcpy(key, hmac_out, 32);
    memcpy(chain_code, hmac_out + 32, 32);

    sodium_memzero(hmac_out, sizeof(hmac_out));
    return 0;
}

/* SLIP-0010 ed25519 child key derivation (hardened only) */
static int slip10_derive_child(const uint8_t parent_key[32],
                                const uint8_t parent_chain[32],
                                uint32_t index,
                                uint8_t child_key[32],
                                uint8_t child_chain[32])
{
    uint8_t data[37];
    uint8_t hmac_out[64];

    /* ed25519 only supports hardened derivation */
    if ((index & 0x80000000) == 0) {
        return -1;  /* Must be hardened */
    }

    /* Data = 0x00 || parent_key || index (big-endian) */
    data[0] = 0x00;
    memcpy(data + 1, parent_key, 32);
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    /* HMAC-SHA512(parent_chain_code, data) */
    crypto_auth_hmacsha512_state state;
    crypto_auth_hmacsha512_init(&state, parent_chain, 32);
    crypto_auth_hmacsha512_update(&state, data, sizeof(data));
    crypto_auth_hmacsha512_final(&state, hmac_out);

    memcpy(child_key, hmac_out, 32);
    memcpy(child_chain, hmac_out + 32, 32);

    sodium_memzero(data, sizeof(data));
    sodium_memzero(hmac_out, sizeof(hmac_out));
    return 0;
}

int sol_derive_keypair(const uint8_t seed[64], uint32_t account,
                       uint32_t change, sol_keypair_t *keypair)
{
    uint8_t key[32], chain_code[32];
    uint8_t child_key[32], child_chain[32];
    int ret = -1;

    if (!seed || !keypair) {
        return -1;
    }

    /* Derive master key from seed using SLIP-0010 */
    if (slip10_derive_master(seed, 64, key, chain_code) != 0) {
        goto cleanup;
    }

    /* Derive path: m/44'/501'/account'/change' */
    /* Purpose: 44' */
    if (slip10_derive_child(key, chain_code, 0x80000000 | 44,
                            child_key, child_chain) != 0) {
        goto cleanup;
    }
    memcpy(key, child_key, 32);
    memcpy(chain_code, child_chain, 32);

    /* Coin type: 501' */
    if (slip10_derive_child(key, chain_code, 0x80000000 | 501,
                            child_key, child_chain) != 0) {
        goto cleanup;
    }
    memcpy(key, child_key, 32);
    memcpy(chain_code, child_chain, 32);

    /* Account: account' */
    if (slip10_derive_child(key, chain_code, 0x80000000 | account,
                            child_key, child_chain) != 0) {
        goto cleanup;
    }
    memcpy(key, child_key, 32);
    memcpy(chain_code, child_chain, 32);

    /* Change: change' (Solana uses hardened for all levels) */
    if (slip10_derive_child(key, chain_code, 0x80000000 | change,
                            child_key, child_chain) != 0) {
        goto cleanup;
    }

    /* Store seed (32-byte private key seed) */
    memcpy(keypair->seed, child_key, 32);

    /* Generate ed25519 keypair from seed */
    if (crypto_sign_seed_keypair(keypair->public_key, keypair->secret_key,
                                  keypair->seed) != 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    sodium_memzero(key, sizeof(key));
    sodium_memzero(chain_code, sizeof(chain_code));
    sodium_memzero(child_key, sizeof(child_key));
    sodium_memzero(child_chain, sizeof(child_chain));
    return ret;
}

int sol_pubkey_to_address(const uint8_t pubkey[SOL_PUBKEY_SIZE],
                          char *address, size_t address_len)
{
    if (!pubkey || !address || address_len < SOL_ADDR_MAX) {
        return -1;
    }

    /* Solana addresses are simply base58-encoded public keys */
    int len = base58_encode(pubkey, SOL_PUBKEY_SIZE, address, address_len);
    if (len < 0) {
        return -1;
    }

    return 0;
}

int sol_validate_address(const char *address)
{
    uint8_t decoded[SOL_PUBKEY_SIZE + 4];
    size_t decoded_len = sizeof(decoded);

    if (!address) {
        return -1;
    }

    /* Check length (32-44 characters typical for 32 bytes) */
    size_t len = strlen(address);
    if (len < 32 || len > 44) {
        return -1;
    }

    /* Attempt to decode */
    if (base58_decode(address, decoded, &decoded_len) != 0) {
        return -1;
    }

    /* Must decode to exactly 32 bytes */
    if (decoded_len != SOL_PUBKEY_SIZE) {
        return -1;
    }

    return 0;
}

int sol_address_to_pubkey(const char *address, uint8_t pubkey[SOL_PUBKEY_SIZE])
{
    size_t decoded_len = SOL_PUBKEY_SIZE;

    if (!address || !pubkey) {
        return -1;
    }

    if (base58_decode(address, pubkey, &decoded_len) != 0) {
        return -1;
    }

    if (decoded_len != SOL_PUBKEY_SIZE) {
        return -1;
    }

    return 0;
}

int sol_sign_message(const sol_keypair_t *keypair,
                     const uint8_t *message, size_t message_len,
                     uint8_t signature[SOL_SIGNATURE_SIZE])
{
    unsigned long long sig_len;

    if (!keypair || !message || !signature) {
        return -1;
    }

    /* Sign using libsodium ed25519 */
    if (crypto_sign_detached(signature, &sig_len, message, message_len,
                             keypair->secret_key) != 0) {
        return -1;
    }

    return 0;
}

int sol_verify_signature(const uint8_t pubkey[SOL_PUBKEY_SIZE],
                         const uint8_t *message, size_t message_len,
                         const uint8_t signature[SOL_SIGNATURE_SIZE])
{
    if (!pubkey || !message || !signature) {
        return -1;
    }

    if (crypto_sign_verify_detached(signature, message, message_len, pubkey) != 0) {
        return -1;
    }

    return 0;
}

int sol_transfer_instruction(const uint8_t from_pubkey[SOL_PUBKEY_SIZE],
                             const uint8_t to_pubkey[SOL_PUBKEY_SIZE],
                             uint64_t lamports,
                             sol_instruction_t *instruction)
{
    if (!from_pubkey || !to_pubkey || !instruction) {
        return -1;
    }

    memset(instruction, 0, sizeof(*instruction));

    /* System Program ID */
    memcpy(instruction->program_id, SOL_SYSTEM_PROGRAM_ID, SOL_PUBKEY_SIZE);

    /* Accounts: from (signer, writable), to (writable) */
    memcpy(instruction->accounts[0].pubkey, from_pubkey, SOL_PUBKEY_SIZE);
    instruction->accounts[0].is_signer = 1;
    instruction->accounts[0].is_writable = 1;

    memcpy(instruction->accounts[1].pubkey, to_pubkey, SOL_PUBKEY_SIZE);
    instruction->accounts[1].is_signer = 0;
    instruction->accounts[1].is_writable = 1;

    instruction->account_count = 2;

    /* Transfer instruction data:
     * - 4 bytes: instruction index (2 = Transfer, little-endian)
     * - 8 bytes: lamports (little-endian)
     */
    static uint8_t transfer_data[12];
    transfer_data[0] = 2;  /* Transfer instruction */
    transfer_data[1] = 0;
    transfer_data[2] = 0;
    transfer_data[3] = 0;

    /* Lamports in little-endian */
    transfer_data[4] = lamports & 0xFF;
    transfer_data[5] = (lamports >> 8) & 0xFF;
    transfer_data[6] = (lamports >> 16) & 0xFF;
    transfer_data[7] = (lamports >> 24) & 0xFF;
    transfer_data[8] = (lamports >> 32) & 0xFF;
    transfer_data[9] = (lamports >> 40) & 0xFF;
    transfer_data[10] = (lamports >> 48) & 0xFF;
    transfer_data[11] = (lamports >> 56) & 0xFF;

    instruction->data = transfer_data;
    instruction->data_len = sizeof(transfer_data);

    return 0;
}

int sol_serialize_message(const sol_tx_t *tx, uint8_t *output, size_t *output_len)
{
    size_t offset = 0;
    size_t max_len;

    if (!tx || !output || !output_len) {
        return -1;
    }

    max_len = *output_len;

    /* Simplified message format:
     * This is a basic implementation - real Solana transactions
     * have a more complex compact message format
     */

    /* Header: num_required_signatures, num_readonly_signed, num_readonly_unsigned */
    if (offset + 3 > max_len) return -1;
    output[offset++] = 1;  /* num_required_signatures */
    output[offset++] = 0;  /* num_readonly_signed */
    output[offset++] = 1;  /* num_readonly_unsigned (system program) */

    /* Account keys compact array */
    /* For simplicity, we include: fee_payer, instruction accounts, programs */
    size_t num_accounts = 0;

    /* Count unique accounts across all instructions + fee payer */
    /* (Simplified: just fee payer + system program for transfer) */
    if (offset + 1 > max_len) return -1;

    /* For a simple transfer: fee_payer, recipient, system_program = 3 accounts */
    if (tx->instruction_count > 0) {
        num_accounts = tx->instructions[0].account_count + 1;  /* +1 for program */
    }
    output[offset++] = (uint8_t)num_accounts;

    /* Fee payer first */
    if (offset + SOL_PUBKEY_SIZE > max_len) return -1;
    memcpy(output + offset, tx->fee_payer, SOL_PUBKEY_SIZE);
    offset += SOL_PUBKEY_SIZE;

    /* Instruction accounts (excluding duplicates with fee payer) */
    for (size_t i = 0; i < tx->instruction_count; i++) {
        for (size_t j = 0; j < tx->instructions[i].account_count; j++) {
            /* Skip if same as fee payer */
            if (memcmp(tx->instructions[i].accounts[j].pubkey, tx->fee_payer,
                       SOL_PUBKEY_SIZE) == 0) {
                continue;
            }
            if (offset + SOL_PUBKEY_SIZE > max_len) return -1;
            memcpy(output + offset, tx->instructions[i].accounts[j].pubkey,
                   SOL_PUBKEY_SIZE);
            offset += SOL_PUBKEY_SIZE;
        }

        /* Program ID */
        if (offset + SOL_PUBKEY_SIZE > max_len) return -1;
        memcpy(output + offset, tx->instructions[i].program_id, SOL_PUBKEY_SIZE);
        offset += SOL_PUBKEY_SIZE;
    }

    /* Recent blockhash */
    if (offset + SOL_PUBKEY_SIZE > max_len) return -1;
    memcpy(output + offset, tx->recent_blockhash, SOL_PUBKEY_SIZE);
    offset += SOL_PUBKEY_SIZE;

    /* Instructions compact array */
    if (offset + 1 > max_len) return -1;
    output[offset++] = (uint8_t)tx->instruction_count;

    for (size_t i = 0; i < tx->instruction_count; i++) {
        const sol_instruction_t *instr = &tx->instructions[i];

        /* Program ID index (last account for system program) */
        if (offset + 1 > max_len) return -1;
        output[offset++] = (uint8_t)(num_accounts - 1);

        /* Account indices compact array */
        if (offset + 1 > max_len) return -1;
        output[offset++] = (uint8_t)instr->account_count;

        for (size_t j = 0; j < instr->account_count; j++) {
            if (offset + 1 > max_len) return -1;
            /* Account index (0 = fee payer, 1 = recipient for transfer) */
            output[offset++] = (uint8_t)j;
        }

        /* Instruction data compact array */
        if (offset + 1 > max_len) return -1;
        output[offset++] = (uint8_t)instr->data_len;

        if (offset + instr->data_len > max_len) return -1;
        memcpy(output + offset, instr->data, instr->data_len);
        offset += instr->data_len;
    }

    *output_len = offset;
    return 0;
}

int sol_sign_tx(sol_tx_t *tx, const sol_keypair_t *keypairs, size_t keypair_count,
                uint8_t *signed_tx, size_t *signed_tx_len)
{
    uint8_t message[1024];
    size_t message_len = sizeof(message);
    uint8_t signature[SOL_SIGNATURE_SIZE];
    size_t offset = 0;

    if (!tx || !keypairs || keypair_count == 0 || !signed_tx || !signed_tx_len) {
        return -1;
    }

    /* Serialize message */
    if (sol_serialize_message(tx, message, &message_len) != 0) {
        return -1;
    }

    /* Signed transaction format:
     * - Compact array of signatures
     * - Message
     */

    /* Number of signatures */
    if (offset + 1 > *signed_tx_len) return -1;
    signed_tx[offset++] = (uint8_t)keypair_count;

    /* Generate signatures */
    for (size_t i = 0; i < keypair_count; i++) {
        if (sol_sign_message(&keypairs[i], message, message_len, signature) != 0) {
            return -1;
        }

        if (offset + SOL_SIGNATURE_SIZE > *signed_tx_len) return -1;
        memcpy(signed_tx + offset, signature, SOL_SIGNATURE_SIZE);
        offset += SOL_SIGNATURE_SIZE;
    }

    /* Append message */
    if (offset + message_len > *signed_tx_len) return -1;
    memcpy(signed_tx + offset, message, message_len);
    offset += message_len;

    *signed_tx_len = offset;

    sodium_memzero(signature, sizeof(signature));
    return 0;
}

int sol_get_derivation_path(uint32_t account, uint32_t change,
                            char *path, size_t path_len)
{
    int ret;

    if (!path || path_len < 24) {
        return -1;
    }

    /* Solana uses: m/44'/501'/account'/change' */
    ret = snprintf(path, path_len, "m/44'/501'/%u'/%u'", account, change);
    if (ret < 0 || (size_t)ret >= path_len) {
        return -1;
    }

    return 0;
}

int sol_format_amount(uint64_t lamports, char *output, size_t output_len)
{
    uint64_t sol_whole = lamports / SOL_LAMPORTS_PER_SOL;
    uint64_t sol_frac = lamports % SOL_LAMPORTS_PER_SOL;
    int ret;

    if (!output || output_len < 24) {
        return -1;
    }

    ret = snprintf(output, output_len, "%lu.%09lu SOL",
                   (unsigned long)sol_whole, (unsigned long)sol_frac);
    if (ret < 0 || (size_t)ret >= output_len) {
        return -1;
    }

    return 0;
}

void sol_keypair_wipe(sol_keypair_t *keypair)
{
    if (keypair) {
        sodium_memzero(keypair, sizeof(*keypair));
    }
}

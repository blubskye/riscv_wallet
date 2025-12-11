/*
 * Bitcoin Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "bitcoin.h"
#include "../crypto/ripemd160.h"
#include "../crypto/secp256k1.h"
#include "../util/base58.h"
#include "../util/bech32.h"
#include "../util/hex.h"
#include "../security/memory.h"
#include <stdio.h>
#include <string.h>
#include <sodium.h>

/* PSBT magic bytes: "psbt" followed by 0xff separator */
static const uint8_t PSBT_MAGIC[5] = {0x70, 0x73, 0x62, 0x74, 0xff};

/* PSBT global types */
#define PSBT_GLOBAL_UNSIGNED_TX  0x00

/* PSBT input types */
#define PSBT_IN_NON_WITNESS_UTXO 0x00
#define PSBT_IN_WITNESS_UTXO     0x01
#define PSBT_IN_PARTIAL_SIG      0x02
#define PSBT_IN_SIGHASH_TYPE     0x03
#define PSBT_IN_REDEEM_SCRIPT    0x04
#define PSBT_IN_WITNESS_SCRIPT   0x05
#define PSBT_IN_BIP32_DERIVATION 0x06
#define PSBT_IN_FINAL_SCRIPTSIG  0x07
#define PSBT_IN_FINAL_SCRIPTWITNESS 0x08

/* PSBT output types */
#define PSBT_OUT_REDEEM_SCRIPT   0x00
#define PSBT_OUT_WITNESS_SCRIPT  0x01
#define PSBT_OUT_BIP32_DERIVATION 0x02

/* Sighash types */
#define SIGHASH_ALL          0x01
#define SIGHASH_NONE         0x02
#define SIGHASH_SINGLE       0x03
#define SIGHASH_ANYONECANPAY 0x80

/* Network version bytes */
#define P2PKH_MAINNET  0x00
#define P2PKH_TESTNET  0x6F
#define P2SH_MAINNET   0x05
#define P2SH_TESTNET   0xC4

/* Bech32 HRP (Human Readable Part) */
#define BECH32_MAINNET "bc"
#define BECH32_TESTNET "tb"

/**
 * BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
 */
static void tagged_hash(const char *tag, const uint8_t *msg, size_t msg_len, uint8_t hash[32])
{
    uint8_t tag_hash[32];
    crypto_hash_sha256_state state;

    /* Hash the tag */
    crypto_hash_sha256((unsigned char *)tag_hash, (const unsigned char *)tag, strlen(tag));

    /* SHA256(tag_hash || tag_hash || msg) */
    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state, tag_hash, 32);
    crypto_hash_sha256_update(&state, tag_hash, 32);
    crypto_hash_sha256_update(&state, msg, msg_len);
    crypto_hash_sha256_final(&state, hash);
}

/**
 * BIP-341 Taproot key tweaking
 * Computes the tweaked public key for a key-path-only output.
 *
 * tweaked_pubkey = pubkey + hash_TapTweak(pubkey) * G
 *
 * For key-path only (no script tree), we use:
 * t = hash_TapTweak(pubkey_x)
 * Q = P + t*G
 *
 * Returns the x-only tweaked public key (32 bytes)
 */
static int taproot_tweak_pubkey(const uint8_t pubkey[33], uint8_t tweaked_x[32])
{
    uint8_t tweak[32];
    uint8_t tweaked_pubkey[33];

    /* Extract x-only coordinate */
    uint8_t x_only[32];
    memcpy(x_only, pubkey + 1, 32);

    /* Compute tweak: t = hash_TapTweak(pubkey_x) */
    tagged_hash("TapTweak", x_only, 32, tweak);

    /* Copy pubkey and apply tweak: Q = P + t*G */
    memcpy(tweaked_pubkey, pubkey, 33);

    if (secp256k1_pubkey_tweak_add(tweaked_pubkey, tweak) != 0) {
        return -1;
    }

    /* Return x-only (skip prefix byte) */
    memcpy(tweaked_x, tweaked_pubkey + 1, 32);

    return 0;
}

/**
 * Read a Bitcoin-style compact size (varint)
 * Returns bytes consumed, or -1 on error
 */
static int read_compact_size(const uint8_t *data, size_t len, uint64_t *value)
{
    if (len < 1) return -1;

    if (data[0] < 0xFD) {
        *value = data[0];
        return 1;
    } else if (data[0] == 0xFD) {
        if (len < 3) return -1;
        *value = data[1] | ((uint64_t)data[2] << 8);
        return 3;
    } else if (data[0] == 0xFE) {
        if (len < 5) return -1;
        *value = data[1] | ((uint64_t)data[2] << 8) |
                 ((uint64_t)data[3] << 16) | ((uint64_t)data[4] << 24);
        return 5;
    } else {
        if (len < 9) return -1;
        *value = data[1] | ((uint64_t)data[2] << 8) |
                 ((uint64_t)data[3] << 16) | ((uint64_t)data[4] << 24) |
                 ((uint64_t)data[5] << 32) | ((uint64_t)data[6] << 40) |
                 ((uint64_t)data[7] << 48) | ((uint64_t)data[8] << 56);
        return 9;
    }
}

/**
 * Write a Bitcoin-style compact size (varint)
 * Returns bytes written, or -1 on error
 */
static int write_compact_size(uint64_t value, uint8_t *output, size_t output_len)
{
    if (value < 0xFD) {
        if (output_len < 1) return -1;
        output[0] = (uint8_t)value;
        return 1;
    } else if (value <= 0xFFFF) {
        if (output_len < 3) return -1;
        output[0] = 0xFD;
        output[1] = value & 0xFF;
        output[2] = (value >> 8) & 0xFF;
        return 3;
    } else if (value <= 0xFFFFFFFF) {
        if (output_len < 5) return -1;
        output[0] = 0xFE;
        output[1] = value & 0xFF;
        output[2] = (value >> 8) & 0xFF;
        output[3] = (value >> 16) & 0xFF;
        output[4] = (value >> 24) & 0xFF;
        return 5;
    } else {
        if (output_len < 9) return -1;
        output[0] = 0xFF;
        for (int i = 0; i < 8; i++) {
            output[1 + i] = (value >> (i * 8)) & 0xFF;
        }
        return 9;
    }
}

/**
 * Read little-endian uint32
 */
static uint32_t read_le32(const uint8_t *data)
{
    return data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

/**
 * Read little-endian uint64
 */
static uint64_t read_le64(const uint8_t *data)
{
    return data[0] | ((uint64_t)data[1] << 8) |
           ((uint64_t)data[2] << 16) | ((uint64_t)data[3] << 24) |
           ((uint64_t)data[4] << 32) | ((uint64_t)data[5] << 40) |
           ((uint64_t)data[6] << 48) | ((uint64_t)data[7] << 56);
}

/**
 * Write little-endian uint32
 */
static void write_le32(uint8_t *data, uint32_t value)
{
    data[0] = value & 0xFF;
    data[1] = (value >> 8) & 0xFF;
    data[2] = (value >> 16) & 0xFF;
    data[3] = (value >> 24) & 0xFF;
}

/**
 * Write little-endian uint64
 */
static void write_le64(uint8_t *data, uint64_t value)
{
    for (int i = 0; i < 8; i++) {
        data[i] = (value >> (i * 8)) & 0xFF;
    }
}

/**
 * Parse unsigned transaction from raw bytes
 */
static int parse_raw_tx(const uint8_t *data, size_t len, btc_tx_t *tx)
{
    size_t offset = 0;
    uint64_t count;
    int consumed;

    if (len < 10) return -1;  /* Minimum tx size */

    /* Version (4 bytes) */
    tx->version = read_le32(data + offset);
    offset += 4;

    /* Check for segwit marker */
    int is_segwit = 0;
    if (data[offset] == 0x00 && data[offset + 1] == 0x01) {
        is_segwit = 1;
        offset += 2;
    }

    /* Input count */
    consumed = read_compact_size(data + offset, len - offset, &count);
    if (consumed < 0 || count > BTC_MAX_INPUTS) return -1;
    tx->input_count = (size_t)count;
    offset += consumed;

    /* Inputs */
    for (size_t i = 0; i < tx->input_count; i++) {
        if (offset + 36 > len) return -1;

        /* Previous txid (reversed) */
        for (int j = 0; j < 32; j++) {
            tx->inputs[i].prev_txid[31 - j] = data[offset + j];
        }
        offset += 32;

        /* Previous output index */
        tx->inputs[i].prev_index = read_le32(data + offset);
        offset += 4;

        /* Script sig (skip for unsigned) */
        consumed = read_compact_size(data + offset, len - offset, &count);
        if (consumed < 0) return -1;
        offset += consumed + count;

        /* Sequence */
        if (offset + 4 > len) return -1;
        offset += 4;
    }

    /* Output count */
    consumed = read_compact_size(data + offset, len - offset, &count);
    if (consumed < 0 || count > BTC_MAX_OUTPUTS) return -1;
    tx->output_count = (size_t)count;
    offset += consumed;

    /* Outputs */
    for (size_t i = 0; i < tx->output_count; i++) {
        if (offset + 8 > len) return -1;

        /* Amount */
        tx->outputs[i].amount = read_le64(data + offset);
        offset += 8;

        /* Script pubkey */
        consumed = read_compact_size(data + offset, len - offset, &count);
        if (consumed < 0 || count > sizeof(tx->outputs[i].script_pubkey)) return -1;
        offset += consumed;

        if (offset + count > len) return -1;
        memcpy(tx->outputs[i].script_pubkey, data + offset, count);
        tx->outputs[i].script_pubkey_len = count;
        offset += count;
    }

    /* Skip witness data if segwit */
    if (is_segwit) {
        for (size_t i = 0; i < tx->input_count; i++) {
            consumed = read_compact_size(data + offset, len - offset, &count);
            if (consumed < 0) return -1;
            offset += consumed;

            for (uint64_t j = 0; j < count; j++) {
                uint64_t witness_len;
                consumed = read_compact_size(data + offset, len - offset, &witness_len);
                if (consumed < 0) return -1;
                offset += consumed + witness_len;
            }
        }
    }

    /* Locktime */
    if (offset + 4 > len) return -1;
    tx->locktime = read_le32(data + offset);

    return 0;
}

int btc_pubkey_to_address(const uint8_t pubkey[33], btc_addr_type_t addr_type,
                          btc_network_t network, char *address, size_t address_len)
{
    uint8_t pubkey_hash[RIPEMD160_DIGEST_LENGTH];
    uint8_t versioned_hash[21];  /* 1 byte version + 20 bytes hash */

    if (pubkey == NULL || address == NULL) {
        return -1;
    }

    /* HASH160(pubkey) = RIPEMD160(SHA256(pubkey)) */
    hash160(pubkey, 33, pubkey_hash);

    switch (addr_type) {
    case BTC_ADDR_P2PKH:
        /* Legacy address: version + HASH160 */
        versioned_hash[0] = (network == BTC_MAINNET) ? P2PKH_MAINNET : P2PKH_TESTNET;
        memcpy(versioned_hash + 1, pubkey_hash, 20);

        if (base58check_encode(versioned_hash, 21, address, address_len) < 0) {
            return -1;
        }
        break;

    case BTC_ADDR_P2SH:
        /* P2SH-wrapped SegWit */
        /* Script: OP_0 <20-byte-key-hash> */
        {
            uint8_t redeem_script[22];
            uint8_t script_hash[RIPEMD160_DIGEST_LENGTH];

            redeem_script[0] = 0x00;  /* OP_0 */
            redeem_script[1] = 0x14;  /* Push 20 bytes */
            memcpy(redeem_script + 2, pubkey_hash, 20);

            /* HASH160 of redeem script */
            hash160(redeem_script, 22, script_hash);

            versioned_hash[0] = (network == BTC_MAINNET) ? P2SH_MAINNET : P2SH_TESTNET;
            memcpy(versioned_hash + 1, script_hash, 20);

            if (base58check_encode(versioned_hash, 21, address, address_len) < 0) {
                return -1;
            }
        }
        break;

    case BTC_ADDR_P2WPKH:
        /* Native SegWit (bech32) - witness version 0, 20-byte pubkey hash */
        {
            const char *hrp = (network == BTC_MAINNET) ? BECH32_MAINNET : BECH32_TESTNET;

            if (bech32_encode_segwit(hrp, 0, pubkey_hash, 20,
                                     address, address_len) < 0) {
                return -1;
            }
        }
        break;

    case BTC_ADDR_P2TR:
        /* Taproot (bech32m) - witness version 1, 32-byte tweaked pubkey */
        /* BIP-341: Q = P + hash_TapTweak(P) * G */
        {
            const char *hrp = (network == BTC_MAINNET) ? BECH32_MAINNET : BECH32_TESTNET;
            uint8_t tweaked_pubkey[32];

            /* Apply BIP-341 key tweaking */
            if (taproot_tweak_pubkey(pubkey, tweaked_pubkey) != 0) {
                return -1;
            }

            if (bech32_encode_segwit(hrp, 1, tweaked_pubkey, 32,
                                     address, address_len) < 0) {
                return -1;
            }
        }
        break;

    default:
        return -1;
    }

    return 0;
}

int btc_parse_psbt(const uint8_t *psbt_data, size_t psbt_len, btc_tx_t *tx)
{
    size_t offset = 0;
    uint64_t key_len, value_len;
    int consumed;

    if (psbt_data == NULL || tx == NULL) {
        return -1;
    }

    memset(tx, 0, sizeof(btc_tx_t));

    /* Verify magic bytes */
    if (psbt_len < 5 || memcmp(psbt_data, PSBT_MAGIC, 5) != 0) {
        return -1;
    }
    offset = 5;

    /* Parse global map */
    while (offset < psbt_len) {
        /* Key length */
        consumed = read_compact_size(psbt_data + offset, psbt_len - offset, &key_len);
        if (consumed < 0) return -1;
        offset += consumed;

        /* Separator (key_len == 0) */
        if (key_len == 0) break;

        if (offset + key_len > psbt_len) return -1;

        uint8_t key_type = psbt_data[offset];
        offset += key_len;

        /* Value length */
        consumed = read_compact_size(psbt_data + offset, psbt_len - offset, &value_len);
        if (consumed < 0) return -1;
        offset += consumed;

        if (offset + value_len > psbt_len) return -1;

        /* Handle unsigned tx */
        if (key_type == PSBT_GLOBAL_UNSIGNED_TX) {
            if (parse_raw_tx(psbt_data + offset, value_len, tx) != 0) {
                return -1;
            }
        }

        offset += value_len;
    }

    /* Parse input maps */
    for (size_t i = 0; i < tx->input_count && offset < psbt_len; i++) {
        while (offset < psbt_len) {
            consumed = read_compact_size(psbt_data + offset, psbt_len - offset, &key_len);
            if (consumed < 0) return -1;
            offset += consumed;

            /* Separator */
            if (key_len == 0) break;

            if (offset + key_len > psbt_len) return -1;

            uint8_t key_type = psbt_data[offset];
            offset += key_len;

            consumed = read_compact_size(psbt_data + offset, psbt_len - offset, &value_len);
            if (consumed < 0) return -1;
            offset += consumed;

            if (offset + value_len > psbt_len) return -1;

            /* Handle witness UTXO (for segwit inputs) */
            if (key_type == PSBT_IN_WITNESS_UTXO && value_len >= 8) {
                tx->inputs[i].amount = read_le64(psbt_data + offset);

                /* Parse script pubkey */
                size_t script_offset = 8;
                uint64_t script_len;
                int sc = read_compact_size(psbt_data + offset + script_offset,
                                           value_len - script_offset, &script_len);
                if (sc > 0 && script_len <= sizeof(tx->inputs[i].script_pubkey)) {
                    script_offset += sc;
                    if (script_offset + script_len <= value_len) {
                        memcpy(tx->inputs[i].script_pubkey,
                               psbt_data + offset + script_offset, script_len);
                        tx->inputs[i].script_pubkey_len = script_len;
                    }
                }
            }

            offset += value_len;
        }
    }

    /* Parse output maps (skip for now) */
    for (size_t i = 0; i < tx->output_count && offset < psbt_len; i++) {
        while (offset < psbt_len) {
            consumed = read_compact_size(psbt_data + offset, psbt_len - offset, &key_len);
            if (consumed < 0) return -1;
            offset += consumed;

            if (key_len == 0) break;

            if (offset + key_len > psbt_len) return -1;
            offset += key_len;

            consumed = read_compact_size(psbt_data + offset, psbt_len - offset, &value_len);
            if (consumed < 0) return -1;
            offset += consumed;

            if (offset + value_len > psbt_len) return -1;
            offset += value_len;
        }
    }

    return 0;
}

/**
 * Create BIP-143 sighash for SegWit inputs
 */
static int create_segwit_sighash(const btc_tx_t *tx, size_t input_idx,
                                  uint32_t sighash_type, uint8_t hash[32])
{
    crypto_hash_sha256_state state;
    uint8_t temp[32];
    uint8_t double_hash[32];

    /* hashPrevouts */
    crypto_hash_sha256_init(&state);
    for (size_t i = 0; i < tx->input_count; i++) {
        /* txid in internal byte order (reversed for display) */
        uint8_t txid_le[32];
        for (int j = 0; j < 32; j++) {
            txid_le[j] = tx->inputs[i].prev_txid[31 - j];
        }
        crypto_hash_sha256_update(&state, txid_le, 32);
        uint8_t idx[4];
        write_le32(idx, tx->inputs[i].prev_index);
        crypto_hash_sha256_update(&state, idx, 4);
    }
    crypto_hash_sha256_final(&state, temp);
    crypto_hash_sha256(double_hash, temp, 32);

    uint8_t hash_prevouts[32];
    memcpy(hash_prevouts, double_hash, 32);

    /* hashSequence */
    crypto_hash_sha256_init(&state);
    for (size_t i = 0; i < tx->input_count; i++) {
        uint8_t seq[4] = {0xFF, 0xFF, 0xFF, 0xFF};  /* Default sequence */
        crypto_hash_sha256_update(&state, seq, 4);
    }
    crypto_hash_sha256_final(&state, temp);
    crypto_hash_sha256(double_hash, temp, 32);

    uint8_t hash_sequence[32];
    memcpy(hash_sequence, double_hash, 32);

    /* hashOutputs */
    crypto_hash_sha256_init(&state);
    for (size_t i = 0; i < tx->output_count; i++) {
        uint8_t amount[8];
        write_le64(amount, tx->outputs[i].amount);
        crypto_hash_sha256_update(&state, amount, 8);

        uint8_t script_len = (uint8_t)tx->outputs[i].script_pubkey_len;
        crypto_hash_sha256_update(&state, &script_len, 1);
        crypto_hash_sha256_update(&state, tx->outputs[i].script_pubkey,
                                   tx->outputs[i].script_pubkey_len);
    }
    crypto_hash_sha256_final(&state, temp);
    crypto_hash_sha256(double_hash, temp, 32);

    uint8_t hash_outputs[32];
    memcpy(hash_outputs, double_hash, 32);

    /* Build preimage */
    crypto_hash_sha256_init(&state);

    /* nVersion */
    uint8_t version[4];
    write_le32(version, tx->version);
    crypto_hash_sha256_update(&state, version, 4);

    /* hashPrevouts */
    crypto_hash_sha256_update(&state, hash_prevouts, 32);

    /* hashSequence */
    crypto_hash_sha256_update(&state, hash_sequence, 32);

    /* outpoint */
    uint8_t txid_le[32];
    for (int j = 0; j < 32; j++) {
        txid_le[j] = tx->inputs[input_idx].prev_txid[31 - j];
    }
    crypto_hash_sha256_update(&state, txid_le, 32);
    uint8_t idx[4];
    write_le32(idx, tx->inputs[input_idx].prev_index);
    crypto_hash_sha256_update(&state, idx, 4);

    /* scriptCode (P2WPKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG) */
    /* For P2WPKH, extract pubkey hash from witness program */
    uint8_t script_code[26];
    script_code[0] = 0x19;  /* length */
    script_code[1] = 0x76;  /* OP_DUP */
    script_code[2] = 0xA9;  /* OP_HASH160 */
    script_code[3] = 0x14;  /* Push 20 bytes */
    /* Assuming P2WPKH: script_pubkey is 0x0014<20-byte-hash> */
    if (tx->inputs[input_idx].script_pubkey_len == 22 &&
        tx->inputs[input_idx].script_pubkey[0] == 0x00 &&
        tx->inputs[input_idx].script_pubkey[1] == 0x14) {
        memcpy(script_code + 4, tx->inputs[input_idx].script_pubkey + 2, 20);
    } else {
        return -1;  /* Unsupported script type */
    }
    script_code[24] = 0x88;  /* OP_EQUALVERIFY */
    script_code[25] = 0xAC;  /* OP_CHECKSIG */
    crypto_hash_sha256_update(&state, script_code, 26);

    /* amount */
    uint8_t amount[8];
    write_le64(amount, tx->inputs[input_idx].amount);
    crypto_hash_sha256_update(&state, amount, 8);

    /* nSequence */
    uint8_t seq[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    crypto_hash_sha256_update(&state, seq, 4);

    /* hashOutputs */
    crypto_hash_sha256_update(&state, hash_outputs, 32);

    /* nLockTime */
    uint8_t locktime[4];
    write_le32(locktime, tx->locktime);
    crypto_hash_sha256_update(&state, locktime, 4);

    /* nHashType */
    uint8_t hashtype[4];
    write_le32(hashtype, sighash_type);
    crypto_hash_sha256_update(&state, hashtype, 4);

    crypto_hash_sha256_final(&state, temp);
    crypto_hash_sha256(hash, temp, 32);

    return 0;
}

int btc_sign_tx(btc_tx_t *tx, const bip32_key_t *keys, size_t key_count,
                uint8_t *signed_tx, size_t *signed_tx_len)
{
    uint8_t sighash[32];
    uint8_t signature[SECP256K1_SIGNATURE_SIZE];
    uint8_t der_sig[SECP256K1_SIGNATURE_DER_MAX + 1];  /* +1 for sighash type */
    size_t der_len;
    size_t offset = 0;
    size_t max_len;

    if (tx == NULL || keys == NULL || signed_tx == NULL || signed_tx_len == NULL) {
        return -1;
    }

    max_len = *signed_tx_len;

    /* Write version */
    if (offset + 4 > max_len) return -1;
    write_le32(signed_tx + offset, tx->version);
    offset += 4;

    /* SegWit marker and flag */
    if (offset + 2 > max_len) return -1;
    signed_tx[offset++] = 0x00;
    signed_tx[offset++] = 0x01;

    /* Input count */
    int cs = write_compact_size(tx->input_count, signed_tx + offset, max_len - offset);
    if (cs < 0) return -1;
    offset += cs;

    /* Inputs (with empty scriptSig for segwit) */
    for (size_t i = 0; i < tx->input_count; i++) {
        /* txid (reversed) */
        if (offset + 32 > max_len) return -1;
        for (int j = 0; j < 32; j++) {
            signed_tx[offset + j] = tx->inputs[i].prev_txid[31 - j];
        }
        offset += 32;

        /* vout */
        if (offset + 4 > max_len) return -1;
        write_le32(signed_tx + offset, tx->inputs[i].prev_index);
        offset += 4;

        /* scriptSig (empty for segwit) */
        if (offset + 1 > max_len) return -1;
        signed_tx[offset++] = 0x00;

        /* sequence */
        if (offset + 4 > max_len) return -1;
        signed_tx[offset++] = 0xFF;
        signed_tx[offset++] = 0xFF;
        signed_tx[offset++] = 0xFF;
        signed_tx[offset++] = 0xFF;
    }

    /* Output count */
    cs = write_compact_size(tx->output_count, signed_tx + offset, max_len - offset);
    if (cs < 0) return -1;
    offset += cs;

    /* Outputs */
    for (size_t i = 0; i < tx->output_count; i++) {
        /* amount */
        if (offset + 8 > max_len) return -1;
        write_le64(signed_tx + offset, tx->outputs[i].amount);
        offset += 8;

        /* scriptPubKey */
        cs = write_compact_size(tx->outputs[i].script_pubkey_len,
                                signed_tx + offset, max_len - offset);
        if (cs < 0) return -1;
        offset += cs;

        if (offset + tx->outputs[i].script_pubkey_len > max_len) return -1;
        memcpy(signed_tx + offset, tx->outputs[i].script_pubkey,
               tx->outputs[i].script_pubkey_len);
        offset += tx->outputs[i].script_pubkey_len;
    }

    /* Witness data */
    for (size_t i = 0; i < tx->input_count; i++) {
        /* Create sighash */
        if (create_segwit_sighash(tx, i, SIGHASH_ALL, sighash) != 0) {
            return -1;
        }

        /* Find matching key */
        int key_found = 0;
        for (size_t k = 0; k < key_count && !key_found; k++) {
            uint8_t pubkey_hash[20];
            hash160(keys[k].public_key, 33, pubkey_hash);

            /* Check if this key matches the input */
            if (tx->inputs[i].script_pubkey_len == 22 &&
                memcmp(tx->inputs[i].script_pubkey + 2, pubkey_hash, 20) == 0) {

                /* Sign */
                if (secp256k1_sign(keys[k].private_key, sighash, signature) != 0) {
                    return -1;
                }

                /* Convert to DER */
                der_len = sizeof(der_sig) - 1;
                if (secp256k1_signature_to_der(signature, der_sig, &der_len) != 0) {
                    return -1;
                }
                der_sig[der_len++] = SIGHASH_ALL;  /* Append sighash type */

                /* Write witness: 2 items (signature, pubkey) */
                if (offset + 1 > max_len) return -1;
                signed_tx[offset++] = 0x02;  /* Number of witness items */

                /* Signature */
                cs = write_compact_size(der_len, signed_tx + offset, max_len - offset);
                if (cs < 0) return -1;
                offset += cs;

                if (offset + der_len > max_len) return -1;
                memcpy(signed_tx + offset, der_sig, der_len);
                offset += der_len;

                /* Public key */
                cs = write_compact_size(33, signed_tx + offset, max_len - offset);
                if (cs < 0) return -1;
                offset += cs;

                if (offset + 33 > max_len) return -1;
                memcpy(signed_tx + offset, keys[k].public_key, 33);
                offset += 33;

                key_found = 1;
            }
        }

        if (!key_found) {
            /* No key found, write empty witness */
            if (offset + 1 > max_len) return -1;
            signed_tx[offset++] = 0x00;
        }
    }

    /* Locktime */
    if (offset + 4 > max_len) return -1;
    write_le32(signed_tx + offset, tx->locktime);
    offset += 4;

    *signed_tx_len = offset;

    /* Wipe sensitive data */
    secure_wipe(sighash, sizeof(sighash));
    secure_wipe(signature, sizeof(signature));

    return 0;
}

uint64_t btc_calculate_fee(const btc_tx_t *tx)
{
    uint64_t total_in = 0;
    uint64_t total_out = 0;
    size_t i;

    if (tx == NULL) {
        return 0;
    }

    for (i = 0; i < tx->input_count; i++) {
        total_in += tx->inputs[i].amount;
    }

    for (i = 0; i < tx->output_count; i++) {
        total_out += tx->outputs[i].amount;
    }

    if (total_out > total_in) {
        return 0;  /* Invalid transaction */
    }

    return total_in - total_out;
}

int btc_validate_address(const char *address, btc_network_t network)
{
    size_t len;
    uint8_t decoded[64];
    size_t decoded_len = sizeof(decoded);

    if (address == NULL) {
        return 0;
    }

    len = strlen(address);

    /* Legacy/P2SH address (Base58Check) */
    if (address[0] == '1' || address[0] == '3' ||
        address[0] == 'm' || address[0] == 'n' || address[0] == '2') {
        if (base58check_decode(address, decoded, &decoded_len) != 0) {
            return 0;
        }

        /* Check version byte */
        if (network == BTC_MAINNET) {
            if (decoded[0] != P2PKH_MAINNET && decoded[0] != P2SH_MAINNET) {
                return 0;
            }
        } else {
            if (decoded[0] != P2PKH_TESTNET && decoded[0] != P2SH_TESTNET) {
                return 0;
            }
        }

        return 1;
    }

    /* Bech32 address */
    if (len >= 4 && (strncmp(address, "bc1", 3) == 0 ||
                     strncmp(address, "tb1", 3) == 0 ||
                     strncmp(address, "BC1", 3) == 0 ||
                     strncmp(address, "TB1", 3) == 0)) {
        /* Basic length check */
        if (len < 14 || len > 90) {
            return 0;
        }

        /* Full bech32/bech32m validation */
        int witness_version;
        uint8_t witness_program[40];
        size_t witness_len = sizeof(witness_program);
        char hrp[8];

        if (bech32_decode_segwit(address, hrp, sizeof(hrp),
                                  &witness_version, witness_program, &witness_len) != 0) {
            return 0;
        }

        /* Verify HRP matches network */
        if (network == BTC_MAINNET) {
            if (strcmp(hrp, "bc") != 0) {
                return 0;
            }
        } else {
            if (strcmp(hrp, "tb") != 0) {
                return 0;
            }
        }

        /* Validate witness version and program length */
        if (witness_version > 16) {
            return 0;
        }

        /* v0: must be 20 (P2WPKH) or 32 (P2WSH) bytes */
        if (witness_version == 0) {
            if (witness_len != 20 && witness_len != 32) {
                return 0;
            }
        }

        /* v1: must be 32 bytes (P2TR) */
        if (witness_version == 1) {
            if (witness_len != 32) {
                return 0;
            }
        }

        return 1;
    }

    return 0;
}

int btc_format_amount(uint64_t satoshis, char *output, size_t output_len)
{
    uint64_t btc = satoshis / 100000000;
    uint64_t sats = satoshis % 100000000;

    if (output == NULL || output_len < 20) {
        return -1;
    }

    snprintf(output, output_len, "%lu.%08lu BTC", (unsigned long)btc, (unsigned long)sats);

    return 0;
}

int btc_script_to_address(const uint8_t *script_pubkey, size_t script_len,
                          btc_network_t network, char *address, size_t address_len)
{
    if (script_pubkey == NULL || address == NULL || address_len < 20) {
        return -1;
    }

    const char *hrp = (network == BTC_MAINNET) ? BECH32_MAINNET : BECH32_TESTNET;

    /*
     * P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
     * 76 a9 14 <20 bytes> 88 ac
     */
    if (script_len == 25 &&
        script_pubkey[0] == 0x76 &&
        script_pubkey[1] == 0xa9 &&
        script_pubkey[2] == 0x14 &&
        script_pubkey[23] == 0x88 &&
        script_pubkey[24] == 0xac) {

        uint8_t versioned_hash[21];
        versioned_hash[0] = (network == BTC_MAINNET) ? P2PKH_MAINNET : P2PKH_TESTNET;
        memcpy(versioned_hash + 1, script_pubkey + 3, 20);

        /* base58check_encode returns length on success, -1 on error */
        return (base58check_encode(versioned_hash, 21, address, address_len) > 0) ? 0 : -1;
    }

    /*
     * P2SH: OP_HASH160 <20 bytes> OP_EQUAL
     * a9 14 <20 bytes> 87
     */
    if (script_len == 23 &&
        script_pubkey[0] == 0xa9 &&
        script_pubkey[1] == 0x14 &&
        script_pubkey[22] == 0x87) {

        uint8_t versioned_hash[21];
        versioned_hash[0] = (network == BTC_MAINNET) ? P2SH_MAINNET : P2SH_TESTNET;
        memcpy(versioned_hash + 1, script_pubkey + 2, 20);

        return (base58check_encode(versioned_hash, 21, address, address_len) > 0) ? 0 : -1;
    }

    /*
     * P2WPKH: OP_0 <20 bytes>
     * 00 14 <20 bytes>
     */
    if (script_len == 22 &&
        script_pubkey[0] == 0x00 &&
        script_pubkey[1] == 0x14) {

        /* bech32_encode_segwit returns length on success, -1 on error */
        return (bech32_encode_segwit(hrp, 0, script_pubkey + 2, 20,
                                      address, address_len) > 0) ? 0 : -1;
    }

    /*
     * P2WSH: OP_0 <32 bytes>
     * 00 20 <32 bytes>
     */
    if (script_len == 34 &&
        script_pubkey[0] == 0x00 &&
        script_pubkey[1] == 0x20) {

        return (bech32_encode_segwit(hrp, 0, script_pubkey + 2, 32,
                                      address, address_len) > 0) ? 0 : -1;
    }

    /*
     * P2TR (Taproot): OP_1 <32 bytes>
     * 51 20 <32 bytes>
     */
    if (script_len == 34 &&
        script_pubkey[0] == 0x51 &&
        script_pubkey[1] == 0x20) {

        return (bech32_encode_segwit(hrp, 1, script_pubkey + 2, 32,
                                      address, address_len) > 0) ? 0 : -1;
    }

    /* Unknown script type */
    return -1;
}

/*
 * Litecoin Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "litecoin.h"
#include "../crypto/ripemd160.h"
#include "../crypto/secp256k1.h"
#include "../util/base58.h"
#include "../util/bech32.h"
#include <string.h>
#include <stdio.h>
#include <sodium.h>

/* Network prefixes */
#define LTC_P2PKH_MAINNET     0x30  /* L or M */
#define LTC_P2PKH_TESTNET     0x6F  /* m or n */
#define LTC_P2SH_MAINNET      0x32  /* M */
#define LTC_P2SH_TESTNET      0xC4  /* Q */

/* Bech32 HRP (Human Readable Part) */
#define LTC_BECH32_MAINNET    "ltc"
#define LTC_BECH32_TESTNET    "tltc"

int ltc_pubkey_to_address(const uint8_t pubkey[33], ltc_addr_type_t addr_type,
                          ltc_network_t network, char *address, size_t address_len)
{
    uint8_t pubkey_hash[20];
    uint8_t versioned[21];
    const char *hrp;
    int ret;

    if (pubkey == NULL || address == NULL) {
        return -1;
    }

    /* Hash160 of pubkey: RIPEMD160(SHA256(pubkey)) */
    hash160(pubkey, 33, pubkey_hash);

    switch (addr_type) {
    case LTC_ADDR_P2PKH:
        versioned[0] = (network == LTC_MAINNET) ? LTC_P2PKH_MAINNET : LTC_P2PKH_TESTNET;
        memcpy(versioned + 1, pubkey_hash, 20);
        ret = base58check_encode(versioned, 21, address, address_len);
        return (ret > 0) ? 0 : -1;

    case LTC_ADDR_P2SH:
        versioned[0] = (network == LTC_MAINNET) ? LTC_P2SH_MAINNET : LTC_P2SH_TESTNET;
        memcpy(versioned + 1, pubkey_hash, 20);
        ret = base58check_encode(versioned, 21, address, address_len);
        return (ret > 0) ? 0 : -1;

    case LTC_ADDR_P2WPKH:
        hrp = (network == LTC_MAINNET) ? LTC_BECH32_MAINNET : LTC_BECH32_TESTNET;
        /* SegWit v0 with 20-byte witness program */
        ret = bech32_encode_segwit(hrp, 0, pubkey_hash, 20, address, address_len);
        return (ret > 0) ? 0 : -1;

    case LTC_ADDR_P2WSH:
        /* P2WSH uses SHA256 hash (32 bytes), not Hash160 */
        /* For now, this is not directly from pubkey - need script hash */
        return -1;  /* Not supported for direct pubkey conversion */

    default:
        return -1;
    }
}

int ltc_validate_address(const char *address, const ltc_network_t *network)
{
    size_t len;
    uint8_t decoded[25];
    size_t decoded_len = sizeof(decoded);
    int witness_version;
    uint8_t witness_program[40];
    size_t witness_len = sizeof(witness_program);

    if (address == NULL) {
        return -1;
    }

    len = strlen(address);
    if (len < 26 || len > 90) {
        return -1;
    }

    /* Check for Bech32 address (ltc1... or tltc1...) */
    if (strncmp(address, "ltc1", 4) == 0 || strncmp(address, "tltc1", 5) == 0) {
        if (bech32_decode_segwit(address, NULL, 0, &witness_version,
                                  witness_program, &witness_len) != 0) {
            return -1;
        }

        /* Validate witness version and program length */
        if (witness_version == 0) {
            if (witness_len != 20 && witness_len != 32) {
                return -1;  /* v0 must be 20 or 32 bytes */
            }
        }

        if (network != NULL) {
            if (*network == LTC_MAINNET && strncmp(address, "ltc1", 4) != 0) {
                return -1;
            }
            if (*network == LTC_TESTNET && strncmp(address, "tltc1", 5) != 0) {
                return -1;
            }
        }

        return 0;
    }

    /* Try Base58Check decode */
    if (base58check_decode(address, decoded, &decoded_len) != 0) {
        return -1;
    }

    if (decoded_len != 21) {
        return -1;
    }

    /* Validate version byte */
    uint8_t version = decoded[0];

    if (network != NULL) {
        if (*network == LTC_MAINNET) {
            if (version != LTC_P2PKH_MAINNET && version != LTC_P2SH_MAINNET) {
                return -1;
            }
        } else {
            if (version != LTC_P2PKH_TESTNET && version != LTC_P2SH_TESTNET) {
                return -1;
            }
        }
    } else {
        /* Accept any valid Litecoin version */
        if (version != LTC_P2PKH_MAINNET && version != LTC_P2SH_MAINNET &&
            version != LTC_P2PKH_TESTNET && version != LTC_P2SH_TESTNET) {
            return -1;
        }
    }

    return 0;
}

int ltc_script_p2pkh(const uint8_t pubkey_hash[20], uint8_t *script, size_t *script_len)
{
    if (pubkey_hash == NULL || script == NULL || script_len == NULL) {
        return -1;
    }

    /* OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG */
    script[0] = 0x76;  /* OP_DUP */
    script[1] = 0xa9;  /* OP_HASH160 */
    script[2] = 0x14;  /* Push 20 bytes */
    memcpy(script + 3, pubkey_hash, 20);
    script[23] = 0x88; /* OP_EQUALVERIFY */
    script[24] = 0xac; /* OP_CHECKSIG */

    *script_len = 25;
    return 0;
}

int ltc_script_p2wpkh(const uint8_t pubkey_hash[20], uint8_t *script, size_t *script_len)
{
    if (pubkey_hash == NULL || script == NULL || script_len == NULL) {
        return -1;
    }

    /* OP_0 <20 bytes> */
    script[0] = 0x00;  /* OP_0 (witness version 0) */
    script[1] = 0x14;  /* Push 20 bytes */
    memcpy(script + 2, pubkey_hash, 20);

    *script_len = 22;
    return 0;
}

int ltc_get_derivation_path(uint32_t account, uint32_t change, uint32_t index,
                            char *path, size_t path_len)
{
    if (path == NULL || path_len < 32) {
        return -1;
    }

    /* BIP44: m/44'/2'/account'/change/index */
    /* BIP84 for SegWit: m/84'/2'/account'/change/index */
    snprintf(path, path_len, "m/84'/2'/%u'/%u/%u", account, change, index);

    return 0;
}

int ltc_format_amount(uint64_t litoshis, char *output, size_t output_len)
{
    if (output == NULL || output_len < 24) {
        return -1;
    }

    uint64_t ltc = litoshis / 100000000ULL;
    uint64_t fraction = litoshis % 100000000ULL;

    snprintf(output, output_len, "%lu.%08lu LTC", (unsigned long)ltc, (unsigned long)fraction);

    return 0;
}

uint64_t ltc_calculate_fee(const ltc_tx_t *tx)
{
    uint64_t total_in = 0;
    uint64_t total_out = 0;

    if (tx == NULL) {
        return 0;
    }

    for (size_t i = 0; i < tx->input_count; i++) {
        total_in += tx->inputs[i].amount;
    }

    for (size_t i = 0; i < tx->output_count; i++) {
        total_out += tx->outputs[i].amount;
    }

    if (total_out > total_in) {
        return 0;  /* Invalid: outputs exceed inputs */
    }

    return total_in - total_out;
}

int ltc_parse_tx(const uint8_t *raw_tx, size_t raw_len, ltc_tx_t *tx)
{
    /* Litecoin uses the same transaction format as Bitcoin */
    /* This is a simplified parser - production code should handle all edge cases */
    size_t offset = 0;

    if (raw_tx == NULL || tx == NULL || raw_len < 10) {
        return -1;
    }

    memset(tx, 0, sizeof(*tx));

    /* Version (4 bytes, little-endian) */
    if (offset + 4 > raw_len) return -1;
    tx->version = raw_tx[offset] | (raw_tx[offset + 1] << 8) |
                  (raw_tx[offset + 2] << 16) | (raw_tx[offset + 3] << 24);
    offset += 4;

    /* Check for SegWit marker (0x00 0x01) */
    int is_segwit = 0;
    if (offset + 2 <= raw_len && raw_tx[offset] == 0x00 && raw_tx[offset + 1] == 0x01) {
        is_segwit = 1;
        offset += 2;
    }

    /* Input count (varint) */
    if (offset >= raw_len) return -1;
    uint64_t input_count = raw_tx[offset++];
    if (input_count >= 0xFD) {
        /* Handle extended varints */
        if (input_count == 0xFD) {
            if (offset + 2 > raw_len) return -1;
            input_count = raw_tx[offset] | (raw_tx[offset + 1] << 8);
            offset += 2;
        } else {
            return -1;  /* Very large counts not supported */
        }
    }

    if (input_count > LTC_MAX_INPUTS) return -1;
    tx->input_count = (size_t)input_count;

    /* Parse inputs */
    for (size_t i = 0; i < tx->input_count; i++) {
        if (offset + 36 > raw_len) return -1;

        /* Previous txid (32 bytes, reversed) */
        for (int j = 0; j < 32; j++) {
            tx->inputs[i].prev_txid[31 - j] = raw_tx[offset + j];
        }
        offset += 32;

        /* Previous output index (4 bytes) */
        tx->inputs[i].prev_index = raw_tx[offset] | (raw_tx[offset + 1] << 8) |
                                   (raw_tx[offset + 2] << 16) | (raw_tx[offset + 3] << 24);
        offset += 4;

        /* Script length and script (varint + data) */
        if (offset >= raw_len) return -1;
        uint64_t script_len = raw_tx[offset++];
        if (script_len >= 0xFD) return -1;  /* Large scripts not supported */

        if (offset + script_len > raw_len) return -1;
        offset += script_len;  /* Skip scriptSig for unsigned tx */

        /* Sequence (4 bytes) */
        if (offset + 4 > raw_len) return -1;
        offset += 4;
    }

    /* Output count (varint) */
    if (offset >= raw_len) return -1;
    uint64_t output_count = raw_tx[offset++];
    if (output_count >= 0xFD) {
        if (output_count == 0xFD) {
            if (offset + 2 > raw_len) return -1;
            output_count = raw_tx[offset] | (raw_tx[offset + 1] << 8);
            offset += 2;
        } else {
            return -1;
        }
    }

    if (output_count > LTC_MAX_OUTPUTS) return -1;
    tx->output_count = (size_t)output_count;

    /* Parse outputs */
    for (size_t i = 0; i < tx->output_count; i++) {
        if (offset + 8 > raw_len) return -1;

        /* Amount (8 bytes, little-endian) */
        tx->outputs[i].amount = 0;
        for (int j = 0; j < 8; j++) {
            tx->outputs[i].amount |= ((uint64_t)raw_tx[offset + j] << (j * 8));
        }
        offset += 8;

        /* Script length and script */
        if (offset >= raw_len) return -1;
        uint64_t script_len = raw_tx[offset++];
        if (script_len >= 0xFD) return -1;

        if (offset + script_len > raw_len) return -1;
        if (script_len <= 64) {
            memcpy(tx->outputs[i].script_pubkey, raw_tx + offset, script_len);
            tx->outputs[i].script_pubkey_len = script_len;
        }
        offset += script_len;
    }

    /* Skip witness data for SegWit */
    if (is_segwit) {
        for (size_t i = 0; i < tx->input_count; i++) {
            if (offset >= raw_len) return -1;
            uint64_t witness_count = raw_tx[offset++];
            for (uint64_t w = 0; w < witness_count; w++) {
                if (offset >= raw_len) return -1;
                uint64_t wit_len = raw_tx[offset++];
                if (offset + wit_len > raw_len) return -1;
                offset += wit_len;
            }
        }
    }

    /* Locktime (4 bytes) */
    if (offset + 4 > raw_len) return -1;
    tx->locktime = raw_tx[offset] | (raw_tx[offset + 1] << 8) |
                   (raw_tx[offset + 2] << 16) | (raw_tx[offset + 3] << 24);

    return 0;
}

/* SIGHASH type */
#define SIGHASH_ALL 0x01

/* Helper functions */
static void write_le32(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

static void write_le64(uint8_t *buf, uint64_t val)
{
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)((val >> (i * 8)) & 0xFF);
    }
}

static int write_compact_size(uint64_t size, uint8_t *buf, size_t buf_len)
{
    if (size < 0xFD) {
        if (buf_len < 1) return -1;
        buf[0] = (uint8_t)size;
        return 1;
    } else if (size <= 0xFFFF) {
        if (buf_len < 3) return -1;
        buf[0] = 0xFD;
        buf[1] = (uint8_t)(size & 0xFF);
        buf[2] = (uint8_t)((size >> 8) & 0xFF);
        return 3;
    } else if (size <= 0xFFFFFFFF) {
        if (buf_len < 5) return -1;
        buf[0] = 0xFE;
        write_le32(buf + 1, (uint32_t)size);
        return 5;
    }
    return -1;
}

/**
 * Create BIP-143 sighash for SegWit inputs (Litecoin uses same algorithm)
 */
static int ltc_create_segwit_sighash(const ltc_tx_t *tx, size_t input_idx,
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
    uint8_t script_code[26];
    script_code[0] = 0x19;  /* length */
    script_code[1] = 0x76;  /* OP_DUP */
    script_code[2] = 0xA9;  /* OP_HASH160 */
    script_code[3] = 0x14;  /* Push 20 bytes */
    /* P2WPKH: script_pubkey is 0x0014<20-byte-hash> */
    if (tx->inputs[input_idx].script_pubkey_len == 22 &&
        tx->inputs[input_idx].script_pubkey[0] == 0x00 &&
        tx->inputs[input_idx].script_pubkey[1] == 0x14) {
        memcpy(script_code + 4, tx->inputs[input_idx].script_pubkey + 2, 20);
    } else {
        return -1;  /* Unsupported script type for now */
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

int ltc_sign_tx(ltc_tx_t *tx, const bip32_key_t *keys, size_t key_count,
                uint8_t *signed_tx, size_t *signed_tx_len)
{
    uint8_t sighash[32];
    uint8_t signature[64];  /* secp256k1 compact signature */
    uint8_t der_sig[73];    /* DER-encoded signature + sighash type */
    size_t der_len;
    size_t offset = 0;
    size_t max_len;
    int cs;

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
    cs = write_compact_size(tx->input_count, signed_tx + offset, max_len - offset);
    if (cs < 0) return -1;
    offset += (size_t)cs;

    /* Inputs (with empty scriptSig for segwit) */
    for (size_t i = 0; i < tx->input_count; i++) {
        /* txid (reversed for serialization) */
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
    offset += (size_t)cs;

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
        offset += (size_t)cs;

        if (offset + tx->outputs[i].script_pubkey_len > max_len) return -1;
        memcpy(signed_tx + offset, tx->outputs[i].script_pubkey,
               tx->outputs[i].script_pubkey_len);
        offset += tx->outputs[i].script_pubkey_len;
    }

    /* Witness data */
    for (size_t i = 0; i < tx->input_count; i++) {
        /* Create sighash */
        if (ltc_create_segwit_sighash(tx, i, SIGHASH_ALL, sighash) != 0) {
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

                /* Sign using secp256k1 */
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
                offset += (size_t)cs;

                if (offset + der_len > max_len) return -1;
                memcpy(signed_tx + offset, der_sig, der_len);
                offset += der_len;

                /* Public key */
                cs = write_compact_size(33, signed_tx + offset, max_len - offset);
                if (cs < 0) return -1;
                offset += (size_t)cs;

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

    return 0;
}

int ltc_script_to_address(const uint8_t *script_pubkey, size_t script_len,
                          ltc_network_t network, char *address, size_t address_len)
{
    if (script_pubkey == NULL || address == NULL || address_len < 20) {
        return -1;
    }

    const char *hrp = (network == LTC_MAINNET) ? LTC_BECH32_MAINNET : LTC_BECH32_TESTNET;

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
        versioned_hash[0] = (network == LTC_MAINNET) ? LTC_P2PKH_MAINNET : LTC_P2PKH_TESTNET;
        memcpy(versioned_hash + 1, script_pubkey + 3, 20);

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
        versioned_hash[0] = (network == LTC_MAINNET) ? LTC_P2SH_MAINNET : LTC_P2SH_TESTNET;
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

    /* Unknown script type */
    return -1;
}

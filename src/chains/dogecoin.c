/*
 * Dogecoin Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "dogecoin.h"
#include "../crypto/ripemd160.h"
#include "../crypto/secp256k1.h"
#include "../util/base58.h"
#include <string.h>
#include <stdio.h>
#include <sodium.h>

/* Network prefixes */
#define DOGE_P2PKH_MAINNET    0x1E  /* D */
#define DOGE_P2PKH_TESTNET    0x71  /* n */
#define DOGE_P2SH_MAINNET     0x16  /* 9 or A */
#define DOGE_P2SH_TESTNET     0xC4  /* 2 */

int doge_pubkey_to_address(const uint8_t pubkey[33], doge_addr_type_t addr_type,
                           doge_network_t network, char *address, size_t address_len)
{
    uint8_t pubkey_hash[20];
    uint8_t versioned[21];
    int ret;

    if (pubkey == NULL || address == NULL) {
        return -1;
    }

    /* Hash160 of pubkey: RIPEMD160(SHA256(pubkey)) */
    hash160(pubkey, 33, pubkey_hash);

    switch (addr_type) {
    case DOGE_ADDR_P2PKH:
        versioned[0] = (network == DOGE_MAINNET) ? DOGE_P2PKH_MAINNET : DOGE_P2PKH_TESTNET;
        memcpy(versioned + 1, pubkey_hash, 20);
        ret = base58check_encode(versioned, 21, address, address_len);
        return (ret > 0) ? 0 : -1;

    case DOGE_ADDR_P2SH:
        versioned[0] = (network == DOGE_MAINNET) ? DOGE_P2SH_MAINNET : DOGE_P2SH_TESTNET;
        memcpy(versioned + 1, pubkey_hash, 20);
        ret = base58check_encode(versioned, 21, address, address_len);
        return (ret > 0) ? 0 : -1;

    default:
        return -1;
    }
}

int doge_validate_address(const char *address, const doge_network_t *network)
{
    size_t len;
    uint8_t decoded[25];
    size_t decoded_len = sizeof(decoded);

    if (address == NULL) {
        return -1;
    }

    len = strlen(address);
    if (len < 26 || len > 35) {
        return -1;
    }

    /* Dogecoin only uses Base58Check (no SegWit/Bech32) */
    if (base58check_decode(address, decoded, &decoded_len) != 0) {
        return -1;
    }

    if (decoded_len != 21) {
        return -1;
    }

    /* Validate version byte */
    uint8_t version = decoded[0];

    if (network != NULL) {
        if (*network == DOGE_MAINNET) {
            if (version != DOGE_P2PKH_MAINNET && version != DOGE_P2SH_MAINNET) {
                return -1;
            }
        } else {
            if (version != DOGE_P2PKH_TESTNET && version != DOGE_P2SH_TESTNET) {
                return -1;
            }
        }
    } else {
        /* Accept any valid Dogecoin version */
        if (version != DOGE_P2PKH_MAINNET && version != DOGE_P2SH_MAINNET &&
            version != DOGE_P2PKH_TESTNET && version != DOGE_P2SH_TESTNET) {
            return -1;
        }
    }

    return 0;
}

int doge_script_p2pkh(const uint8_t pubkey_hash[20], uint8_t *script, size_t *script_len)
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

int doge_script_p2sh(const uint8_t script_hash[20], uint8_t *script, size_t *script_len)
{
    if (script_hash == NULL || script == NULL || script_len == NULL) {
        return -1;
    }

    /* OP_HASH160 <20 bytes> OP_EQUAL */
    script[0] = 0xa9;  /* OP_HASH160 */
    script[1] = 0x14;  /* Push 20 bytes */
    memcpy(script + 2, script_hash, 20);
    script[22] = 0x87; /* OP_EQUAL */

    *script_len = 23;
    return 0;
}

int doge_get_derivation_path(uint32_t account, uint32_t change, uint32_t index,
                             char *path, size_t path_len)
{
    if (path == NULL || path_len < 32) {
        return -1;
    }

    /* BIP44: m/44'/3'/account'/change/index */
    snprintf(path, path_len, "m/44'/3'/%u'/%u/%u", account, change, index);

    return 0;
}

int doge_format_amount(uint64_t satoshis, char *output, size_t output_len)
{
    if (output == NULL || output_len < 24) {
        return -1;
    }

    uint64_t doge = satoshis / 100000000ULL;
    uint64_t fraction = satoshis % 100000000ULL;

    snprintf(output, output_len, "%lu.%08lu DOGE", (unsigned long)doge, (unsigned long)fraction);

    return 0;
}

uint64_t doge_calculate_fee(const doge_tx_t *tx)
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

int doge_parse_tx(const uint8_t *raw_tx, size_t raw_len, doge_tx_t *tx)
{
    /* Dogecoin uses the same transaction format as Bitcoin (no SegWit) */
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

    if (input_count > DOGE_MAX_INPUTS) return -1;
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

    if (output_count > DOGE_MAX_OUTPUTS) return -1;
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

    /* Locktime (4 bytes) */
    if (offset + 4 > raw_len) return -1;
    tx->locktime = raw_tx[offset] | (raw_tx[offset + 1] << 8) |
                   (raw_tx[offset + 2] << 16) | (raw_tx[offset + 3] << 24);

    return 0;
}

/* SIGHASH type */
#define DOGE_SIGHASH_ALL 0x01

/* Helper functions for Dogecoin signing */
static void doge_write_le32(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

static void doge_write_le64(uint8_t *buf, uint64_t val)
{
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)((val >> (i * 8)) & 0xFF);
    }
}

static int doge_write_compact_size(uint64_t size, uint8_t *buf, size_t buf_len)
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
        doge_write_le32(buf + 1, (uint32_t)size);
        return 5;
    }
    return -1;
}

/**
 * Create legacy sighash for P2PKH inputs (Dogecoin uses classic Bitcoin signing)
 */
static int doge_create_legacy_sighash(const doge_tx_t *tx, size_t input_idx,
                                       const uint8_t *script_code, size_t script_code_len,
                                       uint32_t sighash_type, uint8_t hash[32])
{
    /* Build transaction preimage for signing */
    uint8_t preimage[8192];  /* Temporary buffer for preimage */
    size_t offset = 0;
    size_t max_len = sizeof(preimage);
    int cs;

    /* Version */
    if (offset + 4 > max_len) return -1;
    doge_write_le32(preimage + offset, tx->version);
    offset += 4;

    /* Input count */
    cs = doge_write_compact_size(tx->input_count, preimage + offset, max_len - offset);
    if (cs < 0) return -1;
    offset += (size_t)cs;

    /* Inputs */
    for (size_t i = 0; i < tx->input_count; i++) {
        /* txid (reversed) */
        if (offset + 32 > max_len) return -1;
        for (int j = 0; j < 32; j++) {
            preimage[offset + j] = tx->inputs[i].prev_txid[31 - j];
        }
        offset += 32;

        /* vout */
        if (offset + 4 > max_len) return -1;
        doge_write_le32(preimage + offset, tx->inputs[i].prev_index);
        offset += 4;

        /* scriptSig (subscript for signing input, empty for others) */
        if (i == input_idx) {
            cs = doge_write_compact_size(script_code_len, preimage + offset, max_len - offset);
            if (cs < 0) return -1;
            offset += (size_t)cs;

            if (offset + script_code_len > max_len) return -1;
            memcpy(preimage + offset, script_code, script_code_len);
            offset += script_code_len;
        } else {
            /* Empty scriptSig for other inputs */
            if (offset + 1 > max_len) return -1;
            preimage[offset++] = 0x00;
        }

        /* sequence */
        if (offset + 4 > max_len) return -1;
        preimage[offset++] = 0xFF;
        preimage[offset++] = 0xFF;
        preimage[offset++] = 0xFF;
        preimage[offset++] = 0xFF;
    }

    /* Output count */
    cs = doge_write_compact_size(tx->output_count, preimage + offset, max_len - offset);
    if (cs < 0) return -1;
    offset += (size_t)cs;

    /* Outputs */
    for (size_t i = 0; i < tx->output_count; i++) {
        /* amount */
        if (offset + 8 > max_len) return -1;
        doge_write_le64(preimage + offset, tx->outputs[i].amount);
        offset += 8;

        /* scriptPubKey */
        cs = doge_write_compact_size(tx->outputs[i].script_pubkey_len,
                                      preimage + offset, max_len - offset);
        if (cs < 0) return -1;
        offset += (size_t)cs;

        if (offset + tx->outputs[i].script_pubkey_len > max_len) return -1;
        memcpy(preimage + offset, tx->outputs[i].script_pubkey,
               tx->outputs[i].script_pubkey_len);
        offset += tx->outputs[i].script_pubkey_len;
    }

    /* locktime */
    if (offset + 4 > max_len) return -1;
    doge_write_le32(preimage + offset, tx->locktime);
    offset += 4;

    /* sighash type (4 bytes for preimage, 1 byte appended to signature) */
    if (offset + 4 > max_len) return -1;
    doge_write_le32(preimage + offset, sighash_type);
    offset += 4;

    /* Double SHA256 */
    uint8_t temp[32];
    crypto_hash_sha256(temp, preimage, offset);
    crypto_hash_sha256(hash, temp, 32);

    return 0;
}

int doge_sign_tx(doge_tx_t *tx, const bip32_key_t *keys, size_t key_count,
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
    doge_write_le32(signed_tx + offset, tx->version);
    offset += 4;

    /* Input count */
    cs = doge_write_compact_size(tx->input_count, signed_tx + offset, max_len - offset);
    if (cs < 0) return -1;
    offset += (size_t)cs;

    /* Process each input */
    for (size_t i = 0; i < tx->input_count; i++) {
        /* txid (reversed) */
        if (offset + 32 > max_len) return -1;
        for (int j = 0; j < 32; j++) {
            signed_tx[offset + j] = tx->inputs[i].prev_txid[31 - j];
        }
        offset += 32;

        /* vout */
        if (offset + 4 > max_len) return -1;
        doge_write_le32(signed_tx + offset, tx->inputs[i].prev_index);
        offset += 4;

        /* Find matching key and create signature */
        int key_found = 0;
        for (size_t k = 0; k < key_count && !key_found; k++) {
            uint8_t pubkey_hash[20];
            hash160(keys[k].public_key, 33, pubkey_hash);

            /* Check if this key matches the input (P2PKH script) */
            if (tx->inputs[i].script_pubkey_len == 25 &&
                tx->inputs[i].script_pubkey[0] == 0x76 &&  /* OP_DUP */
                tx->inputs[i].script_pubkey[1] == 0xa9 &&  /* OP_HASH160 */
                tx->inputs[i].script_pubkey[2] == 0x14 &&  /* Push 20 bytes */
                memcmp(tx->inputs[i].script_pubkey + 3, pubkey_hash, 20) == 0) {

                /* Create sighash using the scriptPubKey as subscript */
                if (doge_create_legacy_sighash(tx, i, tx->inputs[i].script_pubkey,
                                                tx->inputs[i].script_pubkey_len,
                                                DOGE_SIGHASH_ALL, sighash) != 0) {
                    return -1;
                }

                /* Sign using secp256k1 */
                if (secp256k1_sign(keys[k].private_key, sighash, signature) != 0) {
                    return -1;
                }

                /* Convert to DER */
                der_len = sizeof(der_sig) - 1;
                if (secp256k1_signature_to_der(signature, der_sig, &der_len) != 0) {
                    return -1;
                }
                der_sig[der_len++] = DOGE_SIGHASH_ALL;  /* Append sighash type */

                /* scriptSig: <sig> <pubkey>
                 * Format: [sig_len] [sig+hashtype] [pubkey_len] [pubkey] */
                size_t scriptsig_len = 1 + der_len + 1 + 33;
                cs = doge_write_compact_size(scriptsig_len, signed_tx + offset, max_len - offset);
                if (cs < 0) return -1;
                offset += (size_t)cs;

                /* Signature */
                if (offset + 1 + der_len > max_len) return -1;
                signed_tx[offset++] = (uint8_t)der_len;
                memcpy(signed_tx + offset, der_sig, der_len);
                offset += der_len;

                /* Public key */
                if (offset + 1 + 33 > max_len) return -1;
                signed_tx[offset++] = 33;
                memcpy(signed_tx + offset, keys[k].public_key, 33);
                offset += 33;

                key_found = 1;
            }
        }

        if (!key_found) {
            /* No key found, write empty scriptSig */
            if (offset + 1 > max_len) return -1;
            signed_tx[offset++] = 0x00;
        }

        /* sequence */
        if (offset + 4 > max_len) return -1;
        signed_tx[offset++] = 0xFF;
        signed_tx[offset++] = 0xFF;
        signed_tx[offset++] = 0xFF;
        signed_tx[offset++] = 0xFF;
    }

    /* Output count */
    cs = doge_write_compact_size(tx->output_count, signed_tx + offset, max_len - offset);
    if (cs < 0) return -1;
    offset += (size_t)cs;

    /* Outputs */
    for (size_t i = 0; i < tx->output_count; i++) {
        /* amount */
        if (offset + 8 > max_len) return -1;
        doge_write_le64(signed_tx + offset, tx->outputs[i].amount);
        offset += 8;

        /* scriptPubKey */
        cs = doge_write_compact_size(tx->outputs[i].script_pubkey_len,
                                      signed_tx + offset, max_len - offset);
        if (cs < 0) return -1;
        offset += (size_t)cs;

        if (offset + tx->outputs[i].script_pubkey_len > max_len) return -1;
        memcpy(signed_tx + offset, tx->outputs[i].script_pubkey,
               tx->outputs[i].script_pubkey_len);
        offset += tx->outputs[i].script_pubkey_len;
    }

    /* Locktime */
    if (offset + 4 > max_len) return -1;
    doge_write_le32(signed_tx + offset, tx->locktime);
    offset += 4;

    *signed_tx_len = offset;

    return 0;
}

int doge_script_to_address(const uint8_t *script_pubkey, size_t script_len,
                           doge_network_t network, char *address, size_t address_len)
{
    if (script_pubkey == NULL || address == NULL || address_len < 20) {
        return -1;
    }

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
        versioned_hash[0] = (network == DOGE_MAINNET) ? DOGE_P2PKH_MAINNET : DOGE_P2PKH_TESTNET;
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
        versioned_hash[0] = (network == DOGE_MAINNET) ? DOGE_P2SH_MAINNET : DOGE_P2SH_TESTNET;
        memcpy(versioned_hash + 1, script_pubkey + 2, 20);

        return (base58check_encode(versioned_hash, 21, address, address_len) > 0) ? 0 : -1;
    }

    /* Unknown script type */
    return -1;
}

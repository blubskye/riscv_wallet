/*
 * XRP/Ripple Chain Support Implementation
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _GNU_SOURCE  /* for strncasecmp */
#include "ripple.h"
#include "../crypto/ripemd160.h"
#include "../crypto/secp256k1.h"
#include "../security/memory.h"
#include <sodium.h>
#include <string.h>
#include <strings.h>  /* for strncasecmp on some systems */
#include <stdio.h>
#include <stdlib.h>

/* Use libsodium for SHA-256 */
#define sha256(data, len, out) crypto_hash_sha256((out), (data), (len))

/* XRP uses a different Base58 alphabet than Bitcoin! */
const char *XRP_BASE58_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/* Reverse lookup table for XRP Base58 decoding */
static const int8_t XRP_BASE58_DECODE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0,-1,-1,37,38,39,40,-1,41,-1,-1,-1,-1,-1,-1,  /* 0-9: only some valid */
    -1,57,58,33,53,-1,59,27,28,36,-1,29,30,31,32,60,  /* A-O */
    34,35,24,25,26,61,62,63,64,65,66,-1,-1,-1,-1,-1,  /* P-Z */
    -1,44,45,46,47,48,49,50,51,67,52,54,55,-1, 3, 4,  /* a-o */
     1,-1, 0, 2, 5, 6, 7,42,68,43, 8,-1,-1,-1,-1,-1,  /* p-z */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

/* XRP address type prefixes */
#define XRP_ADDRESS_PREFIX    0x00  /* r... addresses */
#define XRP_SEED_PREFIX       0x21  /* s... seeds */
#define XRP_VALIDATOR_PREFIX  0x1C  /* n... node public keys */

/**
 * XRP Base58Check encode
 */
static int xrp_base58check_encode(const uint8_t *data, size_t data_len,
                                   uint8_t prefix, char *output, size_t output_len)
{
    uint8_t buffer[128];
    uint8_t hash[32];
    size_t buf_len;

    if (data_len > 100) return -1;

    /* Build: prefix + data + checksum */
    buf_len = 1 + data_len + 4;
    buffer[0] = prefix;
    memcpy(buffer + 1, data, data_len);

    /* Double SHA-256 for checksum */
    sha256(buffer, 1 + data_len, hash);
    sha256(hash, 32, hash);
    memcpy(buffer + 1 + data_len, hash, 4);

    /* Convert to XRP Base58 */
    /* Start with leading zeros (as 'r' in XRP alphabet) */
    size_t zeros = 0;
    for (size_t i = 0; i < buf_len && buffer[i] == 0; i++) {
        zeros++;
    }

    /* Allocate temp buffer for base conversion */
    size_t temp_len = buf_len * 138 / 100 + 1;  /* log(256)/log(58) */
    uint8_t *temp = calloc(temp_len, 1);
    if (!temp) return -1;

    /* Big number base conversion */
    size_t high = temp_len - 1;
    for (size_t i = 0; i < buf_len; i++) {
        uint32_t carry = buffer[i];
        size_t j = temp_len - 1;
        while (j > high || carry) {
            carry += 256 * temp[j];
            temp[j] = carry % 58;
            carry /= 58;
            if (j == 0) break;
            j--;
        }
        high = j;
    }

    /* Skip leading zeros in temp buffer */
    size_t start = 0;
    while (start < temp_len && temp[start] == 0) {
        start++;
    }

    /* Output: leading 'r's (for zeros) + encoded data */
    size_t out_idx = 0;
    for (size_t i = 0; i < zeros; i++) {
        if (out_idx >= output_len - 1) {
            free(temp);
            return -1;
        }
        output[out_idx++] = XRP_BASE58_ALPHABET[0];  /* 'r' for zero bytes */
    }
    for (size_t i = start; i < temp_len; i++) {
        if (out_idx >= output_len - 1) {
            free(temp);
            return -1;
        }
        output[out_idx++] = XRP_BASE58_ALPHABET[temp[i]];
    }
    output[out_idx] = '\0';

    free(temp);
    secure_wipe(buffer, sizeof(buffer));
    secure_wipe(hash, sizeof(hash));

    return 0;
}

/**
 * XRP Base58Check decode
 */
static int xrp_base58check_decode(const char *input, uint8_t *output,
                                   size_t *output_len, uint8_t *prefix)
{
    size_t input_len = strlen(input);
    if (input_len == 0 || input_len > 128) return -1;

    /* Count leading 'r's (zeros) */
    size_t zeros = 0;
    while (input[zeros] == 'r') {
        zeros++;
    }

    /* Allocate temp buffer */
    size_t temp_len = input_len * 733 / 1000 + 1;  /* log(58)/log(256) */
    uint8_t *temp = calloc(temp_len, 1);
    if (!temp) return -1;

    /* Base58 to bytes */
    size_t high = temp_len - 1;
    for (size_t i = 0; i < input_len; i++) {
        int8_t val = XRP_BASE58_DECODE[(uint8_t)input[i]];
        if (val < 0) {
            free(temp);
            return -1;
        }

        uint32_t carry = (uint32_t)val;
        size_t j = temp_len - 1;
        while (j > high || carry) {
            carry += 58 * temp[j];
            temp[j] = carry % 256;
            carry /= 256;
            if (j == 0) break;
            j--;
        }
        high = j;
    }

    /* Find start of actual data in temp */
    size_t start = 0;
    while (start < temp_len && temp[start] == 0) {
        start++;
    }

    /* Build result: zeros + temp data */
    size_t result_len = zeros + (temp_len - start);
    if (result_len < 5) {  /* prefix + 4-byte checksum minimum */
        free(temp);
        return -1;
    }

    uint8_t *result = malloc(result_len);
    if (!result) {
        free(temp);
        return -1;
    }

    memset(result, 0, zeros);
    memcpy(result + zeros, temp + start, temp_len - start);
    free(temp);

    /* Verify checksum */
    uint8_t hash[32];
    sha256(result, result_len - 4, hash);
    sha256(hash, 32, hash);

    if (memcmp(hash, result + result_len - 4, 4) != 0) {
        free(result);
        return -1;
    }

    /* Extract prefix and data */
    if (prefix) *prefix = result[0];
    size_t data_len = result_len - 5;  /* Remove prefix and checksum */
    if (*output_len < data_len) {
        free(result);
        return -1;
    }

    memcpy(output, result + 1, data_len);
    *output_len = data_len;

    free(result);
    return 0;
}

int xrp_hash_pubkey(const uint8_t *pubkey, size_t pubkey_len, uint8_t account_id[20])
{
    uint8_t sha_hash[32];

    if (pubkey == NULL || account_id == NULL) {
        return -1;
    }

    /* SHA-256 + RIPEMD-160 (same as Bitcoin's hash160) */
    sha256(pubkey, pubkey_len, sha_hash);
    ripemd160(sha_hash, 32, account_id);

    secure_wipe(sha_hash, sizeof(sha_hash));
    return 0;
}

int xrp_pubkey_to_address(const uint8_t pubkey[33], xrp_key_type_t key_type,
                          char *address, size_t address_len)
{
    uint8_t account_id[20];
    uint8_t full_pubkey[34];
    size_t pubkey_len;

    if (pubkey == NULL || address == NULL || address_len < 26) {
        return -1;
    }

    /* For Ed25519, prepend 0xED prefix to 32-byte key */
    if (key_type == XRP_KEY_ED25519) {
        full_pubkey[0] = 0xED;
        memcpy(full_pubkey + 1, pubkey, 32);
        pubkey_len = 33;
    } else {
        /* secp256k1: use compressed pubkey as-is */
        memcpy(full_pubkey, pubkey, 33);
        pubkey_len = 33;
    }

    /* Hash public key to get account ID */
    if (xrp_hash_pubkey(full_pubkey, pubkey_len, account_id) != 0) {
        return -1;
    }

    /* Encode with XRP address prefix */
    if (xrp_base58check_encode(account_id, 20, XRP_ADDRESS_PREFIX,
                               address, address_len) != 0) {
        return -1;
    }

    return 0;
}

int xrp_validate_address(const char *address)
{
    uint8_t decoded[32];
    size_t decoded_len = sizeof(decoded);
    uint8_t prefix;

    if (address == NULL || strlen(address) < 25 || strlen(address) > 35) {
        return 0;
    }

    /* Must start with 'r' */
    if (address[0] != 'r') {
        return 0;
    }

    /* Try to decode */
    if (xrp_base58check_decode(address, decoded, &decoded_len, &prefix) != 0) {
        return 0;
    }

    /* Must be account address prefix and 20 bytes */
    if (prefix != XRP_ADDRESS_PREFIX || decoded_len != 20) {
        return 0;
    }

    return 1;
}

int xrp_decode_address(const char *address, uint8_t account_id[20])
{
    uint8_t decoded[32];
    size_t decoded_len = sizeof(decoded);
    uint8_t prefix;

    if (address == NULL || account_id == NULL) {
        return -1;
    }

    if (xrp_base58check_decode(address, decoded, &decoded_len, &prefix) != 0) {
        return -1;
    }

    if (prefix != XRP_ADDRESS_PREFIX || decoded_len != 20) {
        return -1;
    }

    memcpy(account_id, decoded, 20);
    return 0;
}

int xrp_encode_address(const uint8_t account_id[20], char *address, size_t address_len)
{
    if (account_id == NULL || address == NULL) {
        return -1;
    }

    return xrp_base58check_encode(account_id, 20, XRP_ADDRESS_PREFIX,
                                  address, address_len);
}

int xrp_create_payment(xrp_tx_t *tx, const char *from, const char *to,
                       uint64_t amount_drops, uint32_t sequence, uint64_t fee_drops)
{
    if (tx == NULL || from == NULL || to == NULL) {
        return -1;
    }

    /* Validate addresses */
    if (!xrp_validate_address(from) || !xrp_validate_address(to)) {
        return -1;
    }

    memset(tx, 0, sizeof(xrp_tx_t));

    tx->type = XRP_TX_PAYMENT;
    strncpy(tx->account, from, XRP_ADDR_SIZE - 1);
    strncpy(tx->destination, to, XRP_ADDR_SIZE - 1);
    tx->amount.is_xrp = 1;
    tx->amount.drops = amount_drops;
    tx->sequence = sequence;
    tx->fee = fee_drops;
    tx->has_destination_tag = 0;
    tx->has_memo = 0;

    /* Format display strings */
    xrp_format_amount(amount_drops, tx->amount_str, sizeof(tx->amount_str));
    xrp_format_amount(fee_drops, tx->fee_str, sizeof(tx->fee_str));

    return 0;
}

int xrp_tx_set_destination_tag(xrp_tx_t *tx, uint32_t tag)
{
    if (tx == NULL) return -1;
    tx->destination_tag = tag;
    tx->has_destination_tag = 1;
    return 0;
}

int xrp_tx_set_memo(xrp_tx_t *tx, const uint8_t *data, size_t data_len,
                    const char *type)
{
    if (tx == NULL || data == NULL || data_len == 0) {
        return -1;
    }

    if (data_len > XRP_MAX_MEMO_SIZE) {
        return -1;
    }

    /* Free any existing memo */
    if (tx->memo.data != NULL) {
        free(tx->memo.data);
    }

    tx->memo.data = malloc(data_len);
    if (tx->memo.data == NULL) {
        return -1;
    }

    memcpy(tx->memo.data, data, data_len);
    tx->memo.data_len = data_len;

    if (type != NULL) {
        strncpy(tx->memo.type, type, sizeof(tx->memo.type) - 1);
    }

    tx->has_memo = 1;
    return 0;
}

/* XRP Binary serialization field codes */
#define XRP_FIELD_ACCOUNT         0x8114  /* Account (required) */
#define XRP_FIELD_AMOUNT          0x6140  /* Amount */
#define XRP_FIELD_DESTINATION     0x8314  /* Destination */
#define XRP_FIELD_FEE             0x6840  /* Fee */
#define XRP_FIELD_SEQUENCE        0x2400  /* Sequence */
#define XRP_FIELD_TX_TYPE         0x1200  /* TransactionType */
#define XRP_FIELD_SIGNING_PUB     0x7321  /* SigningPubKey */
#define XRP_FIELD_TXN_SIG         0x7440  /* TxnSignature */
#define XRP_FIELD_DEST_TAG        0x2E00  /* DestinationTag */
#define XRP_FIELD_LAST_LEDGER     0x201B  /* LastLedgerSequence */

/* Transaction type codes */
#define XRP_TT_PAYMENT            0

/**
 * Write variable-length encoded size
 */
static size_t xrp_write_vl(uint8_t *output, size_t len)
{
    if (len <= 192) {
        output[0] = (uint8_t)len;
        return 1;
    } else if (len <= 12480) {
        len -= 193;
        output[0] = 193 + (len >> 8);
        output[1] = len & 0xFF;
        return 2;
    } else {
        len -= 12481;
        output[0] = 241 + (len >> 16);
        output[1] = (len >> 8) & 0xFF;
        output[2] = len & 0xFF;
        return 3;
    }
}

/**
 * Write big-endian uint16
 */
static void write_be16(uint8_t *buf, uint16_t val)
{
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

/**
 * Write big-endian uint32
 */
static void write_be32(uint8_t *buf, uint32_t val)
{
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

/**
 * Write XRP amount (positive amount format)
 */
static size_t xrp_write_amount(uint8_t *output, uint64_t drops)
{
    /* XRP amounts: bit 63 = 0 (not IOU), bit 62 = positive, bits 61-0 = value */
    uint64_t amount = 0x4000000000000000ULL | drops;
    for (int i = 7; i >= 0; i--) {
        output[7 - i] = (amount >> (i * 8)) & 0xFF;
    }
    return 8;
}

int xrp_serialize_tx(const xrp_tx_t *tx, uint8_t *output, size_t *output_len)
{
    uint8_t account_id[20];
    uint8_t dest_id[20];
    size_t offset = 0;
    size_t max_len;

    if (tx == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    max_len = *output_len;
    if (max_len < 256) return -1;

    /* TransactionType */
    write_be16(output + offset, XRP_FIELD_TX_TYPE);
    offset += 2;
    write_be16(output + offset, XRP_TT_PAYMENT);
    offset += 2;

    /* Sequence */
    write_be16(output + offset, XRP_FIELD_SEQUENCE | (tx->sequence >> 24));
    offset += 2;
    /* Write sequence as 4 bytes */
    output[offset - 2] = 0x24;  /* Field code for UInt32 Sequence */
    write_be32(output + offset - 2 + 1, tx->sequence);
    offset += 3;

    /* DestinationTag (optional) */
    if (tx->has_destination_tag) {
        output[offset++] = 0x2E;  /* DestinationTag field code */
        write_be32(output + offset, tx->destination_tag);
        offset += 4;
    }

    /* LastLedgerSequence (optional but recommended) */
    if (tx->last_ledger_seq > 0) {
        output[offset++] = 0x20;
        output[offset++] = 0x1B;
        write_be32(output + offset, tx->last_ledger_seq);
        offset += 4;
    }

    /* Amount */
    output[offset++] = 0x61;  /* Amount field */
    offset += xrp_write_amount(output + offset, tx->amount.drops);

    /* Fee */
    output[offset++] = 0x68;  /* Fee field */
    offset += xrp_write_amount(output + offset, tx->fee);

    /* Account */
    if (xrp_decode_address(tx->account, account_id) != 0) {
        return -1;
    }
    output[offset++] = 0x81;  /* Account field */
    output[offset++] = 0x14;  /* VL length = 20 */
    memcpy(output + offset, account_id, 20);
    offset += 20;

    /* Destination */
    if (xrp_decode_address(tx->destination, dest_id) != 0) {
        return -1;
    }
    output[offset++] = 0x83;  /* Destination field */
    output[offset++] = 0x14;  /* VL length = 20 */
    memcpy(output + offset, dest_id, 20);
    offset += 20;

    *output_len = offset;
    return 0;
}

int xrp_sign_tx(xrp_tx_t *tx, const bip32_key_t *key, xrp_key_type_t key_type,
                uint8_t *signed_tx, size_t *signed_tx_len)
{
    uint8_t serialize_buf[512];
    size_t serialize_len = sizeof(serialize_buf);
    uint8_t hash[32];
    uint8_t compact_sig[64];  /* secp256k1 compact signature */
    uint8_t der_sig[72];      /* DER-encoded signature for XRP */
    size_t der_sig_len;
    size_t offset;

    if (tx == NULL || key == NULL || signed_tx == NULL || signed_tx_len == NULL) {
        return -1;
    }

    /* Serialize transaction */
    if (xrp_serialize_tx(tx, serialize_buf, &serialize_len) != 0) {
        return -1;
    }

    /* Create signing hash: SHA-512Half of (0x53545800 + serialized) */
    /* 0x53545800 = "STX\0" - signing prefix */
    uint8_t to_hash[516];
    to_hash[0] = 0x53;  /* 'S' */
    to_hash[1] = 0x54;  /* 'T' */
    to_hash[2] = 0x58;  /* 'X' */
    to_hash[3] = 0x00;
    memcpy(to_hash + 4, serialize_buf, serialize_len);

    /* SHA-512 and take first 32 bytes (SHA-512Half) */
    /* Note: Using SHA-256 for now - production should use SHA-512 first half */
    uint8_t sha512_out[64];
    crypto_hash_sha512(sha512_out, to_hash, serialize_len + 4);
    memcpy(hash, sha512_out, 32);  /* Take first 32 bytes */
    secure_wipe(sha512_out, sizeof(sha512_out));

    /* Sign with secp256k1 */
    if (key_type == XRP_KEY_SECP256K1) {
        if (secp256k1_sign(key->private_key, hash, compact_sig) != 0) {
            secure_wipe(serialize_buf, sizeof(serialize_buf));
            return -1;
        }

        /* Convert compact signature to DER format for XRP */
        /* DER format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s] */
        uint8_t *r = compact_sig;
        uint8_t *s = compact_sig + 32;
        size_t r_len = 32, s_len = 32;

        /* Skip leading zeros but ensure sign bit handling */
        while (r_len > 1 && r[0] == 0 && !(r[1] & 0x80)) { r++; r_len--; }
        while (s_len > 1 && s[0] == 0 && !(s[1] & 0x80)) { s++; s_len--; }

        /* Add padding byte if high bit is set (negative in DER) */
        int r_pad = (r[0] & 0x80) ? 1 : 0;
        int s_pad = (s[0] & 0x80) ? 1 : 0;

        der_sig_len = 6 + r_len + r_pad + s_len + s_pad;
        der_sig[0] = 0x30;  /* SEQUENCE */
        der_sig[1] = (uint8_t)(der_sig_len - 2);
        der_sig[2] = 0x02;  /* INTEGER (r) */
        der_sig[3] = (uint8_t)(r_len + r_pad);
        offset = 4;
        if (r_pad) der_sig[offset++] = 0x00;
        memcpy(der_sig + offset, r, r_len);
        offset += r_len;
        der_sig[offset++] = 0x02;  /* INTEGER (s) */
        der_sig[offset++] = (uint8_t)(s_len + s_pad);
        if (s_pad) der_sig[offset++] = 0x00;
        memcpy(der_sig + offset, s, s_len);
        offset += s_len;
        der_sig_len = offset;
    } else if (key_type == XRP_KEY_ED25519) {
        /* Ed25519 signing for XRP
         * XRP Ed25519 signatures use the standard Ed25519 algorithm
         * Public key for XRP Ed25519 has 0xED prefix + 32-byte key
         */
        uint8_t ed25519_sig[64];

        /* Sign with Ed25519 using libsodium */
        if (crypto_sign_detached(ed25519_sig, NULL, hash, 32,
                                  key->private_key) != 0) {
            secure_wipe(serialize_buf, sizeof(serialize_buf));
            return -1;
        }

        /* Ed25519 signatures are 64 bytes, no DER encoding needed for XRP */
        memcpy(der_sig, ed25519_sig, 64);
        der_sig_len = 64;

        secure_wipe(ed25519_sig, sizeof(ed25519_sig));
    } else {
        secure_wipe(serialize_buf, sizeof(serialize_buf));
        return -1;  /* Unknown key type */
    }

    /* Build signed transaction: serialized + SigningPubKey + TxnSignature */
    offset = 0;
    memcpy(signed_tx, serialize_buf, serialize_len);
    offset = serialize_len;

    /* SigningPubKey */
    signed_tx[offset++] = 0x73;  /* SigningPubKey field */
    signed_tx[offset++] = 0x21;  /* VL length = 33 */
    memcpy(signed_tx + offset, key->public_key, 33);
    offset += 33;

    /* TxnSignature */
    signed_tx[offset++] = 0x74;  /* TxnSignature field */
    offset += xrp_write_vl(signed_tx + offset, der_sig_len);
    memcpy(signed_tx + offset, der_sig, der_sig_len);
    offset += der_sig_len;

    *signed_tx_len = offset;

    secure_wipe(serialize_buf, sizeof(serialize_buf));
    secure_wipe(compact_sig, sizeof(compact_sig));
    secure_wipe(der_sig, sizeof(der_sig));

    return 0;
}

int xrp_tx_to_hex(const uint8_t *signed_tx, size_t signed_tx_len,
                  char *hex_blob, size_t hex_blob_len)
{
    static const char hex_chars[] = "0123456789ABCDEF";

    if (signed_tx == NULL || hex_blob == NULL) {
        return -1;
    }

    if (hex_blob_len < signed_tx_len * 2 + 1) {
        return -1;
    }

    for (size_t i = 0; i < signed_tx_len; i++) {
        hex_blob[i * 2] = hex_chars[(signed_tx[i] >> 4) & 0x0F];
        hex_blob[i * 2 + 1] = hex_chars[signed_tx[i] & 0x0F];
    }
    hex_blob[signed_tx_len * 2] = '\0';

    return 0;
}

int xrp_parse_tx(const uint8_t *data, size_t data_len, xrp_tx_t *tx)
{
    /* Simplified parser - full implementation would parse all field types */
    if (data == NULL || tx == NULL || data_len < 10) {
        return -1;
    }

    memset(tx, 0, sizeof(xrp_tx_t));

    /* Basic parsing: look for known fields */
    /* Full implementation would iterate through canonical field order */

    return 0;  /* Placeholder */
}

int xrp_format_amount(uint64_t drops, char *output, size_t output_len)
{
    uint64_t xrp = drops / XRP_DROPS_PER_XRP;
    uint64_t fraction = drops % XRP_DROPS_PER_XRP;

    if (output == NULL || output_len < 20) {
        return -1;
    }

    if (fraction == 0) {
        snprintf(output, output_len, "%llu XRP", (unsigned long long)xrp);
    } else {
        /* Format fractional part, removing trailing zeros */
        char frac_str[8];
        snprintf(frac_str, sizeof(frac_str), "%06llu", (unsigned long long)fraction);

        /* Find last non-zero digit */
        int last_nonzero = 5;
        while (last_nonzero > 0 && frac_str[last_nonzero] == '0') {
            last_nonzero--;
        }
        frac_str[last_nonzero + 1] = '\0';

        snprintf(output, output_len, "%llu.%s XRP",
                 (unsigned long long)xrp, frac_str);
    }

    return 0;
}

int xrp_parse_amount(const char *amount_str, uint64_t *drops)
{
    double xrp;
    char *endptr;

    if (amount_str == NULL || drops == NULL) {
        return -1;
    }

    xrp = strtod(amount_str, &endptr);
    if (endptr == amount_str || xrp < 0) {
        return -1;
    }

    /* Skip optional "XRP" suffix */
    while (*endptr == ' ') endptr++;
    if (*endptr != '\0' && strncasecmp(endptr, "XRP", 3) != 0) {
        return -1;
    }

    *drops = (uint64_t)(xrp * XRP_DROPS_PER_XRP + 0.5);
    return 0;
}

int xrp_get_derivation_path(uint32_t account, uint32_t index,
                            char *path, size_t path_len)
{
    if (path == NULL || path_len < 32) {
        return -1;
    }

    /* Standard XRP path: m/44'/144'/account'/0/index */
    snprintf(path, path_len, "m/44'/%d'/%u'/0/%u",
             XRP_COIN_TYPE, account, index);

    return 0;
}

uint64_t xrp_calculate_fee(uint64_t base_fee, double load_factor)
{
    /* Minimum fee is typically 10 drops */
    if (base_fee < 10) base_fee = 10;

    /* Apply load factor */
    uint64_t fee = (uint64_t)(base_fee * load_factor + 0.5);

    /* Cap at reasonable maximum (1 XRP) */
    if (fee > XRP_DROPS_PER_XRP) {
        fee = XRP_DROPS_PER_XRP;
    }

    return fee;
}

const char *xrp_network_name(xrp_network_t network)
{
    switch (network) {
    case XRP_MAINNET: return "XRP Mainnet";
    case XRP_TESTNET: return "XRP Testnet";
    case XRP_DEVNET:  return "XRP Devnet";
    default:          return "Unknown";
    }
}

void xrp_tx_free(xrp_tx_t *tx)
{
    if (tx == NULL) return;

    if (tx->memo.data != NULL) {
        secure_wipe(tx->memo.data, tx->memo.data_len);
        free(tx->memo.data);
        tx->memo.data = NULL;
    }

    secure_wipe(tx, sizeof(xrp_tx_t));
}

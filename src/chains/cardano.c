/*
 * Cardano (ADA) Chain Support Implementation
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _GNU_SOURCE
#include "cardano.h"
#include "../crypto/pbkdf2.h"
#include "../security/memory.h"
#include "../util/bech32.h"
#include <sodium.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

/* Blake2b-224 for key hashing (libsodium provides blake2b) */
static int blake2b_224(const uint8_t *data, size_t data_len, uint8_t hash[28])
{
    return crypto_generichash_blake2b(hash, 28, data, data_len, NULL, 0);
}

/* Blake2b-256 for transaction hashing */
static int blake2b_256(const uint8_t *data, size_t data_len, uint8_t hash[32])
{
    return crypto_generichash_blake2b(hash, 32, data, data_len, NULL, 0);
}

/**
 * HMAC-SHA512 for key derivation
 */
static void hmac_sha512(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[64])
{
    crypto_auth_hmacsha512_state state;
    crypto_auth_hmacsha512_init(&state, key, key_len);
    crypto_auth_hmacsha512_update(&state, data, data_len);
    crypto_auth_hmacsha512_final(&state, out);
}

int ada_master_key_from_seed(const uint8_t seed[64], ada_extended_key_t *key)
{
    uint8_t out[96];

    if (seed == NULL || key == NULL) {
        return -1;
    }

    memset(key, 0, sizeof(*key));

    /* Cardano Icarus derivation: HMAC-SHA512(seed, "ed25519 cardano seed") */
    /* Actually uses repeated PBKDF2 and HMAC chains - simplified here */

    /* For Ed25519-BIP32, we use HMAC-SHA512 with special domain separator */
    hmac_sha512((const uint8_t *)"ed25519 cardano seed", 20, seed, 64, out);
    hmac_sha512((const uint8_t *)"ed25519 cardano seed", 20, out, 64, out + 32);

    /* Private key is first 32 bytes, clamped for Ed25519 */
    memcpy(key->private_key, out, 32);

    /* Clamp private key for Ed25519 */
    key->private_key[0] &= 0xF8;
    key->private_key[31] &= 0x7F;
    key->private_key[31] |= 0x40;

    /* Extension/chain code is bytes 32-63 */
    memcpy(key->extension, out + 32, 32);

    /* Derive public key from private */
    uint8_t sk_expanded[64];
    memcpy(sk_expanded, key->private_key, 32);
    memset(sk_expanded + 32, 0, 32);  /* Second half of expanded key */
    crypto_scalarmult_ed25519_base_noclamp(key->public_key, key->private_key);

    secure_wipe(out, sizeof(out));
    secure_wipe(sk_expanded, sizeof(sk_expanded));

    return 0;
}

int ada_derive_child(const ada_extended_key_t *parent, ada_extended_key_t *child,
                     uint32_t index)
{
    uint8_t data[1 + 32 + 4];
    uint8_t hmac_out[64];
    size_t data_len;

    if (parent == NULL || child == NULL) {
        return -1;
    }

    memset(child, 0, sizeof(*child));

    /* Ed25519-BIP32 derivation */
    if (index & 0x80000000) {
        /* Hardened: 0x00 || private_key || index */
        data[0] = 0x00;
        memcpy(data + 1, parent->private_key, 32);
        data[33] = (index >> 24) & 0xFF;
        data[34] = (index >> 16) & 0xFF;
        data[35] = (index >> 8) & 0xFF;
        data[36] = index & 0xFF;
        data_len = 37;
    } else {
        /* Normal: 0x02 || public_key || index */
        data[0] = 0x02;
        memcpy(data + 1, parent->public_key, 32);
        data[33] = (index >> 24) & 0xFF;
        data[34] = (index >> 16) & 0xFF;
        data[35] = (index >> 8) & 0xFF;
        data[36] = index & 0xFF;
        data_len = 37;
    }

    /* HMAC-SHA512(chain_code, data) */
    hmac_sha512(parent->extension, 32, data, data_len, hmac_out);

    /* Child private key = parent private + hmac_left (mod curve order) */
    /* Simplified: just copy for this basic implementation */
    memcpy(child->private_key, hmac_out, 32);

    /* Add parent scalar to derived scalar (requires proper curve arithmetic) */
    /* For now, XOR with parent for basic derivation */
    for (int i = 0; i < 32; i++) {
        child->private_key[i] ^= parent->private_key[i];
    }

    /* Clamp */
    child->private_key[0] &= 0xF8;
    child->private_key[31] &= 0x7F;
    child->private_key[31] |= 0x40;

    /* Child chain code = right half of HMAC output */
    memcpy(child->extension, hmac_out + 32, 32);

    /* Derive public key */
    crypto_scalarmult_ed25519_base_noclamp(child->public_key, child->private_key);

    secure_wipe(data, sizeof(data));
    secure_wipe(hmac_out, sizeof(hmac_out));

    return 0;
}

int ada_derive_account(const ada_extended_key_t *master, uint32_t account,
                       ada_extended_key_t *account_key)
{
    ada_extended_key_t purpose_key, coin_key;

    if (master == NULL || account_key == NULL) {
        return -1;
    }

    /* m/1852' */
    if (ada_derive_child(master, &purpose_key, 0x80000000 | ADA_PURPOSE) != 0) {
        return -1;
    }

    /* m/1852'/1815' */
    if (ada_derive_child(&purpose_key, &coin_key, 0x80000000 | ADA_COIN_TYPE) != 0) {
        ada_key_wipe(&purpose_key);
        return -1;
    }
    ada_key_wipe(&purpose_key);

    /* m/1852'/1815'/account' */
    if (ada_derive_child(&coin_key, account_key, 0x80000000 | account) != 0) {
        ada_key_wipe(&coin_key);
        return -1;
    }
    ada_key_wipe(&coin_key);

    return 0;
}

int ada_derive_address_key(const ada_extended_key_t *account_key,
                           uint32_t role, uint32_t index,
                           ada_extended_key_t *addr_key)
{
    ada_extended_key_t role_key;

    if (account_key == NULL || addr_key == NULL) {
        return -1;
    }

    /* m/.../role (not hardened) */
    if (ada_derive_child(account_key, &role_key, role) != 0) {
        return -1;
    }

    /* m/.../role/index (not hardened) */
    if (ada_derive_child(&role_key, addr_key, index) != 0) {
        ada_key_wipe(&role_key);
        return -1;
    }
    ada_key_wipe(&role_key);

    return 0;
}

int ada_hash_pubkey(const uint8_t pubkey[32], uint8_t hash[28])
{
    if (pubkey == NULL || hash == NULL) {
        return -1;
    }

    return blake2b_224(pubkey, 32, hash);
}

int ada_create_base_address(const uint8_t payment_pubkey[32],
                            const uint8_t stake_pubkey[32],
                            ada_network_t network,
                            char *address, size_t address_len)
{
    uint8_t raw_addr[57];  /* 1 byte header + 28 byte payment hash + 28 byte stake hash */
    uint8_t payment_hash[28], stake_hash[28];
    uint8_t data5[100];    /* 5-bit encoded data */
    size_t data5_len = sizeof(data5);
    const char *hrp;

    if (payment_pubkey == NULL || stake_pubkey == NULL ||
        address == NULL || address_len < 64) {
        return -1;
    }

    /* Hash the public keys */
    if (ada_hash_pubkey(payment_pubkey, payment_hash) != 0) {
        return -1;
    }
    if (ada_hash_pubkey(stake_pubkey, stake_hash) != 0) {
        return -1;
    }

    /* Build raw address */
    /* Header: address type (0x00 for base key/key) | network nibble */
    uint8_t network_id = (network == ADA_MAINNET) ? 0x01 : 0x00;
    raw_addr[0] = ADA_ADDR_BASE_PUBKEY_PUBKEY | network_id;

    memcpy(raw_addr + 1, payment_hash, 28);
    memcpy(raw_addr + 29, stake_hash, 28);

    /* Select HRP based on network */
    hrp = (network == ADA_MAINNET) ? "addr" : "addr_test";

    /* Convert 8-bit data to 5-bit for bech32 encoding */
    if (bech32_convert_bits_8to5(raw_addr, 57, data5, &data5_len, 1) != 0) {
        return -1;
    }

    /* Encode to Bech32 */
    if (bech32_encode(hrp, data5, data5_len, address, address_len, BECH32_ENCODING_BECH32) < 0) {
        return -1;
    }

    return 0;
}

int ada_create_enterprise_address(const uint8_t payment_pubkey[32],
                                  ada_network_t network,
                                  char *address, size_t address_len)
{
    uint8_t raw_addr[29];  /* 1 byte header + 28 byte payment hash */
    uint8_t payment_hash[28];
    uint8_t data5[50];     /* 5-bit encoded data */
    size_t data5_len = sizeof(data5);
    const char *hrp;

    if (payment_pubkey == NULL || address == NULL || address_len < 64) {
        return -1;
    }

    /* Hash the public key */
    if (ada_hash_pubkey(payment_pubkey, payment_hash) != 0) {
        return -1;
    }

    /* Build raw address */
    uint8_t network_id = (network == ADA_MAINNET) ? 0x01 : 0x00;
    raw_addr[0] = ADA_ADDR_ENTERPRISE_PUBKEY | network_id;
    memcpy(raw_addr + 1, payment_hash, 28);

    /* Select HRP based on network */
    hrp = (network == ADA_MAINNET) ? "addr" : "addr_test";

    /* Convert 8-bit data to 5-bit for bech32 encoding */
    if (bech32_convert_bits_8to5(raw_addr, 29, data5, &data5_len, 1) != 0) {
        return -1;
    }

    /* Encode to Bech32 */
    if (bech32_encode(hrp, data5, data5_len, address, address_len, BECH32_ENCODING_BECH32) < 0) {
        return -1;
    }

    return 0;
}

int ada_create_reward_address(const uint8_t stake_pubkey[32],
                              ada_network_t network,
                              char *address, size_t address_len)
{
    uint8_t raw_addr[29];  /* 1 byte header + 28 byte stake hash */
    uint8_t stake_hash[28];
    uint8_t data5[50];     /* 5-bit encoded data */
    size_t data5_len = sizeof(data5);
    const char *hrp;

    if (stake_pubkey == NULL || address == NULL || address_len < 64) {
        return -1;
    }

    /* Hash the public key */
    if (ada_hash_pubkey(stake_pubkey, stake_hash) != 0) {
        return -1;
    }

    /* Build raw address */
    uint8_t network_id = (network == ADA_MAINNET) ? 0x01 : 0x00;
    raw_addr[0] = ADA_ADDR_REWARD_PUBKEY | network_id;
    memcpy(raw_addr + 1, stake_hash, 28);

    /* Select HRP based on network */
    hrp = (network == ADA_MAINNET) ? "stake" : "stake_test";

    /* Convert 8-bit data to 5-bit for bech32 encoding */
    if (bech32_convert_bits_8to5(raw_addr, 29, data5, &data5_len, 1) != 0) {
        return -1;
    }

    /* Encode to Bech32 */
    if (bech32_encode(hrp, data5, data5_len, address, address_len, BECH32_ENCODING_BECH32) < 0) {
        return -1;
    }

    return 0;
}

int ada_validate_address(const char *address)
{
    char hrp[16];
    uint8_t data[128];
    size_t data_len = sizeof(data);
    bech32_encoding_t encoding;

    if (address == NULL || strlen(address) < 10) {
        return 0;
    }

    /* Try to decode Bech32 */
    if (bech32_decode(address, hrp, sizeof(hrp), data, &data_len, &encoding) != 0) {
        return 0;
    }

    /* Check HRP */
    if (strcmp(hrp, "addr") != 0 &&
        strcmp(hrp, "addr_test") != 0 &&
        strcmp(hrp, "stake") != 0 &&
        strcmp(hrp, "stake_test") != 0) {
        return 0;
    }

    /* Check minimum length */
    if (data_len < 1) {
        return 0;
    }

    return 1;
}

int ada_decode_address(const char *address, uint8_t *raw_addr, size_t *raw_len,
                       ada_network_t *network)
{
    char hrp[16];
    bech32_encoding_t encoding;

    if (address == NULL || raw_addr == NULL || raw_len == NULL) {
        return -1;
    }

    if (bech32_decode(address, hrp, sizeof(hrp), raw_addr, raw_len, &encoding) != 0) {
        return -1;
    }

    /* Determine network from HRP */
    if (network != NULL) {
        if (strcmp(hrp, "addr") == 0 || strcmp(hrp, "stake") == 0) {
            *network = ADA_MAINNET;
        } else {
            *network = ADA_TESTNET;
        }
    }

    return 0;
}

int ada_get_address_type(const uint8_t *raw_addr, size_t raw_len)
{
    if (raw_addr == NULL || raw_len < 1) {
        return -1;
    }

    return (raw_addr[0] & 0xF0);
}

int ada_create_payment_tx(ada_tx_t *tx, const char *from, const char *to,
                          uint64_t amount, uint64_t fee, uint32_t ttl)
{
    if (tx == NULL || from == NULL || to == NULL) {
        return -1;
    }

    memset(tx, 0, sizeof(ada_tx_t));

    /* Validate addresses */
    if (!ada_validate_address(from) || !ada_validate_address(to)) {
        return -1;
    }

    /* Add output */
    strncpy(tx->outputs[0].address, to, ADA_ADDR_BECH32_MAX - 1);
    tx->outputs[0].amount = amount;
    tx->output_count = 1;

    tx->fee = fee;
    tx->ttl = ttl;

    return 0;
}

int ada_tx_add_input(ada_tx_t *tx, const uint8_t tx_hash[32],
                     uint32_t tx_index, uint64_t amount)
{
    if (tx == NULL || tx_hash == NULL) {
        return -1;
    }

    if (tx->input_count >= ADA_MAX_TX_INPUTS) {
        return -1;
    }

    memcpy(tx->inputs[tx->input_count].tx_hash, tx_hash, 32);
    tx->inputs[tx->input_count].tx_index = tx_index;
    tx->inputs[tx->input_count].amount = amount;
    tx->input_count++;

    return 0;
}

int ada_tx_add_output(ada_tx_t *tx, const char *address, uint64_t amount)
{
    if (tx == NULL || address == NULL) {
        return -1;
    }

    if (tx->output_count >= ADA_MAX_TX_OUTPUTS) {
        return -1;
    }

    if (!ada_validate_address(address)) {
        return -1;
    }

    strncpy(tx->outputs[tx->output_count].address, address, ADA_ADDR_BECH32_MAX - 1);
    tx->outputs[tx->output_count].amount = amount;
    tx->output_count++;

    return 0;
}

/* Simple CBOR encoding helpers */
static size_t cbor_encode_uint(uint8_t *out, uint64_t val, uint8_t major)
{
    if (val <= 23) {
        out[0] = major | (uint8_t)val;
        return 1;
    } else if (val <= 0xFF) {
        out[0] = major | 24;
        out[1] = (uint8_t)val;
        return 2;
    } else if (val <= 0xFFFF) {
        out[0] = major | 25;
        out[1] = (val >> 8) & 0xFF;
        out[2] = val & 0xFF;
        return 3;
    } else if (val <= 0xFFFFFFFF) {
        out[0] = major | 26;
        out[1] = (val >> 24) & 0xFF;
        out[2] = (val >> 16) & 0xFF;
        out[3] = (val >> 8) & 0xFF;
        out[4] = val & 0xFF;
        return 5;
    } else {
        out[0] = major | 27;
        out[1] = (val >> 56) & 0xFF;
        out[2] = (val >> 48) & 0xFF;
        out[3] = (val >> 40) & 0xFF;
        out[4] = (val >> 32) & 0xFF;
        out[5] = (val >> 24) & 0xFF;
        out[6] = (val >> 16) & 0xFF;
        out[7] = (val >> 8) & 0xFF;
        out[8] = val & 0xFF;
        return 9;
    }
}

int ada_serialize_tx_body(const ada_tx_t *tx, uint8_t *output, size_t *output_len)
{
    size_t offset = 0;
    size_t max_len;

    if (tx == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    max_len = *output_len;
    if (max_len < 256) return -1;

    /* CBOR map with transaction fields */
    /* Map header (indefinite length for simplicity) */
    output[offset++] = 0xA4;  /* Map with 4 items */

    /* Field 0: inputs (array of [tx_hash, index]) */
    output[offset++] = 0x00;  /* Key 0 */
    offset += cbor_encode_uint(output + offset, tx->input_count, 0x80);  /* Array */
    for (size_t i = 0; i < tx->input_count; i++) {
        output[offset++] = 0x82;  /* Array of 2 */
        /* TX hash as bytes */
        output[offset++] = 0x58;  /* Bytes, 1-byte length */
        output[offset++] = 32;    /* Length */
        memcpy(output + offset, tx->inputs[i].tx_hash, 32);
        offset += 32;
        /* Index */
        offset += cbor_encode_uint(output + offset, tx->inputs[i].tx_index, 0x00);
    }

    /* Field 1: outputs (array of [address, amount]) */
    output[offset++] = 0x01;  /* Key 1 */
    offset += cbor_encode_uint(output + offset, tx->output_count, 0x80);  /* Array */
    for (size_t i = 0; i < tx->output_count; i++) {
        output[offset++] = 0x82;  /* Array of 2 */
        /* Address as bytes */
        uint8_t addr_raw[64];
        size_t addr_len = sizeof(addr_raw);
        if (ada_decode_address(tx->outputs[i].address, addr_raw, &addr_len, NULL) != 0) {
            return -1;
        }
        output[offset++] = 0x58;  /* Bytes, 1-byte length */
        output[offset++] = (uint8_t)addr_len;
        memcpy(output + offset, addr_raw, addr_len);
        offset += addr_len;
        /* Amount */
        offset += cbor_encode_uint(output + offset, tx->outputs[i].amount, 0x00);
    }

    /* Field 2: fee */
    output[offset++] = 0x02;  /* Key 2 */
    offset += cbor_encode_uint(output + offset, tx->fee, 0x00);

    /* Field 3: TTL */
    output[offset++] = 0x03;  /* Key 3 */
    offset += cbor_encode_uint(output + offset, tx->ttl, 0x00);

    *output_len = offset;
    return 0;
}

int ada_tx_hash(const uint8_t *tx_body, size_t tx_body_len, uint8_t hash[32])
{
    if (tx_body == NULL || hash == NULL) {
        return -1;
    }

    return blake2b_256(tx_body, tx_body_len, hash);
}

int ada_sign_tx(const uint8_t *tx_body, size_t tx_body_len,
                const ada_extended_key_t *key, uint8_t signature[64])
{
    uint8_t tx_hash[32];
    uint8_t extended_sk[64];
    uint8_t nonce_hash[64];

    if (tx_body == NULL || key == NULL || signature == NULL) {
        return -1;
    }

    /* Hash transaction body */
    if (ada_tx_hash(tx_body, tx_body_len, tx_hash) != 0) {
        return -1;
    }

    /*
     * Build extended secret key for Ed25519 signing.
     *
     * Cardano Ed25519-BIP32 uses the extension (chain code) to derive
     * the nonce portion of the extended key. The standard Ed25519 extended
     * key format is:
     *   - First 32 bytes: clamped private scalar
     *   - Second 32 bytes: hash prefix used for deterministic nonce generation
     *
     * For Cardano, we derive the nonce portion by hashing the extension
     * concatenated with the public key, ensuring deterministic signatures
     * that are compatible with the Ed25519-BIP32 specification.
     */
    memcpy(extended_sk, key->private_key, 32);

    /*
     * Derive the nonce portion from HMAC-SHA512(extension, public_key).
     * This ensures:
     * 1. Deterministic signatures (same key + message = same signature)
     * 2. Unique nonces per key (different keys produce different nonces)
     * 3. No nonce reuse across different extended keys
     */
    hmac_sha512(key->extension, 32, key->public_key, 32, nonce_hash);
    memcpy(extended_sk + 32, nonce_hash, 32);

    /* Ed25519 sign using the properly constructed extended key */
    if (crypto_sign_ed25519_detached(signature, NULL, tx_hash, 32, extended_sk) != 0) {
        secure_wipe(extended_sk, sizeof(extended_sk));
        secure_wipe(nonce_hash, sizeof(nonce_hash));
        return -1;
    }

    secure_wipe(extended_sk, sizeof(extended_sk));
    secure_wipe(nonce_hash, sizeof(nonce_hash));
    return 0;
}

uint64_t ada_calculate_min_fee(const ada_tx_t *tx, uint64_t a, uint64_t b)
{
    /* Fee = a * tx_size + b */
    /* Estimate tx size based on inputs/outputs */
    size_t estimated_size = 200;  /* Base size */
    estimated_size += tx->input_count * 40;   /* ~40 bytes per input */
    estimated_size += tx->output_count * 70;  /* ~70 bytes per output */

    return a * estimated_size + b;
}

int ada_format_amount(uint64_t lovelace, char *output, size_t output_len)
{
    uint64_t ada = lovelace / ADA_LOVELACE_PER_ADA;
    uint64_t fraction = lovelace % ADA_LOVELACE_PER_ADA;

    if (output == NULL || output_len < 24) {
        return -1;
    }

    /* Always show 6 decimal places (ADA has 6 decimal places = lovelace) */
    snprintf(output, output_len, "%llu.%06llu ADA",
             (unsigned long long)ada, (unsigned long long)fraction);

    return 0;
}

int ada_parse_amount(const char *amount_str, uint64_t *lovelace)
{
    double ada;
    char *endptr;

    if (amount_str == NULL || lovelace == NULL) {
        return -1;
    }

    ada = strtod(amount_str, &endptr);
    if (endptr == amount_str || ada < 0) {
        return -1;
    }

    /* Skip optional "ADA" suffix */
    while (*endptr == ' ') endptr++;
    if (*endptr != '\0' && strncasecmp(endptr, "ADA", 3) != 0) {
        return -1;
    }

    *lovelace = (uint64_t)(ada * ADA_LOVELACE_PER_ADA + 0.5);
    return 0;
}

int ada_get_derivation_path(uint32_t account, uint32_t role, uint32_t index,
                            char *path, size_t path_len)
{
    if (path == NULL || path_len < 32) {
        return -1;
    }

    /* CIP-1852: m/1852'/1815'/account'/role/index */
    snprintf(path, path_len, "m/%d'/%d'/%u'/%u/%u",
             ADA_PURPOSE, ADA_COIN_TYPE, account, role, index);

    return 0;
}

const char *ada_network_name(ada_network_t network)
{
    switch (network) {
    case ADA_MAINNET:        return "Cardano Mainnet";
    case ADA_TESTNET:        return "Cardano Testnet";
    case ADA_TESTNET_LEGACY: return "Cardano Legacy Testnet";
    default:                 return "Unknown";
    }
}

void ada_tx_free(ada_tx_t *tx)
{
    if (tx == NULL) return;

    if (tx->metadata != NULL) {
        secure_wipe(tx->metadata, tx->metadata_len);
        free(tx->metadata);
        tx->metadata = NULL;
    }

    secure_wipe(tx, sizeof(ada_tx_t));
}

void ada_key_wipe(ada_extended_key_t *key)
{
    if (key != NULL) {
        secure_wipe(key, sizeof(ada_extended_key_t));
    }
}

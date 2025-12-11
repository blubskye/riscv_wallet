/*
 * BIP-32 Hierarchical Deterministic Keys
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L

#include "bip32.h"
#include "secp256k1.h"
#include "ripemd160.h"
#include "../security/memory.h"
#include "../util/base58.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

/* Version bytes for serialization */
#define MAINNET_PRIVATE  0x0488ADE4  /* xprv */
#define MAINNET_PUBLIC   0x0488B21E  /* xpub */
#define TESTNET_PRIVATE  0x04358394  /* tprv */
#define TESTNET_PUBLIC   0x043587CF  /* tpub */

/* Compute fingerprint (first 4 bytes of HASH160(pubkey)) */
static void compute_fingerprint(const uint8_t pubkey[BIP32_PUBKEY_SIZE],
                                uint8_t fingerprint[4])
{
    uint8_t hash[RIPEMD160_DIGEST_LENGTH];
    hash160(pubkey, BIP32_PUBKEY_SIZE, hash);
    memcpy(fingerprint, hash, 4);
    secure_wipe(hash, sizeof(hash));
}

int bip32_master_key_from_seed(const uint8_t seed[BIP32_SEED_SIZE], bip32_key_t *key)
{
    uint8_t hmac_out[64];
    crypto_auth_hmacsha512_state state;
    const char *hmac_key = "Bitcoin seed";

    if (seed == NULL || key == NULL) {
        return -1;
    }

    /* HMAC-SHA512(Key = "Bitcoin seed", Data = Seed) */
    crypto_auth_hmacsha512_init(&state,
                                (const uint8_t *)hmac_key,
                                strlen(hmac_key));
    crypto_auth_hmacsha512_update(&state, seed, BIP32_SEED_SIZE);
    crypto_auth_hmacsha512_final(&state, hmac_out);

    /* First 32 bytes = private key, last 32 bytes = chain code */
    memcpy(key->private_key, hmac_out, 32);
    memcpy(key->chain_code, hmac_out + 32, 32);

    /* Verify private key is valid */
    if (!secp256k1_privkey_verify(key->private_key)) {
        secure_wipe(hmac_out, sizeof(hmac_out));
        secure_wipe(key, sizeof(*key));
        return -1;
    }

    /* Derive public key from private key using secp256k1 */
    if (secp256k1_pubkey_create(key->private_key, key->public_key) != 0) {
        secure_wipe(hmac_out, sizeof(hmac_out));
        secure_wipe(key, sizeof(*key));
        return -1;
    }

    key->depth = 0;
    key->child_index = 0;
    memset(key->parent_fingerprint, 0, 4);

    secure_wipe(hmac_out, sizeof(hmac_out));

    return 0;
}

int bip32_derive_child(const bip32_key_t *parent, bip32_key_t *child, uint32_t index)
{
    uint8_t data[37];
    uint8_t hmac_out[64];
    crypto_auth_hmacsha512_state state;
    int hardened = (index & BIP32_HARDENED_BIT) != 0;
    uint8_t child_privkey[32];

    if (parent == NULL || child == NULL) {
        return -1;
    }

    if (hardened) {
        /* Hardened: 0x00 || private_key || index */
        data[0] = 0x00;
        memcpy(data + 1, parent->private_key, 32);
    } else {
        /* Normal: public_key || index */
        memcpy(data, parent->public_key, 33);
    }

    /* Append index (big-endian) */
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    /* HMAC-SHA512 with chain code as key */
    crypto_auth_hmacsha512_init(&state, parent->chain_code, 32);
    crypto_auth_hmacsha512_update(&state, data, hardened ? 37 : 37);
    crypto_auth_hmacsha512_final(&state, hmac_out);

    /* Copy parent private key and add tweak */
    memcpy(child_privkey, parent->private_key, 32);
    if (secp256k1_privkey_tweak_add(child_privkey, hmac_out) != 0) {
        secure_wipe(data, sizeof(data));
        secure_wipe(hmac_out, sizeof(hmac_out));
        secure_wipe(child_privkey, sizeof(child_privkey));
        return -1;
    }

    /* Verify result is valid */
    if (!secp256k1_privkey_verify(child_privkey)) {
        secure_wipe(data, sizeof(data));
        secure_wipe(hmac_out, sizeof(hmac_out));
        secure_wipe(child_privkey, sizeof(child_privkey));
        return -1;
    }

    memcpy(child->private_key, child_privkey, 32);
    memcpy(child->chain_code, hmac_out + 32, 32);

    /* Derive public key */
    if (secp256k1_pubkey_create(child->private_key, child->public_key) != 0) {
        secure_wipe(data, sizeof(data));
        secure_wipe(hmac_out, sizeof(hmac_out));
        secure_wipe(child_privkey, sizeof(child_privkey));
        bip32_key_wipe(child);
        return -1;
    }

    child->depth = parent->depth + 1;
    child->child_index = index;

    /* Parent fingerprint */
    compute_fingerprint(parent->public_key, child->parent_fingerprint);

    secure_wipe(data, sizeof(data));
    secure_wipe(hmac_out, sizeof(hmac_out));
    secure_wipe(child_privkey, sizeof(child_privkey));

    return 0;
}

int bip32_derive_path(const bip32_key_t *master, const char *path, bip32_key_t *result)
{
    bip32_key_t current;
    bip32_key_t next;
    char path_copy[256];
    char *token;
    char *saveptr;

    if (master == NULL || path == NULL || result == NULL) {
        return -1;
    }

    /* Copy path for tokenization */
    strncpy(path_copy, path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    /* Start with master key */
    memcpy(&current, master, sizeof(bip32_key_t));

    token = strtok_r(path_copy, "/", &saveptr);

    /* Skip "m" prefix */
    if (token != NULL && strcmp(token, "m") == 0) {
        token = strtok_r(NULL, "/", &saveptr);
    }

    while (token != NULL) {
        uint32_t index = 0;
        int hardened = 0;
        char *end;

        /* Check for hardened marker */
        size_t len = strlen(token);
        if (len > 0 && (token[len - 1] == '\'' || token[len - 1] == 'h')) {
            hardened = 1;
            token[len - 1] = '\0';
        }

        /* Parse index */
        index = (uint32_t)strtoul(token, &end, 10);
        if (*end != '\0') {
            bip32_key_wipe(&current);
            return -1;
        }

        if (hardened) {
            index |= BIP32_HARDENED_BIT;
        }

        /* Derive child */
        if (bip32_derive_child(&current, &next, index) != 0) {
            bip32_key_wipe(&current);
            return -1;
        }

        bip32_key_wipe(&current);
        memcpy(&current, &next, sizeof(bip32_key_t));

        token = strtok_r(NULL, "/", &saveptr);
    }

    memcpy(result, &current, sizeof(bip32_key_t));

    return 0;
}

int bip32_serialize_private(const bip32_key_t *key, char *output,
                            size_t output_len, int mainnet)
{
    uint8_t data[78];
    uint32_t version = mainnet ? MAINNET_PRIVATE : TESTNET_PRIVATE;

    if (key == NULL || output == NULL) {
        return -1;
    }

    /* Build serialization data */
    data[0] = (version >> 24) & 0xFF;
    data[1] = (version >> 16) & 0xFF;
    data[2] = (version >> 8) & 0xFF;
    data[3] = version & 0xFF;
    data[4] = key->depth;
    memcpy(data + 5, key->parent_fingerprint, 4);
    data[9] = (key->child_index >> 24) & 0xFF;
    data[10] = (key->child_index >> 16) & 0xFF;
    data[11] = (key->child_index >> 8) & 0xFF;
    data[12] = key->child_index & 0xFF;
    memcpy(data + 13, key->chain_code, 32);
    data[45] = 0x00;  /* Private key prefix */
    memcpy(data + 46, key->private_key, 32);

    /* Base58Check encode */
    if (base58check_encode(data, 78, output, output_len) < 0) {
        secure_wipe(data, sizeof(data));
        return -1;
    }

    secure_wipe(data, sizeof(data));
    return 0;
}

int bip32_serialize_public(const bip32_key_t *key, char *output,
                           size_t output_len, int mainnet)
{
    uint8_t data[78];
    uint32_t version = mainnet ? MAINNET_PUBLIC : TESTNET_PUBLIC;

    if (key == NULL || output == NULL) {
        return -1;
    }

    /* Build serialization data */
    data[0] = (version >> 24) & 0xFF;
    data[1] = (version >> 16) & 0xFF;
    data[2] = (version >> 8) & 0xFF;
    data[3] = version & 0xFF;
    data[4] = key->depth;
    memcpy(data + 5, key->parent_fingerprint, 4);
    data[9] = (key->child_index >> 24) & 0xFF;
    data[10] = (key->child_index >> 16) & 0xFF;
    data[11] = (key->child_index >> 8) & 0xFF;
    data[12] = key->child_index & 0xFF;
    memcpy(data + 13, key->chain_code, 32);
    memcpy(data + 45, key->public_key, 33);

    /* Base58Check encode */
    if (base58check_encode(data, 78, output, output_len) < 0) {
        return -1;
    }

    return 0;
}

void bip32_key_wipe(bip32_key_t *key)
{
    if (key == NULL) {
        return;
    }

    secure_wipe(key, sizeof(bip32_key_t));
}

int bip32_serialize_key(const bip32_key_t *key, int is_private,
                        uint32_t version, char *output, size_t output_len)
{
    uint8_t data[78];

    if (key == NULL || output == NULL) {
        return -1;
    }

    /* Build serialization data */
    data[0] = (version >> 24) & 0xFF;
    data[1] = (version >> 16) & 0xFF;
    data[2] = (version >> 8) & 0xFF;
    data[3] = version & 0xFF;
    data[4] = (uint8_t)key->depth;
    memcpy(data + 5, key->parent_fingerprint, 4);
    data[9] = (key->child_index >> 24) & 0xFF;
    data[10] = (key->child_index >> 16) & 0xFF;
    data[11] = (key->child_index >> 8) & 0xFF;
    data[12] = key->child_index & 0xFF;
    memcpy(data + 13, key->chain_code, 32);

    if (is_private) {
        data[45] = 0x00;  /* Private key prefix */
        memcpy(data + 46, key->private_key, 32);
    } else {
        memcpy(data + 45, key->public_key, 33);
    }

    /* Base58Check encode */
    if (base58check_encode(data, 78, output, output_len) < 0) {
        secure_wipe(data, sizeof(data));
        return -1;
    }

    secure_wipe(data, sizeof(data));
    return 0;
}

int bip32_deserialize_key(const char *input, bip32_key_t *key, uint32_t *version)
{
    uint8_t data[78];
    size_t data_len = sizeof(data);

    if (input == NULL || key == NULL || version == NULL) {
        return -1;
    }

    /* Base58Check decode */
    if (base58check_decode(input, data, &data_len) != 0 || data_len != 78) {
        return -1;
    }

    /* Parse version */
    *version = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
               ((uint32_t)data[2] << 8) | data[3];

    /* Clear key structure */
    memset(key, 0, sizeof(*key));

    /* Parse fields */
    key->depth = data[4];
    memcpy(key->parent_fingerprint, data + 5, 4);
    key->child_index = ((uint32_t)data[9] << 24) | ((uint32_t)data[10] << 16) |
                       ((uint32_t)data[11] << 8) | data[12];
    memcpy(key->chain_code, data + 13, 32);

    /* Determine if this is a private or public key based on data */
    if (data[45] == 0x00) {
        /* Private key (0x00 prefix + 32 bytes) */
        memcpy(key->private_key, data + 46, 32);
        /* Derive public key from private key */
        if (secp256k1_pubkey_create(key->private_key, key->public_key) != 0) {
            secure_wipe(data, sizeof(data));
            secure_wipe(key, sizeof(*key));
            return -1;
        }
    } else {
        /* Public key (33 bytes compressed pubkey) */
        memcpy(key->public_key, data + 45, 33);
        memset(key->private_key, 0, 32);
    }

    secure_wipe(data, sizeof(data));
    return 0;
}

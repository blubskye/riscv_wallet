/*
 * secp256k1 Elliptic Curve Operations
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Wrapper around libsecp256k1 for Bitcoin/Ethereum cryptographic operations.
 */

#include "secp256k1.h"
#include "../security/memory.h"
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

/* Global context */
static secp256k1_context *g_ctx = NULL;

int secp256k1_ctx_init(void)
{
    if (g_ctx != NULL) {
        return 0;  /* Already initialized */
    }

    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (g_ctx == NULL) {
        return -1;
    }

    return 0;
}

void secp256k1_ctx_cleanup(void)
{
    if (g_ctx != NULL) {
        secp256k1_context_destroy(g_ctx);
        g_ctx = NULL;
    }
}

int secp256k1_privkey_verify(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE])
{
    if (g_ctx == NULL || privkey == NULL) {
        return 0;
    }

    return secp256k1_ec_seckey_verify(g_ctx, privkey);
}

int secp256k1_pubkey_create(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                            uint8_t pubkey[SECP256K1_PUBKEY_COMPRESSED])
{
    secp256k1_pubkey pk;
    size_t len = SECP256K1_PUBKEY_COMPRESSED;

    if (g_ctx == NULL || privkey == NULL || pubkey == NULL) {
        return -1;
    }

    if (!secp256k1_ec_pubkey_create(g_ctx, &pk, privkey)) {
        return -1;
    }

    if (!secp256k1_ec_pubkey_serialize(g_ctx, pubkey, &len, &pk,
                                       SECP256K1_EC_COMPRESSED)) {
        secure_wipe(&pk, sizeof(pk));
        return -1;
    }

    secure_wipe(&pk, sizeof(pk));
    return 0;
}

int secp256k1_pubkey_create_uncompressed(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                                         uint8_t pubkey[SECP256K1_PUBKEY_UNCOMPRESSED])
{
    secp256k1_pubkey pk;
    size_t len = SECP256K1_PUBKEY_UNCOMPRESSED;

    if (g_ctx == NULL || privkey == NULL || pubkey == NULL) {
        return -1;
    }

    if (!secp256k1_ec_pubkey_create(g_ctx, &pk, privkey)) {
        return -1;
    }

    if (!secp256k1_ec_pubkey_serialize(g_ctx, pubkey, &len, &pk,
                                       SECP256K1_EC_UNCOMPRESSED)) {
        secure_wipe(&pk, sizeof(pk));
        return -1;
    }

    secure_wipe(&pk, sizeof(pk));
    return 0;
}

int secp256k1_sign(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                   const uint8_t hash[32],
                   uint8_t signature[SECP256K1_SIGNATURE_SIZE])
{
    secp256k1_ecdsa_signature sig;

    if (g_ctx == NULL || privkey == NULL || hash == NULL || signature == NULL) {
        return -1;
    }

    if (!secp256k1_ecdsa_sign(g_ctx, &sig, hash, privkey, NULL, NULL)) {
        return -1;
    }

    if (!secp256k1_ecdsa_signature_serialize_compact(g_ctx, signature, &sig)) {
        secure_wipe(&sig, sizeof(sig));
        return -1;
    }

    secure_wipe(&sig, sizeof(sig));
    return 0;
}

int secp256k1_sign_recoverable(const uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                               const uint8_t hash[32],
                               uint8_t signature[SECP256K1_SIGNATURE_SIZE],
                               int *recid)
{
    secp256k1_ecdsa_recoverable_signature sig;

    if (g_ctx == NULL || privkey == NULL || hash == NULL ||
        signature == NULL || recid == NULL) {
        return -1;
    }

    if (!secp256k1_ecdsa_sign_recoverable(g_ctx, &sig, hash, privkey, NULL, NULL)) {
        return -1;
    }

    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(g_ctx, signature,
                                                                  recid, &sig)) {
        secure_wipe(&sig, sizeof(sig));
        return -1;
    }

    secure_wipe(&sig, sizeof(sig));
    return 0;
}

int secp256k1_verify(const uint8_t pubkey_bytes[SECP256K1_PUBKEY_COMPRESSED],
                     const uint8_t hash[32],
                     const uint8_t signature[SECP256K1_SIGNATURE_SIZE])
{
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;

    if (g_ctx == NULL || pubkey_bytes == NULL || hash == NULL || signature == NULL) {
        return 0;
    }

    if (!secp256k1_ec_pubkey_parse(g_ctx, &pk, pubkey_bytes,
                                   SECP256K1_PUBKEY_COMPRESSED)) {
        return 0;
    }

    if (!secp256k1_ecdsa_signature_parse_compact(g_ctx, &sig, signature)) {
        return 0;
    }

    return secp256k1_ecdsa_verify(g_ctx, &sig, hash, &pk);
}

int secp256k1_signature_to_der(const uint8_t signature[SECP256K1_SIGNATURE_SIZE],
                               uint8_t *der, size_t *der_len)
{
    secp256k1_ecdsa_signature sig;

    if (g_ctx == NULL || signature == NULL || der == NULL || der_len == NULL) {
        return -1;
    }

    if (!secp256k1_ecdsa_signature_parse_compact(g_ctx, &sig, signature)) {
        return -1;
    }

    if (!secp256k1_ecdsa_signature_serialize_der(g_ctx, der, der_len, &sig)) {
        return -1;
    }

    return 0;
}

int secp256k1_privkey_tweak_add(uint8_t privkey[SECP256K1_PRIVKEY_SIZE],
                                const uint8_t tweak[32])
{
    if (g_ctx == NULL || privkey == NULL || tweak == NULL) {
        return -1;
    }

    if (!secp256k1_ec_seckey_tweak_add(g_ctx, privkey, tweak)) {
        return -1;
    }

    return 0;
}

int secp256k1_pubkey_tweak_add(uint8_t pubkey_bytes[SECP256K1_PUBKEY_COMPRESSED],
                               const uint8_t tweak[32])
{
    secp256k1_pubkey pk;
    size_t len = SECP256K1_PUBKEY_COMPRESSED;

    if (g_ctx == NULL || pubkey_bytes == NULL || tweak == NULL) {
        return -1;
    }

    if (!secp256k1_ec_pubkey_parse(g_ctx, &pk, pubkey_bytes,
                                   SECP256K1_PUBKEY_COMPRESSED)) {
        return -1;
    }

    if (!secp256k1_ec_pubkey_tweak_add(g_ctx, &pk, tweak)) {
        return -1;
    }

    if (!secp256k1_ec_pubkey_serialize(g_ctx, pubkey_bytes, &len, &pk,
                                       SECP256K1_EC_COMPRESSED)) {
        return -1;
    }

    return 0;
}

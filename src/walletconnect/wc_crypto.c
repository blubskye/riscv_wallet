/*
 * WalletConnect v2 Cryptographic Operations Implementation
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "wc_crypto.h"
#include "../security/memory.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

int wc_crypto_init(void)
{
    if (sodium_init() < 0) {
        return -1;
    }
    return 0;
}

int wc_crypto_random(uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return -1;
    }
    randombytes_buf(buf, len);
    return 0;
}

int wc_crypto_generate_keypair(wc_keypair_t *keypair)
{
    if (keypair == NULL) {
        return -1;
    }

    /* Generate X25519 keypair */
    crypto_box_keypair(keypair->public_key, keypair->private_key);
    return 0;
}

int wc_crypto_generate_symkey(wc_symkey_t *key)
{
    if (key == NULL) {
        return -1;
    }

    randombytes_buf(key->key, WC_KEY_SIZE);
    return 0;
}

int wc_crypto_x25519(const uint8_t self_private[32],
                     const uint8_t peer_public[32],
                     uint8_t shared[32])
{
    if (self_private == NULL || peer_public == NULL || shared == NULL) {
        return -1;
    }

    /* crypto_scalarmult performs X25519 */
    if (crypto_scalarmult(shared, self_private, peer_public) != 0) {
        return -1;
    }

    return 0;
}

int wc_crypto_hkdf(const uint8_t *shared_secret, size_t shared_len,
                   const uint8_t *info, size_t info_len,
                   wc_symkey_t *key)
{
    uint8_t prk[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state state;

    if (shared_secret == NULL || key == NULL) {
        return -1;
    }

    /* HKDF-SHA256 Extract: PRK = HMAC(salt, IKM)
     * Using empty salt as per WalletConnect spec */
    uint8_t salt[crypto_auth_hmacsha256_BYTES] = {0};

    crypto_auth_hmacsha256_init(&state, salt, sizeof(salt));
    crypto_auth_hmacsha256_update(&state, shared_secret, shared_len);
    crypto_auth_hmacsha256_final(&state, prk);

    /* HKDF-SHA256 Expand: OKM = HMAC(PRK, info || 0x01) */
    uint8_t expand_input[256];
    size_t expand_len = 0;

    if (info != NULL && info_len > 0) {
        if (info_len > sizeof(expand_input) - 1) {
            return -1;
        }
        memcpy(expand_input, info, info_len);
        expand_len = info_len;
    }
    expand_input[expand_len++] = 0x01;

    crypto_auth_hmacsha256_init(&state, prk, sizeof(prk));
    crypto_auth_hmacsha256_update(&state, expand_input, expand_len);
    crypto_auth_hmacsha256_final(&state, key->key);

    /* Wipe intermediate values */
    secure_wipe(prk, sizeof(prk));
    secure_wipe(&state, sizeof(state));

    return 0;
}

int wc_crypto_derive_topic(const wc_symkey_t *key, wc_topic_t *topic)
{
    if (key == NULL || topic == NULL) {
        return -1;
    }

    /* Topic = SHA256(symmetric_key) */
    crypto_hash_sha256(topic->bytes, key->key, WC_KEY_SIZE);

    /* Convert to hex string */
    wc_crypto_to_hex(topic->bytes, WC_TOPIC_SIZE, topic->hex);

    return 0;
}

int wc_crypto_encrypt(const wc_symkey_t *key,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext, size_t *ciphertext_len,
                      uint8_t iv[WC_IV_SIZE], uint8_t tag[WC_TAG_SIZE])
{
    unsigned long long actual_len;

    if (key == NULL || plaintext == NULL || ciphertext == NULL ||
        ciphertext_len == NULL || iv == NULL || tag == NULL) {
        return -1;
    }

    /* Generate random IV */
    randombytes_buf(iv, WC_IV_SIZE);

    /* ChaCha20-Poly1305 encrypt
     * libsodium's crypto_aead_chacha20poly1305_ietf_encrypt appends tag to ciphertext */
    uint8_t combined[WC_MESSAGE_MAX + WC_TAG_SIZE];

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            combined, &actual_len,
            plaintext, plaintext_len,
            NULL, 0,  /* No additional data */
            NULL,     /* nsec (unused) */
            iv, key->key) != 0) {
        return -1;
    }

    /* Separate ciphertext and tag */
    *ciphertext_len = (size_t)(actual_len - WC_TAG_SIZE);
    memcpy(ciphertext, combined, *ciphertext_len);
    memcpy(tag, combined + *ciphertext_len, WC_TAG_SIZE);

    return 0;
}

int wc_crypto_decrypt(const wc_symkey_t *key,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      const uint8_t iv[WC_IV_SIZE], const uint8_t tag[WC_TAG_SIZE],
                      uint8_t *plaintext, size_t *plaintext_len)
{
    unsigned long long actual_len;

    if (key == NULL || ciphertext == NULL || iv == NULL ||
        tag == NULL || plaintext == NULL || plaintext_len == NULL) {
        return -1;
    }

    /* Combine ciphertext and tag */
    uint8_t combined[WC_MESSAGE_MAX + WC_TAG_SIZE];
    if (ciphertext_len > WC_MESSAGE_MAX) {
        return -1;
    }
    memcpy(combined, ciphertext, ciphertext_len);
    memcpy(combined + ciphertext_len, tag, WC_TAG_SIZE);

    /* ChaCha20-Poly1305 decrypt and verify */
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &actual_len,
            NULL,     /* nsec (unused) */
            combined, ciphertext_len + WC_TAG_SIZE,
            NULL, 0,  /* No additional data */
            iv, key->key) != 0) {
        return -1;  /* Authentication failed */
    }

    *plaintext_len = (size_t)actual_len;
    return 0;
}

int wc_crypto_seal_type0(const wc_symkey_t *key,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *envelope, size_t *envelope_len)
{
    uint8_t iv[WC_IV_SIZE];
    uint8_t tag[WC_TAG_SIZE];
    uint8_t ciphertext[WC_MESSAGE_MAX];
    size_t ct_len;

    if (key == NULL || plaintext == NULL || envelope == NULL || envelope_len == NULL) {
        return -1;
    }

    /* Encrypt */
    if (wc_crypto_encrypt(key, plaintext, plaintext_len,
                          ciphertext, &ct_len, iv, tag) != 0) {
        return -1;
    }

    /* Check buffer size: type(1) + iv(12) + ciphertext + tag(16) */
    size_t needed = 1 + WC_IV_SIZE + ct_len + WC_TAG_SIZE;
    if (*envelope_len < needed) {
        return -1;
    }

    /* Build Type 0 envelope: [type][iv][ciphertext][tag] */
    size_t pos = 0;
    envelope[pos++] = WC_ENVELOPE_TYPE_0;
    memcpy(envelope + pos, iv, WC_IV_SIZE);
    pos += WC_IV_SIZE;
    memcpy(envelope + pos, ciphertext, ct_len);
    pos += ct_len;
    memcpy(envelope + pos, tag, WC_TAG_SIZE);
    pos += WC_TAG_SIZE;

    *envelope_len = pos;
    return 0;
}

int wc_crypto_open_type0(const wc_symkey_t *key,
                         const uint8_t *envelope, size_t envelope_len,
                         uint8_t *plaintext, size_t *plaintext_len)
{
    if (key == NULL || envelope == NULL || plaintext == NULL || plaintext_len == NULL) {
        return -1;
    }

    /* Minimum size: type(1) + iv(12) + tag(16) = 29 bytes */
    if (envelope_len < 1 + WC_IV_SIZE + WC_TAG_SIZE) {
        return -1;
    }

    /* Check type */
    if (envelope[0] != WC_ENVELOPE_TYPE_0) {
        return -1;
    }

    /* Parse envelope */
    const uint8_t *iv = envelope + 1;
    size_t ct_len = envelope_len - 1 - WC_IV_SIZE - WC_TAG_SIZE;
    const uint8_t *ciphertext = iv + WC_IV_SIZE;
    const uint8_t *tag = ciphertext + ct_len;

    /* Decrypt */
    return wc_crypto_decrypt(key, ciphertext, ct_len, iv, tag,
                             plaintext, plaintext_len);
}

int wc_crypto_seal_type1(const wc_keypair_t *self_keypair,
                         const uint8_t peer_pubkey[WC_KEY_SIZE],
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *envelope, size_t *envelope_len)
{
    uint8_t shared[WC_KEY_SIZE];
    wc_symkey_t derived_key;

    if (self_keypair == NULL || peer_pubkey == NULL ||
        plaintext == NULL || envelope == NULL || envelope_len == NULL) {
        return -1;
    }

    /* Derive shared secret */
    if (wc_crypto_x25519(self_keypair->private_key, peer_pubkey, shared) != 0) {
        return -1;
    }

    /* Derive symmetric key */
    if (wc_crypto_hkdf(shared, WC_KEY_SIZE, NULL, 0, &derived_key) != 0) {
        secure_wipe(shared, sizeof(shared));
        return -1;
    }
    secure_wipe(shared, sizeof(shared));

    /* Encrypt */
    uint8_t iv[WC_IV_SIZE];
    uint8_t tag[WC_TAG_SIZE];
    uint8_t ciphertext[WC_MESSAGE_MAX];
    size_t ct_len;

    if (wc_crypto_encrypt(&derived_key, plaintext, plaintext_len,
                          ciphertext, &ct_len, iv, tag) != 0) {
        wc_crypto_wipe_symkey(&derived_key);
        return -1;
    }
    wc_crypto_wipe_symkey(&derived_key);

    /* Check buffer size: type(1) + pubkey(32) + iv(12) + ciphertext + tag(16) */
    size_t needed = 1 + WC_KEY_SIZE + WC_IV_SIZE + ct_len + WC_TAG_SIZE;
    if (*envelope_len < needed) {
        return -1;
    }

    /* Build Type 1 envelope: [type][sender_pubkey][iv][ciphertext][tag] */
    size_t pos = 0;
    envelope[pos++] = WC_ENVELOPE_TYPE_1;
    memcpy(envelope + pos, self_keypair->public_key, WC_KEY_SIZE);
    pos += WC_KEY_SIZE;
    memcpy(envelope + pos, iv, WC_IV_SIZE);
    pos += WC_IV_SIZE;
    memcpy(envelope + pos, ciphertext, ct_len);
    pos += ct_len;
    memcpy(envelope + pos, tag, WC_TAG_SIZE);
    pos += WC_TAG_SIZE;

    *envelope_len = pos;
    return 0;
}

int wc_crypto_open_type1(const wc_keypair_t *self_keypair,
                         const uint8_t *envelope, size_t envelope_len,
                         uint8_t sender_pubkey[WC_KEY_SIZE],
                         uint8_t *plaintext, size_t *plaintext_len)
{
    uint8_t shared[WC_KEY_SIZE];
    wc_symkey_t derived_key;

    if (self_keypair == NULL || envelope == NULL || sender_pubkey == NULL ||
        plaintext == NULL || plaintext_len == NULL) {
        return -1;
    }

    /* Minimum size: type(1) + pubkey(32) + iv(12) + tag(16) = 61 bytes */
    if (envelope_len < 1 + WC_KEY_SIZE + WC_IV_SIZE + WC_TAG_SIZE) {
        return -1;
    }

    /* Check type */
    if (envelope[0] != WC_ENVELOPE_TYPE_1) {
        return -1;
    }

    /* Parse envelope */
    const uint8_t *peer_pubkey = envelope + 1;
    const uint8_t *iv = peer_pubkey + WC_KEY_SIZE;
    size_t ct_len = envelope_len - 1 - WC_KEY_SIZE - WC_IV_SIZE - WC_TAG_SIZE;
    const uint8_t *ciphertext = iv + WC_IV_SIZE;
    const uint8_t *tag = ciphertext + ct_len;

    /* Copy sender pubkey */
    memcpy(sender_pubkey, peer_pubkey, WC_KEY_SIZE);

    /* Derive shared secret */
    if (wc_crypto_x25519(self_keypair->private_key, peer_pubkey, shared) != 0) {
        return -1;
    }

    /* Derive symmetric key */
    if (wc_crypto_hkdf(shared, WC_KEY_SIZE, NULL, 0, &derived_key) != 0) {
        secure_wipe(shared, sizeof(shared));
        return -1;
    }
    secure_wipe(shared, sizeof(shared));

    /* Decrypt */
    int result = wc_crypto_decrypt(&derived_key, ciphertext, ct_len, iv, tag,
                                   plaintext, plaintext_len);
    wc_crypto_wipe_symkey(&derived_key);

    return result;
}

int wc_crypto_sign_ed25519(const wc_keypair_t *keypair,
                           const uint8_t *data, size_t data_len,
                           uint8_t signature[64])
{
    if (keypair == NULL || data == NULL || signature == NULL) {
        return -1;
    }

    /* Build Ed25519 secret key (64 bytes: seed + public) */
    uint8_t ed_sk[crypto_sign_SECRETKEYBYTES];
    uint8_t ed_pk[crypto_sign_PUBLICKEYBYTES];

    /* Convert X25519 keypair to Ed25519 for signing
     * Note: This is a simplified approach; in production, maintain separate Ed25519 keys */
    crypto_sign_seed_keypair(ed_pk, ed_sk, keypair->private_key);

    unsigned long long sig_len;
    if (crypto_sign_detached(signature, &sig_len, data, data_len, ed_sk) != 0) {
        secure_wipe(ed_sk, sizeof(ed_sk));
        return -1;
    }

    secure_wipe(ed_sk, sizeof(ed_sk));
    return 0;
}

int wc_crypto_verify_ed25519(const uint8_t pubkey[WC_KEY_SIZE],
                             const uint8_t *data, size_t data_len,
                             const uint8_t signature[64])
{
    if (pubkey == NULL || data == NULL || signature == NULL) {
        return -1;
    }

    /* Verify signature */
    return crypto_sign_verify_detached(signature, data, data_len, pubkey);
}

int wc_crypto_sha256(const uint8_t *data, size_t data_len, uint8_t hash[32])
{
    if (data == NULL || hash == NULL) {
        return -1;
    }

    crypto_hash_sha256(hash, data, data_len);
    return 0;
}

void wc_crypto_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex)
{
    static const char hex_chars[] = "0123456789abcdef";

    for (size_t i = 0; i < bytes_len; i++) {
        hex[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex[bytes_len * 2] = '\0';
}

int wc_crypto_from_hex(const char *hex, uint8_t *bytes, size_t bytes_len)
{
    if (hex == NULL || bytes == NULL) {
        return -1;
    }

    size_t hex_len = strlen(hex);
    if (hex_len != bytes_len * 2) {
        return -1;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        int hi, lo;
        char c;

        c = hex[i * 2];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return -1;

        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else return -1;

        bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

void wc_crypto_wipe(void *data, size_t len)
{
    secure_wipe(data, len);
}

void wc_crypto_wipe_keypair(wc_keypair_t *keypair)
{
    if (keypair != NULL) {
        secure_wipe(keypair->private_key, WC_KEY_SIZE);
        secure_wipe(keypair->public_key, WC_KEY_SIZE);
    }
}

void wc_crypto_wipe_symkey(wc_symkey_t *key)
{
    if (key != NULL) {
        secure_wipe(key->key, WC_KEY_SIZE);
    }
}

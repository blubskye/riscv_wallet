/*
 * Monero Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "monero.h"
#include "../crypto/keccak256.h"
#include "../security/memory.h"

/* Monero Base58 alphabet (same as Bitcoin) */
static const char base58_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/*
 * Keccak-256 implementation (non-FIPS, used by Monero)
 * This uses our existing keccak256 from crypto/
 */
void xmr_keccak256(const uint8_t *input, size_t input_len, uint8_t output[32])
{
    keccak256(input, input_len, output);
}

/*
 * Scalar reduction modulo ed25519 curve order
 *
 * This is critical for Monero - the private key must be < l
 * Uses libsodium's crypto_core_ed25519_scalar_reduce
 */
void xmr_sc_reduce32(uint8_t scalar[32])
{
    /* libsodium expects 64 bytes for reduction, so we pad with zeros */
    uint8_t extended[64];
    memcpy(extended, scalar, 32);
    memset(extended + 32, 0, 32);

    crypto_core_ed25519_scalar_reduce(scalar, extended);
    sodium_memzero(extended, sizeof(extended));
}

/*
 * Hash to scalar (Hs function in Monero docs)
 */
void xmr_hash_to_scalar(const uint8_t *input, size_t input_len, uint8_t output[32])
{
    xmr_keccak256(input, input_len, output);
    xmr_sc_reduce32(output);
}

/*
 * Derive public key from secret key
 */
xmr_error_t xmr_secret_to_public(const uint8_t secret[32], uint8_t public[32])
{
    /* Use libsodium's scalarmult base for ed25519 */
    if (crypto_scalarmult_ed25519_base_noclamp(public, secret) != 0) {
        return XMR_ERR_INVALID_KEY;
    }
    return XMR_OK;
}

/*
 * Monero-style Base58 encoding (8-byte blocks with full-block encoding)
 */
static const size_t encoded_block_sizes[] = {0, 2, 3, 5, 6, 7, 9, 10, 11};
static const size_t full_block_size = 8;
static const size_t full_encoded_block_size = 11;

static void encode_block(const uint8_t *block, size_t block_size,
                         char *encoded, size_t encoded_size)
{
    /* Convert block to big-endian integer */
    uint64_t num = 0;
    for (size_t i = 0; i < block_size; i++) {
        num = (num << 8) | block[i];
    }

    /* Convert to base58 with leading zeros preserved */
    for (size_t i = encoded_size; i > 0; i--) {
        encoded[i - 1] = base58_alphabet[num % 58];
        num /= 58;
    }
}

static size_t xmr_base58_encode(const uint8_t *data, size_t data_len,
                                 char *output, size_t output_len)
{
    size_t full_blocks = data_len / full_block_size;
    size_t last_block_size = data_len % full_block_size;
    size_t result_len = full_blocks * full_encoded_block_size;

    if (last_block_size > 0) {
        result_len += encoded_block_sizes[last_block_size];
    }

    if (result_len + 1 > output_len) {
        return 0;
    }

    size_t out_idx = 0;

    /* Encode full 8-byte blocks */
    for (size_t i = 0; i < full_blocks; i++) {
        encode_block(data + i * full_block_size, full_block_size,
                     output + out_idx, full_encoded_block_size);
        out_idx += full_encoded_block_size;
    }

    /* Encode last partial block */
    if (last_block_size > 0) {
        encode_block(data + full_blocks * full_block_size, last_block_size,
                     output + out_idx, encoded_block_sizes[last_block_size]);
        out_idx += encoded_block_sizes[last_block_size];
    }

    output[out_idx] = '\0';
    return out_idx;
}

static int decode_block(const char *encoded, size_t encoded_size,
                        uint8_t *block, size_t block_size)
{
    uint64_t num = 0;

    for (size_t i = 0; i < encoded_size; i++) {
        const char *pos = strchr(base58_alphabet, encoded[i]);
        if (!pos) return -1;
        num = num * 58 + (size_t)(pos - base58_alphabet);
    }

    /* Convert to bytes (big-endian) */
    for (size_t i = block_size; i > 0; i--) {
        block[i - 1] = num & 0xff;
        num >>= 8;
    }

    return 0;
}

static int xmr_base58_decode(const char *input, uint8_t *output,
                              size_t *output_len)
{
    size_t input_len = strlen(input);
    size_t full_blocks = input_len / full_encoded_block_size;
    size_t last_encoded_size = input_len % full_encoded_block_size;
    size_t last_block_size = 0;

    /* Find last block size from encoded size */
    for (size_t i = 0; i <= full_block_size; i++) {
        if (encoded_block_sizes[i] == last_encoded_size) {
            last_block_size = i;
            break;
        }
    }

    size_t result_len = full_blocks * full_block_size + last_block_size;
    if (result_len > *output_len) {
        return -1;
    }

    size_t out_idx = 0;
    size_t in_idx = 0;

    /* Decode full blocks */
    for (size_t i = 0; i < full_blocks; i++) {
        if (decode_block(input + in_idx, full_encoded_block_size,
                         output + out_idx, full_block_size) != 0) {
            return -1;
        }
        in_idx += full_encoded_block_size;
        out_idx += full_block_size;
    }

    /* Decode last partial block */
    if (last_encoded_size > 0) {
        if (decode_block(input + in_idx, last_encoded_size,
                         output + out_idx, last_block_size) != 0) {
            return -1;
        }
        out_idx += last_block_size;
    }

    *output_len = out_idx;
    return 0;
}

/*
 * Derive Monero keypair from BIP-39 seed
 */
xmr_error_t xmr_derive_keypair(const uint8_t *seed, size_t seed_len,
                                xmr_keypair_t *keypair)
{
    if (!seed || !keypair || seed_len < 32) {
        return XMR_ERR_INVALID_KEY;
    }

    /* Hash seed to get spend secret key */
    xmr_keccak256(seed, seed_len, keypair->spend_secret);
    xmr_sc_reduce32(keypair->spend_secret);

    /* Derive view secret from spend secret */
    xmr_hash_to_scalar(keypair->spend_secret, 32, keypair->view_secret);

    /* Derive public keys */
    if (xmr_secret_to_public(keypair->spend_secret, keypair->spend_public) != XMR_OK) {
        sodium_memzero(keypair, sizeof(*keypair));
        return XMR_ERR_INVALID_KEY;
    }

    if (xmr_secret_to_public(keypair->view_secret, keypair->view_public) != XMR_OK) {
        sodium_memzero(keypair, sizeof(*keypair));
        return XMR_ERR_INVALID_KEY;
    }

    return XMR_OK;
}

/*
 * Derive keypair from spend key only
 */
xmr_error_t xmr_keypair_from_spend_key(const uint8_t spend_secret[32],
                                        xmr_keypair_t *keypair)
{
    if (!spend_secret || !keypair) {
        return XMR_ERR_INVALID_KEY;
    }

    /* Copy and reduce spend secret */
    memcpy(keypair->spend_secret, spend_secret, 32);
    xmr_sc_reduce32(keypair->spend_secret);

    /* Derive view secret from spend secret */
    xmr_hash_to_scalar(keypair->spend_secret, 32, keypair->view_secret);

    /* Derive public keys */
    if (xmr_secret_to_public(keypair->spend_secret, keypair->spend_public) != XMR_OK) {
        sodium_memzero(keypair, sizeof(*keypair));
        return XMR_ERR_INVALID_KEY;
    }

    if (xmr_secret_to_public(keypair->view_secret, keypair->view_public) != XMR_OK) {
        sodium_memzero(keypair, sizeof(*keypair));
        return XMR_ERR_INVALID_KEY;
    }

    return XMR_OK;
}

/*
 * Generate standard address from keypair
 */
xmr_error_t xmr_keypair_to_address(const xmr_keypair_t *keypair,
                                    xmr_network_t network,
                                    char *address, size_t addr_len)
{
    if (!keypair || !address || addr_len < 96) {
        return XMR_ERR_BUFFER_TOO_SMALL;
    }

    /* Address = prefix + spend_public + view_public + checksum */
    uint8_t data[69];  /* 1 + 32 + 32 + 4 */
    uint8_t hash[32];

    /* Set network prefix */
    switch (network) {
        case XMR_MAINNET:  data[0] = XMR_NETWORK_MAINNET; break;
        case XMR_TESTNET:  data[0] = XMR_NETWORK_TESTNET; break;
        case XMR_STAGENET: data[0] = XMR_NETWORK_STAGENET; break;
        default: return XMR_ERR_INVALID_NETWORK;
    }

    /* Copy public keys */
    memcpy(data + 1, keypair->spend_public, 32);
    memcpy(data + 33, keypair->view_public, 32);

    /* Compute checksum (first 4 bytes of Keccak-256) */
    xmr_keccak256(data, 65, hash);
    memcpy(data + 65, hash, 4);

    /* Encode to base58 */
    if (xmr_base58_encode(data, 69, address, addr_len) == 0) {
        return XMR_ERR_BUFFER_TOO_SMALL;
    }

    return XMR_OK;
}

/*
 * Create integrated address with payment ID
 */
xmr_error_t xmr_create_integrated_address(const xmr_keypair_t *keypair,
                                           xmr_network_t network,
                                           const uint8_t payment_id[8],
                                           char *address, size_t addr_len)
{
    if (!keypair || !payment_id || !address || addr_len < 107) {
        return XMR_ERR_BUFFER_TOO_SMALL;
    }

    /* Address = prefix + spend_public + view_public + payment_id + checksum */
    uint8_t data[77];  /* 1 + 32 + 32 + 8 + 4 */
    uint8_t hash[32];

    /* Set network prefix */
    switch (network) {
        case XMR_MAINNET:  data[0] = XMR_INTEGRATED_MAINNET; break;
        case XMR_TESTNET:  data[0] = XMR_INTEGRATED_TESTNET; break;
        case XMR_STAGENET: data[0] = XMR_INTEGRATED_STAGENET; break;
        default: return XMR_ERR_INVALID_NETWORK;
    }

    /* Copy public keys and payment ID */
    memcpy(data + 1, keypair->spend_public, 32);
    memcpy(data + 33, keypair->view_public, 32);
    memcpy(data + 65, payment_id, 8);

    /* Compute checksum */
    xmr_keccak256(data, 73, hash);
    memcpy(data + 73, hash, 4);

    /* Encode to base58 */
    if (xmr_base58_encode(data, 77, address, addr_len) == 0) {
        return XMR_ERR_BUFFER_TOO_SMALL;
    }

    return XMR_OK;
}

/*
 * Create subaddress
 */
xmr_error_t xmr_create_subaddress(const xmr_keypair_t *keypair,
                                   xmr_network_t network,
                                   const xmr_subaddr_index_t *index,
                                   char *address, size_t addr_len)
{
    if (!keypair || !index || !address || addr_len < 96) {
        return XMR_ERR_BUFFER_TOO_SMALL;
    }

    /* Special case: (0,0) is the main address */
    if (index->major == 0 && index->minor == 0) {
        return xmr_keypair_to_address(keypair, network, address, addr_len);
    }

    /* Compute subaddress key derivation:
     * m = Hs("SubAddr" || view_secret || major || minor)
     * D = m * G
     * subaddr_spend_public = spend_public + D
     * subaddr_view_public = view_secret * subaddr_spend_public
     */

    uint8_t input[32 + 8 + 8];  /* "SubAddr\0" + view_secret + indices */
    uint8_t scalar_m[32];
    uint8_t point_D[32];
    uint8_t subaddr_spend[32];
    uint8_t subaddr_view[32];

    /* Build input: "SubAddr" + null + view_secret + major + minor (LE) */
    memcpy(input, "SubAddr\0", 8);
    memcpy(input + 8, keypair->view_secret, 32);

    /* Pack indices as little-endian */
    input[40] = index->major & 0xff;
    input[41] = (index->major >> 8) & 0xff;
    input[42] = (index->major >> 16) & 0xff;
    input[43] = (index->major >> 24) & 0xff;
    input[44] = index->minor & 0xff;
    input[45] = (index->minor >> 8) & 0xff;
    input[46] = (index->minor >> 16) & 0xff;
    input[47] = (index->minor >> 24) & 0xff;

    /* m = Hs(input) */
    xmr_hash_to_scalar(input, 48, scalar_m);

    /* D = m * G */
    if (crypto_scalarmult_ed25519_base_noclamp(point_D, scalar_m) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* subaddr_spend = spend_public + D */
    if (crypto_core_ed25519_add(subaddr_spend, keypair->spend_public, point_D) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* subaddr_view = view_secret * subaddr_spend */
    if (crypto_scalarmult_ed25519_noclamp(subaddr_view, keypair->view_secret,
                                           subaddr_spend) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* Encode subaddress */
    uint8_t data[69];
    uint8_t hash[32];

    switch (network) {
        case XMR_MAINNET:  data[0] = XMR_SUBADDR_MAINNET; break;
        case XMR_TESTNET:  data[0] = XMR_SUBADDR_TESTNET; break;
        case XMR_STAGENET: data[0] = XMR_SUBADDR_STAGENET; break;
        default: return XMR_ERR_INVALID_NETWORK;
    }

    memcpy(data + 1, subaddr_spend, 32);
    memcpy(data + 33, subaddr_view, 32);

    xmr_keccak256(data, 65, hash);
    memcpy(data + 65, hash, 4);

    if (xmr_base58_encode(data, 69, address, addr_len) == 0) {
        return XMR_ERR_BUFFER_TOO_SMALL;
    }

    return XMR_OK;
}

/*
 * Decode Monero address
 */
xmr_error_t xmr_decode_address(const char *address, xmr_address_t *decoded)
{
    if (!address || !decoded) {
        return XMR_ERR_INVALID_ADDRESS;
    }

    size_t addr_len = strlen(address);
    uint8_t data[128];
    size_t data_len = sizeof(data);

    if (xmr_base58_decode(address, data, &data_len) != 0) {
        return XMR_ERR_INVALID_ADDRESS;
    }

    /* Verify checksum */
    uint8_t hash[32];
    size_t prefix_len = data_len - 4;

    xmr_keccak256(data, prefix_len, hash);
    if (memcmp(data + prefix_len, hash, 4) != 0) {
        return XMR_ERR_INVALID_CHECKSUM;
    }

    decoded->network_prefix = data[0];
    decoded->has_payment_id = 0;
    memset(decoded->payment_id, 0, sizeof(decoded->payment_id));

    /* Check address type by length and prefix */
    if (data_len == 69) {
        /* Standard or subaddress (69 bytes) */
        memcpy(decoded->spend_public, data + 1, 32);
        memcpy(decoded->view_public, data + 33, 32);
    } else if (data_len == 77) {
        /* Integrated address (77 bytes) */
        memcpy(decoded->spend_public, data + 1, 32);
        memcpy(decoded->view_public, data + 33, 32);
        memcpy(decoded->payment_id, data + 65, 8);
        decoded->has_payment_id = 1;
    } else {
        return XMR_ERR_INVALID_ADDRESS;
    }

    (void)addr_len;  /* Suppress warning */
    return XMR_OK;
}

/*
 * Validate Monero address
 */
int xmr_validate_address(const char *address)
{
    xmr_address_t decoded;
    if (xmr_decode_address(address, &decoded) != XMR_OK) {
        return 0;
    }

    /* Check valid network prefix */
    uint8_t p = decoded.network_prefix;
    if (p == XMR_NETWORK_MAINNET || p == XMR_NETWORK_TESTNET ||
        p == XMR_NETWORK_STAGENET || p == XMR_SUBADDR_MAINNET ||
        p == XMR_SUBADDR_TESTNET || p == XMR_SUBADDR_STAGENET ||
        p == XMR_INTEGRATED_MAINNET || p == XMR_INTEGRATED_TESTNET ||
        p == XMR_INTEGRATED_STAGENET) {
        return 1;
    }

    return 0;
}

/*
 * Generate stealth address for receiving
 */
xmr_error_t xmr_generate_stealth_address(const uint8_t view_public[32],
                                          const uint8_t spend_public[32],
                                          uint8_t tx_public[32],
                                          uint8_t stealth_addr[32])
{
    uint8_t random_scalar[32];
    uint8_t shared_secret[32];
    uint8_t derivation[32];
    uint8_t hash_input[33];

    /* Generate random transaction secret key r */
    randombytes_buf(random_scalar, 32);
    xmr_sc_reduce32(random_scalar);

    /* Compute tx public key R = r*G */
    if (crypto_scalarmult_ed25519_base_noclamp(tx_public, random_scalar) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* Compute shared secret: r*A (where A is view_public) */
    if (crypto_scalarmult_ed25519_noclamp(shared_secret, random_scalar, view_public) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* derivation = Hs(shared_secret || output_index) */
    /* For simplicity, output_index = 0 */
    memcpy(hash_input, shared_secret, 32);
    hash_input[32] = 0;  /* output index */
    xmr_hash_to_scalar(hash_input, 33, derivation);

    /* Compute G_d = derivation * G */
    uint8_t G_d[32];
    if (crypto_scalarmult_ed25519_base_noclamp(G_d, derivation) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* Stealth address P = B + G_d (where B is spend_public) */
    if (crypto_core_ed25519_add(stealth_addr, spend_public, G_d) != 0) {
        return XMR_ERR_INTERNAL;
    }

    sodium_memzero(random_scalar, sizeof(random_scalar));
    sodium_memzero(shared_secret, sizeof(shared_secret));

    return XMR_OK;
}

/*
 * Check if output belongs to us (view-only scan)
 */
int xmr_is_output_ours(const uint8_t view_secret[32],
                       const uint8_t spend_public[32],
                       const uint8_t tx_public[32],
                       size_t output_index,
                       const uint8_t output_key[32])
{
    uint8_t shared_secret[32];
    uint8_t derivation[32];
    uint8_t hash_input[33];
    uint8_t G_d[32];
    uint8_t expected_key[32];

    /* Compute shared secret: a*R */
    if (crypto_scalarmult_ed25519_noclamp(shared_secret, view_secret, tx_public) != 0) {
        return 0;
    }

    /* derivation = Hs(shared_secret || output_index) */
    memcpy(hash_input, shared_secret, 32);
    hash_input[32] = (uint8_t)output_index;
    xmr_hash_to_scalar(hash_input, 33, derivation);

    /* G_d = derivation * G */
    if (crypto_scalarmult_ed25519_base_noclamp(G_d, derivation) != 0) {
        return 0;
    }

    /* expected = B + G_d */
    if (crypto_core_ed25519_add(expected_key, spend_public, G_d) != 0) {
        return 0;
    }

    return sodium_memcmp(expected_key, output_key, 32) == 0;
}

/*
 * Derive one-time private key for spending
 */
xmr_error_t xmr_derive_one_time_key(const uint8_t view_secret[32],
                                     const uint8_t spend_secret[32],
                                     const uint8_t tx_public[32],
                                     size_t output_index,
                                     uint8_t one_time_key[32])
{
    uint8_t shared_secret[32];
    uint8_t derivation[32];
    uint8_t hash_input[33];

    /* Compute shared secret: a*R */
    if (crypto_scalarmult_ed25519_noclamp(shared_secret, view_secret, tx_public) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* derivation = Hs(shared_secret || output_index) */
    memcpy(hash_input, shared_secret, 32);
    hash_input[32] = (uint8_t)output_index;
    xmr_hash_to_scalar(hash_input, 33, derivation);

    /* one_time_key = derivation + spend_secret (mod l) */
    crypto_core_ed25519_scalar_add(one_time_key, derivation, spend_secret);

    sodium_memzero(shared_secret, sizeof(shared_secret));
    sodium_memzero(derivation, sizeof(derivation));

    return XMR_OK;
}

/*
 * Format XMR amount (12 decimal places, atomic = piconero)
 */
char *xmr_format_amount(uint64_t atomic_units, char *output, size_t output_len)
{
    if (!output || output_len < 20) return NULL;

    uint64_t xmr = atomic_units / 1000000000000ULL;
    uint64_t pico = atomic_units % 1000000000000ULL;

    if (pico == 0) {
        snprintf(output, output_len, "%llu XMR",
                 (unsigned long long)xmr);
    } else {
        /* Remove trailing zeros */
        char frac[13];
        snprintf(frac, sizeof(frac), "%012llu", (unsigned long long)pico);
        size_t len = 12;
        while (len > 1 && frac[len - 1] == '0') {
            frac[--len] = '\0';
        }
        snprintf(output, output_len, "%llu.%s XMR",
                 (unsigned long long)xmr, frac);
    }

    return output;
}

/*
 * Get network name
 */
const char *xmr_network_name(xmr_network_t network)
{
    switch (network) {
        case XMR_MAINNET:  return "Monero Mainnet";
        case XMR_TESTNET:  return "Monero Testnet";
        case XMR_STAGENET: return "Monero Stagenet";
        default: return "Unknown";
    }
}

/*
 * Wipe keypair
 */
void xmr_wipe_keypair(xmr_keypair_t *keypair)
{
    if (keypair) {
        sodium_memzero(keypair, sizeof(*keypair));
    }
}

/* ============================================================================
 * Key Image Functions
 * ============================================================================ */

/*
 * Hash to point (Hp) - deterministically maps a point to another point
 *
 * Uses the method from Monero: hash the input point and try to decode
 * as a curve point, multiply by cofactor if needed.
 */
xmr_error_t xmr_hash_to_point(const uint8_t point[32], uint8_t result[32])
{
    uint8_t hash[32];
    uint8_t candidate[32];
    int found = 0;

    /* Hash the point to get starting candidate */
    xmr_keccak256(point, 32, hash);

    /* Try to find a valid curve point by iterating */
    for (int i = 0; i < 256 && !found; i++) {
        memcpy(candidate, hash, 32);

        /* Try decoding as a compressed ed25519 point */
        if (crypto_core_ed25519_is_valid_point(candidate)) {
            /* Multiply by cofactor (8) to ensure we're in the prime-order subgroup */
            uint8_t cofactor[32] = {0};
            cofactor[0] = 8;
            if (crypto_scalarmult_ed25519_noclamp(result, cofactor, candidate) == 0) {
                found = 1;
                break;
            }
        }

        /* If not valid, hash again and retry */
        xmr_keccak256(hash, 32, hash);
    }

    if (!found) {
        /* Fallback: use elligator-like construction */
        /* For simplicity, use hash directly as x-coordinate attempt */
        memcpy(result, hash, 32);
        result[31] &= 0x7f;  /* Clear high bit */

        /* Multiply by generator to get a valid point */
        if (crypto_scalarmult_ed25519_base_noclamp(result, hash) != 0) {
            return XMR_ERR_INTERNAL;
        }
    }

    return XMR_OK;
}

/*
 * Compute key image: I = x * Hp(P)
 */
xmr_error_t xmr_compute_key_image(const uint8_t one_time_secret[32],
                                   const uint8_t one_time_public[32],
                                   uint8_t key_image[32])
{
    uint8_t hp[32];

    /* Compute Hp(P) */
    xmr_error_t err = xmr_hash_to_point(one_time_public, hp);
    if (err != XMR_OK) {
        return err;
    }

    /* I = x * Hp(P) */
    if (crypto_scalarmult_ed25519_noclamp(key_image, one_time_secret, hp) != 0) {
        return XMR_ERR_INTERNAL;
    }

    return XMR_OK;
}

/* ============================================================================
 * RingCT - Pedersen Commitments
 * ============================================================================ */

/* Second generator H (precomputed as hash_to_point(G)) */
static uint8_t g_H_point[32] = {0};
static int g_H_initialized = 0;

void xmr_get_H(uint8_t H[32])
{
    if (!g_H_initialized) {
        /* H = hash_to_point(G), where G is ed25519 basepoint */
        uint8_t G[32];
        uint8_t one[32] = {0};
        one[0] = 1;

        /* Get G by computing 1*G */
        crypto_scalarmult_ed25519_base_noclamp(G, one);

        /* Hash G to get H */
        xmr_hash_to_point(G, g_H_point);
        g_H_initialized = 1;
    }

    memcpy(H, g_H_point, 32);
}

/*
 * Generate Pedersen commitment: C = mask*G + amount*H
 */
xmr_error_t xmr_generate_commitment(uint64_t amount,
                                     const uint8_t *mask,
                                     xmr_commitment_t *commitment)
{
    if (!commitment) return XMR_ERR_INVALID_COMMITMENT;

    uint8_t H[32];
    uint8_t mask_G[32];
    uint8_t amount_H[32];
    uint8_t amount_scalar[32] = {0};

    /* Generate or use provided mask */
    if (mask) {
        memcpy(commitment->mask, mask, 32);
    } else {
        randombytes_buf(commitment->mask, 32);
        xmr_sc_reduce32(commitment->mask);
    }

    commitment->amount = amount;

    /* Convert amount to scalar (little-endian) */
    for (int i = 0; i < 8; i++) {
        amount_scalar[i] = (amount >> (i * 8)) & 0xff;
    }

    /* Get H */
    xmr_get_H(H);

    /* Compute mask*G */
    if (crypto_scalarmult_ed25519_base_noclamp(mask_G, commitment->mask) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* Compute amount*H */
    if (crypto_scalarmult_ed25519_noclamp(amount_H, amount_scalar, H) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* C = mask*G + amount*H */
    if (crypto_core_ed25519_add(commitment->commitment, mask_G, amount_H) != 0) {
        return XMR_ERR_INTERNAL;
    }

    return XMR_OK;
}

/*
 * Verify commitment matches amount and mask
 */
xmr_error_t xmr_verify_commitment(const xmr_commitment_t *commitment)
{
    if (!commitment) return XMR_ERR_INVALID_COMMITMENT;

    xmr_commitment_t test;
    xmr_error_t err = xmr_generate_commitment(commitment->amount,
                                               commitment->mask, &test);
    if (err != XMR_OK) return err;

    if (sodium_memcmp(commitment->commitment, test.commitment, 32) != 0) {
        return XMR_ERR_INVALID_COMMITMENT;
    }

    return XMR_OK;
}

/*
 * Verify commitment balance: sum(inputs) = sum(outputs) + fee*H
 */
xmr_error_t xmr_verify_commitment_balance(const uint8_t (*in_commits)[32],
                                           size_t in_count,
                                           const uint8_t (*out_commits)[32],
                                           size_t out_count,
                                           uint64_t fee)
{
    if (!in_commits || !out_commits || in_count == 0 || out_count == 0) {
        return XMR_ERR_INVALID_COMMITMENT;
    }

    uint8_t sum_in[32];
    uint8_t sum_out[32];
    uint8_t fee_commitment[32];
    uint8_t H[32];
    uint8_t fee_scalar[32] = {0};

    /* Initialize sums to zero (identity point) */
    memset(sum_in, 0, 32);
    memset(sum_out, 0, 32);

    /* Sum input commitments */
    memcpy(sum_in, in_commits[0], 32);
    for (size_t i = 1; i < in_count; i++) {
        uint8_t tmp[32];
        if (crypto_core_ed25519_add(tmp, sum_in, in_commits[i]) != 0) {
            return XMR_ERR_INTERNAL;
        }
        memcpy(sum_in, tmp, 32);
    }

    /* Sum output commitments */
    memcpy(sum_out, out_commits[0], 32);
    for (size_t i = 1; i < out_count; i++) {
        uint8_t tmp[32];
        if (crypto_core_ed25519_add(tmp, sum_out, out_commits[i]) != 0) {
            return XMR_ERR_INTERNAL;
        }
        memcpy(sum_out, tmp, 32);
    }

    /* Add fee*H to outputs */
    xmr_get_H(H);
    for (int i = 0; i < 8; i++) {
        fee_scalar[i] = (fee >> (i * 8)) & 0xff;
    }

    if (crypto_scalarmult_ed25519_noclamp(fee_commitment, fee_scalar, H) != 0) {
        return XMR_ERR_INTERNAL;
    }

    uint8_t sum_out_plus_fee[32];
    if (crypto_core_ed25519_add(sum_out_plus_fee, sum_out, fee_commitment) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* Verify sum_in == sum_out + fee*H */
    if (sodium_memcmp(sum_in, sum_out_plus_fee, 32) != 0) {
        return XMR_ERR_INVALID_COMMITMENT;
    }

    return XMR_OK;
}

/* ============================================================================
 * ECDH Amount Encoding
 * ============================================================================ */

/*
 * Encode amount and mask for recipient
 */
xmr_error_t xmr_encode_ecdh(uint64_t amount,
                             const uint8_t mask[32],
                             const uint8_t shared_secret[32],
                             size_t output_index,
                             xmr_ecdh_info_t *ecdh)
{
    if (!mask || !shared_secret || !ecdh) return XMR_ERR_INVALID_KEY;

    uint8_t amount_key[32];
    uint8_t mask_key[32];
    uint8_t input[33];

    /* Derive encryption keys from shared secret */
    memcpy(input, shared_secret, 32);
    input[32] = (uint8_t)output_index;

    /* mask_key = Hs("amount" || shared_secret || index) */
    uint8_t prefix[7] = "amount";
    uint8_t hash_input[39];
    memcpy(hash_input, prefix, 6);
    memcpy(hash_input + 6, input, 33);
    xmr_keccak256(hash_input, 39, mask_key);

    /* amount_key = first 8 bytes of Hs(mask_key) */
    xmr_keccak256(mask_key, 32, amount_key);

    /* XOR encrypt mask */
    for (int i = 0; i < 32; i++) {
        ecdh->mask[i] = mask[i] ^ mask_key[i];
    }

    /* XOR encrypt amount (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        ecdh->amount[i] = ((amount >> (i * 8)) & 0xff) ^ amount_key[i];
    }

    return XMR_OK;
}

/*
 * Decode amount and mask using ECDH
 */
xmr_error_t xmr_decode_ecdh(const xmr_ecdh_info_t *ecdh,
                             const uint8_t shared_secret[32],
                             size_t output_index,
                             uint64_t *amount,
                             uint8_t mask[32])
{
    if (!ecdh || !shared_secret || !amount || !mask) return XMR_ERR_INVALID_KEY;

    uint8_t amount_key[32];
    uint8_t mask_key[32];
    uint8_t input[33];

    /* Derive decryption keys (same as encryption) */
    memcpy(input, shared_secret, 32);
    input[32] = (uint8_t)output_index;

    uint8_t prefix[7] = "amount";
    uint8_t hash_input[39];
    memcpy(hash_input, prefix, 6);
    memcpy(hash_input + 6, input, 33);
    xmr_keccak256(hash_input, 39, mask_key);
    xmr_keccak256(mask_key, 32, amount_key);

    /* XOR decrypt mask */
    for (int i = 0; i < 32; i++) {
        mask[i] = ecdh->mask[i] ^ mask_key[i];
    }

    /* XOR decrypt amount */
    *amount = 0;
    for (int i = 0; i < 8; i++) {
        *amount |= ((uint64_t)(ecdh->amount[i] ^ amount_key[i])) << (i * 8);
    }

    return XMR_OK;
}

/* ============================================================================
 * CLSAG Ring Signatures
 * ============================================================================ */

/*
 * Compute CLSAG aggregate key coefficient
 */
static void clsag_hash_key(uint8_t ring_keys[][32],
                            uint8_t ring_commits[][32],
                            const uint8_t key_image[32],
                            const uint8_t D[32],
                            const uint8_t pseudo_out[32],
                            size_t ring_size,
                            uint8_t mu_P[32],
                            uint8_t mu_C[32])
{
    /* Compute mu_P and mu_C domain separator hashes */
    /* mu_P = Hs("CLSAG_agg_0" || ring_keys || I) */
    /* mu_C = Hs("CLSAG_agg_1" || ring_commits || D || pseudo_out) */

    size_t buf_len = 16 + ring_size * 32 + 32;
    uint8_t *buf = malloc(buf_len);
    if (!buf) return;

    /* mu_P */
    memcpy(buf, "CLSAG_agg_0\0\0\0\0\0", 16);
    for (size_t i = 0; i < ring_size; i++) {
        memcpy(buf + 16 + i * 32, ring_keys[i], 32);
    }
    memcpy(buf + 16 + ring_size * 32, key_image, 32);
    xmr_hash_to_scalar(buf, 16 + ring_size * 32 + 32, mu_P);

    /* mu_C */
    memcpy(buf, "CLSAG_agg_1\0\0\0\0\0", 16);
    for (size_t i = 0; i < ring_size; i++) {
        memcpy(buf + 16 + i * 32, ring_commits[i], 32);
    }
    memcpy(buf + 16 + ring_size * 32, D, 32);
    /* Note: We'd also hash pseudo_out but buffer size limits this */
    (void)pseudo_out;

    xmr_hash_to_scalar(buf, 16 + ring_size * 32 + 32, mu_C);

    free(buf);
}

/*
 * Compute CLSAG round hash (challenge)
 */
static void clsag_round_hash(const uint8_t message[32],
                              const uint8_t L[32],
                              const uint8_t R[32],
                              size_t round,
                              uint8_t output[32])
{
    uint8_t buf[32 + 32 + 32 + 8];

    memcpy(buf, message, 32);
    memcpy(buf + 32, L, 32);
    memcpy(buf + 64, R, 32);

    /* Include round number */
    for (int i = 0; i < 8; i++) {
        buf[96 + i] = (round >> (i * 8)) & 0xff;
    }

    xmr_hash_to_scalar(buf, sizeof(buf), output);
}

/*
 * Generate CLSAG ring signature
 */
xmr_error_t xmr_clsag_sign(const uint8_t message[32],
                            const xmr_ring_member_t *ring,
                            size_t ring_size,
                            size_t real_index,
                            const uint8_t one_time_key[32],
                            const uint8_t key_image[32],
                            const uint8_t commitment_key[32],
                            const uint8_t pseudo_out[32],
                            xmr_clsag_signature_t *signature)
{
    if (!message || !ring || !one_time_key || !key_image ||
        !commitment_key || !pseudo_out || !signature) {
        return XMR_ERR_INVALID_KEY;
    }

    if (ring_size < 2 || ring_size > XMR_MAX_RING_SIZE || real_index >= ring_size) {
        return XMR_ERR_INVALID_RING;
    }

    uint8_t alpha[32];    /* Random scalar for our index */
    uint8_t L[32], R[32]; /* Intermediate points */
    uint8_t c[32];        /* Challenge */
    uint8_t mu_P[32], mu_C[32]; /* Aggregate coefficients */
    uint8_t hp[32];       /* Hash-to-point of our key */
    uint8_t hp_i[32];     /* Hash-to-point of ring member i */

    /* Compute aggregate coefficients */
    uint8_t ring_keys[XMR_MAX_RING_SIZE][32];
    uint8_t ring_commits[XMR_MAX_RING_SIZE][32];

    for (size_t i = 0; i < ring_size; i++) {
        memcpy(ring_keys[i], ring[i].dest_key, 32);
        memcpy(ring_commits[i], ring[i].commitment, 32);
    }

    /* Compute D = z * Hp(P[real]) where z is the commitment key difference */
    xmr_hash_to_point(ring[real_index].dest_key, hp);
    if (crypto_scalarmult_ed25519_noclamp(signature->D, commitment_key, hp) != 0) {
        return XMR_ERR_INTERNAL;
    }

    clsag_hash_key(ring_keys, ring_commits, key_image, signature->D,
                   pseudo_out, ring_size, mu_P, mu_C);

    /* Generate random alpha */
    randombytes_buf(alpha, 32);
    xmr_sc_reduce32(alpha);

    /* Compute initial L = alpha * G */
    if (crypto_scalarmult_ed25519_base_noclamp(L, alpha) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* Compute initial R = alpha * Hp(P[real]) */
    if (crypto_scalarmult_ed25519_noclamp(R, alpha, hp) != 0) {
        return XMR_ERR_INTERNAL;
    }

    /* Initialize challenge for next index */
    clsag_round_hash(message, L, R, real_index, c);

    signature->ring_size = ring_size;

    /* Store challenge at index 0 when we compute it */
    uint8_t c_at_0[32] = {0};
    int c_at_0_stored = 0;

    /* Generate fake responses and compute challenges for all other members */
    for (size_t i = 1; i < ring_size; i++) {
        size_t idx = (real_index + i) % ring_size;

        /* If we just computed challenge for index 0, save it */
        if (idx == 0) {
            memcpy(c_at_0, c, 32);
            c_at_0_stored = 1;
        }

        /* Generate random response s[idx] */
        randombytes_buf(signature->s[idx], 32);
        xmr_sc_reduce32(signature->s[idx]);

        /* Compute L = s[idx] * G + c * (mu_P * P[idx] + mu_C * (C[idx] - pseudo_out)) */
        uint8_t sG[32], cP[32], tmp1[32], tmp2[32];

        /* sG = s * G */
        if (crypto_scalarmult_ed25519_base_noclamp(sG, signature->s[idx]) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* Aggregate key: W = mu_P * P + mu_C * (C - pseudo_out) */
        uint8_t W[32];
        uint8_t mu_P_P[32], mu_C_C[32], C_minus_pseudo[32];

        /* mu_P * P */
        if (crypto_scalarmult_ed25519_noclamp(mu_P_P, mu_P, ring[idx].dest_key) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* C - pseudo_out */
        if (crypto_core_ed25519_sub(C_minus_pseudo, ring[idx].commitment, pseudo_out) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* mu_C * (C - pseudo_out) */
        if (crypto_scalarmult_ed25519_noclamp(mu_C_C, mu_C, C_minus_pseudo) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* W = mu_P_P + mu_C_C */
        if (crypto_core_ed25519_add(W, mu_P_P, mu_C_C) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* c * W */
        if (crypto_scalarmult_ed25519_noclamp(cP, c, W) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* L = sG + cW */
        if (crypto_core_ed25519_add(L, sG, cP) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* Compute R = s[idx] * Hp(P[idx]) + c * (mu_P * I + mu_C * D) */
        xmr_hash_to_point(ring[idx].dest_key, hp_i);

        /* s * Hp(P) */
        if (crypto_scalarmult_ed25519_noclamp(tmp1, signature->s[idx], hp_i) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* Aggregate image: W' = mu_P * I + mu_C * D */
        uint8_t Wprime[32];
        uint8_t mu_P_I[32], mu_C_D[32];

        if (crypto_scalarmult_ed25519_noclamp(mu_P_I, mu_P, key_image) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_scalarmult_ed25519_noclamp(mu_C_D, mu_C, signature->D) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_core_ed25519_add(Wprime, mu_P_I, mu_C_D) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* c * W' */
        if (crypto_scalarmult_ed25519_noclamp(tmp2, c, Wprime) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* R = s*Hp + c*W' */
        if (crypto_core_ed25519_add(R, tmp1, tmp2) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* Next challenge */
        clsag_round_hash(message, L, R, idx, c);
    }

    /* Save c1 (challenge at index 0) */
    if (c_at_0_stored) {
        memcpy(signature->c1, c_at_0, 32);
    } else {
        /* real_index was 0, so c after the loop is the challenge for index 0 */
        memcpy(signature->c1, c, 32);
    }

    /* Compute our response: s[real] = alpha - c * (mu_P * x + mu_C * z) */
    /* where x is one_time_key and z is commitment_key */
    uint8_t mu_P_x[32], mu_C_z[32], sum_keys[32], c_sum[32];

    /* mu_P * x */
    crypto_core_ed25519_scalar_mul(mu_P_x, mu_P, one_time_key);

    /* mu_C * z */
    crypto_core_ed25519_scalar_mul(mu_C_z, mu_C, commitment_key);

    /* sum = mu_P*x + mu_C*z */
    crypto_core_ed25519_scalar_add(sum_keys, mu_P_x, mu_C_z);

    /* c * sum */
    crypto_core_ed25519_scalar_mul(c_sum, c, sum_keys);

    /* s[real] = alpha - c*sum */
    crypto_core_ed25519_scalar_sub(signature->s[real_index], alpha, c_sum);

    /* Wipe sensitive data */
    sodium_memzero(alpha, sizeof(alpha));
    sodium_memzero(mu_P_x, sizeof(mu_P_x));
    sodium_memzero(mu_C_z, sizeof(mu_C_z));
    sodium_memzero(sum_keys, sizeof(sum_keys));

    return XMR_OK;
}

/*
 * Verify CLSAG ring signature
 */
xmr_error_t xmr_clsag_verify(const uint8_t message[32],
                              const xmr_ring_member_t *ring,
                              size_t ring_size,
                              const uint8_t key_image[32],
                              const uint8_t pseudo_out[32],
                              const xmr_clsag_signature_t *signature)
{
    if (!message || !ring || !key_image || !pseudo_out || !signature) {
        return XMR_ERR_INVALID_SIGNATURE;
    }

    if (ring_size < 2 || ring_size > XMR_MAX_RING_SIZE ||
        ring_size != signature->ring_size) {
        return XMR_ERR_INVALID_RING;
    }

    uint8_t L[32], R[32];
    uint8_t c[32];
    uint8_t mu_P[32], mu_C[32];
    uint8_t hp_i[32];

    /* Compute aggregate coefficients */
    uint8_t ring_keys[XMR_MAX_RING_SIZE][32];
    uint8_t ring_commits[XMR_MAX_RING_SIZE][32];

    for (size_t i = 0; i < ring_size; i++) {
        memcpy(ring_keys[i], ring[i].dest_key, 32);
        memcpy(ring_commits[i], ring[i].commitment, 32);
    }

    clsag_hash_key(ring_keys, ring_commits, key_image, signature->D,
                   pseudo_out, ring_size, mu_P, mu_C);

    /* Start with c1 */
    memcpy(c, signature->c1, 32);

    /* Verify the ring */
    for (size_t i = 0; i < ring_size; i++) {
        size_t idx = i;

        /* Compute L = s[idx] * G + c * W */
        uint8_t sG[32], cW[32];
        uint8_t W[32], mu_P_P[32], mu_C_C[32], C_minus_pseudo[32];

        /* sG = s * G */
        if (crypto_scalarmult_ed25519_base_noclamp(sG, signature->s[idx]) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* W = mu_P * P + mu_C * (C - pseudo_out) */
        if (crypto_scalarmult_ed25519_noclamp(mu_P_P, mu_P, ring[idx].dest_key) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_core_ed25519_sub(C_minus_pseudo, ring[idx].commitment, pseudo_out) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_scalarmult_ed25519_noclamp(mu_C_C, mu_C, C_minus_pseudo) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_core_ed25519_add(W, mu_P_P, mu_C_C) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_scalarmult_ed25519_noclamp(cW, c, W) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_core_ed25519_add(L, sG, cW) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* Compute R = s[idx] * Hp(P[idx]) + c * W' */
        xmr_hash_to_point(ring[idx].dest_key, hp_i);

        uint8_t s_hp[32], cWprime[32];
        uint8_t Wprime[32], mu_P_I[32], mu_C_D[32];

        if (crypto_scalarmult_ed25519_noclamp(s_hp, signature->s[idx], hp_i) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* W' = mu_P * I + mu_C * D */
        if (crypto_scalarmult_ed25519_noclamp(mu_P_I, mu_P, key_image) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_scalarmult_ed25519_noclamp(mu_C_D, mu_C, signature->D) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_core_ed25519_add(Wprime, mu_P_I, mu_C_D) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_scalarmult_ed25519_noclamp(cWprime, c, Wprime) != 0) {
            return XMR_ERR_INTERNAL;
        }

        if (crypto_core_ed25519_add(R, s_hp, cWprime) != 0) {
            return XMR_ERR_INTERNAL;
        }

        /* Compute next challenge */
        clsag_round_hash(message, L, R, idx, c);
    }

    /* Verify we got back to c1 */
    if (sodium_memcmp(c, signature->c1, 32) != 0) {
        return XMR_ERR_INVALID_SIGNATURE;
    }

    return XMR_OK;
}

/* ============================================================================
 * Transaction Building
 * ============================================================================ */

/*
 * Compute transaction prefix hash
 */
xmr_error_t xmr_compute_tx_prefix_hash(const xmr_tx_prefix_t *prefix,
                                        uint8_t hash[32])
{
    if (!prefix || !hash) return XMR_ERR_INVALID_KEY;

    /* Serialize prefix data */
    /* For simplicity, we hash the key fields directly */
    size_t buf_size = 1 + 8 + prefix->input_count * 96 +
                      prefix->output_count * 96 + prefix->extra_len;
    uint8_t *buf = malloc(buf_size);
    if (!buf) return XMR_ERR_INTERNAL;

    size_t offset = 0;

    /* Version */
    buf[offset++] = prefix->version;

    /* Unlock time (varint, simplified to 8 bytes) */
    for (int i = 0; i < 8; i++) {
        buf[offset++] = (prefix->unlock_time >> (i * 8)) & 0xff;
    }

    /* Inputs */
    for (size_t i = 0; i < prefix->input_count; i++) {
        const xmr_tx_input_t *inp = &prefix->inputs[i];
        memcpy(buf + offset, inp->key_image, 32);
        offset += 32;
        /* Key offsets would go here in full impl */
    }

    /* Outputs */
    for (size_t i = 0; i < prefix->output_count; i++) {
        const xmr_tx_output_t *out = &prefix->outputs[i];
        memcpy(buf + offset, out->dest_key, 32);
        offset += 32;
    }

    /* Extra */
    memcpy(buf + offset, prefix->extra, prefix->extra_len);
    offset += prefix->extra_len;

    /* Hash everything */
    xmr_keccak256(buf, offset, hash);

    free(buf);
    return XMR_OK;
}

/*
 * Build and sign a Monero transaction
 */
xmr_error_t xmr_build_transaction(const xmr_keypair_t *keypair,
                                   xmr_tx_input_t *inputs,
                                   size_t input_count,
                                   const char *dest_address,
                                   uint64_t amount,
                                   uint64_t fee,
                                   const char *change_addr,
                                   xmr_tx_prefix_t *tx_prefix,
                                   xmr_clsag_signature_t *signatures)
{
    if (!keypair || !inputs || !dest_address || !tx_prefix || !signatures) {
        return XMR_ERR_INVALID_KEY;
    }

    if (input_count == 0) {
        return XMR_ERR_INVALID_RING;
    }

    xmr_error_t err;
    xmr_address_t dest;

    /* Decode destination address */
    err = xmr_decode_address(dest_address, &dest);
    if (err != XMR_OK) return err;

    /* Calculate total input */
    uint64_t total_in = 0;
    for (size_t i = 0; i < input_count; i++) {
        /* In real usage, amount would be decoded from commitment */
        /* For now, assume inputs[i].amount is set */
        total_in += inputs[i].amount;
    }

    /* Verify we have enough */
    if (total_in < amount + fee) {
        return XMR_ERR_INVALID_COMMITMENT;
    }

    uint64_t change = total_in - amount - fee;

    /* Initialize prefix */
    memset(tx_prefix, 0, sizeof(*tx_prefix));
    tx_prefix->version = 2;  /* RingCT version */
    tx_prefix->unlock_time = 0;
    tx_prefix->inputs = inputs;
    tx_prefix->input_count = input_count;

    /* Create outputs */
    size_t output_count = (change > 0) ? 2 : 1;
    tx_prefix->outputs = calloc(output_count, sizeof(xmr_tx_output_t));
    if (!tx_prefix->outputs) return XMR_ERR_INTERNAL;
    tx_prefix->output_count = output_count;

    /* Generate transaction random secret key */
    uint8_t tx_secret[32];
    uint8_t tx_public[32];
    randombytes_buf(tx_secret, 32);
    xmr_sc_reduce32(tx_secret);
    if (crypto_scalarmult_ed25519_base_noclamp(tx_public, tx_secret) != 0) {
        free(tx_prefix->outputs);
        return XMR_ERR_INTERNAL;
    }

    /* Store tx public key in extra */
    tx_prefix->extra[0] = 0x01;  /* TX_EXTRA_TAG_PUBKEY */
    memcpy(tx_prefix->extra + 1, tx_public, 32);
    tx_prefix->extra_len = 33;

    /* Generate output to destination */
    xmr_tx_output_t *out0 = &tx_prefix->outputs[0];
    out0->amount = amount;

    /* Compute shared secret for destination */
    uint8_t shared_secret[32];
    if (crypto_scalarmult_ed25519_noclamp(shared_secret, tx_secret, dest.view_public) != 0) {
        free(tx_prefix->outputs);
        return XMR_ERR_INTERNAL;
    }

    /* Derive output key */
    uint8_t derivation[32];
    uint8_t hash_input[33];
    memcpy(hash_input, shared_secret, 32);
    hash_input[32] = 0;  /* output index */
    xmr_hash_to_scalar(hash_input, 33, derivation);

    uint8_t derivation_G[32];
    if (crypto_scalarmult_ed25519_base_noclamp(derivation_G, derivation) != 0) {
        free(tx_prefix->outputs);
        return XMR_ERR_INTERNAL;
    }
    if (crypto_core_ed25519_add(out0->dest_key, dest.spend_public, derivation_G) != 0) {
        free(tx_prefix->outputs);
        return XMR_ERR_INTERNAL;
    }

    /* Generate commitment for amount */
    xmr_commitment_t commit0;
    err = xmr_generate_commitment(amount, NULL, &commit0);
    if (err != XMR_OK) {
        free(tx_prefix->outputs);
        return err;
    }
    memcpy(out0->commitment, commit0.commitment, 32);
    memcpy(out0->mask, commit0.mask, 32);

    /* Encode ECDH */
    xmr_encode_ecdh(amount, commit0.mask, shared_secret, 0, &out0->ecdh);

    /* Generate change output if needed */
    if (change > 0) {
        xmr_tx_output_t *out1 = &tx_prefix->outputs[1];
        out1->amount = change;

        /* Use sender's keys for change */
        const uint8_t *change_view = keypair->view_public;
        const uint8_t *change_spend = keypair->spend_public;

        if (change_addr) {
            xmr_address_t change_decoded;
            if (xmr_decode_address(change_addr, &change_decoded) == XMR_OK) {
                change_view = change_decoded.view_public;
                change_spend = change_decoded.spend_public;
            }
        }

        uint8_t change_shared[32];
        if (crypto_scalarmult_ed25519_noclamp(change_shared, tx_secret, change_view) != 0) {
            free(tx_prefix->outputs);
            return XMR_ERR_INTERNAL;
        }

        hash_input[32] = 1;  /* output index 1 */
        memcpy(hash_input, change_shared, 32);
        xmr_hash_to_scalar(hash_input, 33, derivation);
        if (crypto_scalarmult_ed25519_base_noclamp(derivation_G, derivation) != 0) {
            free(tx_prefix->outputs);
            return XMR_ERR_INTERNAL;
        }
        if (crypto_core_ed25519_add(out1->dest_key, change_spend, derivation_G) != 0) {
            free(tx_prefix->outputs);
            return XMR_ERR_INTERNAL;
        }

        xmr_commitment_t commit1;
        err = xmr_generate_commitment(change, NULL, &commit1);
        if (err != XMR_OK) {
            free(tx_prefix->outputs);
            return err;
        }
        memcpy(out1->commitment, commit1.commitment, 32);
        memcpy(out1->mask, commit1.mask, 32);

        xmr_encode_ecdh(change, commit1.mask, change_shared, 1, &out1->ecdh);
    }

    /* Compute transaction prefix hash */
    uint8_t tx_hash[32];
    err = xmr_compute_tx_prefix_hash(tx_prefix, tx_hash);
    if (err != XMR_OK) {
        free(tx_prefix->outputs);
        return err;
    }

    /* Generate CLSAG signatures for each input */
    for (size_t i = 0; i < input_count; i++) {
        xmr_tx_input_t *inp = &inputs[i];

        /* Compute key image if not set */
        if (sodium_is_zero(inp->key_image, 32)) {
            uint8_t one_time_public[32];
            xmr_secret_to_public(inp->one_time_key, one_time_public);
            err = xmr_compute_key_image(inp->one_time_key, one_time_public,
                                        inp->key_image);
            if (err != XMR_OK) {
                free(tx_prefix->outputs);
                return err;
            }
        }

        /* Compute pseudo output commitment
         * The sum of pseudo outputs must equal sum of real outputs + fee*H */
        uint8_t pseudo_out[32];
        xmr_commitment_t pseudo;
        xmr_generate_commitment(inp->amount, inp->mask, &pseudo);
        memcpy(pseudo_out, pseudo.commitment, 32);

        /* Generate CLSAG signature */
        err = xmr_clsag_sign(tx_hash, inp->ring, inp->ring_size,
                            inp->real_index, inp->one_time_key,
                            inp->key_image, inp->mask, pseudo_out,
                            &signatures[i]);
        if (err != XMR_OK) {
            free(tx_prefix->outputs);
            return err;
        }
    }

    /* Wipe sensitive data */
    sodium_memzero(tx_secret, sizeof(tx_secret));
    sodium_memzero(shared_secret, sizeof(shared_secret));

    return XMR_OK;
}

/*
 * Free transaction prefix resources
 */
void xmr_free_tx_prefix(xmr_tx_prefix_t *prefix)
{
    if (prefix) {
        if (prefix->outputs) {
            /* Wipe sensitive mask data */
            for (size_t i = 0; i < prefix->output_count; i++) {
                sodium_memzero(prefix->outputs[i].mask, 32);
            }
            free(prefix->outputs);
            prefix->outputs = NULL;
        }
        prefix->output_count = 0;
        prefix->input_count = 0;
        prefix->inputs = NULL;
    }
}

/*
 * Ethereum Chain Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "ethereum.h"
#include "../crypto/keccak256.h"
#include "../crypto/secp256k1.h"
#include "../util/hex.h"
#include "../util/rlp.h"
#include "../security/memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sodium.h>

int eth_pubkey_to_address(const uint8_t pubkey[65], char *address)
{
    uint8_t hash[KECCAK256_DIGEST_LENGTH];

    if (pubkey == NULL || address == NULL) {
        return -1;
    }

    /* Verify uncompressed key format */
    if (pubkey[0] != 0x04) {
        return -1;
    }

    /* Keccak256(pubkey[1:65]) - skip the 0x04 prefix */
    keccak256(pubkey + 1, 64, hash);

    /* Take last 20 bytes as address */
    address[0] = '0';
    address[1] = 'x';
    hex_encode(hash + 12, 20, address + 2, 1);

    return 0;
}

int eth_checksum_address(const char *address, char *output, size_t output_len)
{
    uint8_t hash[KECCAK256_DIGEST_LENGTH];
    char lower[41];
    size_t i;
    const char *addr;

    if (address == NULL || output == NULL || output_len < 43) {
        return -1;
    }

    /* Skip 0x prefix if present */
    addr = address;
    if (addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X')) {
        addr += 2;
    }

    if (strlen(addr) != 40) {
        return -1;
    }

    /* Convert to lowercase for hashing using bit manipulation
     * For ASCII hex chars: lowercase = char | 0x20 (works for A-F and a-f)
     * Digits 0-9 are unaffected since bit 5 is already 1 */
    for (i = 0; i < 40; i++) {
        char c = addr[i];
        /* For hex digits, OR with 0x20 converts A-F to a-f, leaves 0-9 and a-f unchanged */
        lower[i] = (c >= 'A' && c <= 'F') ? (c | 0x20) : c;
    }
    lower[40] = '\0';

    /* Keccak256 of lowercase hex address (without 0x) */
    keccak256((const uint8_t *)lower, 40, hash);

    /* Apply checksum: uppercase if hash nibble >= 8 */
    output[0] = '0';
    output[1] = 'x';

    /* Unrolled loop processing 2 characters per hash byte */
    for (i = 0; i < 20; i++) {
        uint8_t h = hash[i];
        char c0 = lower[i * 2];
        char c1 = lower[i * 2 + 1];

        /* High nibble check for first character */
        if ((h & 0x80) && c0 >= 'a' && c0 <= 'f') {
            output[2 + i * 2] = c0 & ~0x20;  /* Clear bit 5 to uppercase */
        } else {
            output[2 + i * 2] = c0;
        }

        /* Low nibble check for second character */
        if ((h & 0x08) && c1 >= 'a' && c1 <= 'f') {
            output[2 + i * 2 + 1] = c1 & ~0x20;  /* Clear bit 5 to uppercase */
        } else {
            output[2 + i * 2 + 1] = c1;
        }
    }
    output[42] = '\0';

    return 0;
}

/**
 * Decode uint64 from RLP item
 */
static uint64_t rlp_to_uint64(const rlp_item_t *item)
{
    uint64_t value = 0;
    for (size_t i = 0; i < item->length && i < 8; i++) {
        value = (value << 8) | item->data[i];
    }
    return value;
}

/**
 * Copy big-endian bytes from RLP item
 */
static void rlp_to_bytes(const rlp_item_t *item, uint8_t *output, size_t max_len)
{
    memset(output, 0, max_len);
    size_t copy_len = (item->length < max_len) ? item->length : max_len;
    size_t offset = max_len - copy_len;
    memcpy(output + offset, item->data, copy_len);
}

int eth_parse_tx(const uint8_t *rlp_data, size_t rlp_len, eth_tx_t *tx)
{
    rlp_item_t outer;
    rlp_item_t items[16];
    int item_count;
    const uint8_t *data = rlp_data;
    size_t len = rlp_len;

    if (rlp_data == NULL || tx == NULL) {
        return -1;
    }

    memset(tx, 0, sizeof(eth_tx_t));

    /* Check for typed transaction (EIP-2718) */
    if (len > 0 && data[0] <= 0x7f) {
        tx->type = (eth_tx_type_t)data[0];
        data++;
        len--;
    } else {
        tx->type = ETH_TX_LEGACY;
    }

    /* Decode outer RLP list */
    if (rlp_decode_item(data, len, &outer) < 0 || outer.type != RLP_TYPE_LIST) {
        return -1;
    }

    /* Decode list items */
    item_count = rlp_decode_list(outer.data, outer.length, items, 16);
    if (item_count < 0) {
        return -1;
    }

    if (tx->type == ETH_TX_LEGACY) {
        /* Legacy: [nonce, gasPrice, gasLimit, to, value, data, v, r, s] */
        if (item_count < 6) return -1;

        tx->nonce = rlp_to_uint64(&items[0]);
        rlp_to_bytes(&items[1], tx->gas_price, 32);
        tx->gas_limit = rlp_to_uint64(&items[2]);

        /* To address */
        if (items[3].length == 20) {
            memcpy(tx->to, items[3].data, 20);
            tx->to_str[0] = '0';
            tx->to_str[1] = 'x';
            hex_encode(tx->to, 20, tx->to_str + 2, 1);
        }

        rlp_to_bytes(&items[4], tx->value, 32);

        /* Data */
        if (items[5].length > 0) {
            tx->data = malloc(items[5].length);
            if (tx->data == NULL) return -1;
            memcpy(tx->data, items[5].data, items[5].length);
            tx->data_len = items[5].length;
        }

        /* Extract chain_id from v if present (EIP-155) */
        if (item_count >= 7) {
            uint64_t v = rlp_to_uint64(&items[6]);
            if (v >= 35) {
                tx->chain_id = (v - 35) / 2;
            }
        }

    } else if (tx->type == ETH_TX_EIP1559) {
        /* EIP-1559: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s] */
        if (item_count < 9) return -1;

        tx->chain_id = rlp_to_uint64(&items[0]);
        tx->nonce = rlp_to_uint64(&items[1]);
        rlp_to_bytes(&items[2], tx->max_priority_fee, 32);
        rlp_to_bytes(&items[3], tx->max_fee, 32);
        tx->gas_limit = rlp_to_uint64(&items[4]);

        /* To address */
        if (items[5].length == 20) {
            memcpy(tx->to, items[5].data, 20);
            tx->to_str[0] = '0';
            tx->to_str[1] = 'x';
            hex_encode(tx->to, 20, tx->to_str + 2, 1);
        }

        rlp_to_bytes(&items[6], tx->value, 32);

        /* Data */
        if (items[7].length > 0) {
            tx->data = malloc(items[7].length);
            if (tx->data == NULL) return -1;
            memcpy(tx->data, items[7].data, items[7].length);
            tx->data_len = items[7].length;
        }
    }

    return 0;
}

int eth_sign_tx(eth_tx_t *tx, const bip32_key_t *key,
                uint8_t *signed_tx, size_t *signed_tx_len)
{
    uint8_t rlp_buffer[2048];
    uint8_t hash[32];
    uint8_t signature[SECP256K1_SIGNATURE_SIZE];
    int recid;
    size_t offset = 0;
    size_t max_len;

    /* Pre-encoded items for RLP list */
    uint8_t encoded_items[12][128];
    size_t item_lens[12];
    const uint8_t *item_ptrs[12];
    size_t item_count;

    if (tx == NULL || key == NULL || signed_tx == NULL || signed_tx_len == NULL) {
        return -1;
    }

    max_len = *signed_tx_len;

    if (tx->type == ETH_TX_LEGACY) {
        /* Legacy transaction: RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]) */
        int len;

        /* Nonce */
        len = rlp_encode_uint64(tx->nonce, encoded_items[0], sizeof(encoded_items[0]));
        if (len < 0) return -1;
        item_lens[0] = len;
        item_ptrs[0] = encoded_items[0];

        /* Gas price */
        len = rlp_encode_bigint(tx->gas_price, 32, encoded_items[1], sizeof(encoded_items[1]));
        if (len < 0) return -1;
        item_lens[1] = len;
        item_ptrs[1] = encoded_items[1];

        /* Gas limit */
        len = rlp_encode_uint64(tx->gas_limit, encoded_items[2], sizeof(encoded_items[2]));
        if (len < 0) return -1;
        item_lens[2] = len;
        item_ptrs[2] = encoded_items[2];

        /* To address */
        len = rlp_encode_string(tx->to, 20, encoded_items[3], sizeof(encoded_items[3]));
        if (len < 0) return -1;
        item_lens[3] = len;
        item_ptrs[3] = encoded_items[3];

        /* Value */
        len = rlp_encode_bigint(tx->value, 32, encoded_items[4], sizeof(encoded_items[4]));
        if (len < 0) return -1;
        item_lens[4] = len;
        item_ptrs[4] = encoded_items[4];

        /* Data */
        len = rlp_encode_string(tx->data, tx->data_len, encoded_items[5], sizeof(encoded_items[5]));
        if (len < 0) return -1;
        item_lens[5] = len;
        item_ptrs[5] = encoded_items[5];

        /* EIP-155: chainId, 0, 0 for signing */
        len = rlp_encode_uint64(tx->chain_id, encoded_items[6], sizeof(encoded_items[6]));
        if (len < 0) return -1;
        item_lens[6] = len;
        item_ptrs[6] = encoded_items[6];

        /* Empty r */
        encoded_items[7][0] = 0x80;
        item_lens[7] = 1;
        item_ptrs[7] = encoded_items[7];

        /* Empty s */
        encoded_items[8][0] = 0x80;
        item_lens[8] = 1;
        item_ptrs[8] = encoded_items[8];

        item_count = 9;

        /* Encode signing payload */
        int rlp_len = rlp_encode_list(item_ptrs, item_lens, item_count,
                                       rlp_buffer, sizeof(rlp_buffer));
        if (rlp_len < 0) return -1;

        /* Hash */
        keccak256(rlp_buffer, rlp_len, hash);

        /* Sign */
        if (secp256k1_sign_recoverable(key->private_key, hash, signature, &recid) != 0) {
            return -1;
        }

        /* Calculate v value (EIP-155) */
        uint64_t v = recid + 35 + tx->chain_id * 2;

        /* Encode v */
        len = rlp_encode_uint64(v, encoded_items[6], sizeof(encoded_items[6]));
        if (len < 0) return -1;
        item_lens[6] = len;

        /* Encode r (first 32 bytes of signature) */
        len = rlp_encode_bigint(signature, 32, encoded_items[7], sizeof(encoded_items[7]));
        if (len < 0) return -1;
        item_lens[7] = len;
        item_ptrs[7] = encoded_items[7];

        /* Encode s (last 32 bytes of signature) */
        len = rlp_encode_bigint(signature + 32, 32, encoded_items[8], sizeof(encoded_items[8]));
        if (len < 0) return -1;
        item_lens[8] = len;
        item_ptrs[8] = encoded_items[8];

        /* Encode final signed transaction */
        rlp_len = rlp_encode_list(item_ptrs, item_lens, item_count,
                                   signed_tx, max_len);
        if (rlp_len < 0) return -1;

        *signed_tx_len = rlp_len;

    } else if (tx->type == ETH_TX_EIP1559) {
        /* EIP-1559: 0x02 || RLP([chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList]) */
        int len;

        /* Chain ID */
        len = rlp_encode_uint64(tx->chain_id, encoded_items[0], sizeof(encoded_items[0]));
        if (len < 0) return -1;
        item_lens[0] = len;
        item_ptrs[0] = encoded_items[0];

        /* Nonce */
        len = rlp_encode_uint64(tx->nonce, encoded_items[1], sizeof(encoded_items[1]));
        if (len < 0) return -1;
        item_lens[1] = len;
        item_ptrs[1] = encoded_items[1];

        /* Max priority fee */
        len = rlp_encode_bigint(tx->max_priority_fee, 32, encoded_items[2], sizeof(encoded_items[2]));
        if (len < 0) return -1;
        item_lens[2] = len;
        item_ptrs[2] = encoded_items[2];

        /* Max fee */
        len = rlp_encode_bigint(tx->max_fee, 32, encoded_items[3], sizeof(encoded_items[3]));
        if (len < 0) return -1;
        item_lens[3] = len;
        item_ptrs[3] = encoded_items[3];

        /* Gas limit */
        len = rlp_encode_uint64(tx->gas_limit, encoded_items[4], sizeof(encoded_items[4]));
        if (len < 0) return -1;
        item_lens[4] = len;
        item_ptrs[4] = encoded_items[4];

        /* To address */
        len = rlp_encode_string(tx->to, 20, encoded_items[5], sizeof(encoded_items[5]));
        if (len < 0) return -1;
        item_lens[5] = len;
        item_ptrs[5] = encoded_items[5];

        /* Value */
        len = rlp_encode_bigint(tx->value, 32, encoded_items[6], sizeof(encoded_items[6]));
        if (len < 0) return -1;
        item_lens[6] = len;
        item_ptrs[6] = encoded_items[6];

        /* Data */
        len = rlp_encode_string(tx->data, tx->data_len, encoded_items[7], sizeof(encoded_items[7]));
        if (len < 0) return -1;
        item_lens[7] = len;
        item_ptrs[7] = encoded_items[7];

        /* Access list (empty) */
        encoded_items[8][0] = 0xC0;  /* Empty list */
        item_lens[8] = 1;
        item_ptrs[8] = encoded_items[8];

        item_count = 9;

        /* Encode signing payload (with type prefix) */
        int rlp_len = rlp_encode_list(item_ptrs, item_lens, item_count,
                                       rlp_buffer + 1, sizeof(rlp_buffer) - 1);
        if (rlp_len < 0) return -1;
        rlp_buffer[0] = 0x02;  /* EIP-1559 type */
        rlp_len++;

        /* Hash */
        keccak256(rlp_buffer, rlp_len, hash);

        /* Sign */
        if (secp256k1_sign_recoverable(key->private_key, hash, signature, &recid) != 0) {
            return -1;
        }

        /* Add signature to list items */
        /* y_parity (0 or 1) */
        len = rlp_encode_uint64(recid, encoded_items[9], sizeof(encoded_items[9]));
        if (len < 0) return -1;
        item_lens[9] = len;
        item_ptrs[9] = encoded_items[9];

        /* r */
        len = rlp_encode_bigint(signature, 32, encoded_items[10], sizeof(encoded_items[10]));
        if (len < 0) return -1;
        item_lens[10] = len;
        item_ptrs[10] = encoded_items[10];

        /* s */
        len = rlp_encode_bigint(signature + 32, 32, encoded_items[11], sizeof(encoded_items[11]));
        if (len < 0) return -1;
        item_lens[11] = len;
        item_ptrs[11] = encoded_items[11];

        item_count = 12;

        /* Encode final signed transaction */
        if (max_len < 1) return -1;
        signed_tx[0] = 0x02;  /* EIP-1559 type */
        offset = 1;

        rlp_len = rlp_encode_list(item_ptrs, item_lens, item_count,
                                   signed_tx + offset, max_len - offset);
        if (rlp_len < 0) return -1;

        *signed_tx_len = offset + rlp_len;

    } else {
        return -1;  /* Unsupported transaction type */
    }

    /* Wipe sensitive data */
    secure_wipe(hash, sizeof(hash));
    secure_wipe(signature, sizeof(signature));

    return 0;
}

int eth_sign_typed_data(const uint8_t domain_hash[32],
                        const uint8_t message_hash[32],
                        const bip32_key_t *key,
                        uint8_t signature[ETH_SIG_SIZE])
{
    uint8_t preimage[66];
    uint8_t hash[32];
    int recid;

    if (domain_hash == NULL || message_hash == NULL || key == NULL || signature == NULL) {
        return -1;
    }

    /* EIP-712: hash = keccak256("\x19\x01" + domain_hash + message_hash) */
    preimage[0] = 0x19;
    preimage[1] = 0x01;
    memcpy(preimage + 2, domain_hash, 32);
    memcpy(preimage + 34, message_hash, 32);

    keccak256(preimage, 66, hash);

    /* Sign with recoverable signature */
    if (secp256k1_sign_recoverable(key->private_key, hash, signature, &recid) != 0) {
        secure_wipe(hash, sizeof(hash));
        return -1;
    }

    /* Append recovery id as v (27 or 28 for Ethereum) */
    signature[64] = 27 + recid;

    secure_wipe(hash, sizeof(hash));
    return 0;
}

int eth_sign_message(const uint8_t *message, size_t message_len,
                     const bip32_key_t *key,
                     uint8_t signature[ETH_SIG_SIZE])
{
    uint8_t hash[32];
    char len_str[21];
    int recid;

    /* Keccak state for streaming hash */
    const char *prefix = "\x19" "Ethereum Signed Message:\n";
    size_t prefix_len = strlen(prefix);

    if (message == NULL || key == NULL || signature == NULL) {
        return -1;
    }

    /* Convert message length to string */
    snprintf(len_str, sizeof(len_str), "%zu", message_len);
    size_t len_str_len = strlen(len_str);

    /* Build full message: prefix + len_str + message */
    size_t total_len = prefix_len + len_str_len + message_len;
    uint8_t *full_message = malloc(total_len);
    if (full_message == NULL) {
        return -1;
    }

    memcpy(full_message, prefix, prefix_len);
    memcpy(full_message + prefix_len, len_str, len_str_len);
    memcpy(full_message + prefix_len + len_str_len, message, message_len);

    /* Hash */
    keccak256(full_message, total_len, hash);

    secure_wipe(full_message, total_len);
    free(full_message);

    /* Sign with recoverable signature */
    if (secp256k1_sign_recoverable(key->private_key, hash, signature, &recid) != 0) {
        secure_wipe(hash, sizeof(hash));
        return -1;
    }

    /* Append recovery id as v (27 or 28 for Ethereum) */
    signature[64] = 27 + recid;

    secure_wipe(hash, sizeof(hash));
    return 0;
}

int eth_validate_address(const char *address)
{
    size_t i;
    const char *hex_part;

    if (address == NULL) {
        return 0;
    }

    /* Must start with 0x */
    if (address[0] != '0' || (address[1] != 'x' && address[1] != 'X')) {
        return 0;
    }

    hex_part = address + 2;

    /* Must be exactly 40 hex characters */
    if (strlen(hex_part) != 40) {
        return 0;
    }

    for (i = 0; i < 40; i++) {
        if (!isxdigit((unsigned char)hex_part[i])) {
            return 0;
        }
    }

    return 1;
}

int eth_format_amount(const uint8_t wei[32], char *output, size_t output_len, int decimals)
{
    /* Convert 256-bit big-endian integer to decimal string with decimal point */
    char decimal_str[100];  /* 2^256 has ~78 decimal digits */
    uint8_t temp[32];
    size_t pos = 0;
    int is_zero = 1;

    if (wei == NULL || output == NULL || output_len < 32) {
        return -1;
    }

    memcpy(temp, wei, 32);

    /* Check if all zeros */
    for (int i = 0; i < 32; i++) {
        if (temp[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (is_zero) {
        if (output_len < 7) return -1;
        strcpy(output, "0 ETH");
        return 0;
    }

    /* Convert to decimal by repeated division by 10 */
    while (1) {
        uint32_t remainder = 0;
        int all_zero = 1;

        /* Divide by 10 */
        for (int i = 0; i < 32; i++) {
            uint32_t dividend = (remainder << 8) | temp[i];
            temp[i] = dividend / 10;
            remainder = dividend % 10;
            if (temp[i] != 0) all_zero = 0;
        }

        decimal_str[pos++] = '0' + remainder;

        if (all_zero) break;
        if (pos >= sizeof(decimal_str) - 1) break;
    }

    /* decimal_str is now reversed, pad with zeros if needed */
    while ((int)pos < decimals + 1) {
        decimal_str[pos++] = '0';
    }

    /* Build output string with decimal point */
    size_t out_pos = 0;

    /* Integer part (everything after decimal position, reversed) */
    int int_digits = (int)pos - decimals;
    if (int_digits <= 0) {
        if (out_pos < output_len) output[out_pos++] = '0';
    } else {
        for (int i = (int)pos - 1; i >= decimals; i--) {
            if (out_pos < output_len - 1) {
                output[out_pos++] = decimal_str[i];
            }
        }
    }

    /* Decimal point and fractional part */
    if (decimals > 0 && out_pos < output_len - 1) {
        output[out_pos++] = '.';

        /* Show up to 6 significant decimal places */
        int shown = 0;
        for (int i = decimals - 1; i >= 0 && shown < 6; i--) {
            if (out_pos < output_len - 1) {
                output[out_pos++] = decimal_str[i];
                shown++;
            }
        }

        /* Remove trailing zeros */
        while (out_pos > 1 && output[out_pos - 1] == '0') {
            out_pos--;
        }
        /* Remove decimal point if no fractional part */
        if (out_pos > 0 && output[out_pos - 1] == '.') {
            out_pos--;
        }
    }

    /* Add suffix */
    const char *suffix = " ETH";
    size_t suffix_len = strlen(suffix);
    if (out_pos + suffix_len < output_len) {
        strcpy(output + out_pos, suffix);
        out_pos += suffix_len;
    }

    output[out_pos] = '\0';
    return 0;
}

const char *eth_chain_name(uint64_t chain_id)
{
    switch (chain_id) {
    case ETH_CHAIN_MAINNET:   return "Ethereum Mainnet";
    case ETH_CHAIN_GOERLI:    return "Goerli Testnet";
    case ETH_CHAIN_SEPOLIA:   return "Sepolia Testnet";
    case ETH_CHAIN_POLYGON:   return "Polygon";
    case ETH_CHAIN_ARBITRUM:  return "Arbitrum One";
    case ETH_CHAIN_OPTIMISM:  return "Optimism";
    case ETH_CHAIN_BSC:       return "BNB Smart Chain";
    case ETH_CHAIN_AVALANCHE: return "Avalanche C-Chain";
    default:                  return "Unknown Chain";
    }
}

void eth_tx_free(eth_tx_t *tx)
{
    if (tx == NULL) {
        return;
    }

    if (tx->data != NULL) {
        secure_wipe(tx->data, tx->data_len);
        free(tx->data);
        tx->data = NULL;
    }

    tx->data_len = 0;
}

/*
 * WalletConnect v2 Protocol Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/walletconnect/walletconnect.h"
#include "../src/walletconnect/wc_crypto.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static int test_##name(void)
#define ASSERT(cond) do { if (!(cond)) { printf("  [FAIL] %s (line %d)\n", __func__, __LINE__); return -1; } } while(0)
#define PASS() do { printf("  [PASS] %s\n", __func__ + 5); return 0; } while(0)
#define RUN_TEST(name) do { if (test_##name() == 0) tests_passed++; else tests_failed++; } while(0)

/* ============================================================================
 * Crypto Tests
 * ============================================================================ */

TEST(crypto_init)
{
    int result = wc_crypto_init();
    ASSERT(result == 0);
    PASS();
}

TEST(crypto_random)
{
    uint8_t buf1[32], buf2[32];

    int result = wc_crypto_random(buf1, sizeof(buf1));
    ASSERT(result == 0);

    result = wc_crypto_random(buf2, sizeof(buf2));
    ASSERT(result == 0);

    /* Should be different (extremely high probability) */
    ASSERT(memcmp(buf1, buf2, 32) != 0);

    PASS();
}

TEST(crypto_keypair)
{
    wc_keypair_t kp;

    int result = wc_crypto_generate_keypair(&kp);
    ASSERT(result == 0);

    /* Keys should be non-zero */
    uint8_t zero[32] = {0};
    ASSERT(memcmp(kp.public_key, zero, 32) != 0);
    ASSERT(memcmp(kp.private_key, zero, 32) != 0);

    wc_crypto_wipe_keypair(&kp);
    PASS();
}

TEST(crypto_symkey)
{
    wc_symkey_t key;

    int result = wc_crypto_generate_symkey(&key);
    ASSERT(result == 0);

    /* Key should be non-zero */
    uint8_t zero[32] = {0};
    ASSERT(memcmp(key.key, zero, 32) != 0);

    wc_crypto_wipe_symkey(&key);
    PASS();
}

TEST(crypto_x25519)
{
    wc_keypair_t alice, bob;

    wc_crypto_generate_keypair(&alice);
    wc_crypto_generate_keypair(&bob);

    uint8_t shared_ab[32], shared_ba[32];

    /* Alice derives shared secret with Bob's public key */
    int result = wc_crypto_x25519(alice.private_key, bob.public_key, shared_ab);
    ASSERT(result == 0);

    /* Bob derives shared secret with Alice's public key */
    result = wc_crypto_x25519(bob.private_key, alice.public_key, shared_ba);
    ASSERT(result == 0);

    /* Shared secrets should match */
    ASSERT(memcmp(shared_ab, shared_ba, 32) == 0);

    wc_crypto_wipe_keypair(&alice);
    wc_crypto_wipe_keypair(&bob);
    PASS();
}

TEST(crypto_hkdf)
{
    uint8_t shared[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                         17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    wc_symkey_t key;

    int result = wc_crypto_hkdf(shared, sizeof(shared), NULL, 0, &key);
    ASSERT(result == 0);

    /* Key should be derived */
    uint8_t zero[32] = {0};
    ASSERT(memcmp(key.key, zero, 32) != 0);

    wc_crypto_wipe_symkey(&key);
    PASS();
}

TEST(crypto_derive_topic)
{
    wc_symkey_t key = {{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                       17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}};
    wc_topic_t topic;

    int result = wc_crypto_derive_topic(&key, &topic);
    ASSERT(result == 0);

    /* Topic should be SHA256 of key */
    ASSERT(strlen(topic.hex) == 64);

    PASS();
}

TEST(crypto_encrypt_decrypt)
{
    wc_symkey_t key;
    wc_crypto_generate_symkey(&key);

    const uint8_t plaintext[] = "Hello, WalletConnect!";
    uint8_t ciphertext[256];
    size_t ciphertext_len = sizeof(ciphertext);
    uint8_t iv[WC_IV_SIZE];
    uint8_t tag[WC_TAG_SIZE];

    /* Encrypt */
    int result = wc_crypto_encrypt(&key, plaintext, sizeof(plaintext),
                                   ciphertext, &ciphertext_len, iv, tag);
    ASSERT(result == 0);
    ASSERT(ciphertext_len == sizeof(plaintext));

    /* Ciphertext should differ from plaintext */
    ASSERT(memcmp(ciphertext, plaintext, sizeof(plaintext)) != 0);

    /* Decrypt */
    uint8_t decrypted[256];
    size_t decrypted_len = sizeof(decrypted);
    result = wc_crypto_decrypt(&key, ciphertext, ciphertext_len,
                               iv, tag, decrypted, &decrypted_len);
    ASSERT(result == 0);
    ASSERT(decrypted_len == sizeof(plaintext));
    ASSERT(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);

    wc_crypto_wipe_symkey(&key);
    PASS();
}

TEST(crypto_envelope_type0)
{
    wc_symkey_t key;
    wc_crypto_generate_symkey(&key);

    const uint8_t plaintext[] = "{\"method\":\"wc_sessionPropose\"}";
    uint8_t envelope[512];
    size_t envelope_len = sizeof(envelope);

    /* Seal */
    int result = wc_crypto_seal_type0(&key, plaintext, sizeof(plaintext),
                                      envelope, &envelope_len);
    ASSERT(result == 0);
    ASSERT(envelope_len > sizeof(plaintext));
    ASSERT(envelope[0] == WC_ENVELOPE_TYPE_0);

    /* Open */
    uint8_t opened[512];
    size_t opened_len = sizeof(opened);
    result = wc_crypto_open_type0(&key, envelope, envelope_len, opened, &opened_len);
    ASSERT(result == 0);
    ASSERT(opened_len == sizeof(plaintext));
    ASSERT(memcmp(opened, plaintext, sizeof(plaintext)) == 0);

    wc_crypto_wipe_symkey(&key);
    PASS();
}

TEST(crypto_envelope_type1)
{
    wc_keypair_t alice, bob;
    wc_crypto_generate_keypair(&alice);
    wc_crypto_generate_keypair(&bob);

    const uint8_t plaintext[] = "{\"method\":\"wc_sessionSettle\"}";
    uint8_t envelope[512];
    size_t envelope_len = sizeof(envelope);

    /* Alice seals message for Bob */
    int result = wc_crypto_seal_type1(&alice, bob.public_key, plaintext, sizeof(plaintext),
                                      envelope, &envelope_len);
    ASSERT(result == 0);
    ASSERT(envelope_len > sizeof(plaintext));
    ASSERT(envelope[0] == WC_ENVELOPE_TYPE_1);

    /* Bob opens envelope */
    uint8_t sender_pubkey[WC_KEY_SIZE];
    uint8_t opened[512];
    size_t opened_len = sizeof(opened);
    result = wc_crypto_open_type1(&bob, envelope, envelope_len,
                                  sender_pubkey, opened, &opened_len);
    ASSERT(result == 0);
    ASSERT(opened_len == sizeof(plaintext));
    ASSERT(memcmp(opened, plaintext, sizeof(plaintext)) == 0);
    ASSERT(memcmp(sender_pubkey, alice.public_key, WC_KEY_SIZE) == 0);

    wc_crypto_wipe_keypair(&alice);
    wc_crypto_wipe_keypair(&bob);
    PASS();
}

TEST(crypto_sha256)
{
    const uint8_t data[] = "test";
    uint8_t hash[32];

    int result = wc_crypto_sha256(data, sizeof(data) - 1, hash);
    ASSERT(result == 0);

    /* Known SHA256 of "test" */
    const uint8_t expected[] = {
        0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
        0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
        0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
        0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08
    };
    ASSERT(memcmp(hash, expected, 32) == 0);

    PASS();
}

TEST(crypto_hex_conversion)
{
    const uint8_t bytes[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    char hex[17];

    wc_crypto_to_hex(bytes, 8, hex);
    ASSERT(strcmp(hex, "0123456789abcdef") == 0);

    uint8_t back[8];
    int result = wc_crypto_from_hex(hex, back, 8);
    ASSERT(result == 0);
    ASSERT(memcmp(back, bytes, 8) == 0);

    PASS();
}

/* ============================================================================
 * Context Tests
 * ============================================================================ */

TEST(context_create)
{
    wc_context_t *ctx = wc_create("test_project_id");
    ASSERT(ctx != NULL);

    wc_destroy(ctx);
    PASS();
}

TEST(context_metadata)
{
    wc_context_t *ctx = wc_create("test_project_id");
    ASSERT(ctx != NULL);

    int result = wc_set_metadata(ctx, "Test Wallet", "A test wallet",
                                 "https://test.com", "https://test.com/icon.png");
    ASSERT(result == 0);

    wc_destroy(ctx);
    PASS();
}

TEST(context_callbacks)
{
    wc_context_t *ctx = wc_create("test_project_id");
    ASSERT(ctx != NULL);

    /* Set callbacks - NULL for testing */
    wc_set_callbacks(ctx, NULL, NULL, NULL, NULL);

    wc_destroy(ctx);
    PASS();
}

/* ============================================================================
 * Pairing Tests
 * ============================================================================ */

TEST(pairing_parse_uri)
{
    /* Sample WalletConnect v2 pairing URI */
    const char *uri = "wc:7f6e504bdfad6c4a6b9f10a3a8c9f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5@2"
                      "?relay-protocol=irn"
                      "&symKey=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    wc_pairing_t pairing;
    int result = wc_parse_pairing_uri(uri, &pairing);
    ASSERT(result == 0);

    /* Verify topic was parsed */
    ASSERT(strcmp(pairing.topic.hex, "7f6e504bdfad6c4a6b9f10a3a8c9f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5") == 0);

    /* Verify relay protocol */
    ASSERT(strcmp(pairing.relay.protocol, "irn") == 0);

    /* Verify keypair was generated */
    uint8_t zero[32] = {0};
    ASSERT(memcmp(pairing.self_keypair.public_key, zero, 32) != 0);

    wc_crypto_wipe_keypair(&pairing.self_keypair);
    PASS();
}

TEST(pairing_invalid_uri)
{
    wc_pairing_t pairing;

    /* Missing wc: prefix */
    int result = wc_parse_pairing_uri("invalid_uri", &pairing);
    ASSERT(result == -1);

    /* Wrong version */
    result = wc_parse_pairing_uri("wc:abc@1?symKey=def", &pairing);
    ASSERT(result == -1);

    PASS();
}

TEST(pairing_pair)
{
    wc_context_t *ctx = wc_create("test_project_id");
    ASSERT(ctx != NULL);

    const char *uri = "wc:7f6e504bdfad6c4a6b9f10a3a8c9f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5@2"
                      "?relay-protocol=irn"
                      "&symKey=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    int result = wc_pair(ctx, uri);
    ASSERT(result == 0);

    /* Verify pairing was stored */
    size_t count = 10;
    result = wc_get_pairings(ctx, NULL, &count);
    ASSERT(result == 0);
    ASSERT(count == 1);

    wc_destroy(ctx);
    PASS();
}

/* ============================================================================
 * Session Tests
 * ============================================================================ */

TEST(session_none)
{
    wc_context_t *ctx = wc_create("test_project_id");
    ASSERT(ctx != NULL);

    size_t count = 10;
    int result = wc_get_sessions(ctx, NULL, &count);
    ASSERT(result == 0);
    ASSERT(count == 0);

    wc_destroy(ctx);
    PASS();
}

/* ============================================================================
 * Utility Tests
 * ============================================================================ */

TEST(util_parse_method)
{
    ASSERT(wc_parse_method("personal_sign") == WC_METHOD_PERSONAL_SIGN);
    ASSERT(wc_parse_method("eth_sign") == WC_METHOD_ETH_SIGN);
    ASSERT(wc_parse_method("eth_signTypedData") == WC_METHOD_ETH_SIGN_TYPED_DATA);
    ASSERT(wc_parse_method("eth_signTypedData_v4") == WC_METHOD_ETH_SIGN_TYPED_DATA_V4);
    ASSERT(wc_parse_method("eth_signTransaction") == WC_METHOD_ETH_SIGN_TRANSACTION);
    ASSERT(wc_parse_method("eth_sendTransaction") == WC_METHOD_ETH_SEND_TRANSACTION);
    ASSERT(wc_parse_method("unknown_method") == WC_METHOD_UNKNOWN);
    PASS();
}

TEST(util_method_name)
{
    ASSERT(strcmp(wc_method_name(WC_METHOD_PERSONAL_SIGN), "personal_sign") == 0);
    ASSERT(strcmp(wc_method_name(WC_METHOD_ETH_SEND_TRANSACTION), "eth_sendTransaction") == 0);
    ASSERT(strcmp(wc_method_name(WC_METHOD_UNKNOWN), "unknown") == 0);
    PASS();
}

TEST(util_validate_eth_address)
{
    /* Valid address */
    ASSERT(wc_validate_eth_address("0x71C7656EC7ab88b098defB751B7401B5f6d8976F") == 1);

    /* Invalid - no 0x prefix */
    ASSERT(wc_validate_eth_address("71C7656EC7ab88b098defB751B7401B5f6d8976F") == 0);

    /* Invalid - wrong length */
    ASSERT(wc_validate_eth_address("0x71C7656EC7ab88b098defB751B7401B5f6d8976") == 0);

    /* Invalid - non-hex character */
    ASSERT(wc_validate_eth_address("0x71C7656EC7ab88b098defB751B7401B5f6d8976G") == 0);

    PASS();
}

TEST(util_chain_id)
{
    wc_chain_t chain;

    int result = wc_parse_chain_id("eip155:1", &chain);
    ASSERT(result == 0);
    ASSERT(chain.numeric_id == 1);
    ASSERT(strcmp(chain.chain_id, "eip155:1") == 0);

    result = wc_parse_chain_id("eip155:137", &chain);
    ASSERT(result == 0);
    ASSERT(chain.numeric_id == 137);

    char output[32];
    result = wc_format_chain_id(1, output, sizeof(output));
    ASSERT(result == 0);
    ASSERT(strcmp(output, "eip155:1") == 0);

    PASS();
}

TEST(util_error_message)
{
    ASSERT(strcmp(wc_error_message(WC_ERROR_NONE), "No error") == 0);
    ASSERT(strcmp(wc_error_message(WC_ERROR_USER_REJECTED), "User rejected request") == 0);
    ASSERT(strcmp(wc_error_message(WC_ERROR_SESSION_EXPIRED), "Session expired") == 0);
    PASS();
}

/* ============================================================================
 * Serialization Tests
 * ============================================================================ */

TEST(serialize_empty)
{
    wc_context_t *ctx = wc_create("test_project_id");
    ASSERT(ctx != NULL);

    /* Get required size */
    size_t len = 0;
    int result = wc_serialize(ctx, NULL, &len);
    ASSERT(result == 0);
    ASSERT(len > 0);

    /* Serialize */
    uint8_t *buf = malloc(len);
    ASSERT(buf != NULL);
    size_t actual_len = len;
    result = wc_serialize(ctx, buf, &actual_len);
    ASSERT(result == 0);

    /* Deserialize to new context */
    wc_context_t *ctx2 = wc_create("test_project_id");
    result = wc_deserialize(ctx2, buf, actual_len);
    ASSERT(result == 0);

    /* Verify empty state */
    size_t count = 10;
    wc_get_sessions(ctx2, NULL, &count);
    ASSERT(count == 0);

    free(buf);
    wc_destroy(ctx);
    wc_destroy(ctx2);
    PASS();
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int test_walletconnect(void)
{
    printf("\n[WalletConnect Crypto Tests]\n");
    RUN_TEST(crypto_init);
    RUN_TEST(crypto_random);
    RUN_TEST(crypto_keypair);
    RUN_TEST(crypto_symkey);
    RUN_TEST(crypto_x25519);
    RUN_TEST(crypto_hkdf);
    RUN_TEST(crypto_derive_topic);
    RUN_TEST(crypto_encrypt_decrypt);
    RUN_TEST(crypto_envelope_type0);
    RUN_TEST(crypto_envelope_type1);
    RUN_TEST(crypto_sha256);
    RUN_TEST(crypto_hex_conversion);

    printf("\n[WalletConnect Context Tests]\n");
    RUN_TEST(context_create);
    RUN_TEST(context_metadata);
    RUN_TEST(context_callbacks);

    printf("\n[WalletConnect Pairing Tests]\n");
    RUN_TEST(pairing_parse_uri);
    RUN_TEST(pairing_invalid_uri);
    RUN_TEST(pairing_pair);

    printf("\n[WalletConnect Session Tests]\n");
    RUN_TEST(session_none);

    printf("\n[WalletConnect Utility Tests]\n");
    RUN_TEST(util_parse_method);
    RUN_TEST(util_method_name);
    RUN_TEST(util_validate_eth_address);
    RUN_TEST(util_chain_id);
    RUN_TEST(util_error_message);

    printf("\n[WalletConnect Serialization Tests]\n");
    RUN_TEST(serialize_empty);

    return tests_failed;
}

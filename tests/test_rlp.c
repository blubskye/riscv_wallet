/*
 * RLP Encoding/Decoding Tests
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "../src/util/rlp.h"

extern void test_report(const char *name, int result);

static int test_encode_empty_string(void)
{
    uint8_t output[10];

    int len = rlp_encode_string(NULL, 0, output, sizeof(output));

    if (len != 1 || output[0] != 0x80) {
        printf("    Expected 0x80 for empty string\n");
        return -1;
    }

    return 0;
}

static int test_encode_single_byte(void)
{
    uint8_t output[10];
    uint8_t data = 0x7f;

    /* Single byte < 0x80 should encode as itself */
    int len = rlp_encode_string(&data, 1, output, sizeof(output));

    if (len != 1 || output[0] != 0x7f) {
        printf("    Expected 0x7f, got 0x%02x\n", output[0]);
        return -1;
    }

    return 0;
}

static int test_encode_single_byte_0x80(void)
{
    uint8_t output[10];
    uint8_t data = 0x80;

    /* Byte 0x80 should encode as 0x81 0x80 */
    int len = rlp_encode_string(&data, 1, output, sizeof(output));

    if (len != 2 || output[0] != 0x81 || output[1] != 0x80) {
        printf("    Expected 0x81 0x80\n");
        return -1;
    }

    return 0;
}

static int test_encode_short_string(void)
{
    uint8_t output[64];
    const uint8_t *data = (const uint8_t *)"dog";

    int len = rlp_encode_string(data, 3, output, sizeof(output));

    /* "dog" -> 0x83 'd' 'o' 'g' */
    if (len != 4) {
        printf("    Expected length 4, got %d\n", len);
        return -1;
    }

    if (output[0] != 0x83 || output[1] != 'd' || output[2] != 'o' || output[3] != 'g') {
        printf("    Encoding mismatch\n");
        return -1;
    }

    return 0;
}

static int test_encode_long_string(void)
{
    uint8_t output[100];
    uint8_t data[56];
    memset(data, 'a', 56);

    int len = rlp_encode_string(data, 56, output, sizeof(output));

    /* 56 bytes -> 0xb8 0x38 + data */
    if (len != 58) {
        printf("    Expected length 58, got %d\n", len);
        return -1;
    }

    if (output[0] != 0xb8 || output[1] != 56) {
        printf("    Expected prefix 0xb8 0x38, got 0x%02x 0x%02x\n", output[0], output[1]);
        return -1;
    }

    return 0;
}

static int test_encode_uint64_zero(void)
{
    uint8_t output[10];

    int len = rlp_encode_uint64(0, output, sizeof(output));

    /* Zero encodes as empty string (0x80) */
    if (len != 1 || output[0] != 0x80) {
        printf("    Expected 0x80 for zero\n");
        return -1;
    }

    return 0;
}

static int test_encode_uint64_small(void)
{
    uint8_t output[10];

    int len = rlp_encode_uint64(127, output, sizeof(output));

    /* 127 (0x7f) encodes as itself */
    if (len != 1 || output[0] != 0x7f) {
        printf("    Expected 0x7f, got 0x%02x\n", output[0]);
        return -1;
    }

    return 0;
}

static int test_encode_uint64_large(void)
{
    uint8_t output[10];

    int len = rlp_encode_uint64(1024, output, sizeof(output));

    /* 1024 (0x0400) encodes as 0x82 0x04 0x00 */
    if (len != 3) {
        printf("    Expected length 3, got %d\n", len);
        return -1;
    }

    if (output[0] != 0x82 || output[1] != 0x04 || output[2] != 0x00) {
        printf("    Encoding mismatch\n");
        return -1;
    }

    return 0;
}

static int test_encode_list(void)
{
    uint8_t output[64];

    /* Encode ["cat", "dog"] */
    uint8_t cat_enc[4], dog_enc[4];
    int cat_len = rlp_encode_string((const uint8_t *)"cat", 3, cat_enc, sizeof(cat_enc));
    int dog_len = rlp_encode_string((const uint8_t *)"dog", 3, dog_enc, sizeof(dog_enc));

    const uint8_t *items[] = {cat_enc, dog_enc};
    size_t item_lens[] = {(size_t)cat_len, (size_t)dog_len};

    int len = rlp_encode_list(items, item_lens, 2, output, sizeof(output));

    /* Expected: 0xc8 0x83 'c' 'a' 't' 0x83 'd' 'o' 'g' */
    if (len != 9) {
        printf("    Expected length 9, got %d\n", len);
        return -1;
    }

    if (output[0] != 0xc8) {
        printf("    Expected list prefix 0xc8, got 0x%02x\n", output[0]);
        return -1;
    }

    return 0;
}

static int test_decode_string(void)
{
    uint8_t encoded[] = {0x83, 'd', 'o', 'g'};
    rlp_item_t item;

    int consumed = rlp_decode_item(encoded, sizeof(encoded), &item);

    if (consumed != 4) {
        printf("    Expected 4 bytes consumed, got %d\n", consumed);
        return -1;
    }

    if (item.type != RLP_TYPE_STRING) {
        printf("    Expected string type\n");
        return -1;
    }

    if (item.length != 3) {
        printf("    Expected length 3, got %zu\n", item.length);
        return -1;
    }

    if (memcmp(item.data, "dog", 3) != 0) {
        printf("    Data mismatch\n");
        return -1;
    }

    return 0;
}

static int test_decode_list(void)
{
    /* Encoded ["cat", "dog"] */
    uint8_t encoded[] = {0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g'};
    rlp_item_t outer;

    int consumed = rlp_decode_item(encoded, sizeof(encoded), &outer);

    if (consumed != 9) {
        printf("    Expected 9 bytes consumed, got %d\n", consumed);
        return -1;
    }

    if (outer.type != RLP_TYPE_LIST) {
        printf("    Expected list type\n");
        return -1;
    }

    /* Decode inner items */
    rlp_item_t items[2];
    int count = rlp_decode_list(outer.data, outer.length, items, 2);

    if (count != 2) {
        printf("    Expected 2 items, got %d\n", count);
        return -1;
    }

    if (items[0].length != 3 || memcmp(items[0].data, "cat", 3) != 0) {
        printf("    First item mismatch\n");
        return -1;
    }

    if (items[1].length != 3 || memcmp(items[1].data, "dog", 3) != 0) {
        printf("    Second item mismatch\n");
        return -1;
    }

    return 0;
}

static int test_encode_bigint(void)
{
    uint8_t output[10];

    /* Bigint with leading zeros should be stripped */
    uint8_t bigint[] = {0x00, 0x00, 0x04, 0x00};

    int len = rlp_encode_bigint(bigint, sizeof(bigint), output, sizeof(output));

    /* Should encode as 0x82 0x04 0x00 (leading zeros stripped) */
    if (len != 3) {
        printf("    Expected length 3, got %d\n", len);
        return -1;
    }

    if (output[0] != 0x82 || output[1] != 0x04 || output[2] != 0x00) {
        printf("    Encoding mismatch\n");
        return -1;
    }

    return 0;
}

int test_rlp(void)
{
    int failures = 0;

    test_report("Encode empty string", test_encode_empty_string());
    test_report("Encode single byte < 0x80", test_encode_single_byte());
    test_report("Encode single byte 0x80", test_encode_single_byte_0x80());
    test_report("Encode short string", test_encode_short_string());
    test_report("Encode long string (>55 bytes)", test_encode_long_string());
    test_report("Encode uint64 zero", test_encode_uint64_zero());
    test_report("Encode uint64 small", test_encode_uint64_small());
    test_report("Encode uint64 large", test_encode_uint64_large());
    test_report("Encode list", test_encode_list());
    test_report("Decode string", test_decode_string());
    test_report("Decode list", test_decode_list());
    test_report("Encode bigint (strip leading zeros)", test_encode_bigint());

    return failures;
}

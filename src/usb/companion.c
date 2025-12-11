/*
 * USB HID Companion App Protocol
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L

#include "companion.h"
#include "../crypto/bip32.h"
#include "../security/memory.h"
#include "../chains/bitcoin.h"
#include "../hw/hal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Protocol message header */
#define COMP_HEADER_SIZE    4
#define COMP_HEADER_MSG     0  /* Message type */
#define COMP_HEADER_FLAGS   1  /* Flags */
#define COMP_HEADER_LEN_HI  2  /* Payload length (high byte) */
#define COMP_HEADER_LEN_LO  3  /* Payload length (low byte) */

/* Response header */
#define COMP_RESP_HEADER_SIZE  3
#define COMP_RESP_STATUS       0
#define COMP_RESP_LEN_HI       1
#define COMP_RESP_LEN_LO       2


/* Status messages */
static const char *status_messages[] = {
    [COMP_STATUS_OK]            = "Success",
    [COMP_STATUS_ERROR]         = "General error",
    [COMP_STATUS_USER_REJECTED] = "User rejected",
    [COMP_STATUS_BUSY]          = "Device busy",
    [COMP_STATUS_LOCKED]        = "Device locked",
    [COMP_STATUS_INVALID_CMD]   = "Invalid command",
    [COMP_STATUS_INVALID_DATA]  = "Invalid data",
    [COMP_STATUS_NOT_SUPPORTED] = "Not supported",
    [COMP_STATUS_TIMEOUT]       = "Timeout",
};

/* Device model name */
static const char *DEVICE_MODEL = "RISC-V Cold Wallet";


/* ============================================================================
 * Session Management
 * ============================================================================ */

int companion_init_session(usb_hid_device_t *device, companion_session_t *session)
{
    if (device == NULL || session == NULL) {
        return -1;
    }

    memset(session, 0, sizeof(*session));
    session->device = device;
    session->authenticated = 0;
    session->current_account = 0;

    /* Get device info */
    if (companion_get_info(session, &session->info) != 0) {
        return -1;
    }

    return 0;
}

void companion_close_session(companion_session_t *session)
{
    if (session == NULL) {
        return;
    }

    secure_wipe(session->session_key, sizeof(session->session_key));
    memset(session, 0, sizeof(*session));
}

int companion_ping(companion_session_t *session)
{
    if (session == NULL || session->device == NULL) {
        return -1;
    }

    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_PING,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = 0,
        .le = 0
    };

    apdu_response_t resp;
    if (usb_hid_apdu_exchange(session->device, &cmd, &resp) != 0) {
        return -1;
    }

    return (resp.sw == APDU_SW_OK) ? 0 : -1;
}

int companion_get_info(companion_session_t *session, companion_device_info_t *info)
{
    if (session == NULL || session->device == NULL || info == NULL) {
        return -1;
    }

    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_GET_INFO,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = 0,
        .le = 0
    };

    apdu_response_t resp;
    if (usb_hid_apdu_exchange(session->device, &cmd, &resp) != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK || resp.data_len < 24) {
        return -1;
    }

    /* Parse response */
    size_t offset = 0;
    info->protocol_version = ((uint16_t)resp.data[offset] << 8) | resp.data[offset + 1];
    offset += 2;

    info->firmware_major = resp.data[offset++];
    info->firmware_minor = resp.data[offset++];
    info->firmware_patch = resp.data[offset++];

    memcpy(info->device_id, resp.data + offset, 16);
    offset += 16;

    info->supported_chains = resp.data[offset++];
    info->flags = resp.data[offset++];

    /* Model name (remaining bytes) */
    size_t name_len = resp.data_len - offset;
    if (name_len > sizeof(info->model_name) - 1) {
        name_len = sizeof(info->model_name) - 1;
    }
    memcpy(info->model_name, resp.data + offset, name_len);
    info->model_name[name_len] = '\0';

    return 0;
}

/* ============================================================================
 * Key and Address Operations
 * ============================================================================ */

int companion_get_pubkey(companion_session_t *session,
                         const companion_path_t *path,
                         uint8_t display,
                         companion_pubkey_t *pubkey)
{
    if (session == NULL || path == NULL || pubkey == NULL) {
        return -1;
    }

    /* Build request: path depth + path elements */
    uint8_t data[1 + COMP_MAX_PATH_DEPTH * 4];
    size_t data_len = 0;

    data[data_len++] = (uint8_t)path->depth;
    for (size_t i = 0; i < path->depth; i++) {
        data[data_len++] = (path->path[i] >> 24) & 0xFF;
        data[data_len++] = (path->path[i] >> 16) & 0xFF;
        data[data_len++] = (path->path[i] >> 8) & 0xFF;
        data[data_len++] = path->path[i] & 0xFF;
    }

    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_GET_PUBKEY,
        .p1 = display,
        .p2 = 0x00,
        .lc = (uint8_t)data_len,
        .le = 0
    };
    memcpy(cmd.data, data, data_len);

    apdu_response_t resp;
    if (usb_hid_apdu_exchange(session->device, &cmd, &resp) != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK) {
        return -1;
    }

    /* Parse response: pubkey length + pubkey + chain code */
    if (resp.data_len < 1) {
        return -1;
    }

    pubkey->pubkey_len = resp.data[0];
    if (pubkey->pubkey_len > 65 || resp.data_len < 1 + pubkey->pubkey_len + 32) {
        return -1;
    }

    memcpy(pubkey->pubkey, resp.data + 1, pubkey->pubkey_len);

    /* Chain code as hex */
    for (size_t i = 0; i < 32; i++) {
        snprintf(pubkey->chain_code + i * 2, 3, "%02x",
                 resp.data[1 + pubkey->pubkey_len + i]);
    }

    return 0;
}

int companion_get_address(companion_session_t *session,
                          chain_type_t chain,
                          const companion_path_t *path,
                          address_type_t addr_type,
                          uint8_t display,
                          companion_address_t *address)
{
    if (session == NULL || path == NULL || address == NULL) {
        return -1;
    }

    /* Build request: chain + addr_type + path depth + path elements */
    uint8_t data[3 + COMP_MAX_PATH_DEPTH * 4];
    size_t data_len = 0;

    data[data_len++] = (uint8_t)chain;
    data[data_len++] = (uint8_t)addr_type;
    data[data_len++] = (uint8_t)path->depth;

    for (size_t i = 0; i < path->depth; i++) {
        data[data_len++] = (path->path[i] >> 24) & 0xFF;
        data[data_len++] = (path->path[i] >> 16) & 0xFF;
        data[data_len++] = (path->path[i] >> 8) & 0xFF;
        data[data_len++] = path->path[i] & 0xFF;
    }

    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_GET_ADDRESS,
        .p1 = display,
        .p2 = 0x00,
        .lc = (uint8_t)data_len,
        .le = 0
    };
    memcpy(cmd.data, data, data_len);

    apdu_response_t resp;
    if (usb_hid_apdu_exchange(session->device, &cmd, &resp) != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK) {
        return -1;
    }

    /* Parse response: address length + address + pubkey */
    if (resp.data_len < 1) {
        return -1;
    }

    size_t addr_len = resp.data[0];
    if (addr_len > COMP_MAX_ADDRESS_SIZE - 1 || resp.data_len < 1 + addr_len + 33) {
        return -1;
    }

    memcpy(address->address, resp.data + 1, addr_len);
    address->address[addr_len] = '\0';
    memcpy(address->pubkey, resp.data + 1 + addr_len, 33);

    return 0;
}

int companion_verify_address(companion_session_t *session,
                             chain_type_t chain,
                             const companion_path_t *path,
                             const char *address)
{
    if (session == NULL || path == NULL || address == NULL) {
        return -1;
    }

    size_t addr_len = strlen(address);
    if (addr_len > COMP_MAX_ADDRESS_SIZE - 1) {
        return -1;
    }

    /* Build request: chain + path depth + path + address length + address */
    uint8_t data[2 + COMP_MAX_PATH_DEPTH * 4 + 1 + COMP_MAX_ADDRESS_SIZE];
    size_t data_len = 0;

    data[data_len++] = (uint8_t)chain;
    data[data_len++] = (uint8_t)path->depth;

    for (size_t i = 0; i < path->depth; i++) {
        data[data_len++] = (path->path[i] >> 24) & 0xFF;
        data[data_len++] = (path->path[i] >> 16) & 0xFF;
        data[data_len++] = (path->path[i] >> 8) & 0xFF;
        data[data_len++] = path->path[i] & 0xFF;
    }

    data[data_len++] = (uint8_t)addr_len;
    memcpy(data + data_len, address, addr_len);
    data_len += addr_len;

    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_VERIFY_ADDRESS,
        .p1 = COMP_DISPLAY_VERIFY,
        .p2 = 0x00,
        .lc = (uint8_t)((data_len > 255) ? 255 : data_len),
        .le = 0
    };
    memcpy(cmd.data, data, (data_len > 255) ? 255 : data_len);

    apdu_response_t resp;
    if (usb_hid_apdu_exchange(session->device, &cmd, &resp) != 0) {
        return -1;
    }

    return (resp.sw == APDU_SW_OK) ? 0 : -1;
}

int companion_get_xpub(companion_session_t *session,
                       chain_type_t chain,
                       const companion_path_t *path,
                       address_type_t addr_type,
                       char *xpub, size_t xpub_len)
{
    if (session == NULL || path == NULL || xpub == NULL || xpub_len == 0) {
        return -1;
    }

    /* Build request: chain + addr_type + path depth + path elements */
    uint8_t data[3 + COMP_MAX_PATH_DEPTH * 4];
    size_t data_len = 0;

    data[data_len++] = (uint8_t)chain;
    data[data_len++] = (uint8_t)addr_type;
    data[data_len++] = (uint8_t)path->depth;

    for (size_t i = 0; i < path->depth; i++) {
        data[data_len++] = (path->path[i] >> 24) & 0xFF;
        data[data_len++] = (path->path[i] >> 16) & 0xFF;
        data[data_len++] = (path->path[i] >> 8) & 0xFF;
        data[data_len++] = path->path[i] & 0xFF;
    }

    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_GET_XPUB,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = (uint8_t)data_len,
        .le = 0
    };
    memcpy(cmd.data, data, data_len);

    apdu_response_t resp;
    if (usb_hid_apdu_exchange(session->device, &cmd, &resp) != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK || resp.data_len < 1) {
        return -1;
    }

    size_t len = resp.data[0];
    if (len >= xpub_len || resp.data_len < 1 + len) {
        return -1;
    }

    memcpy(xpub, resp.data + 1, len);
    xpub[len] = '\0';

    return 0;
}

/* ============================================================================
 * Transaction Signing
 * ============================================================================ */

int companion_sign_transaction(companion_session_t *session,
                               const companion_sign_request_t *request,
                               companion_signature_t *signature)
{
    if (session == NULL || request == NULL || signature == NULL) {
        return -1;
    }

    if (request->tx_len > COMP_MAX_TX_SIZE) {
        return -1;
    }

    /* Build request: chain + flags + path depth + path + tx length + tx */
    size_t max_data = 3 + COMP_MAX_PATH_DEPTH * 4 + 2 + request->tx_len;
    uint8_t *data = malloc(max_data);
    if (data == NULL) {
        return -1;
    }

    size_t data_len = 0;
    data[data_len++] = (uint8_t)request->chain;
    data[data_len++] = request->flags;
    data[data_len++] = (uint8_t)request->path.depth;

    for (size_t i = 0; i < request->path.depth; i++) {
        data[data_len++] = (request->path.path[i] >> 24) & 0xFF;
        data[data_len++] = (request->path.path[i] >> 16) & 0xFF;
        data[data_len++] = (request->path.path[i] >> 8) & 0xFF;
        data[data_len++] = request->path.path[i] & 0xFF;
    }

    data[data_len++] = (request->tx_len >> 8) & 0xFF;
    data[data_len++] = request->tx_len & 0xFF;
    memcpy(data + data_len, request->tx_data, request->tx_len);
    data_len += request->tx_len;

    /* For large transactions, use chunked transfer */
    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_SIGN_TX,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = (uint8_t)((data_len > 255) ? 255 : data_len),
        .le = 0
    };
    memcpy(cmd.data, data, (data_len > 255) ? 255 : data_len);

    apdu_response_t resp;
    int result = usb_hid_apdu_exchange(session->device, &cmd, &resp);
    free(data);

    if (result != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK) {
        return -1;
    }

    /* Parse signature response */
    if (resp.data_len < 2) {
        return -1;
    }

    signature->sig_len = resp.data[0];
    if (signature->sig_len > 73 || resp.data_len < 1 + signature->sig_len + 1) {
        return -1;
    }

    memcpy(signature->signature, resp.data + 1, signature->sig_len);
    signature->v = resp.data[1 + signature->sig_len];

    return 0;
}

int companion_sign_psbt(companion_session_t *session,
                        const uint8_t *psbt_data, size_t psbt_len,
                        uint8_t flags,
                        uint8_t *signed_psbt, size_t *signed_len)
{
    if (session == NULL || psbt_data == NULL || signed_psbt == NULL || signed_len == NULL) {
        return -1;
    }

    if (psbt_len > COMP_MAX_TX_SIZE) {
        return -1;
    }

    /* Build request: flags + psbt length + psbt data */
    size_t data_size = 1 + 2 + psbt_len;
    uint8_t *data = malloc(data_size);
    if (data == NULL) {
        return -1;
    }

    size_t data_len = 0;
    data[data_len++] = flags;
    data[data_len++] = (psbt_len >> 8) & 0xFF;
    data[data_len++] = psbt_len & 0xFF;
    memcpy(data + data_len, psbt_data, psbt_len);
    data_len += psbt_len;

    apdu_command_t cmd = {
        .cla = APDU_CLA_BITCOIN,
        .ins = COMP_MSG_SIGN_PSBT,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = (uint8_t)((data_len > 255) ? 255 : data_len),
        .le = 0
    };
    memcpy(cmd.data, data, (data_len > 255) ? 255 : data_len);

    apdu_response_t resp;
    int result = usb_hid_apdu_exchange(session->device, &cmd, &resp);
    free(data);

    if (result != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK) {
        return -1;
    }

    /* Response contains signed PSBT length + data */
    if (resp.data_len < 2) {
        return -1;
    }

    size_t out_len = ((size_t)resp.data[0] << 8) | resp.data[1];
    if (out_len > *signed_len || resp.data_len < 2 + out_len) {
        return -1;
    }

    memcpy(signed_psbt, resp.data + 2, out_len);
    *signed_len = out_len;

    return 0;
}

int companion_sign_message(companion_session_t *session,
                           const companion_message_request_t *request,
                           companion_signature_t *signature)
{
    if (session == NULL || request == NULL || signature == NULL) {
        return -1;
    }

    if (request->msg_len > COMP_MAX_MESSAGE_SIZE) {
        return -1;
    }

    /* Build request: chain + flags + path depth + path + msg length + msg */
    size_t max_data = 3 + COMP_MAX_PATH_DEPTH * 4 + 2 + request->msg_len;
    uint8_t *data = malloc(max_data);
    if (data == NULL) {
        return -1;
    }

    size_t data_len = 0;
    data[data_len++] = (uint8_t)request->chain;
    data[data_len++] = request->flags;
    data[data_len++] = (uint8_t)request->path.depth;

    for (size_t i = 0; i < request->path.depth; i++) {
        data[data_len++] = (request->path.path[i] >> 24) & 0xFF;
        data[data_len++] = (request->path.path[i] >> 16) & 0xFF;
        data[data_len++] = (request->path.path[i] >> 8) & 0xFF;
        data[data_len++] = request->path.path[i] & 0xFF;
    }

    data[data_len++] = (request->msg_len >> 8) & 0xFF;
    data[data_len++] = request->msg_len & 0xFF;
    memcpy(data + data_len, request->message, request->msg_len);
    data_len += request->msg_len;

    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_SIGN_MESSAGE,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = (uint8_t)((data_len > 255) ? 255 : data_len),
        .le = 0
    };
    memcpy(cmd.data, data, (data_len > 255) ? 255 : data_len);

    apdu_response_t resp;
    int result = usb_hid_apdu_exchange(session->device, &cmd, &resp);
    free(data);

    if (result != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK) {
        return -1;
    }

    /* Parse signature response */
    if (resp.data_len < 2) {
        return -1;
    }

    signature->sig_len = resp.data[0];
    if (signature->sig_len > 73 || resp.data_len < 1 + signature->sig_len + 1) {
        return -1;
    }

    memcpy(signature->signature, resp.data + 1, signature->sig_len);
    signature->v = resp.data[1 + signature->sig_len];

    return 0;
}

int companion_sign_typed_data(companion_session_t *session,
                              const uint8_t domain_hash[32],
                              const uint8_t message_hash[32],
                              const companion_path_t *path,
                              companion_signature_t *signature)
{
    if (session == NULL || domain_hash == NULL || message_hash == NULL ||
        path == NULL || signature == NULL) {
        return -1;
    }

    /* Build request: path depth + path + domain hash + message hash */
    uint8_t data[1 + COMP_MAX_PATH_DEPTH * 4 + 64];
    size_t data_len = 0;

    data[data_len++] = (uint8_t)path->depth;
    for (size_t i = 0; i < path->depth; i++) {
        data[data_len++] = (path->path[i] >> 24) & 0xFF;
        data[data_len++] = (path->path[i] >> 16) & 0xFF;
        data[data_len++] = (path->path[i] >> 8) & 0xFF;
        data[data_len++] = path->path[i] & 0xFF;
    }

    memcpy(data + data_len, domain_hash, 32);
    data_len += 32;
    memcpy(data + data_len, message_hash, 32);
    data_len += 32;

    apdu_command_t cmd = {
        .cla = APDU_CLA_ETHEREUM,
        .ins = COMP_MSG_SIGN_TYPED_DATA,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = (uint8_t)data_len,
        .le = 0
    };
    memcpy(cmd.data, data, data_len);

    apdu_response_t resp;
    if (usb_hid_apdu_exchange(session->device, &cmd, &resp) != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK) {
        return -1;
    }

    /* Parse signature response: v (1) + r (32) + s (32) */
    if (resp.data_len < 65) {
        return -1;
    }

    signature->v = resp.data[0];
    signature->sig_len = 64;
    memcpy(signature->signature, resp.data + 1, 64);

    return 0;
}

/* ============================================================================
 * Account Management
 * ============================================================================ */

int companion_list_accounts(companion_session_t *session,
                            companion_account_info_t *accounts,
                            size_t max_accounts)
{
    if (session == NULL || accounts == NULL || max_accounts == 0) {
        return -1;
    }

    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_LIST_ACCOUNTS,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = 0,
        .le = 0
    };

    apdu_response_t resp;
    if (usb_hid_apdu_exchange(session->device, &cmd, &resp) != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK || resp.data_len < 1) {
        return -1;
    }

    size_t count = resp.data[0];
    if (count > max_accounts) {
        count = max_accounts;
    }

    /* Parse accounts: each is index(4) + chain(1) + addr_type(1) + flags(4) + label_len(1) + label */
    size_t offset = 1;
    for (size_t i = 0; i < count && offset < resp.data_len; i++) {
        if (offset + 11 > resp.data_len) {
            break;
        }

        accounts[i].index = ((uint32_t)resp.data[offset] << 24) |
                           ((uint32_t)resp.data[offset + 1] << 16) |
                           ((uint32_t)resp.data[offset + 2] << 8) |
                           resp.data[offset + 3];
        offset += 4;

        accounts[i].chain = (chain_type_t)resp.data[offset++];
        accounts[i].addr_type = (address_type_t)resp.data[offset++];

        accounts[i].flags = ((uint32_t)resp.data[offset] << 24) |
                           ((uint32_t)resp.data[offset + 1] << 16) |
                           ((uint32_t)resp.data[offset + 2] << 8) |
                           resp.data[offset + 3];
        offset += 4;

        size_t label_len = resp.data[offset++];
        if (label_len > WALLET_LABEL_MAX_LEN - 1) {
            label_len = WALLET_LABEL_MAX_LEN - 1;
        }
        if (offset + label_len > resp.data_len) {
            break;
        }

        memcpy(accounts[i].label, resp.data + offset, label_len);
        accounts[i].label[label_len] = '\0';
        offset += label_len;
    }

    return (int)count;
}

int companion_set_account(companion_session_t *session, uint32_t account_index)
{
    if (session == NULL) {
        return -1;
    }

    uint8_t data[4];
    data[0] = (account_index >> 24) & 0xFF;
    data[1] = (account_index >> 16) & 0xFF;
    data[2] = (account_index >> 8) & 0xFF;
    data[3] = account_index & 0xFF;

    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = COMP_MSG_SET_ACCOUNT,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = 4,
        .le = 0
    };
    memcpy(cmd.data, data, 4);

    apdu_response_t resp;
    if (usb_hid_apdu_exchange(session->device, &cmd, &resp) != 0) {
        return -1;
    }

    if (resp.sw == APDU_SW_OK) {
        session->current_account = account_index;
        return 0;
    }

    return -1;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

int companion_parse_path(const char *path_str, companion_path_t *path)
{
    if (path_str == NULL || path == NULL) {
        return -1;
    }

    memset(path, 0, sizeof(*path));

    const char *p = path_str;

    /* Skip 'm/' prefix if present */
    if (*p == 'm') {
        p++;
        if (*p == '/') {
            p++;
        }
    }

    while (*p != '\0' && path->depth < COMP_MAX_PATH_DEPTH) {
        char *end;
        unsigned long val = strtoul(p, &end, 10);

        if (end == p) {
            return -1;  /* No number found */
        }

        if (val > 0x7FFFFFFF) {
            return -1;  /* Index too large */
        }

        path->path[path->depth] = (uint32_t)val;

        /* Check for hardened marker */
        if (*end == '\'' || *end == 'h' || *end == 'H') {
            path->path[path->depth] |= BIP32_HARDENED_BIT;
            end++;
        }

        path->depth++;

        /* Skip separator */
        if (*end == '/') {
            end++;
        }

        p = end;
    }

    return (path->depth > 0) ? 0 : -1;
}

int companion_format_path(const companion_path_t *path, char *str, size_t str_len)
{
    if (path == NULL || str == NULL || str_len == 0) {
        return -1;
    }

    size_t offset = 0;
    int ret = snprintf(str + offset, str_len - offset, "m");
    if (ret < 0 || (size_t)ret >= str_len - offset) {
        return -1;
    }
    offset += (size_t)ret;

    for (size_t i = 0; i < path->depth; i++) {
        uint32_t index = path->path[i] & ~BIP32_HARDENED_BIT;
        int hardened = (path->path[i] & BIP32_HARDENED_BIT) != 0;

        ret = snprintf(str + offset, str_len - offset, "/%u%s",
                       index, hardened ? "'" : "");
        if (ret < 0 || (size_t)ret >= str_len - offset) {
            return -1;
        }
        offset += (size_t)ret;
    }

    return 0;
}

const char *companion_status_string(uint8_t status)
{
    if (status < sizeof(status_messages) / sizeof(status_messages[0]) &&
        status_messages[status] != NULL) {
        return status_messages[status];
    }
    return "Unknown error";
}

int companion_supports_chain(const companion_device_info_t *info, chain_type_t chain)
{
    if (info == NULL) {
        return 0;
    }

    switch (chain) {
        case CHAIN_BITCOIN:
        case CHAIN_BITCOIN_TESTNET:
            return (info->supported_chains & COMP_CAP_BITCOIN) != 0;
        case CHAIN_ETHEREUM:
            return (info->supported_chains & COMP_CAP_ETHEREUM) != 0;
        case CHAIN_LITECOIN:
            return (info->supported_chains & COMP_CAP_LITECOIN) != 0;
        case CHAIN_SOLANA:
            return (info->supported_chains & COMP_CAP_SOLANA) != 0;
        default:
            return 0;
    }
}

/* ============================================================================
 * Device-Side Handler (Firmware)
 * ============================================================================ */

/**
 * Internal helper to derive key for path
 */
static int derive_key_for_path(const wallet_t *wallet,
                               const uint8_t *path_data, size_t path_len,
                               bip32_key_t *out_key)
{
    if (path_len < 1) {
        return -1;
    }

    uint8_t depth = path_data[0];
    if (depth > COMP_MAX_PATH_DEPTH || path_len < 1 + (size_t)depth * 4) {
        return -1;
    }

    /* Start from master key */
    bip32_key_t current;
    memcpy(&current, &wallet->master_key, sizeof(bip32_key_t));

    /* Derive each path component */
    for (size_t i = 0; i < depth; i++) {
        size_t offset = 1 + i * 4;
        uint32_t index = ((uint32_t)path_data[offset] << 24) |
                         ((uint32_t)path_data[offset + 1] << 16) |
                         ((uint32_t)path_data[offset + 2] << 8) |
                         path_data[offset + 3];

        bip32_key_t child;
        if (bip32_derive_child(&current, &child, index) != 0) {
            secure_wipe(&current, sizeof(current));
            return -1;
        }
        memcpy(&current, &child, sizeof(bip32_key_t));
    }

    memcpy(out_key, &current, sizeof(bip32_key_t));
    return 0;
}

/**
 * Handle GET_PUBKEY request
 */
static int handle_get_pubkey(const uint8_t *request, size_t request_len,
                             uint8_t *response, size_t *response_len,
                             wallet_t *wallet)
{
    /* Request: display(1) + path_depth(1) + path(4*depth) */
    if (request_len < 2) {
        response[0] = COMP_STATUS_INVALID_DATA;
        *response_len = 1;
        return 0;
    }

    /* uint8_t display = request[1]; -- for future use with display confirmation */
    const uint8_t *path_data = request + 2;
    size_t path_data_len = request_len - 2;

    bip32_key_t key;
    if (derive_key_for_path(wallet, path_data, path_data_len, &key) != 0) {
        response[0] = COMP_STATUS_INVALID_DATA;
        *response_len = 1;
        return 0;
    }

    /* Build response: status + pubkey_len + pubkey + chain_code */
    size_t offset = 0;
    response[offset++] = COMP_STATUS_OK;
    response[offset++] = 33;  /* Compressed pubkey length */
    memcpy(response + offset, key.public_key, 33);
    offset += 33;
    memcpy(response + offset, key.chain_code, 32);
    offset += 32;

    *response_len = offset;
    secure_wipe(&key, sizeof(key));
    return 0;
}

/**
 * Handle GET_ADDRESS request
 */
static int handle_get_address(const uint8_t *request, size_t request_len,
                              uint8_t *response, size_t *response_len,
                              wallet_t *wallet)
{
    /* Request: display(1) + chain(1) + addr_type(1) + path_depth(1) + path */
    if (request_len < 4) {
        response[0] = COMP_STATUS_INVALID_DATA;
        *response_len = 1;
        return 0;
    }

    /* uint8_t display = request[1]; -- for future display */
    chain_type_t chain = (chain_type_t)request[2];
    address_type_t addr_type = (address_type_t)request[3];
    const uint8_t *path_data = request + 4;
    size_t path_data_len = request_len - 4;

    bip32_key_t key;
    if (derive_key_for_path(wallet, path_data, path_data_len, &key) != 0) {
        response[0] = COMP_STATUS_INVALID_DATA;
        *response_len = 1;
        return 0;
    }

    /* Generate address based on chain and type */
    char address[COMP_MAX_ADDRESS_SIZE];
    int result = -1;

    /* Map wallet address type to Bitcoin address type */
    btc_addr_type_t btc_type;
    switch (addr_type) {
        case ADDR_TYPE_LEGACY:         btc_type = BTC_ADDR_P2PKH; break;
        case ADDR_TYPE_SEGWIT_COMPAT:  btc_type = BTC_ADDR_P2SH; break;
        case ADDR_TYPE_SEGWIT_NATIVE:  btc_type = BTC_ADDR_P2WPKH; break;
        case ADDR_TYPE_TAPROOT:        btc_type = BTC_ADDR_P2TR; break;
        default:                       btc_type = BTC_ADDR_P2WPKH; break;
    }

    switch (chain) {
        case CHAIN_BITCOIN:
        case CHAIN_BITCOIN_TESTNET:
            result = btc_pubkey_to_address(key.public_key, btc_type,
                                           chain == CHAIN_BITCOIN_TESTNET ? BTC_TESTNET : BTC_MAINNET,
                                           address, sizeof(address));
            break;

        case CHAIN_LITECOIN:
            /* Use Bitcoin with different prefix - simplified */
            result = btc_pubkey_to_address(key.public_key, btc_type, BTC_MAINNET,
                                           address, sizeof(address));
            break;

        default:
            /* Not supported yet */
            result = -1;
            break;
    }

    if (result != 0) {
        response[0] = COMP_STATUS_NOT_SUPPORTED;
        *response_len = 1;
        secure_wipe(&key, sizeof(key));
        return 0;
    }

    /* Build response: status + addr_len + addr + pubkey */
    size_t offset = 0;
    size_t addr_len = strlen(address);
    response[offset++] = COMP_STATUS_OK;
    response[offset++] = (uint8_t)addr_len;
    memcpy(response + offset, address, addr_len);
    offset += addr_len;
    memcpy(response + offset, key.public_key, 33);
    offset += 33;

    *response_len = offset;
    secure_wipe(&key, sizeof(key));
    return 0;
}

/**
 * Handle GET_XPUB request
 */
static int handle_get_xpub(const uint8_t *request, size_t request_len,
                           uint8_t *response, size_t *response_len,
                           wallet_t *wallet)
{
    /* Request: chain(1) + addr_type(1) + path_depth(1) + path */
    if (request_len < 3) {
        response[0] = COMP_STATUS_INVALID_DATA;
        *response_len = 1;
        return 0;
    }

    chain_type_t chain = (chain_type_t)request[1];
    address_type_t addr_type = (address_type_t)request[2];
    const uint8_t *path_data = request + 3;
    size_t path_data_len = request_len - 3;

    bip32_key_t key;
    if (derive_key_for_path(wallet, path_data, path_data_len, &key) != 0) {
        response[0] = COMP_STATUS_INVALID_DATA;
        *response_len = 1;
        return 0;
    }

    /* Serialize to xpub format */
    char xpub[COMP_MAX_XPUB_SIZE];
    uint32_t version = wallet_get_xpub_version(chain, addr_type);

    /* Use bip32_serialize_key with custom version for proper xpub/ypub/zpub support */
    if (bip32_serialize_key(&key, 0 /* public */, version, xpub, sizeof(xpub)) != 0) {
        response[0] = COMP_STATUS_ERROR;
        *response_len = 1;
        secure_wipe(&key, sizeof(key));
        return 0;
    }

    /* Build response: status + xpub_len + xpub */
    size_t offset = 0;
    size_t xpub_len = strlen(xpub);
    response[offset++] = COMP_STATUS_OK;
    response[offset++] = (uint8_t)xpub_len;
    memcpy(response + offset, xpub, xpub_len);
    offset += xpub_len;

    *response_len = offset;
    secure_wipe(&key, sizeof(key));
    return 0;
}

/**
 * Handle LIST_ACCOUNTS request
 */
static int handle_list_accounts(uint8_t *response, size_t *response_len,
                                wallet_t *wallet)
{
    size_t offset = 0;
    response[offset++] = COMP_STATUS_OK;
    response[offset++] = (uint8_t)wallet->account_count;

    for (size_t i = 0; i < wallet->account_count && offset < 200; i++) {
        wallet_account_t *acc = &wallet->accounts[i];

        /* Index (4 bytes, big-endian) */
        response[offset++] = (acc->index >> 24) & 0xFF;
        response[offset++] = (acc->index >> 16) & 0xFF;
        response[offset++] = (acc->index >> 8) & 0xFF;
        response[offset++] = acc->index & 0xFF;

        /* Chain and address type */
        response[offset++] = (uint8_t)acc->chain;
        response[offset++] = (uint8_t)acc->addr_type;

        /* Flags (4 bytes) */
        response[offset++] = (acc->flags >> 24) & 0xFF;
        response[offset++] = (acc->flags >> 16) & 0xFF;
        response[offset++] = (acc->flags >> 8) & 0xFF;
        response[offset++] = acc->flags & 0xFF;

        /* Label */
        size_t label_len = strlen(acc->label);
        if (label_len > WALLET_LABEL_MAX_LEN - 1) {
            label_len = WALLET_LABEL_MAX_LEN - 1;
        }
        response[offset++] = (uint8_t)label_len;
        memcpy(response + offset, acc->label, label_len);
        offset += label_len;
    }

    *response_len = offset;
    return 0;
}

/**
 * Handle SET_ACCOUNT request
 */
static int handle_set_account(const uint8_t *request, size_t request_len,
                              uint8_t *response, size_t *response_len,
                              wallet_t *wallet)
{
    if (request_len < 5) {
        response[0] = COMP_STATUS_INVALID_DATA;
        *response_len = 1;
        return 0;
    }

    uint32_t account_index = ((uint32_t)request[1] << 24) |
                             ((uint32_t)request[2] << 16) |
                             ((uint32_t)request[3] << 8) |
                             request[4];

    if (account_index >= wallet->account_count) {
        response[0] = COMP_STATUS_INVALID_DATA;
        *response_len = 1;
        return 0;
    }

    response[0] = COMP_STATUS_OK;
    *response_len = 1;
    return 0;
}

int companion_handle_request(const uint8_t *request, size_t request_len,
                             uint8_t *response, size_t *response_len,
                             wallet_t *wallet)
{
    if (request == NULL || response == NULL || response_len == NULL) {
        return -1;
    }

    if (request_len < 1) {
        response[0] = COMP_STATUS_INVALID_CMD;
        *response_len = 1;
        return 0;
    }

    uint8_t msg_type = request[0];

    switch (msg_type) {
        case COMP_MSG_PING:
            /* Simple ping response */
            response[0] = COMP_STATUS_OK;
            *response_len = 1;
            break;

        case COMP_MSG_GET_INFO:
            /* Return device info */
            {
                size_t offset = 0;
                response[offset++] = COMP_STATUS_OK;

                /* Protocol version */
                response[offset++] = (COMPANION_PROTOCOL_VERSION >> 8) & 0xFF;
                response[offset++] = COMPANION_PROTOCOL_VERSION & 0xFF;

                /* Firmware version (1.0.0) */
                response[offset++] = 1;
                response[offset++] = 0;
                response[offset++] = 0;

                /* Device ID from HAL storage backend */
                const hal_backend_t *backend = hal_get_backend();
                if (backend && backend->storage && backend->storage->get_device_id) {
                    backend->storage->get_device_id(response + offset);
                } else {
                    memset(response + offset, 0, 16);
                }
                offset += 16;

                /* Supported chains */
                uint8_t chain_caps = COMP_CAP_BITCOIN | COMP_CAP_ETHEREUM |
                                     COMP_CAP_LITECOIN | COMP_CAP_SOLANA |
                                     COMP_CAP_MONERO;
                response[offset++] = chain_caps;

                /* Device flags */
                uint8_t device_flags = COMP_CAP_PASSPHRASE;
                /* Add secure element flag if hardware SE detected */
                if (backend && backend->storage && backend->storage->has_secure_element &&
                    backend->storage->has_secure_element()) {
                    device_flags |= COMP_CAP_SECURE_ELEMENT;
                }
                response[offset++] = device_flags;

                /* Model name */
                size_t name_len = strlen(DEVICE_MODEL);
                memcpy(response + offset, DEVICE_MODEL, name_len);
                offset += name_len;

                *response_len = offset;
            }
            break;

        case COMP_MSG_GET_PUBKEY:
            if (wallet == NULL || !wallet->is_initialized) {
                response[0] = COMP_STATUS_LOCKED;
                *response_len = 1;
            } else {
                handle_get_pubkey(request, request_len, response, response_len, wallet);
            }
            break;

        case COMP_MSG_GET_ADDRESS:
            if (wallet == NULL || !wallet->is_initialized) {
                response[0] = COMP_STATUS_LOCKED;
                *response_len = 1;
            } else {
                handle_get_address(request, request_len, response, response_len, wallet);
            }
            break;

        case COMP_MSG_GET_XPUB:
            if (wallet == NULL || !wallet->is_initialized) {
                response[0] = COMP_STATUS_LOCKED;
                *response_len = 1;
            } else {
                handle_get_xpub(request, request_len, response, response_len, wallet);
            }
            break;

        case COMP_MSG_LIST_ACCOUNTS:
            if (wallet == NULL || !wallet->is_initialized) {
                response[0] = COMP_STATUS_LOCKED;
                *response_len = 1;
            } else {
                handle_list_accounts(response, response_len, wallet);
            }
            break;

        case COMP_MSG_SET_ACCOUNT:
            if (wallet == NULL || !wallet->is_initialized) {
                response[0] = COMP_STATUS_LOCKED;
                *response_len = 1;
            } else {
                handle_set_account(request, request_len, response, response_len, wallet);
            }
            break;

        case COMP_MSG_SIGN_TX:
        case COMP_MSG_SIGN_MESSAGE:
        case COMP_MSG_SIGN_PSBT:
        case COMP_MSG_SIGN_TYPED_DATA:
            /* Signing requires user confirmation - handled separately via UI flow */
            if (wallet == NULL || !wallet->is_initialized) {
                response[0] = COMP_STATUS_LOCKED;
                *response_len = 1;
            } else {
                /* Return busy status - signing must be initiated through UI flow */
                response[0] = COMP_STATUS_BUSY;
                *response_len = 1;
            }
            break;

        case COMP_MSG_VERIFY_ADDRESS:
            /* Address verification requires display - also handled via UI */
            if (wallet == NULL || !wallet->is_initialized) {
                response[0] = COMP_STATUS_LOCKED;
                *response_len = 1;
            } else {
                response[0] = COMP_STATUS_BUSY;
                *response_len = 1;
            }
            break;

        default:
            response[0] = COMP_STATUS_INVALID_CMD;
            *response_len = 1;
            break;
    }

    return 0;
}

/*
 * WalletConnect v2 Protocol Handler Implementation
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "walletconnect.h"
#include "wc_crypto.h"
#include "../util/base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

/* Internal context structure */
struct wc_context {
    char project_id[WC_PROJECT_ID_MAX];
    wc_metadata_t metadata;

    /* Pairings */
    wc_pairing_t pairings[WC_MAX_PAIRINGS];
    size_t pairing_count;

    /* Sessions */
    wc_session_t sessions[WC_MAX_SESSIONS];
    size_t session_count;

    /* Pending proposals */
    wc_session_proposal_t pending_proposal;
    int has_pending_proposal;

    /* Callbacks */
    wc_proposal_callback_t on_proposal;
    wc_request_callback_t on_request;
    wc_error_callback_t on_error;
    void *user_data;

    /* Message queue for outgoing */
    wc_relay_message_t outgoing[16];
    size_t outgoing_count;
};

/* ============================================================================
 * Internal JSON helpers (minimal implementation)
 * ============================================================================ */

/* Skip whitespace in JSON */
static const char *json_skip_ws(const char *p)
{
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
        p++;
    }
    return p;
}

/* Extract string value from JSON (returns pointer to start, sets len) */
static const char *json_get_string(const char *json, const char *key, size_t *len)
{
    char search[128];
    const char *p;

    snprintf(search, sizeof(search), "\"%s\"", key);
    p = strstr(json, search);
    if (!p) {
        *len = 0;
        return NULL;
    }

    /* Find the colon */
    p += strlen(search);
    p = json_skip_ws(p);
    if (*p != ':') {
        *len = 0;
        return NULL;
    }
    p++;
    p = json_skip_ws(p);

    /* Expect string value */
    if (*p != '"') {
        *len = 0;
        return NULL;
    }
    p++;

    /* Find end of string */
    const char *start = p;
    while (*p && *p != '"') {
        if (*p == '\\' && *(p + 1)) {
            p += 2;  /* Skip escape sequence */
        } else {
            p++;
        }
    }

    *len = p - start;
    return start;
}

/* Extract integer value from JSON */
static int json_get_int(const char *json, const char *key, int64_t *value)
{
    char search[128];
    const char *p;

    snprintf(search, sizeof(search), "\"%s\"", key);
    p = strstr(json, search);
    if (!p) {
        return -1;
    }

    p += strlen(search);
    p = json_skip_ws(p);
    if (*p != ':') {
        return -1;
    }
    p++;
    p = json_skip_ws(p);

    /* Parse number */
    char *end;
    *value = strtoll(p, &end, 10);
    if (end == p) {
        return -1;
    }

    return 0;
}

/* Extract nested object from JSON */
static const char *json_get_object(const char *json, const char *key, size_t *len)
{
    char search[128];
    const char *p;

    snprintf(search, sizeof(search), "\"%s\"", key);
    p = strstr(json, search);
    if (!p) {
        *len = 0;
        return NULL;
    }

    p += strlen(search);
    p = json_skip_ws(p);
    if (*p != ':') {
        *len = 0;
        return NULL;
    }
    p++;
    p = json_skip_ws(p);

    if (*p != '{') {
        *len = 0;
        return NULL;
    }

    const char *start = p;
    int depth = 1;
    p++;

    while (*p && depth > 0) {
        if (*p == '{') depth++;
        else if (*p == '}') depth--;
        else if (*p == '"') {
            /* Skip string */
            p++;
            while (*p && *p != '"') {
                if (*p == '\\' && *(p + 1)) p++;
                p++;
            }
        }
        p++;
    }

    *len = p - start;
    return start;
}

/* Build JSON object */
static int json_start_object(char *buf, size_t *pos, size_t max)
{
    if (*pos >= max) return -1;
    buf[(*pos)++] = '{';
    return 0;
}

static int json_end_object(char *buf, size_t *pos, size_t max)
    __attribute__((unused));
static int json_end_object(char *buf, size_t *pos, size_t max)
{
    /* Remove trailing comma if present */
    if (*pos > 0 && buf[*pos - 1] == ',') {
        (*pos)--;
    }
    if (*pos >= max) return -1;
    buf[(*pos)++] = '}';
    return 0;
}

static int json_add_string(char *buf, size_t *pos, size_t max,
                           const char *key, const char *value)
{
    int n = snprintf(buf + *pos, max - *pos, "\"%s\":\"%s\",", key, value);
    if (n < 0 || (size_t)n >= max - *pos) return -1;
    *pos += n;
    return 0;
}

static int json_add_int(char *buf, size_t *pos, size_t max,
                        const char *key, int64_t value)
{
    int n = snprintf(buf + *pos, max - *pos, "\"%s\":%lld,", key, (long long)value);
    if (n < 0 || (size_t)n >= max - *pos) return -1;
    *pos += n;
    return 0;
}

static int json_add_bool(char *buf, size_t *pos, size_t max,
                         const char *key, int value)
    __attribute__((unused));
static int json_add_bool(char *buf, size_t *pos, size_t max,
                         const char *key, int value)
{
    int n = snprintf(buf + *pos, max - *pos, "\"%s\":%s,",
                     key, value ? "true" : "false");
    if (n < 0 || (size_t)n >= max - *pos) return -1;
    *pos += n;
    return 0;
}

static int json_add_raw(char *buf, size_t *pos, size_t max,
                        const char *key, const char *raw)
    __attribute__((unused));
static int json_add_raw(char *buf, size_t *pos, size_t max,
                        const char *key, const char *raw)
{
    int n = snprintf(buf + *pos, max - *pos, "\"%s\":%s,", key, raw);
    if (n < 0 || (size_t)n >= max - *pos) return -1;
    *pos += n;
    return 0;
}

/* ============================================================================
 * Initialization and Lifecycle
 * ============================================================================ */

wc_context_t *wc_create(const char *project_id)
{
    if (!project_id || strlen(project_id) == 0) {
        return NULL;
    }

    if (wc_crypto_init() != 0) {
        return NULL;
    }

    wc_context_t *ctx = calloc(1, sizeof(wc_context_t));
    if (!ctx) {
        return NULL;
    }

    strncpy(ctx->project_id, project_id, WC_PROJECT_ID_MAX - 1);
    ctx->project_id[WC_PROJECT_ID_MAX - 1] = '\0';

    /* Set default metadata */
    strncpy(ctx->metadata.name, "RISC-V Wallet", WC_NAME_MAX - 1);
    strncpy(ctx->metadata.description, "Hardware wallet", WC_URL_MAX - 1);
    strncpy(ctx->metadata.url, "https://github.com/blubskye/riscv_wallet", WC_URL_MAX - 1);

    return ctx;
}

void wc_destroy(wc_context_t *ctx)
{
    if (!ctx) {
        return;
    }

    /* Wipe sensitive data */
    for (size_t i = 0; i < ctx->pairing_count; i++) {
        wc_crypto_wipe_keypair(&ctx->pairings[i].self_keypair);
        wc_crypto_wipe_symkey(&ctx->pairings[i].sym_key);
    }

    for (size_t i = 0; i < ctx->session_count; i++) {
        wc_crypto_wipe_keypair(&ctx->sessions[i].self_keypair);
        wc_crypto_wipe_symkey(&ctx->sessions[i].sym_key);
    }

    wc_crypto_wipe(ctx, sizeof(wc_context_t));
    free(ctx);
}

int wc_set_metadata(wc_context_t *ctx, const char *name, const char *description,
                    const char *url, const char *icon)
{
    if (!ctx) {
        return -1;
    }

    if (name) {
        strncpy(ctx->metadata.name, name, WC_NAME_MAX - 1);
        ctx->metadata.name[WC_NAME_MAX - 1] = '\0';
    }

    if (description) {
        strncpy(ctx->metadata.description, description, WC_URL_MAX - 1);
        ctx->metadata.description[WC_URL_MAX - 1] = '\0';
    }

    if (url) {
        strncpy(ctx->metadata.url, url, WC_URL_MAX - 1);
        ctx->metadata.url[WC_URL_MAX - 1] = '\0';
    }

    if (icon) {
        strncpy(ctx->metadata.icon_url, icon, WC_URL_MAX - 1);
        ctx->metadata.icon_url[WC_URL_MAX - 1] = '\0';
    }

    return 0;
}

void wc_set_callbacks(wc_context_t *ctx,
                      wc_proposal_callback_t on_proposal,
                      wc_request_callback_t on_request,
                      wc_error_callback_t on_error,
                      void *user_data)
{
    if (!ctx) {
        return;
    }

    ctx->on_proposal = on_proposal;
    ctx->on_request = on_request;
    ctx->on_error = on_error;
    ctx->user_data = user_data;
}

/* ============================================================================
 * Pairing URI Parsing
 * ============================================================================ */

int wc_parse_pairing_uri(const char *uri, wc_pairing_t *pairing)
{
    if (!uri || !pairing) {
        return -1;
    }

    memset(pairing, 0, sizeof(wc_pairing_t));

    /* URI format: wc:topic@2?relay-protocol=irn&symKey=... */
    if (strncmp(uri, "wc:", 3) != 0) {
        return -1;
    }

    const char *p = uri + 3;

    /* Extract topic (hex string before @) */
    const char *at = strchr(p, '@');
    if (!at) {
        return -1;
    }

    size_t topic_len = at - p;
    if (topic_len != WC_TOPIC_SIZE * 2) {  /* Topic is 32 bytes = 64 hex chars */
        return -1;
    }

    /* Copy topic hex string */
    memcpy(pairing->topic.hex, p, topic_len);
    pairing->topic.hex[topic_len] = '\0';

    /* Convert hex to bytes */
    if (wc_crypto_from_hex(pairing->topic.hex, pairing->topic.bytes, WC_TOPIC_SIZE) != 0) {
        return -1;
    }

    /* Skip @version? */
    p = at + 1;
    if (*p != '2') {
        return -1;  /* Only WalletConnect v2 supported */
    }
    p++;

    if (*p != '?') {
        return -1;
    }
    p++;

    /* Parse query parameters */
    while (*p) {
        /* Find key */
        const char *eq = strchr(p, '=');
        if (!eq) break;

        /* Find value end */
        const char *amp = strchr(eq + 1, '&');
        size_t value_len = amp ? (size_t)(amp - eq - 1) : strlen(eq + 1);

        if (strncmp(p, "relay-protocol", 14) == 0) {
            size_t len = value_len < WC_NAME_MAX - 1 ? value_len : WC_NAME_MAX - 1;
            memcpy(pairing->relay.protocol, eq + 1, len);
            pairing->relay.protocol[len] = '\0';
        }
        else if (strncmp(p, "symKey", 6) == 0) {
            /* Symmetric key in hex */
            if (value_len != WC_KEY_SIZE * 2) {
                return -1;
            }
            if (wc_crypto_from_hex(eq + 1, pairing->sym_key.key, WC_KEY_SIZE) != 0) {
                return -1;
            }
        }

        /* Move to next parameter */
        if (amp) {
            p = amp + 1;
        } else {
            break;
        }
    }

    /* Set default relay URL */
    strncpy(pairing->relay.url, WC_DEFAULT_RELAY_URL, WC_URL_MAX - 1);

    /* Generate our ephemeral keypair for this pairing */
    if (wc_crypto_generate_keypair(&pairing->self_keypair) != 0) {
        return -1;
    }

    pairing->state = WC_PAIRING_INACTIVE;

    return 0;
}

int wc_pair(wc_context_t *ctx, const char *uri)
{
    if (!ctx || !uri) {
        return -1;
    }

    if (ctx->pairing_count >= WC_MAX_PAIRINGS) {
        if (ctx->on_error) {
            ctx->on_error(WC_ERROR_INTERNAL, "Max pairings reached", ctx->user_data);
        }
        return -1;
    }

    wc_pairing_t *pairing = &ctx->pairings[ctx->pairing_count];

    if (wc_parse_pairing_uri(uri, pairing) != 0) {
        if (ctx->on_error) {
            ctx->on_error(WC_ERROR_INVALID_REQUEST, "Invalid pairing URI", ctx->user_data);
        }
        return -1;
    }

    ctx->pairing_count++;

    return 0;
}

int wc_get_pairings(wc_context_t *ctx, wc_pairing_t *pairings, size_t *count)
{
    if (!ctx || !count) {
        return -1;
    }

    size_t to_copy = ctx->pairing_count;
    if (pairings && *count < to_copy) {
        to_copy = *count;
    }

    if (pairings) {
        for (size_t i = 0; i < to_copy; i++) {
            memcpy(&pairings[i], &ctx->pairings[i], sizeof(wc_pairing_t));
            /* Don't expose private keys */
            memset(pairings[i].self_keypair.private_key, 0, WC_KEY_SIZE);
        }
    }

    *count = ctx->pairing_count;
    return 0;
}

int wc_delete_pairing(wc_context_t *ctx, const wc_topic_t *topic)
{
    if (!ctx || !topic) {
        return -1;
    }

    for (size_t i = 0; i < ctx->pairing_count; i++) {
        if (memcmp(ctx->pairings[i].topic.bytes, topic->bytes, WC_TOPIC_SIZE) == 0) {
            /* Wipe sensitive data */
            wc_crypto_wipe_keypair(&ctx->pairings[i].self_keypair);
            wc_crypto_wipe_symkey(&ctx->pairings[i].sym_key);

            /* Shift remaining pairings */
            for (size_t j = i; j < ctx->pairing_count - 1; j++) {
                ctx->pairings[j] = ctx->pairings[j + 1];
            }
            ctx->pairing_count--;

            return 0;
        }
    }

    return -1;  /* Not found */
}

/* ============================================================================
 * Session Management
 * ============================================================================ */

/* Build session settlement JSON-RPC (prepared for relay transport) */
static int build_session_settle(wc_context_t *ctx, const wc_session_proposal_t *proposal,
                                const char **accounts, size_t account_count,
                                char *output, size_t output_len)
    __attribute__((unused));
static int build_session_settle(wc_context_t *ctx, const wc_session_proposal_t *proposal,
                                const char **accounts, size_t account_count,
                                char *output, size_t output_len)
{
    size_t pos = 0;

    json_start_object(output, &pos, output_len);
    json_add_int(output, &pos, output_len, "id", (int64_t)proposal->id);
    json_add_string(output, &pos, output_len, "jsonrpc", "2.0");

    /* Result object */
    int n = snprintf(output + pos, output_len - pos, "\"result\":{");
    if (n < 0) return -1;
    pos += n;

    /* Relay */
    n = snprintf(output + pos, output_len - pos,
                 "\"relay\":{\"protocol\":\"%s\"},",
                 proposal->relay.protocol[0] ? proposal->relay.protocol : WC_DEFAULT_RELAY_PROTO);
    if (n < 0) return -1;
    pos += n;

    /* Controller (our public key) */
    char pubkey_hex[WC_KEY_SIZE * 2 + 1];
    wc_keypair_t session_keypair;
    wc_crypto_generate_keypair(&session_keypair);
    wc_crypto_to_hex(session_keypair.public_key, WC_KEY_SIZE, pubkey_hex);

    n = snprintf(output + pos, output_len - pos,
                 "\"controller\":{\"publicKey\":\"%s\",\"metadata\":{\"name\":\"%s\","
                 "\"description\":\"%s\",\"url\":\"%s\",\"icons\":[\"%s\"]}},",
                 pubkey_hex,
                 ctx->metadata.name,
                 ctx->metadata.description,
                 ctx->metadata.url,
                 ctx->metadata.icon_url);
    if (n < 0) return -1;
    pos += n;

    /* Namespaces with accounts */
    n = snprintf(output + pos, output_len - pos, "\"namespaces\":{\"eip155\":{\"accounts\":[");
    if (n < 0) return -1;
    pos += n;

    for (size_t i = 0; i < account_count; i++) {
        n = snprintf(output + pos, output_len - pos, "\"%s\"%s",
                     accounts[i], (i < account_count - 1) ? "," : "");
        if (n < 0) return -1;
        pos += n;
    }

    /* Standard Ethereum methods and events */
    n = snprintf(output + pos, output_len - pos,
                 "],\"methods\":[\"eth_sendTransaction\",\"eth_signTransaction\","
                 "\"eth_sign\",\"personal_sign\",\"eth_signTypedData\",\"eth_signTypedData_v4\"],"
                 "\"events\":[\"chainChanged\",\"accountsChanged\"]}},");
    if (n < 0) return -1;
    pos += n;

    /* Expiry */
    uint64_t expiry = (uint64_t)time(NULL) + WC_SESSION_TTL;
    n = snprintf(output + pos, output_len - pos, "\"expiry\":%llu", (unsigned long long)expiry);
    if (n < 0) return -1;
    pos += n;

    /* Close result and root objects */
    n = snprintf(output + pos, output_len - pos, "}}");
    if (n < 0) return -1;
    pos += n;

    /* Wipe temporary keypair */
    wc_crypto_wipe_keypair(&session_keypair);

    return 0;
}

int wc_approve_session(wc_context_t *ctx, const wc_session_proposal_t *proposal,
                       const char **accounts, size_t account_count)
{
    if (!ctx || !proposal || !accounts || account_count == 0) {
        return -1;
    }

    if (ctx->session_count >= WC_MAX_SESSIONS) {
        if (ctx->on_error) {
            ctx->on_error(WC_ERROR_INTERNAL, "Max sessions reached", ctx->user_data);
        }
        return -1;
    }

    /* Create new session */
    wc_session_t *session = &ctx->sessions[ctx->session_count];
    memset(session, 0, sizeof(wc_session_t));

    /* Generate session keypair */
    if (wc_crypto_generate_keypair(&session->self_keypair) != 0) {
        return -1;
    }

    /* Store proposer's public key */
    memcpy(session->peer_pubkey, proposal->proposer_pubkey, WC_KEY_SIZE);

    /* Derive shared secret and session key */
    uint8_t shared_secret[32];
    if (wc_crypto_x25519(session->self_keypair.private_key,
                         proposal->proposer_pubkey, shared_secret) != 0) {
        wc_crypto_wipe_keypair(&session->self_keypair);
        return -1;
    }

    if (wc_crypto_hkdf(shared_secret, 32, NULL, 0, &session->sym_key) != 0) {
        wc_crypto_wipe(shared_secret, 32);
        wc_crypto_wipe_keypair(&session->self_keypair);
        return -1;
    }
    wc_crypto_wipe(shared_secret, 32);

    /* Derive session topic from symmetric key */
    if (wc_crypto_derive_topic(&session->sym_key, &session->topic) != 0) {
        wc_crypto_wipe_keypair(&session->self_keypair);
        wc_crypto_wipe_symkey(&session->sym_key);
        return -1;
    }

    /* Copy peer metadata */
    memcpy(&session->peer_metadata, &proposal->proposer_metadata, sizeof(wc_metadata_t));
    memcpy(&session->relay, &proposal->relay, sizeof(wc_relay_t));

    /* Set session state */
    session->state = WC_SESSION_ACTIVE;
    session->is_controller = 1;  /* Wallet is always controller */
    session->expiry = (uint64_t)time(NULL) + WC_SESSION_TTL;

    /* Store accounts in namespace */
    session->namespace_count = 1;
    strncpy(session->namespaces[0].name, "eip155", WC_NAME_MAX - 1);
    session->namespaces[0].account_count = account_count < WC_MAX_ACCOUNTS ?
                                           account_count : WC_MAX_ACCOUNTS;
    for (size_t i = 0; i < session->namespaces[0].account_count; i++) {
        strncpy(session->namespaces[0].accounts[i], accounts[i], 63);
        session->namespaces[0].accounts[i][63] = '\0';
    }

    ctx->session_count++;
    ctx->has_pending_proposal = 0;

    return 0;
}

int wc_reject_session(wc_context_t *ctx, const wc_session_proposal_t *proposal,
                      const char *reason)
{
    (void)reason;  /* Will be used when relay transport is implemented */

    if (!ctx || !proposal) {
        return -1;
    }

    ctx->has_pending_proposal = 0;

    /* Build rejection response JSON-RPC */
    /* This would be sent via relay - implementation depends on transport layer */

    return 0;
}

int wc_get_sessions(wc_context_t *ctx, wc_session_t *sessions, size_t *count)
{
    if (!ctx || !count) {
        return -1;
    }

    size_t to_copy = ctx->session_count;
    if (sessions && *count < to_copy) {
        to_copy = *count;
    }

    if (sessions) {
        for (size_t i = 0; i < to_copy; i++) {
            memcpy(&sessions[i], &ctx->sessions[i], sizeof(wc_session_t));
            /* Don't expose private keys */
            memset(sessions[i].self_keypair.private_key, 0, WC_KEY_SIZE);
        }
    }

    *count = ctx->session_count;
    return 0;
}

int wc_get_session(wc_context_t *ctx, const wc_topic_t *topic, wc_session_t *session)
{
    if (!ctx || !topic || !session) {
        return -1;
    }

    for (size_t i = 0; i < ctx->session_count; i++) {
        if (memcmp(ctx->sessions[i].topic.bytes, topic->bytes, WC_TOPIC_SIZE) == 0) {
            memcpy(session, &ctx->sessions[i], sizeof(wc_session_t));
            /* Don't expose private key */
            memset(session->self_keypair.private_key, 0, WC_KEY_SIZE);
            return 0;
        }
    }

    return -1;  /* Not found */
}

int wc_update_session(wc_context_t *ctx, const wc_session_t *session,
                      const char **accounts, size_t account_count)
{
    if (!ctx || !session || !accounts || account_count == 0) {
        return -1;
    }

    /* Find session */
    for (size_t i = 0; i < ctx->session_count; i++) {
        if (memcmp(ctx->sessions[i].topic.bytes, session->topic.bytes, WC_TOPIC_SIZE) == 0) {
            /* Update accounts */
            wc_namespace_t *ns = &ctx->sessions[i].namespaces[0];
            ns->account_count = account_count < WC_MAX_ACCOUNTS ?
                               account_count : WC_MAX_ACCOUNTS;
            for (size_t j = 0; j < ns->account_count; j++) {
                strncpy(ns->accounts[j], accounts[j], 63);
                ns->accounts[j][63] = '\0';
            }
            return 0;
        }
    }

    return -1;
}

int wc_extend_session(wc_context_t *ctx, const wc_session_t *session)
{
    if (!ctx || !session) {
        return -1;
    }

    for (size_t i = 0; i < ctx->session_count; i++) {
        if (memcmp(ctx->sessions[i].topic.bytes, session->topic.bytes, WC_TOPIC_SIZE) == 0) {
            ctx->sessions[i].expiry = (uint64_t)time(NULL) + WC_SESSION_TTL;
            return 0;
        }
    }

    return -1;
}

int wc_disconnect_session(wc_context_t *ctx, const wc_session_t *session,
                          const char *reason)
{
    (void)reason;  /* Will be used when relay transport is implemented */

    if (!ctx || !session) {
        return -1;
    }

    for (size_t i = 0; i < ctx->session_count; i++) {
        if (memcmp(ctx->sessions[i].topic.bytes, session->topic.bytes, WC_TOPIC_SIZE) == 0) {
            /* Wipe sensitive data */
            wc_crypto_wipe_keypair(&ctx->sessions[i].self_keypair);
            wc_crypto_wipe_symkey(&ctx->sessions[i].sym_key);

            /* Shift remaining sessions */
            for (size_t j = i; j < ctx->session_count - 1; j++) {
                ctx->sessions[j] = ctx->sessions[j + 1];
            }
            ctx->session_count--;

            return 0;
        }
    }

    return -1;
}

int wc_ping_session(wc_context_t *ctx, const wc_session_t *session)
{
    if (!ctx || !session) {
        return -1;
    }

    /* Verify session exists and is active */
    for (size_t i = 0; i < ctx->session_count; i++) {
        if (memcmp(ctx->sessions[i].topic.bytes, session->topic.bytes, WC_TOPIC_SIZE) == 0) {
            if (ctx->sessions[i].state == WC_SESSION_ACTIVE) {
                return 0;
            }
            break;
        }
    }

    return -1;
}

/* ============================================================================
 * Signing Request Handling
 * ============================================================================ */

int wc_approve_request(wc_context_t *ctx, const wc_signing_request_t *request,
                       const uint8_t *signature, size_t signature_len)
{
    if (!ctx || !request || !signature) {
        return -1;
    }

    if (signature_len != 65) {  /* Ethereum signature: r(32) + s(32) + v(1) */
        return -1;
    }

    /* Build JSON-RPC response with signature */
    char response[WC_JSON_MAX];
    char sig_hex[132];  /* 65 bytes * 2 + "0x" + null */

    sig_hex[0] = '0';
    sig_hex[1] = 'x';
    wc_crypto_to_hex(signature, signature_len, sig_hex + 2);

    snprintf(response, sizeof(response),
             "{\"id\":%llu,\"jsonrpc\":\"2.0\",\"result\":\"%s\"}",
             (unsigned long long)request->id, sig_hex);

    /* Response would be encrypted and sent via relay */
    /* This depends on the transport layer implementation */

    return 0;
}

int wc_approve_transaction(wc_context_t *ctx, const wc_signing_request_t *request,
                           const uint8_t tx_hash[32])
{
    if (!ctx || !request || !tx_hash) {
        return -1;
    }

    char response[WC_JSON_MAX];
    char hash_hex[68];  /* 32 bytes * 2 + "0x" + null */

    hash_hex[0] = '0';
    hash_hex[1] = 'x';
    wc_crypto_to_hex(tx_hash, 32, hash_hex + 2);

    snprintf(response, sizeof(response),
             "{\"id\":%llu,\"jsonrpc\":\"2.0\",\"result\":\"%s\"}",
             (unsigned long long)request->id, hash_hex);

    return 0;
}

int wc_reject_request(wc_context_t *ctx, const wc_signing_request_t *request,
                      wc_error_t error, const char *reason)
{
    if (!ctx || !request) {
        return -1;
    }

    char response[WC_JSON_MAX];

    snprintf(response, sizeof(response),
             "{\"id\":%llu,\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"%s\"}}",
             (unsigned long long)request->id, (int)error,
             reason ? reason : "User rejected request");

    return 0;
}

/* ============================================================================
 * Message Processing
 * ============================================================================ */

/* Find session or pairing for topic */
static int find_topic_context(wc_context_t *ctx, const char *topic_hex,
                              wc_symkey_t *key, int *is_session)
{
    uint8_t topic_bytes[WC_TOPIC_SIZE];

    if (wc_crypto_from_hex(topic_hex, topic_bytes, WC_TOPIC_SIZE) != 0) {
        return -1;
    }

    /* Check sessions first */
    for (size_t i = 0; i < ctx->session_count; i++) {
        if (memcmp(ctx->sessions[i].topic.bytes, topic_bytes, WC_TOPIC_SIZE) == 0) {
            memcpy(key, &ctx->sessions[i].sym_key, sizeof(wc_symkey_t));
            *is_session = 1;
            return (int)i;
        }
    }

    /* Check pairings */
    for (size_t i = 0; i < ctx->pairing_count; i++) {
        if (memcmp(ctx->pairings[i].topic.bytes, topic_bytes, WC_TOPIC_SIZE) == 0) {
            memcpy(key, &ctx->pairings[i].sym_key, sizeof(wc_symkey_t));
            *is_session = 0;
            return (int)i;
        }
    }

    return -1;
}

/* Parse signing request from JSON */
static int parse_signing_request(const char *json, wc_signing_request_t *request)
{
    int64_t id;
    size_t len;
    const char *method;
    const char *params;

    memset(request, 0, sizeof(wc_signing_request_t));

    /* Get request ID */
    if (json_get_int(json, "id", &id) != 0) {
        return -1;
    }
    request->id = (uint64_t)id;

    /* Get method name */
    method = json_get_string(json, "method", &len);
    if (!method || len >= WC_NAME_MAX) {
        return -1;
    }
    memcpy(request->method_name, method, len);
    request->method_name[len] = '\0';

    /* Parse method type */
    request->method = wc_parse_method(request->method_name);

    /* Get params object */
    params = json_get_object(json, "params", &len);
    if (!params) {
        return -1;
    }

    /* Parse based on method type */
    switch (request->method) {
        case WC_METHOD_PERSONAL_SIGN: {
            /* params: { request: { method, params: [message, address] } } */
            const char *inner_params = json_get_object(params, "request", &len);
            if (inner_params) {
                /* Find params array - simplified parsing */
                const char *arr_start = strstr(inner_params, "\"params\":[");
                if (arr_start) {
                    arr_start += 10;  /* Skip "params":[ */
                    /* First param is message (hex-encoded) */
                    if (*arr_start == '"') {
                        arr_start++;
                        const char *msg_end = strchr(arr_start, '"');
                        if (msg_end) {
                            size_t msg_len = msg_end - arr_start;
                            if (msg_len < WC_MESSAGE_MAX) {
                                memcpy(request->params.personal_sign.message, arr_start, msg_len);
                                request->params.personal_sign.message_len = msg_len;
                            }
                            /* Second param is address */
                            const char *addr_start = strchr(msg_end + 1, '"');
                            if (addr_start) {
                                addr_start++;
                                const char *addr_end = strchr(addr_start, '"');
                                if (addr_end) {
                                    size_t addr_len = addr_end - addr_start;
                                    if (addr_len < 64) {
                                        memcpy(request->params.personal_sign.address,
                                               addr_start, addr_len);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            break;
        }

        case WC_METHOD_ETH_SIGN_TRANSACTION:
        case WC_METHOD_ETH_SEND_TRANSACTION: {
            /* params: { request: { method, params: [{ from, to, value, data, ... }] } } */
            const char *inner_params = json_get_object(params, "request", &len);
            if (inner_params) {
                const char *tx = json_get_object(inner_params, "params", &len);
                if (tx) {
                    /* Parse transaction fields */
                    const char *val;

                    val = json_get_string(tx, "from", &len);
                    if (val && len < 64) {
                        memcpy(request->params.transaction.from, val, len);
                    }

                    val = json_get_string(tx, "to", &len);
                    if (val && len < 64) {
                        memcpy(request->params.transaction.to, val, len);
                    }

                    val = json_get_string(tx, "value", &len);
                    if (val && len < 32) {
                        memcpy(request->params.transaction.value, val, len);
                    }

                    val = json_get_string(tx, "data", &len);
                    if (val && len < WC_MESSAGE_MAX) {
                        memcpy(request->params.transaction.data, val, len);
                    }

                    val = json_get_string(tx, "gas", &len);
                    if (val && len < 16) {
                        memcpy(request->params.transaction.gas, val, len);
                    }
                }
            }
            break;
        }

        case WC_METHOD_ETH_SIGN_TYPED_DATA:
        case WC_METHOD_ETH_SIGN_TYPED_DATA_V4: {
            /* params: { request: { method, params: [address, typedData] } } */
            const char *inner_params = json_get_object(params, "request", &len);
            if (inner_params) {
                /* Simplified - would need proper JSON array parsing */
                const char *addr = json_get_string(inner_params, "address", &len);
                if (addr && len < 64) {
                    memcpy(request->params.typed_data.address, addr, len);
                }
            }
            break;
        }

        default:
            break;
    }

    request->state = WC_REQUEST_PENDING;
    request->timestamp = (uint64_t)time(NULL);

    return 0;
}

/* Parse session proposal from JSON */
static int parse_session_proposal(const char *json, wc_session_proposal_t *proposal)
{
    int64_t id;
    size_t len;

    memset(proposal, 0, sizeof(wc_session_proposal_t));

    /* Get proposal ID */
    if (json_get_int(json, "id", &id) != 0) {
        return -1;
    }
    proposal->id = (uint64_t)id;

    /* Get params object */
    const char *params = json_get_object(json, "params", &len);
    if (!params) {
        return -1;
    }

    /* Get proposer public key */
    const char *proposer = json_get_object(params, "proposer", &len);
    if (proposer) {
        const char *pubkey = json_get_string(proposer, "publicKey", &len);
        if (pubkey && len == WC_KEY_SIZE * 2) {
            wc_crypto_from_hex(pubkey, proposal->proposer_pubkey, WC_KEY_SIZE);
        }

        /* Get proposer metadata */
        const char *metadata = json_get_object(proposer, "metadata", &len);
        if (metadata) {
            const char *val;

            val = json_get_string(metadata, "name", &len);
            if (val && len < WC_NAME_MAX) {
                memcpy(proposal->proposer_metadata.name, val, len);
            }

            val = json_get_string(metadata, "description", &len);
            if (val && len < WC_URL_MAX) {
                memcpy(proposal->proposer_metadata.description, val, len);
            }

            val = json_get_string(metadata, "url", &len);
            if (val && len < WC_URL_MAX) {
                memcpy(proposal->proposer_metadata.url, val, len);
            }
        }
    }

    /* Get relay info */
    const char *relay = json_get_object(params, "relay", &len);
    if (relay) {
        const char *protocol = json_get_string(relay, "protocol", &len);
        if (protocol && len < WC_NAME_MAX) {
            memcpy(proposal->relay.protocol, protocol, len);
        }
    }

    /* Get required namespaces - simplified parsing */
    const char *required_ns = json_get_object(params, "requiredNamespaces", &len);
    if (required_ns) {
        /* Check for eip155 namespace */
        const char *eip155 = json_get_object(required_ns, "eip155", &len);
        if (eip155) {
            proposal->required_count = 1;
            strncpy(proposal->required_namespaces[0].name, "eip155", WC_NAME_MAX - 1);

            /* Parse chains array - simplified */
            const char *chains = strstr(eip155, "\"chains\":[");
            if (chains) {
                chains += 10;
                /* Parse chain IDs like "eip155:1" */
                while (*chains && *chains != ']') {
                    if (*chains == '"') {
                        chains++;
                        const char *end = strchr(chains, '"');
                        if (end && proposal->required_namespaces[0].chain_count < WC_MAX_CHAINS) {
                            size_t clen = end - chains;
                            if (clen < WC_NAME_MAX) {
                                wc_chain_t *chain = &proposal->required_namespaces[0].chains[
                                    proposal->required_namespaces[0].chain_count++];
                                memcpy(chain->chain_id, chains, clen);
                                chain->chain_id[clen] = '\0';
                                /* Extract numeric ID */
                                const char *colon = strchr(chain->chain_id, ':');
                                if (colon) {
                                    chain->numeric_id = strtoull(colon + 1, NULL, 10);
                                }
                            }
                        }
                        chains = end + 1;
                    } else {
                        chains++;
                    }
                }
            }
        }
    }

    /* Set expiry */
    proposal->expiry = (uint64_t)time(NULL) + WC_PROPOSAL_TTL;

    return 0;
}

int wc_process_message(wc_context_t *ctx, const char *topic,
                       const char *message, size_t message_len)
{
    if (!ctx || !topic || !message) {
        return -1;
    }

    /* Find key for this topic */
    wc_symkey_t key;
    int is_session;
    int idx = find_topic_context(ctx, topic, &key, &is_session);

    if (idx < 0) {
        if (ctx->on_error) {
            ctx->on_error(WC_ERROR_INVALID_TOPIC, "Unknown topic", ctx->user_data);
        }
        return -1;
    }

    /* Decode base64 message */
    uint8_t envelope[WC_MESSAGE_MAX];
    size_t envelope_len = sizeof(envelope);

    if (base64_decode(message, message_len, envelope, &envelope_len) != 0) {
        if (ctx->on_error) {
            ctx->on_error(WC_ERROR_PARSE_ERROR, "Base64 decode failed", ctx->user_data);
        }
        return -1;
    }

    /* Decrypt envelope */
    uint8_t plaintext[WC_JSON_MAX];
    size_t plaintext_len = sizeof(plaintext);

    /* Check envelope type (first byte) */
    if (envelope_len < 1) {
        return -1;
    }

    int result;
    if (envelope[0] == WC_ENVELOPE_TYPE_0) {
        result = wc_crypto_open_type0(&key, envelope, envelope_len,
                                      plaintext, &plaintext_len);
    } else if (envelope[0] == WC_ENVELOPE_TYPE_1) {
        /* Type 1 envelope - need keypair */
        if (is_session) {
            uint8_t sender_pubkey[WC_KEY_SIZE];
            result = wc_crypto_open_type1(&ctx->sessions[idx].self_keypair,
                                          envelope, envelope_len,
                                          sender_pubkey, plaintext, &plaintext_len);
        } else {
            uint8_t sender_pubkey[WC_KEY_SIZE];
            result = wc_crypto_open_type1(&ctx->pairings[idx].self_keypair,
                                          envelope, envelope_len,
                                          sender_pubkey, plaintext, &plaintext_len);
        }
    } else {
        if (ctx->on_error) {
            ctx->on_error(WC_ERROR_PARSE_ERROR, "Unknown envelope type", ctx->user_data);
        }
        return -1;
    }

    if (result != 0) {
        if (ctx->on_error) {
            ctx->on_error(WC_ERROR_PARSE_ERROR, "Decryption failed", ctx->user_data);
        }
        wc_crypto_wipe_symkey(&key);
        return -1;
    }

    wc_crypto_wipe_symkey(&key);

    /* Null-terminate JSON */
    if (plaintext_len >= WC_JSON_MAX) {
        plaintext_len = WC_JSON_MAX - 1;
    }
    plaintext[plaintext_len] = '\0';

    /* Parse JSON-RPC message */
    const char *json = (const char *)plaintext;
    size_t method_len;
    const char *method = json_get_string(json, "method", &method_len);

    if (method) {
        /* This is a request */
        if (strncmp(method, "wc_sessionPropose", method_len) == 0) {
            /* Session proposal */
            if (parse_session_proposal(json, &ctx->pending_proposal) == 0) {
                ctx->has_pending_proposal = 1;
                memcpy(&ctx->pending_proposal.pairing_topic,
                       &ctx->pairings[idx].topic, sizeof(wc_topic_t));

                if (ctx->on_proposal) {
                    ctx->on_proposal(&ctx->pending_proposal, ctx->user_data);
                }
            }
        }
        else if (strncmp(method, "wc_sessionRequest", method_len) == 0) {
            /* Signing request */
            wc_signing_request_t request;
            if (parse_signing_request(json, &request) == 0) {
                memcpy(&request.session_topic, &ctx->sessions[idx].topic,
                       sizeof(wc_topic_t));

                if (ctx->on_request) {
                    ctx->on_request(&request, ctx->user_data);
                }
            }
        }
        else if (strncmp(method, "wc_sessionDelete", method_len) == 0) {
            /* Session deletion */
            if (is_session) {
                wc_disconnect_session(ctx, &ctx->sessions[idx], "Peer disconnected");
            }
        }
        else if (strncmp(method, "wc_sessionPing", method_len) == 0) {
            /* Respond to ping - would send pong response */
        }
    }

    return 0;
}

int wc_poll(wc_context_t *ctx)
{
    if (!ctx) {
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    /* Check for expired pairings */
    for (size_t i = 0; i < ctx->pairing_count; ) {
        if (ctx->pairings[i].expiry > 0 && ctx->pairings[i].expiry < now) {
            ctx->pairings[i].state = WC_PAIRING_EXPIRED;
            wc_delete_pairing(ctx, &ctx->pairings[i].topic);
            /* Don't increment i - array shifted */
        } else {
            i++;
        }
    }

    /* Check for expired sessions */
    for (size_t i = 0; i < ctx->session_count; ) {
        if (ctx->sessions[i].expiry > 0 && ctx->sessions[i].expiry < now) {
            ctx->sessions[i].state = WC_SESSION_EXPIRED;
            wc_disconnect_session(ctx, &ctx->sessions[i], "Session expired");
        } else {
            i++;
        }
    }

    return 0;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

wc_method_type_t wc_parse_method(const char *method)
{
    if (!method) {
        return WC_METHOD_UNKNOWN;
    }

    if (strcmp(method, "personal_sign") == 0) {
        return WC_METHOD_PERSONAL_SIGN;
    }
    if (strcmp(method, "eth_sign") == 0) {
        return WC_METHOD_ETH_SIGN;
    }
    if (strcmp(method, "eth_signTypedData") == 0) {
        return WC_METHOD_ETH_SIGN_TYPED_DATA;
    }
    if (strcmp(method, "eth_signTypedData_v4") == 0) {
        return WC_METHOD_ETH_SIGN_TYPED_DATA_V4;
    }
    if (strcmp(method, "eth_signTransaction") == 0) {
        return WC_METHOD_ETH_SIGN_TRANSACTION;
    }
    if (strcmp(method, "eth_sendTransaction") == 0) {
        return WC_METHOD_ETH_SEND_TRANSACTION;
    }
    if (strcmp(method, "eth_accounts") == 0) {
        return WC_METHOD_ETH_ACCOUNTS;
    }
    if (strcmp(method, "eth_chainId") == 0) {
        return WC_METHOD_ETH_CHAIN_ID;
    }
    if (strcmp(method, "wallet_switchEthereumChain") == 0) {
        return WC_METHOD_WALLET_SWITCH_CHAIN;
    }
    if (strcmp(method, "wallet_addEthereumChain") == 0) {
        return WC_METHOD_WALLET_ADD_CHAIN;
    }

    return WC_METHOD_UNKNOWN;
}

const char *wc_method_name(wc_method_type_t method)
{
    switch (method) {
        case WC_METHOD_PERSONAL_SIGN:
            return "personal_sign";
        case WC_METHOD_ETH_SIGN:
            return "eth_sign";
        case WC_METHOD_ETH_SIGN_TYPED_DATA:
            return "eth_signTypedData";
        case WC_METHOD_ETH_SIGN_TYPED_DATA_V4:
            return "eth_signTypedData_v4";
        case WC_METHOD_ETH_SIGN_TRANSACTION:
            return "eth_signTransaction";
        case WC_METHOD_ETH_SEND_TRANSACTION:
            return "eth_sendTransaction";
        case WC_METHOD_ETH_ACCOUNTS:
            return "eth_accounts";
        case WC_METHOD_ETH_CHAIN_ID:
            return "eth_chainId";
        case WC_METHOD_WALLET_SWITCH_CHAIN:
            return "wallet_switchEthereumChain";
        case WC_METHOD_WALLET_ADD_CHAIN:
            return "wallet_addEthereumChain";
        default:
            return "unknown";
    }
}

int wc_validate_eth_address(const char *address)
{
    if (!address) {
        return 0;
    }

    /* Check 0x prefix */
    if (strncmp(address, "0x", 2) != 0 && strncmp(address, "0X", 2) != 0) {
        return 0;
    }

    /* Check length (0x + 40 hex chars = 42) */
    if (strlen(address) != 42) {
        return 0;
    }

    /* Check all characters are hex */
    for (int i = 2; i < 42; i++) {
        if (!isxdigit((unsigned char)address[i])) {
            return 0;
        }
    }

    return 1;
}

int wc_parse_chain_id(const char *caip2, wc_chain_t *chain)
{
    if (!caip2 || !chain) {
        return -1;
    }

    memset(chain, 0, sizeof(wc_chain_t));

    /* Copy full CAIP-2 string */
    strncpy(chain->chain_id, caip2, WC_NAME_MAX - 1);
    chain->chain_id[WC_NAME_MAX - 1] = '\0';

    /* Parse numeric ID from "eip155:1" format */
    const char *colon = strchr(caip2, ':');
    if (colon) {
        chain->numeric_id = strtoull(colon + 1, NULL, 10);
    }

    return 0;
}

int wc_format_chain_id(uint64_t chain_id, char *output, size_t output_len)
{
    if (!output || output_len < 20) {
        return -1;
    }

    int n = snprintf(output, output_len, "eip155:%llu", (unsigned long long)chain_id);
    if (n < 0 || (size_t)n >= output_len) {
        return -1;
    }

    return 0;
}

const char *wc_error_message(wc_error_t error)
{
    switch (error) {
        case WC_ERROR_NONE:
            return "No error";
        case WC_ERROR_INVALID_METHOD:
            return "Invalid method";
        case WC_ERROR_INVALID_PARAMS:
            return "Invalid parameters";
        case WC_ERROR_INTERNAL:
            return "Internal error";
        case WC_ERROR_INVALID_REQUEST:
            return "Invalid request";
        case WC_ERROR_PARSE_ERROR:
            return "Parse error";
        case WC_ERROR_USER_REJECTED:
            return "User rejected request";
        case WC_ERROR_UNAUTHORIZED:
            return "Unauthorized";
        case WC_ERROR_UNSUPPORTED_METHOD:
            return "Method not supported";
        case WC_ERROR_DISCONNECTED:
            return "Disconnected";
        case WC_ERROR_CHAIN_NOT_APPROVED:
            return "Chain not approved";
        case WC_ERROR_SESSION_EXPIRED:
            return "Session expired";
        case WC_ERROR_NO_SESSION:
            return "No active session";
        case WC_ERROR_INVALID_TOPIC:
            return "Invalid topic";
        default:
            return "Unknown error";
    }
}

/* ============================================================================
 * Persistence
 * ============================================================================ */

/* Simple serialization format:
 * - 4 bytes: magic "WC02"
 * - 4 bytes: version
 * - 4 bytes: pairing count
 * - pairings...
 * - 4 bytes: session count
 * - sessions...
 */

#define WC_SERIALIZE_MAGIC  0x57433032  /* "WC02" */
#define WC_SERIALIZE_VERSION 1

int wc_serialize(wc_context_t *ctx, uint8_t *output, size_t *output_len)
{
    if (!ctx || !output_len) {
        return -1;
    }

    /* Calculate needed size */
    size_t needed = 4 + 4 + 4;  /* magic + version + pairing_count */
    needed += ctx->pairing_count * sizeof(wc_pairing_t);
    needed += 4;  /* session_count */
    needed += ctx->session_count * sizeof(wc_session_t);

    if (!output) {
        *output_len = needed;
        return 0;
    }

    if (*output_len < needed) {
        return -1;
    }

    uint8_t *p = output;

    /* Write header */
    uint32_t magic = WC_SERIALIZE_MAGIC;
    uint32_t version = WC_SERIALIZE_VERSION;
    uint32_t pairing_count = (uint32_t)ctx->pairing_count;
    uint32_t session_count = (uint32_t)ctx->session_count;

    memcpy(p, &magic, 4); p += 4;
    memcpy(p, &version, 4); p += 4;
    memcpy(p, &pairing_count, 4); p += 4;

    /* Write pairings */
    for (size_t i = 0; i < ctx->pairing_count; i++) {
        memcpy(p, &ctx->pairings[i], sizeof(wc_pairing_t));
        p += sizeof(wc_pairing_t);
    }

    memcpy(p, &session_count, 4); p += 4;

    /* Write sessions */
    for (size_t i = 0; i < ctx->session_count; i++) {
        memcpy(p, &ctx->sessions[i], sizeof(wc_session_t));
        p += sizeof(wc_session_t);
    }

    *output_len = p - output;
    return 0;
}

int wc_deserialize(wc_context_t *ctx, const uint8_t *data, size_t data_len)
{
    if (!ctx || !data || data_len < 12) {
        return -1;
    }

    const uint8_t *p = data;

    /* Read and verify header */
    uint32_t magic, version, pairing_count, session_count;

    memcpy(&magic, p, 4); p += 4;
    memcpy(&version, p, 4); p += 4;
    memcpy(&pairing_count, p, 4); p += 4;

    if (magic != WC_SERIALIZE_MAGIC || version != WC_SERIALIZE_VERSION) {
        return -1;
    }

    if (pairing_count > WC_MAX_PAIRINGS) {
        return -1;
    }

    /* Read pairings */
    for (uint32_t i = 0; i < pairing_count; i++) {
        if (p + sizeof(wc_pairing_t) > data + data_len) {
            return -1;
        }
        memcpy(&ctx->pairings[i], p, sizeof(wc_pairing_t));
        p += sizeof(wc_pairing_t);
    }
    ctx->pairing_count = pairing_count;

    /* Read session count */
    if (p + 4 > data + data_len) {
        return -1;
    }
    memcpy(&session_count, p, 4); p += 4;

    if (session_count > WC_MAX_SESSIONS) {
        return -1;
    }

    /* Read sessions */
    for (uint32_t i = 0; i < session_count; i++) {
        if (p + sizeof(wc_session_t) > data + data_len) {
            return -1;
        }
        memcpy(&ctx->sessions[i], p, sizeof(wc_session_t));
        p += sizeof(wc_session_t);
    }
    ctx->session_count = session_count;

    return 0;
}

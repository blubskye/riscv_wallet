/*
 * WalletConnect v2 Protocol Types
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Type definitions for WalletConnect v2 protocol implementation.
 * Supports pairing, sessions, and JSON-RPC signing requests.
 */

#ifndef WC_TYPES_H
#define WC_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* Protocol version */
#define WC_PROTOCOL_VERSION     2

/* Key sizes */
#define WC_KEY_SIZE             32      /* X25519/Ed25519 key size */
#define WC_IV_SIZE              12      /* ChaCha20 IV size */
#define WC_TAG_SIZE             16      /* Poly1305 tag size */
#define WC_TOPIC_SIZE           32      /* SHA256 topic hash */

/* Buffer sizes */
#define WC_URI_MAX              512     /* Max pairing URI length */
#define WC_MESSAGE_MAX          4096    /* Max encrypted message */
#define WC_JSON_MAX             8192    /* Max JSON payload */
#define WC_NAME_MAX             64      /* Max name/label length */
#define WC_URL_MAX              256     /* Max URL length */

/* Limits */
#define WC_MAX_CHAINS           16      /* Max chains per session */
#define WC_MAX_METHODS          32      /* Max methods per namespace */
#define WC_MAX_EVENTS           16      /* Max events per namespace */
#define WC_MAX_ACCOUNTS         8       /* Max accounts per chain */
#define WC_MAX_SESSIONS         4       /* Max concurrent sessions */
#define WC_MAX_PAIRINGS         8       /* Max cached pairings */

/* Timeouts (seconds) */
#define WC_PAIRING_INACTIVE_TTL     300     /* 5 minutes for inactive pairing */
#define WC_PAIRING_ACTIVE_TTL       2592000 /* 30 days for active pairing */
#define WC_SESSION_TTL              604800  /* 7 days default session */
#define WC_PROPOSAL_TTL             300     /* 5 minutes for proposal response */
#define WC_PING_TIMEOUT             30      /* 30 seconds ping timeout */

/* JSON-RPC Tags */
#define WC_TAG_SESSION_PROPOSE      1100
#define WC_TAG_SESSION_SETTLE       1101
#define WC_TAG_SESSION_UPDATE       1104
#define WC_TAG_SESSION_EXTEND       1106
#define WC_TAG_SESSION_REQUEST      1108
#define WC_TAG_SESSION_EVENT        1110
#define WC_TAG_SESSION_DELETE       1112
#define WC_TAG_SESSION_PING         1114

/* Error codes (JSON-RPC) */
typedef enum {
    WC_ERROR_NONE = 0,
    WC_ERROR_INVALID_METHOD = -32601,
    WC_ERROR_INVALID_PARAMS = -32602,
    WC_ERROR_INTERNAL = -32603,
    WC_ERROR_INVALID_REQUEST = -32600,
    WC_ERROR_PARSE_ERROR = -32700,
    /* Custom WC errors */
    WC_ERROR_USER_REJECTED = 4001,
    WC_ERROR_UNAUTHORIZED = 4100,
    WC_ERROR_UNSUPPORTED_METHOD = 4200,
    WC_ERROR_DISCONNECTED = 4900,
    WC_ERROR_CHAIN_NOT_APPROVED = 4901,
    WC_ERROR_SESSION_EXPIRED = 5000,
    WC_ERROR_NO_SESSION = 5001,
    WC_ERROR_INVALID_TOPIC = 5002
} wc_error_t;

/* Envelope types for message serialization */
typedef enum {
    WC_ENVELOPE_TYPE_0 = 0,     /* Symmetric key encryption */
    WC_ENVELOPE_TYPE_1 = 1      /* DH key agreement (includes pubkey) */
} wc_envelope_type_t;

/* Pairing state */
typedef enum {
    WC_PAIRING_INACTIVE = 0,    /* Not yet active */
    WC_PAIRING_ACTIVE,          /* Peer responded, active */
    WC_PAIRING_EXPIRED          /* Past expiry time */
} wc_pairing_state_t;

/* Session state */
typedef enum {
    WC_SESSION_NONE = 0,
    WC_SESSION_PROPOSED,        /* Proposal sent/received */
    WC_SESSION_SETTLING,        /* Settlement in progress */
    WC_SESSION_ACTIVE,          /* Fully established */
    WC_SESSION_EXPIRED          /* Past expiry time */
} wc_session_state_t;

/* Signing request state */
typedef enum {
    WC_REQUEST_PENDING = 0,     /* Awaiting user action */
    WC_REQUEST_APPROVED,        /* User approved */
    WC_REQUEST_REJECTED,        /* User rejected */
    WC_REQUEST_TIMEOUT,         /* Request timed out */
    WC_REQUEST_COMPLETED        /* Response sent */
} wc_request_state_t;

/* Ethereum signing method types */
typedef enum {
    WC_METHOD_UNKNOWN = 0,
    WC_METHOD_PERSONAL_SIGN,        /* personal_sign */
    WC_METHOD_ETH_SIGN,             /* eth_sign (deprecated) */
    WC_METHOD_ETH_SIGN_TYPED_DATA,  /* eth_signTypedData (EIP-712) */
    WC_METHOD_ETH_SIGN_TYPED_DATA_V4, /* eth_signTypedData_v4 */
    WC_METHOD_ETH_SIGN_TRANSACTION, /* eth_signTransaction */
    WC_METHOD_ETH_SEND_TRANSACTION, /* eth_sendTransaction */
    WC_METHOD_ETH_ACCOUNTS,         /* eth_accounts */
    WC_METHOD_ETH_CHAIN_ID,         /* eth_chainId */
    WC_METHOD_WALLET_SWITCH_CHAIN,  /* wallet_switchEthereumChain */
    WC_METHOD_WALLET_ADD_CHAIN      /* wallet_addEthereumChain */
} wc_method_type_t;

/* Keypair for X25519/Ed25519 */
typedef struct {
    uint8_t public_key[WC_KEY_SIZE];
    uint8_t private_key[WC_KEY_SIZE];
} wc_keypair_t;

/* Symmetric key */
typedef struct {
    uint8_t key[WC_KEY_SIZE];
} wc_symkey_t;

/* Topic (SHA256 hash of symmetric key) */
typedef struct {
    uint8_t bytes[WC_TOPIC_SIZE];
    char hex[WC_TOPIC_SIZE * 2 + 1];  /* Hex string representation */
} wc_topic_t;

/* Relay server info */
typedef struct {
    char protocol[WC_NAME_MAX];     /* Usually "irn" */
    char url[WC_URL_MAX];           /* wss://relay.walletconnect.com */
} wc_relay_t;

/* App metadata */
typedef struct {
    char name[WC_NAME_MAX];
    char description[WC_URL_MAX];
    char url[WC_URL_MAX];
    char icon_url[WC_URL_MAX];
} wc_metadata_t;

/* Chain reference (CAIP-2 format) */
typedef struct {
    char chain_id[WC_NAME_MAX];     /* e.g., "eip155:1" for Ethereum mainnet */
    uint64_t numeric_id;            /* Numeric chain ID (e.g., 1 for ETH mainnet) */
} wc_chain_t;

/* Namespace (e.g., "eip155" for EVM chains) */
typedef struct {
    char name[WC_NAME_MAX];         /* Namespace identifier */
    wc_chain_t chains[WC_MAX_CHAINS];
    size_t chain_count;
    char methods[WC_MAX_METHODS][WC_NAME_MAX];
    size_t method_count;
    char events[WC_MAX_EVENTS][WC_NAME_MAX];
    size_t event_count;
    char accounts[WC_MAX_ACCOUNTS][64];  /* CAIP-10 account IDs */
    size_t account_count;
} wc_namespace_t;

/* Pairing structure */
typedef struct {
    wc_topic_t topic;
    wc_symkey_t sym_key;
    wc_keypair_t self_keypair;      /* Our ephemeral keypair */
    uint8_t peer_pubkey[WC_KEY_SIZE];
    wc_relay_t relay;
    wc_pairing_state_t state;
    uint64_t expiry;                /* Unix timestamp */
    int active;                     /* Has peer responded */
} wc_pairing_t;

/* Session proposal */
typedef struct {
    uint64_t id;                    /* Proposal ID */
    wc_topic_t pairing_topic;       /* Topic from pairing */
    uint8_t proposer_pubkey[WC_KEY_SIZE];
    wc_relay_t relay;
    wc_namespace_t required_namespaces[4];
    size_t required_count;
    wc_namespace_t optional_namespaces[4];
    size_t optional_count;
    wc_metadata_t proposer_metadata;
    uint64_t expiry;
} wc_session_proposal_t;

/* Active session */
typedef struct {
    wc_topic_t topic;               /* Session topic */
    wc_symkey_t sym_key;            /* Session symmetric key */
    wc_keypair_t self_keypair;
    uint8_t peer_pubkey[WC_KEY_SIZE];
    wc_session_state_t state;
    wc_namespace_t namespaces[4];
    size_t namespace_count;
    wc_metadata_t peer_metadata;
    wc_relay_t relay;
    uint64_t expiry;
    int is_controller;              /* True if we're the controller (wallet) */
} wc_session_t;

/* Ethereum transaction parameters */
typedef struct {
    char from[64];                  /* 0x-prefixed address */
    char to[64];
    char value[32];                 /* Wei value as hex */
    char data[WC_MESSAGE_MAX];      /* Contract data */
    char gas[16];
    char gas_price[16];             /* Legacy gas price */
    char max_fee_per_gas[16];       /* EIP-1559 */
    char max_priority_fee[16];      /* EIP-1559 */
    char nonce[16];
    uint64_t chain_id;
} wc_eth_tx_params_t;

/* Signing request */
typedef struct {
    uint64_t id;                    /* Request ID */
    wc_topic_t session_topic;
    wc_method_type_t method;
    char method_name[WC_NAME_MAX];
    wc_chain_t chain;

    /* Method-specific data */
    union {
        struct {
            char message[WC_MESSAGE_MAX];
            size_t message_len;
            char address[64];
        } personal_sign;

        struct {
            uint8_t hash[32];
            char address[64];
        } eth_sign;

        wc_eth_tx_params_t transaction;

        struct {
            char domain[WC_JSON_MAX];
            char message[WC_JSON_MAX];
            char address[64];
        } typed_data;
    } params;

    wc_request_state_t state;
    uint64_t timestamp;
} wc_signing_request_t;

/* Signing response */
typedef struct {
    uint64_t id;
    int success;
    union {
        struct {
            uint8_t signature[65];  /* r, s, v */
        } sign_result;

        struct {
            char tx_hash[66];       /* 0x + 64 hex chars */
        } tx_result;

        struct {
            wc_error_t code;
            char message[256];
        } error;
    } result;
} wc_signing_response_t;

/* Encrypted envelope */
typedef struct {
    wc_envelope_type_t type;
    uint8_t iv[WC_IV_SIZE];
    uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t tag[WC_TAG_SIZE];
    uint8_t sender_pubkey[WC_KEY_SIZE];  /* Only for Type 1 */
} wc_envelope_t;

/* JSON-RPC request */
typedef struct {
    uint64_t id;
    char method[WC_NAME_MAX];
    char params[WC_JSON_MAX];
} wc_jsonrpc_request_t;

/* JSON-RPC response */
typedef struct {
    uint64_t id;
    int is_error;
    union {
        char result[WC_JSON_MAX];
        struct {
            int code;
            char message[256];
        } error;
    } data;
} wc_jsonrpc_response_t;

/* Relay message */
typedef struct {
    wc_topic_t topic;
    char message[WC_MESSAGE_MAX];   /* Base64-encoded envelope */
    size_t message_len;
    uint32_t ttl;
    uint32_t tag;
} wc_relay_message_t;

/* Callback types */
typedef void (*wc_pairing_callback_t)(const wc_pairing_t *pairing, void *user_data);
typedef void (*wc_proposal_callback_t)(const wc_session_proposal_t *proposal, void *user_data);
typedef void (*wc_session_callback_t)(const wc_session_t *session, void *user_data);
typedef void (*wc_request_callback_t)(const wc_signing_request_t *request, void *user_data);
typedef void (*wc_error_callback_t)(wc_error_t error, const char *message, void *user_data);

#endif /* WC_TYPES_H */

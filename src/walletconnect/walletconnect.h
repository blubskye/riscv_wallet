/*
 * WalletConnect v2 Protocol Handler
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Main API for WalletConnect v2 protocol:
 * - Pairing via QR code / URI
 * - Session management
 * - Signing request handling
 */

#ifndef WALLETCONNECT_H
#define WALLETCONNECT_H

#include "wc_types.h"

/* Default relay server */
#define WC_DEFAULT_RELAY_URL    "wss://relay.walletconnect.com"
#define WC_DEFAULT_RELAY_PROTO  "irn"

/* Project ID (required for WalletConnect cloud) */
#define WC_PROJECT_ID_MAX       64

/**
 * WalletConnect context
 */
typedef struct wc_context wc_context_t;

/* ============================================================================
 * Initialization and Lifecycle
 * ============================================================================ */

/**
 * Create WalletConnect context
 *
 * @param project_id WalletConnect project ID (from cloud.walletconnect.com)
 * @return Context pointer, or NULL on error
 */
wc_context_t *wc_create(const char *project_id);

/**
 * Destroy WalletConnect context
 *
 * @param ctx Context to destroy
 */
void wc_destroy(wc_context_t *ctx);

/**
 * Set wallet metadata
 *
 * @param ctx Context
 * @param name Wallet name
 * @param description Short description
 * @param url Wallet website URL
 * @param icon Icon URL
 * @return 0 on success, -1 on error
 */
int wc_set_metadata(wc_context_t *ctx, const char *name, const char *description,
                    const char *url, const char *icon);

/**
 * Set callback handlers
 *
 * @param ctx Context
 * @param on_proposal Called when session proposal received
 * @param on_request Called when signing request received
 * @param on_error Called on errors
 * @param user_data User data passed to callbacks
 */
void wc_set_callbacks(wc_context_t *ctx,
                      wc_proposal_callback_t on_proposal,
                      wc_request_callback_t on_request,
                      wc_error_callback_t on_error,
                      void *user_data);

/* ============================================================================
 * Pairing
 * ============================================================================ */

/**
 * Parse pairing URI from QR code
 *
 * @param uri Pairing URI (wc:...)
 * @param pairing Output pairing structure
 * @return 0 on success, -1 on error
 */
int wc_parse_pairing_uri(const char *uri, wc_pairing_t *pairing);

/**
 * Initiate pairing from URI
 *
 * @param ctx Context
 * @param uri Pairing URI from QR code
 * @return 0 on success, -1 on error
 */
int wc_pair(wc_context_t *ctx, const char *uri);

/**
 * Get active pairings
 *
 * @param ctx Context
 * @param pairings Output array
 * @param count Input: array size, Output: number of pairings
 * @return 0 on success, -1 on error
 */
int wc_get_pairings(wc_context_t *ctx, wc_pairing_t *pairings, size_t *count);

/**
 * Delete pairing
 *
 * @param ctx Context
 * @param topic Pairing topic to delete
 * @return 0 on success, -1 on error
 */
int wc_delete_pairing(wc_context_t *ctx, const wc_topic_t *topic);

/* ============================================================================
 * Session Management
 * ============================================================================ */

/**
 * Approve session proposal
 *
 * @param ctx Context
 * @param proposal Proposal to approve
 * @param accounts Array of account addresses (CAIP-10 format: "eip155:1:0x...")
 * @param account_count Number of accounts
 * @return 0 on success, -1 on error
 */
int wc_approve_session(wc_context_t *ctx, const wc_session_proposal_t *proposal,
                       const char **accounts, size_t account_count);

/**
 * Reject session proposal
 *
 * @param ctx Context
 * @param proposal Proposal to reject
 * @param reason Rejection reason
 * @return 0 on success, -1 on error
 */
int wc_reject_session(wc_context_t *ctx, const wc_session_proposal_t *proposal,
                      const char *reason);

/**
 * Get active sessions
 *
 * @param ctx Context
 * @param sessions Output array
 * @param count Input: array size, Output: number of sessions
 * @return 0 on success, -1 on error
 */
int wc_get_sessions(wc_context_t *ctx, wc_session_t *sessions, size_t *count);

/**
 * Get session by topic
 *
 * @param ctx Context
 * @param topic Session topic
 * @param session Output session structure
 * @return 0 on success, -1 if not found
 */
int wc_get_session(wc_context_t *ctx, const wc_topic_t *topic, wc_session_t *session);

/**
 * Update session accounts
 *
 * @param ctx Context
 * @param session Session to update
 * @param accounts New account list
 * @param account_count Number of accounts
 * @return 0 on success, -1 on error
 */
int wc_update_session(wc_context_t *ctx, const wc_session_t *session,
                      const char **accounts, size_t account_count);

/**
 * Extend session expiry
 *
 * @param ctx Context
 * @param session Session to extend
 * @return 0 on success, -1 on error
 */
int wc_extend_session(wc_context_t *ctx, const wc_session_t *session);

/**
 * Disconnect session
 *
 * @param ctx Context
 * @param session Session to disconnect
 * @param reason Disconnect reason
 * @return 0 on success, -1 on error
 */
int wc_disconnect_session(wc_context_t *ctx, const wc_session_t *session,
                          const char *reason);

/**
 * Ping session (health check)
 *
 * @param ctx Context
 * @param session Session to ping
 * @return 0 if responding, -1 on error/timeout
 */
int wc_ping_session(wc_context_t *ctx, const wc_session_t *session);

/* ============================================================================
 * Signing Requests
 * ============================================================================ */

/**
 * Approve signing request
 *
 * @param ctx Context
 * @param request Request to approve
 * @param signature Signature bytes (65 bytes for Ethereum)
 * @param signature_len Length of signature
 * @return 0 on success, -1 on error
 */
int wc_approve_request(wc_context_t *ctx, const wc_signing_request_t *request,
                       const uint8_t *signature, size_t signature_len);

/**
 * Approve transaction request with tx hash
 *
 * @param ctx Context
 * @param request Request to approve
 * @param tx_hash Transaction hash (32 bytes)
 * @return 0 on success, -1 on error
 */
int wc_approve_transaction(wc_context_t *ctx, const wc_signing_request_t *request,
                           const uint8_t tx_hash[32]);

/**
 * Reject signing request
 *
 * @param ctx Context
 * @param request Request to reject
 * @param error Error code
 * @param reason Rejection reason
 * @return 0 on success, -1 on error
 */
int wc_reject_request(wc_context_t *ctx, const wc_signing_request_t *request,
                      wc_error_t error, const char *reason);

/* ============================================================================
 * Message Processing
 * ============================================================================ */

/**
 * Process incoming relay message
 * Call this when message received from WebSocket
 *
 * @param ctx Context
 * @param topic Message topic
 * @param message Base64-encoded encrypted message
 * @param message_len Message length
 * @return 0 on success, -1 on error
 */
int wc_process_message(wc_context_t *ctx, const char *topic,
                       const char *message, size_t message_len);

/**
 * Poll for pending operations
 * Call this periodically
 *
 * @param ctx Context
 * @return 0 on success, -1 on error
 */
int wc_poll(wc_context_t *ctx);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Parse signing method from string
 *
 * @param method Method name string
 * @return Method type enum
 */
wc_method_type_t wc_parse_method(const char *method);

/**
 * Get method name string
 *
 * @param method Method type
 * @return Method name string
 */
const char *wc_method_name(wc_method_type_t method);

/**
 * Validate Ethereum address
 *
 * @param address Address string (0x-prefixed)
 * @return 1 if valid, 0 if invalid
 */
int wc_validate_eth_address(const char *address);

/**
 * Parse chain ID from CAIP-2 format
 *
 * @param caip2 CAIP-2 string (e.g., "eip155:1")
 * @param chain Output chain structure
 * @return 0 on success, -1 on error
 */
int wc_parse_chain_id(const char *caip2, wc_chain_t *chain);

/**
 * Format chain ID to CAIP-2 string
 *
 * @param chain_id Numeric chain ID
 * @param output Output buffer
 * @param output_len Buffer size
 * @return 0 on success, -1 on error
 */
int wc_format_chain_id(uint64_t chain_id, char *output, size_t output_len);

/**
 * Get error message for error code
 *
 * @param error Error code
 * @return Error message string
 */
const char *wc_error_message(wc_error_t error);

/* ============================================================================
 * Persistence (for session recovery)
 * ============================================================================ */

/**
 * Serialize context state for storage
 *
 * @param ctx Context
 * @param output Output buffer
 * @param output_len Input: buffer size, Output: data length
 * @return 0 on success, -1 on error
 */
int wc_serialize(wc_context_t *ctx, uint8_t *output, size_t *output_len);

/**
 * Restore context from serialized state
 *
 * @param ctx Context
 * @param data Serialized data
 * @param data_len Data length
 * @return 0 on success, -1 on error
 */
int wc_deserialize(wc_context_t *ctx, const uint8_t *data, size_t data_len);

#endif /* WALLETCONNECT_H */

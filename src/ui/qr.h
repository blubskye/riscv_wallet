/*
 * QR Code Handling
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef QR_H
#define QR_H

#include <stdint.h>
#include <stddef.h>

/* Maximum QR data size */
#define QR_MAX_DATA_SIZE  2953  /* Version 40-L */

/* QR code structure */
typedef struct {
    int version;
    int width;
    uint8_t *modules;  /* 1 = black, 0 = white */
} qr_code_t;

/**
 * Generate QR code from data
 *
 * @param data Data to encode
 * @param qr Output QR code structure
 * @return 0 on success, -1 on error
 */
int qr_encode(const char *data, qr_code_t *qr);

/**
 * Free QR code structure
 *
 * @param qr QR code to free
 */
void qr_free(qr_code_t *qr);

/**
 * Get module (pixel) value
 *
 * @param qr QR code
 * @param x X coordinate
 * @param y Y coordinate
 * @return 1 if black, 0 if white
 */
int qr_get_module(const qr_code_t *qr, int x, int y);

/**
 * Decode QR code from camera image
 *
 * @param image_data Grayscale image data
 * @param width Image width
 * @param height Image height
 * @param output Output buffer for decoded data
 * @param output_len Size of output buffer
 * @return Length of decoded data, -1 on error
 */
int qr_decode(const uint8_t *image_data, int width, int height,
              char *output, size_t output_len);

/**
 * Encode data as animated QR (for large data)
 *
 * Uses the UR (Uniform Resources) format for multi-part QR codes.
 *
 * @param data Data to encode
 * @param data_len Length of data
 * @param frame_callback Callback for each QR frame
 * @param user_data User data for callback
 * @return 0 on success, -1 on error
 */
int qr_encode_animated(const uint8_t *data, size_t data_len,
                       void (*frame_callback)(const qr_code_t *qr, int frame, int total, void *user_data),
                       void *user_data);

/**
 * Print QR code to terminal using Unicode block characters
 *
 * @param qr QR code to print
 * @param indent Number of spaces to indent
 */
void qr_print_terminal(const qr_code_t *qr, int indent);

/**
 * Print QR code to terminal with compact format (2 rows per line)
 *
 * @param qr QR code to print
 * @param indent Number of spaces to indent
 */
void qr_print_terminal_compact(const qr_code_t *qr, int indent);

/**
 * Encode binary data to QR code
 *
 * @param data Binary data to encode
 * @param data_len Length of data
 * @param qr Output QR code structure
 * @return 0 on success, -1 on error
 */
int qr_encode_binary(const uint8_t *data, size_t data_len, qr_code_t *qr);

/*
 * QR Scanner (Camera-based) API
 */

/* Scanner status */
typedef enum {
    QR_SCANNER_OK = 0,
    QR_SCANNER_NO_DEVICE,
    QR_SCANNER_BUSY,
    QR_SCANNER_ERROR,
    QR_SCANNER_NO_QR,
} qr_scanner_status_t;

/**
 * Initialize QR scanner (camera device)
 *
 * @param device Camera device path (e.g., "/dev/video0") or NULL for auto
 * @return QR_SCANNER_OK on success
 */
qr_scanner_status_t qr_scanner_init(const char *device);

/**
 * Shutdown QR scanner
 */
void qr_scanner_shutdown(void);

/**
 * Check if scanner is available
 *
 * @return 1 if available, 0 if not
 */
int qr_scanner_available(void);

/**
 * Scan for QR code (single frame capture and decode)
 *
 * @param output Output buffer for decoded data
 * @param output_len Size of output buffer
 * @param timeout_ms Timeout in milliseconds (0 for single shot)
 * @return Length of decoded data, -1 on error, 0 if no QR found
 */
int qr_scanner_scan(char *output, size_t output_len, int timeout_ms);

/**
 * Start continuous scanning
 *
 * @param callback Called when QR code is detected
 * @param user_data User data for callback
 * @return QR_SCANNER_OK on success
 */
qr_scanner_status_t qr_scanner_start_continuous(
    void (*callback)(const char *data, size_t len, void *user_data),
    void *user_data);

/**
 * Stop continuous scanning
 */
void qr_scanner_stop_continuous(void);

/**
 * Get the last captured frame (for preview)
 *
 * @param width Output width
 * @param height Output height
 * @return Pointer to grayscale image data (valid until next capture) or NULL
 */
const uint8_t *qr_scanner_get_preview(int *width, int *height);

#endif /* QR_H */

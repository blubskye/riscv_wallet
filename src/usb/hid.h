/*
 * USB HID Communication
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Hardware wallet USB HID protocol implementation.
 * Based on common protocols used by Ledger/Trezor devices.
 */

#ifndef USB_HID_H
#define USB_HID_H

#include <stdint.h>
#include <stddef.h>

/* HID packet size (standard for hardware wallets) */
#define HID_PACKET_SIZE     64

/* USB HID channel magic */
#define HID_CHANNEL_MASK    0xFFFF0000
#define HID_CHANNEL_DEFAULT 0x0101

/* APDU command/response structure sizes */
#define APDU_MAX_DATA_SIZE  255
#define APDU_HEADER_SIZE    5

/* Common APDU instruction classes */
#define APDU_CLA_BITCOIN    0xE1
#define APDU_CLA_ETHEREUM   0xE0
#define APDU_CLA_COMMON     0xB0

/* Common APDU instructions */
#define APDU_INS_GET_VERSION        0x01
#define APDU_INS_GET_PUBKEY         0x02
#define APDU_INS_SIGN_TX            0x03
#define APDU_INS_SIGN_MESSAGE       0x04
#define APDU_INS_GET_ADDRESS        0x05

/* Bitcoin-specific instructions */
#define APDU_INS_BTC_GET_ADDRESS    0x40
#define APDU_INS_BTC_SIGN_PSBT      0x41

/* Ethereum-specific instructions */
#define APDU_INS_ETH_GET_ADDRESS    0x02
#define APDU_INS_ETH_SIGN_TX        0x04
#define APDU_INS_ETH_SIGN_MESSAGE   0x08
#define APDU_INS_ETH_SIGN_TYPED     0x0C

/* APDU status codes (SW1-SW2) */
#define APDU_SW_OK                  0x9000
#define APDU_SW_WRONG_LENGTH        0x6700
#define APDU_SW_SECURITY_NOT_SAT    0x6982
#define APDU_SW_CONDITIONS_NOT_SAT  0x6985
#define APDU_SW_WRONG_DATA          0x6A80
#define APDU_SW_INCORRECT_P1P2      0x6B00
#define APDU_SW_INS_NOT_SUPPORTED   0x6D00
#define APDU_SW_CLA_NOT_SUPPORTED   0x6E00
#define APDU_SW_UNKNOWN             0x6F00
#define APDU_SW_USER_REJECTED       0x6985

/* APDU command structure */
typedef struct {
    uint8_t cla;        /* Class byte */
    uint8_t ins;        /* Instruction byte */
    uint8_t p1;         /* Parameter 1 */
    uint8_t p2;         /* Parameter 2 */
    uint8_t lc;         /* Length of command data */
    uint8_t data[APDU_MAX_DATA_SIZE];
    uint8_t le;         /* Expected response length (0 = any) */
} apdu_command_t;

/* APDU response structure */
typedef struct {
    uint8_t data[APDU_MAX_DATA_SIZE];
    size_t data_len;
    uint16_t sw;        /* Status word (SW1 || SW2) */
} apdu_response_t;

/* USB HID device handle */
typedef struct usb_hid_device usb_hid_device_t;

/**
 * Initialize USB HID subsystem
 * @return 0 on success, -1 on error
 */
int usb_hid_init(void);

/**
 * Cleanup USB HID subsystem
 */
void usb_hid_cleanup(void);

/**
 * Enumerate available HID devices
 * @param vendor_id Vendor ID to filter (0 = any)
 * @param product_id Product ID to filter (0 = any)
 * @param devices Output array of device paths
 * @param max_devices Maximum devices to enumerate
 * @return Number of devices found, or -1 on error
 */
int usb_hid_enumerate(uint16_t vendor_id, uint16_t product_id,
                      char **devices, size_t max_devices);

/**
 * Open a HID device
 * @param path Device path from enumeration
 * @return Device handle, or NULL on error
 */
usb_hid_device_t *usb_hid_open(const char *path);

/**
 * Open a HID device by vendor/product ID
 * @param vendor_id USB vendor ID
 * @param product_id USB product ID
 * @return Device handle, or NULL on error
 */
usb_hid_device_t *usb_hid_open_id(uint16_t vendor_id, uint16_t product_id);

/**
 * Close a HID device
 * @param device Device handle
 */
void usb_hid_close(usb_hid_device_t *device);

/**
 * Send raw HID packet
 * @param device Device handle
 * @param data Data to send (HID_PACKET_SIZE bytes)
 * @return 0 on success, -1 on error
 */
int usb_hid_write(usb_hid_device_t *device, const uint8_t data[HID_PACKET_SIZE]);

/**
 * Receive raw HID packet
 * @param device Device handle
 * @param data Output buffer (HID_PACKET_SIZE bytes)
 * @param timeout_ms Timeout in milliseconds (0 = no timeout)
 * @return 0 on success, -1 on error/timeout
 */
int usb_hid_read(usb_hid_device_t *device, uint8_t data[HID_PACKET_SIZE], int timeout_ms);

/**
 * Send APDU command and receive response
 * @param device Device handle
 * @param cmd APDU command
 * @param resp Output APDU response
 * @return 0 on success, -1 on error
 */
int usb_hid_apdu_exchange(usb_hid_device_t *device,
                          const apdu_command_t *cmd,
                          apdu_response_t *resp);

/**
 * Get device version info
 * @param device Device handle
 * @param version Output version string
 * @param version_len Size of version buffer
 * @return 0 on success, -1 on error
 */
int usb_hid_get_version(usb_hid_device_t *device, char *version, size_t version_len);

/**
 * Check if device requires user confirmation
 * @param sw Status word from APDU response
 * @return 1 if user confirmation needed, 0 otherwise
 */
int usb_hid_needs_confirmation(uint16_t sw);

/**
 * Get human-readable error message for status word
 * @param sw Status word
 * @return Error message string
 */
const char *usb_hid_error_string(uint16_t sw);

#endif /* USB_HID_H */

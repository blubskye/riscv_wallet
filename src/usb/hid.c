/*
 * USB HID Communication Implementation
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Hardware wallet USB HID protocol implementation using HIDAPI.
 */

/* Enable POSIX extensions for strdup, fileno */
#define _POSIX_C_SOURCE 200809L

#include "hid.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef USE_HIDAPI
#include <hidapi/hidapi.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

/* Internal device structure */
struct usb_hid_device {
#ifdef USE_HIDAPI
    hid_device *handle;
#else
    int fd;  /* Fallback file descriptor for /dev/hidrawX */
#endif
    uint16_t channel;
    uint16_t sequence;
};

/* HID transport framing (Ledger-style) */
#define HID_FRAME_CHANNEL_OFFSET    0
#define HID_FRAME_TAG_OFFSET        2
#define HID_FRAME_SEQUENCE_OFFSET   3
#define HID_FRAME_DATA_OFFSET       5
#define HID_FRAME_DATA_SIZE         (HID_PACKET_SIZE - HID_FRAME_DATA_OFFSET)

#define HID_TAG_APDU                0x05

/* Static error messages */
static const char *error_messages[] = {
    [0] = "Success",
    [1] = "Wrong length",
    [2] = "Security condition not satisfied",
    [3] = "Conditions not satisfied / User rejected",
    [4] = "Wrong data",
    [5] = "Incorrect P1/P2",
    [6] = "Instruction not supported",
    [7] = "Class not supported",
    [8] = "Unknown error",
};

int usb_hid_init(void)
{
#ifdef USE_HIDAPI
    return hid_init();
#else
    return 0;
#endif
}

void usb_hid_cleanup(void)
{
#ifdef USE_HIDAPI
    hid_exit();
#endif
}

int usb_hid_enumerate(uint16_t vendor_id, uint16_t product_id,
                      char **devices, size_t max_devices)
{
#ifdef USE_HIDAPI
    struct hid_device_info *devs, *cur;
    int count = 0;

    devs = hid_enumerate(vendor_id, product_id);
    if (!devs) {
        return 0;
    }

    cur = devs;
    while (cur && (size_t)count < max_devices) {
        if (cur->path) {
            devices[count] = strdup(cur->path);
            if (devices[count]) {
                count++;
            }
        }
        cur = cur->next;
    }

    hid_free_enumeration(devs);
    return count;
#else
    /* Fallback: scan /dev/hidraw* devices */
    char path[32];
    int count = 0;

    (void)vendor_id;
    (void)product_id;

    for (int i = 0; i < 16 && (size_t)count < max_devices; i++) {
        snprintf(path, sizeof(path), "/dev/hidraw%d", i);
        FILE *f = fopen(path, "r");
        if (f) {
            fclose(f);
            devices[count] = strdup(path);
            if (devices[count]) {
                count++;
            }
        }
    }
    return count;
#endif
}

usb_hid_device_t *usb_hid_open(const char *path)
{
    usb_hid_device_t *dev = calloc(1, sizeof(*dev));
    if (!dev) {
        return NULL;
    }

    dev->channel = HID_CHANNEL_DEFAULT;
    dev->sequence = 0;

#ifdef USE_HIDAPI
    dev->handle = hid_open_path(path);
    if (!dev->handle) {
        free(dev);
        return NULL;
    }

    /* Set non-blocking mode */
    hid_set_nonblocking(dev->handle, 0);
#else
    /* Fallback: open as raw file */
    FILE *f = fopen(path, "r+b");
    if (!f) {
        free(dev);
        return NULL;
    }
    dev->fd = fileno(f);
#endif

    return dev;
}

usb_hid_device_t *usb_hid_open_id(uint16_t vendor_id, uint16_t product_id)
{
#ifdef USE_HIDAPI
    usb_hid_device_t *dev = calloc(1, sizeof(*dev));
    if (!dev) {
        return NULL;
    }

    dev->channel = HID_CHANNEL_DEFAULT;
    dev->sequence = 0;

    dev->handle = hid_open(vendor_id, product_id, NULL);
    if (!dev->handle) {
        free(dev);
        return NULL;
    }

    hid_set_nonblocking(dev->handle, 0);
    return dev;
#else
    /* Fallback: enumerate and open first match */
    char *devices[1];
    if (usb_hid_enumerate(vendor_id, product_id, devices, 1) > 0) {
        usb_hid_device_t *dev = usb_hid_open(devices[0]);
        free(devices[0]);
        return dev;
    }
    return NULL;
#endif
}

void usb_hid_close(usb_hid_device_t *device)
{
    if (!device) {
        return;
    }

#ifdef USE_HIDAPI
    if (device->handle) {
        hid_close(device->handle);
    }
#else
    if (device->fd >= 0) {
        close(device->fd);
    }
#endif

    free(device);
}

int usb_hid_write(usb_hid_device_t *device, const uint8_t data[HID_PACKET_SIZE])
{
    if (!device) {
        return -1;
    }

#ifdef USE_HIDAPI
    /* HIDAPI requires report ID as first byte */
    uint8_t buf[HID_PACKET_SIZE + 1];
    buf[0] = 0x00;  /* Report ID */
    memcpy(buf + 1, data, HID_PACKET_SIZE);

    int ret = hid_write(device->handle, buf, sizeof(buf));
    return (ret == sizeof(buf)) ? 0 : -1;
#else
    ssize_t ret = write(device->fd, data, HID_PACKET_SIZE);
    return (ret == HID_PACKET_SIZE) ? 0 : -1;
#endif
}

int usb_hid_read(usb_hid_device_t *device, uint8_t data[HID_PACKET_SIZE], int timeout_ms)
{
    if (!device) {
        return -1;
    }

#ifdef USE_HIDAPI
    int ret = hid_read_timeout(device->handle, data, HID_PACKET_SIZE, timeout_ms);
    return (ret == HID_PACKET_SIZE) ? 0 : -1;
#else
    /* Simple blocking read for fallback */
    (void)timeout_ms;
    ssize_t ret = read(device->fd, data, HID_PACKET_SIZE);
    return (ret == HID_PACKET_SIZE) ? 0 : -1;
#endif
}

/**
 * Frame APDU data for HID transport (Ledger-style framing)
 */
static int frame_apdu_request(usb_hid_device_t *device,
                              const uint8_t *apdu_data, size_t apdu_len,
                              uint8_t frames[][HID_PACKET_SIZE], size_t *frame_count)
{
    size_t offset = 0;
    size_t seq = 0;
    size_t max_frames = *frame_count;

    *frame_count = 0;

    while (offset < apdu_len && *frame_count < max_frames) {
        uint8_t *frame = frames[*frame_count];
        memset(frame, 0, HID_PACKET_SIZE);

        /* Channel ID (big-endian) */
        frame[HID_FRAME_CHANNEL_OFFSET] = (device->channel >> 8) & 0xFF;
        frame[HID_FRAME_CHANNEL_OFFSET + 1] = device->channel & 0xFF;

        /* Tag */
        frame[HID_FRAME_TAG_OFFSET] = HID_TAG_APDU;

        /* Sequence (big-endian) */
        frame[HID_FRAME_SEQUENCE_OFFSET] = (seq >> 8) & 0xFF;
        frame[HID_FRAME_SEQUENCE_OFFSET + 1] = seq & 0xFF;

        size_t data_offset = HID_FRAME_DATA_OFFSET;
        size_t chunk_size;

        if (seq == 0) {
            /* First frame includes total length (big-endian) */
            frame[data_offset++] = (apdu_len >> 8) & 0xFF;
            frame[data_offset++] = apdu_len & 0xFF;
            chunk_size = HID_PACKET_SIZE - data_offset;
        } else {
            chunk_size = HID_FRAME_DATA_SIZE;
        }

        if (chunk_size > apdu_len - offset) {
            chunk_size = apdu_len - offset;
        }

        memcpy(frame + data_offset, apdu_data + offset, chunk_size);
        offset += chunk_size;
        seq++;
        (*frame_count)++;
    }

    return (offset == apdu_len) ? 0 : -1;
}

/**
 * Reassemble APDU response from HID frames
 */
static int reassemble_apdu_response(usb_hid_device_t *device,
                                    uint8_t *apdu_data, size_t *apdu_len,
                                    int timeout_ms)
{
    uint8_t frame[HID_PACKET_SIZE];
    size_t expected_len = 0;
    size_t offset = 0;
    size_t seq = 0;
    size_t max_len = *apdu_len;

    *apdu_len = 0;

    while (1) {
        if (usb_hid_read(device, frame, timeout_ms) != 0) {
            return -1;
        }

        /* Verify channel */
        uint16_t channel = ((uint16_t)frame[HID_FRAME_CHANNEL_OFFSET] << 8) |
                           frame[HID_FRAME_CHANNEL_OFFSET + 1];
        if (channel != device->channel) {
            continue;  /* Wrong channel, skip */
        }

        /* Verify tag */
        if (frame[HID_FRAME_TAG_OFFSET] != HID_TAG_APDU) {
            continue;  /* Wrong tag, skip */
        }

        /* Verify sequence */
        uint16_t frame_seq = ((uint16_t)frame[HID_FRAME_SEQUENCE_OFFSET] << 8) |
                             frame[HID_FRAME_SEQUENCE_OFFSET + 1];
        if (frame_seq != seq) {
            return -1;  /* Out of sequence */
        }

        size_t data_offset = HID_FRAME_DATA_OFFSET;
        size_t chunk_size;

        if (seq == 0) {
            /* First frame includes total length */
            expected_len = ((size_t)frame[data_offset] << 8) |
                           frame[data_offset + 1];
            data_offset += 2;

            if (expected_len > max_len) {
                return -1;  /* Response too large */
            }

            chunk_size = HID_PACKET_SIZE - data_offset;
        } else {
            chunk_size = HID_FRAME_DATA_SIZE;
        }

        if (chunk_size > expected_len - offset) {
            chunk_size = expected_len - offset;
        }

        memcpy(apdu_data + offset, frame + data_offset, chunk_size);
        offset += chunk_size;
        seq++;

        if (offset >= expected_len) {
            *apdu_len = expected_len;
            return 0;
        }
    }
}

int usb_hid_apdu_exchange(usb_hid_device_t *device,
                          const apdu_command_t *cmd,
                          apdu_response_t *resp)
{
    if (!device || !cmd || !resp) {
        return -1;
    }

    /* Build raw APDU */
    uint8_t apdu_buf[APDU_HEADER_SIZE + APDU_MAX_DATA_SIZE + 1];
    size_t apdu_len = 0;

    apdu_buf[apdu_len++] = cmd->cla;
    apdu_buf[apdu_len++] = cmd->ins;
    apdu_buf[apdu_len++] = cmd->p1;
    apdu_buf[apdu_len++] = cmd->p2;
    apdu_buf[apdu_len++] = cmd->lc;

    if (cmd->lc > 0) {
        memcpy(apdu_buf + apdu_len, cmd->data, cmd->lc);
        apdu_len += cmd->lc;
    }

    /* Add Le if expected response */
    if (cmd->le > 0) {
        apdu_buf[apdu_len++] = cmd->le;
    }

    /* Frame and send */
    uint8_t frames[16][HID_PACKET_SIZE];
    size_t frame_count = 16;

    if (frame_apdu_request(device, apdu_buf, apdu_len, frames, &frame_count) != 0) {
        return -1;
    }

    for (size_t i = 0; i < frame_count; i++) {
        if (usb_hid_write(device, frames[i]) != 0) {
            return -1;
        }
    }

    /* Receive response */
    uint8_t resp_buf[APDU_MAX_DATA_SIZE + 2];
    size_t resp_len = sizeof(resp_buf);

    if (reassemble_apdu_response(device, resp_buf, &resp_len, 30000) != 0) {
        return -1;
    }

    /* Parse response */
    if (resp_len < 2) {
        return -1;  /* Need at least SW1-SW2 */
    }

    resp->data_len = resp_len - 2;
    if (resp->data_len > 0) {
        memcpy(resp->data, resp_buf, resp->data_len);
    }

    /* Status word is last two bytes */
    resp->sw = ((uint16_t)resp_buf[resp_len - 2] << 8) | resp_buf[resp_len - 1];

    return 0;
}

int usb_hid_get_version(usb_hid_device_t *device, char *version, size_t version_len)
{
    apdu_command_t cmd = {
        .cla = APDU_CLA_COMMON,
        .ins = APDU_INS_GET_VERSION,
        .p1 = 0x00,
        .p2 = 0x00,
        .lc = 0,
        .le = 0
    };

    apdu_response_t resp;

    if (usb_hid_apdu_exchange(device, &cmd, &resp) != 0) {
        return -1;
    }

    if (resp.sw != APDU_SW_OK) {
        return -1;
    }

    /* Format version string from response */
    if (resp.data_len >= 3 && version_len > 0) {
        int written = snprintf(version, version_len, "%u.%u.%u",
                               resp.data[0], resp.data[1], resp.data[2]);
        if (written < 0 || (size_t)written >= version_len) {
            return -1;
        }
    } else if (version_len > 0) {
        version[0] = '\0';
    }

    return 0;
}

int usb_hid_needs_confirmation(uint16_t sw)
{
    /* Check for conditions that indicate user confirmation is pending */
    return (sw == APDU_SW_CONDITIONS_NOT_SAT ||
            sw == APDU_SW_SECURITY_NOT_SAT);
}

const char *usb_hid_error_string(uint16_t sw)
{
    switch (sw) {
        case APDU_SW_OK:
            return error_messages[0];
        case APDU_SW_WRONG_LENGTH:
            return error_messages[1];
        case APDU_SW_SECURITY_NOT_SAT:
            return error_messages[2];
        case APDU_SW_CONDITIONS_NOT_SAT:
            /* APDU_SW_USER_REJECTED has the same value (0x6985) */
            return error_messages[3];
        case APDU_SW_WRONG_DATA:
            return error_messages[4];
        case APDU_SW_INCORRECT_P1P2:
            return error_messages[5];
        case APDU_SW_INS_NOT_SUPPORTED:
            return error_messages[6];
        case APDU_SW_CLA_NOT_SUPPORTED:
            return error_messages[7];
        default:
            return error_messages[8];
    }
}

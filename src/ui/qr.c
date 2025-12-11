/*
 * QR Code Handling
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "qr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qrencode.h>

int qr_encode(const char *data, qr_code_t *qr)
{
    QRcode *qrcode;
    int i;

    if (data == NULL || qr == NULL) {
        return -1;
    }

    /* Use libqrencode to generate QR code */
    qrcode = QRcode_encodeString(data, 0, QR_ECLEVEL_M, QR_MODE_8, 1);
    if (qrcode == NULL) {
        return -1;
    }

    qr->version = qrcode->version;
    qr->width = qrcode->width;
    qr->modules = malloc((size_t)(qr->width * qr->width));
    if (qr->modules == NULL) {
        QRcode_free(qrcode);
        return -1;
    }

    /* Copy module data (1 = black, 0 = white) */
    for (i = 0; i < qr->width * qr->width; i++) {
        qr->modules[i] = (qrcode->data[i] & 1) ? 1 : 0;
    }

    QRcode_free(qrcode);
    return 0;
}

void qr_free(qr_code_t *qr)
{
    if (qr == NULL) {
        return;
    }

    if (qr->modules != NULL) {
        free(qr->modules);
        qr->modules = NULL;
    }

    qr->version = 0;
    qr->width = 0;
}

int qr_get_module(const qr_code_t *qr, int x, int y)
{
    if (qr == NULL || qr->modules == NULL) {
        return 0;
    }

    if (x < 0 || x >= qr->width || y < 0 || y >= qr->width) {
        return 0;
    }

    return qr->modules[y * qr->width + x] ? 1 : 0;
}

int qr_decode(const uint8_t *image_data, int width, int height,
              char *output, size_t output_len)
{
    /* QR decoding requires a camera/image input which is hardware-dependent.
     * For a CLI wallet, QR codes are typically scanned externally and
     * pasted as text. This stub is here for future hardware integration.
     */

    (void)image_data;
    (void)width;
    (void)height;
    (void)output;
    (void)output_len;

    return -1;  /* Not implemented for CLI */
}

int qr_encode_binary(const uint8_t *data, size_t data_len, qr_code_t *qr)
{
    QRcode *qrcode;
    int i;

    if (data == NULL || qr == NULL || data_len == 0) {
        return -1;
    }

    /* Use libqrencode to generate QR code from binary data */
    qrcode = QRcode_encodeData((int)data_len, data, 0, QR_ECLEVEL_M);
    if (qrcode == NULL) {
        return -1;
    }

    qr->version = qrcode->version;
    qr->width = qrcode->width;
    qr->modules = malloc((size_t)(qr->width * qr->width));
    if (qr->modules == NULL) {
        QRcode_free(qrcode);
        return -1;
    }

    /* Copy module data (1 = black, 0 = white) */
    for (i = 0; i < qr->width * qr->width; i++) {
        qr->modules[i] = (qrcode->data[i] & 1) ? 1 : 0;
    }

    QRcode_free(qrcode);
    return 0;
}

void qr_print_terminal(const qr_code_t *qr, int indent)
{
    int x, y;

    if (qr == NULL || qr->modules == NULL) {
        return;
    }

    /* Print with quiet zone (2 modules) */
    for (y = -2; y < qr->width + 2; y++) {
        /* Indent */
        for (int i = 0; i < indent; i++) {
            printf(" ");
        }

        for (x = -2; x < qr->width + 2; x++) {
            int black = 0;
            if (x >= 0 && x < qr->width && y >= 0 && y < qr->width) {
                black = qr->modules[y * qr->width + x];
            }

            /* Use Unicode block characters for better visibility */
            if (black) {
                printf("\u2588\u2588");  /* Full block (black) */
            } else {
                printf("  ");  /* Space (white) */
            }
        }
        printf("\n");
    }
}

void qr_print_terminal_compact(const qr_code_t *qr, int indent)
{
    int x, y;

    if (qr == NULL || qr->modules == NULL) {
        return;
    }

    /* Use Unicode half-block characters to pack 2 rows into 1 line
     * Upper half block: \u2580
     * Lower half block: \u2584
     * Full block: \u2588
     * Space for white-white
     */

    /* Print with quiet zone (2 modules) */
    for (y = -2; y < qr->width + 2; y += 2) {
        /* Indent */
        for (int i = 0; i < indent; i++) {
            printf(" ");
        }

        for (x = -2; x < qr->width + 2; x++) {
            int top = 0, bottom = 0;

            /* Get top pixel */
            if (x >= 0 && x < qr->width && y >= 0 && y < qr->width) {
                top = qr->modules[y * qr->width + x];
            }

            /* Get bottom pixel */
            if (x >= 0 && x < qr->width && (y + 1) >= 0 && (y + 1) < qr->width) {
                bottom = qr->modules[(y + 1) * qr->width + x];
            }

            /* Select appropriate Unicode character
             * We use inverted colors for better visibility on light terminals:
             * White background with black modules
             */
            if (top && bottom) {
                printf("\u2588");  /* Full block */
            } else if (top && !bottom) {
                printf("\u2580");  /* Upper half block */
            } else if (!top && bottom) {
                printf("\u2584");  /* Lower half block */
            } else {
                printf(" ");  /* Space */
            }
        }
        printf("\n");
    }
}

/* ============================================================================
 * QR Scanner Implementation (V4L2 + quirc)
 * ============================================================================ */

#if defined(HAVE_V4L2) && defined(HAVE_QUIRC)

#include <time.h>  /* for struct timespec before videodev2.h */
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <quirc.h>

/* Scanner state */
static int scanner_fd = -1;
static int scanner_initialized = 0;
static int scanner_continuous = 0;
static void (*scanner_callback)(const char *data, size_t len, void *user_data) = NULL;
static void *scanner_user_data = NULL;

/* V4L2 buffers */
#define SCANNER_NUM_BUFFERS 4
static struct {
    void *start;
    size_t length;
} scanner_buffers[SCANNER_NUM_BUFFERS];
static int scanner_num_buffers = 0;

/* Capture dimensions */
static int scanner_width = 0;
static int scanner_height = 0;

/* Preview frame (grayscale) */
static uint8_t *scanner_preview = NULL;
static int preview_width = 0;
static int preview_height = 0;

static struct quirc *quirc_ctx = NULL;
/* Helper to execute V4L2 ioctl with retry on EINTR */
static int xioctl(int fd, unsigned long request, void *arg)
{
    int r;
    do {
        r = ioctl(fd, request, arg);
    } while (r < 0 && errno == EINTR);
    return r;
}

/* Find a camera device */
static int scanner_find_device(char *device, size_t len)
{
    /* Try common video device paths */
    const char *candidates[] = {
        "/dev/video0",
        "/dev/video1",
        "/dev/video2",
        NULL
    };

    for (const char **path = candidates; *path; path++) {
        int fd = open(*path, O_RDWR | O_NONBLOCK);
        if (fd < 0) continue;

        /* Check if it's a video capture device */
        struct v4l2_capability cap;
        if (xioctl(fd, VIDIOC_QUERYCAP, &cap) == 0) {
            if ((cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) &&
                (cap.capabilities & V4L2_CAP_STREAMING)) {
                close(fd);
                strncpy(device, *path, len - 1);
                device[len - 1] = '\0';
                return 0;
            }
        }
        close(fd);
    }

    return -1;
}

/* Convert YUYV to grayscale */
static void yuyv_to_grayscale(const uint8_t *src, uint8_t *dst,
                               int width, int height)
{
    /* YUYV format: Y0 U0 Y1 V0 Y2 U1 Y3 V1 ...
     * We only need the Y (luminance) values */
    for (int i = 0; i < width * height; i++) {
        dst[i] = src[i * 2];  /* Every other byte is Y */
    }
}

/* Initialize V4L2 capture */
static int v4l2_init_capture(int fd, int *width, int *height)
{
    struct v4l2_format fmt = {0};
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

    /* Try to get current format */
    if (xioctl(fd, VIDIOC_G_FMT, &fmt) < 0) {
        return -1;
    }

    /* Request a reasonable resolution for QR scanning */
    fmt.fmt.pix.width = 640;
    fmt.fmt.pix.height = 480;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    fmt.fmt.pix.field = V4L2_FIELD_NONE;

    if (xioctl(fd, VIDIOC_S_FMT, &fmt) < 0) {
        /* Try with whatever format the device supports */
        if (xioctl(fd, VIDIOC_G_FMT, &fmt) < 0) {
            return -1;
        }
    }

    *width = (int)fmt.fmt.pix.width;
    *height = (int)fmt.fmt.pix.height;

    /* Request buffers */
    struct v4l2_requestbuffers req = {0};
    req.count = SCANNER_NUM_BUFFERS;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (xioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
        return -1;
    }

    if (req.count < 2) {
        return -1;  /* Not enough buffers */
    }

    /* Map buffers */
    for (unsigned int i = 0; i < req.count; i++) {
        struct v4l2_buffer buf = {0};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;

        if (xioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) {
            return -1;
        }

        scanner_buffers[i].length = buf.length;
        scanner_buffers[i].start = mmap(NULL, buf.length,
                                         PROT_READ | PROT_WRITE,
                                         MAP_SHARED, fd, buf.m.offset);

        if (scanner_buffers[i].start == MAP_FAILED) {
            return -1;
        }
    }
    scanner_num_buffers = (int)req.count;

    /* Queue all buffers */
    for (int i = 0; i < scanner_num_buffers; i++) {
        struct v4l2_buffer buf = {0};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = (unsigned int)i;

        if (xioctl(fd, VIDIOC_QBUF, &buf) < 0) {
            return -1;
        }
    }

    /* Start streaming */
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(fd, VIDIOC_STREAMON, &type) < 0) {
        return -1;
    }

    return 0;
}

/* Cleanup V4L2 capture */
static void v4l2_cleanup_capture(int fd)
{
    /* Stop streaming */
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    xioctl(fd, VIDIOC_STREAMOFF, &type);

    /* Unmap buffers */
    for (int i = 0; i < scanner_num_buffers; i++) {
        if (scanner_buffers[i].start != MAP_FAILED) {
            munmap(scanner_buffers[i].start, scanner_buffers[i].length);
        }
    }
    scanner_num_buffers = 0;
}

/* Capture a single frame */
static int v4l2_capture_frame(int fd, uint8_t **data, size_t *len)
{
    struct pollfd pfd = {0};
    pfd.fd = fd;
    pfd.events = POLLIN;

    /* Wait for frame (100ms timeout) */
    int ret = poll(&pfd, 1, 100);
    if (ret <= 0) {
        return -1;
    }

    /* Dequeue buffer */
    struct v4l2_buffer buf = {0};
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;

    if (xioctl(fd, VIDIOC_DQBUF, &buf) < 0) {
        return -1;
    }

    *data = scanner_buffers[buf.index].start;
    *len = buf.bytesused;

    /* Re-queue buffer for next capture */
    if (xioctl(fd, VIDIOC_QBUF, &buf) < 0) {
        return -1;
    }

    return 0;
}

qr_scanner_status_t qr_scanner_init(const char *device)
{
    if (scanner_initialized) {
        return QR_SCANNER_BUSY;
    }

    char dev_path[256];
    if (device && device[0] != '\0') {
        strncpy(dev_path, device, sizeof(dev_path) - 1);
        dev_path[sizeof(dev_path) - 1] = '\0';
    } else {
        /* Auto-detect camera */
        if (scanner_find_device(dev_path, sizeof(dev_path)) < 0) {
            return QR_SCANNER_NO_DEVICE;
        }
    }

    /* Open camera device */
    scanner_fd = open(dev_path, O_RDWR | O_NONBLOCK);
    if (scanner_fd < 0) {
        return QR_SCANNER_NO_DEVICE;
    }

    /* Initialize V4L2 capture */
    if (v4l2_init_capture(scanner_fd, &scanner_width, &scanner_height) < 0) {
        close(scanner_fd);
        scanner_fd = -1;
        return QR_SCANNER_ERROR;
    }

    /* Initialize quirc decoder */
    quirc_ctx = quirc_new();
    if (!quirc_ctx) {
        v4l2_cleanup_capture(scanner_fd);
        close(scanner_fd);
        scanner_fd = -1;
        return QR_SCANNER_ERROR;
    }

    if (quirc_resize(quirc_ctx, scanner_width, scanner_height) < 0) {
        quirc_destroy(quirc_ctx);
        quirc_ctx = NULL;
        v4l2_cleanup_capture(scanner_fd);
        close(scanner_fd);
        scanner_fd = -1;
        return QR_SCANNER_ERROR;
    }

    /* Allocate preview buffer */
    scanner_preview = malloc((size_t)(scanner_width * scanner_height));
    if (!scanner_preview) {
        quirc_destroy(quirc_ctx);
        quirc_ctx = NULL;
        v4l2_cleanup_capture(scanner_fd);
        close(scanner_fd);
        scanner_fd = -1;
        return QR_SCANNER_ERROR;
    }
    preview_width = scanner_width;
    preview_height = scanner_height;

    scanner_initialized = 1;
    return QR_SCANNER_OK;
}

void qr_scanner_shutdown(void)
{
    if (!scanner_initialized) return;

    scanner_continuous = 0;
    scanner_callback = NULL;
    scanner_user_data = NULL;

    if (scanner_preview) {
        free(scanner_preview);
        scanner_preview = NULL;
    }
    preview_width = 0;
    preview_height = 0;

    if (quirc_ctx) {
        quirc_destroy(quirc_ctx);
        quirc_ctx = NULL;
    }

    if (scanner_fd >= 0) {
        v4l2_cleanup_capture(scanner_fd);
        close(scanner_fd);
        scanner_fd = -1;
    }

    scanner_initialized = 0;
}

int qr_scanner_available(void)
{
    return scanner_initialized ? 1 : 0;
}

int qr_scanner_scan(char *output, size_t output_len, int timeout_ms)
{
    if (!scanner_initialized || !output || output_len == 0) {
        return -1;
    }

    int elapsed = 0;
    const int frame_time = 100;  /* ~10 fps */

    do {
        uint8_t *frame_data = NULL;
        size_t frame_len = 0;

        /* Capture frame */
        if (v4l2_capture_frame(scanner_fd, &frame_data, &frame_len) < 0) {
            elapsed += frame_time;
            continue;
        }

        /* Convert to grayscale */
        yuyv_to_grayscale(frame_data, scanner_preview,
                          scanner_width, scanner_height);

        /* Copy to quirc buffer */
        uint8_t *qbuf = quirc_begin(quirc_ctx, NULL, NULL);
        memcpy(qbuf, scanner_preview, (size_t)(scanner_width * scanner_height));
        quirc_end(quirc_ctx);

        /* Check for QR codes */
        int count = quirc_count(quirc_ctx);
        for (int i = 0; i < count; i++) {
            struct quirc_code code;
            struct quirc_data data;

            quirc_extract(quirc_ctx, i, &code);
            quirc_decode_error_t err = quirc_decode(&code, &data);

            if (err == QUIRC_SUCCESS) {
                /* Found a valid QR code */
                size_t copy_len = data.payload_len;
                if (copy_len >= output_len) {
                    copy_len = output_len - 1;
                }
                memcpy(output, data.payload, copy_len);
                output[copy_len] = '\0';
                return (int)data.payload_len;
            }
        }

        elapsed += frame_time;

    } while (timeout_ms > 0 && elapsed < timeout_ms);

    return 0;  /* No QR code found */
}

qr_scanner_status_t qr_scanner_start_continuous(
    void (*callback)(const char *data, size_t len, void *user_data),
    void *user_data)
{
    if (!scanner_initialized) {
        return QR_SCANNER_NO_DEVICE;
    }

    if (scanner_continuous) {
        return QR_SCANNER_BUSY;
    }

    scanner_callback = callback;
    scanner_user_data = user_data;
    scanner_continuous = 1;

    return QR_SCANNER_OK;
}

void qr_scanner_stop_continuous(void)
{
    scanner_continuous = 0;
    scanner_callback = NULL;
    scanner_user_data = NULL;
}

const uint8_t *qr_scanner_get_preview(int *width, int *height)
{
    if (!scanner_initialized || !scanner_preview) {
        if (width) *width = 0;
        if (height) *height = 0;
        return NULL;
    }

    if (width) *width = preview_width;
    if (height) *height = preview_height;
    return scanner_preview;
}

#else /* !HAVE_V4L2 || !HAVE_QUIRC */

/* Stub implementations when V4L2/quirc not available */
qr_scanner_status_t qr_scanner_init(const char *device)
{
    (void)device;
    return QR_SCANNER_NO_DEVICE;
}

void qr_scanner_shutdown(void) {}

int qr_scanner_available(void) { return 0; }

int qr_scanner_scan(char *output, size_t output_len, int timeout_ms)
{
    (void)output;
    (void)output_len;
    (void)timeout_ms;
    return -1;
}

qr_scanner_status_t qr_scanner_start_continuous(
    void (*callback)(const char *data, size_t len, void *user_data),
    void *user_data)
{
    (void)callback;
    (void)user_data;
    return QR_SCANNER_NO_DEVICE;
}

void qr_scanner_stop_continuous(void) {}

const uint8_t *qr_scanner_get_preview(int *width, int *height)
{
    if (width) *width = 0;
    if (height) *height = 0;
    return NULL;
}

#endif /* HAVE_V4L2 && HAVE_QUIRC */

int qr_encode_animated(const uint8_t *data, size_t data_len,
                       void (*frame_callback)(const qr_code_t *qr, int frame, int total, void *user_data),
                       void *user_data)
{
    /*
     * Implement basic multi-part QR encoding for large data.
     * This uses a simple format: each frame contains a header with
     * frame number and total frames, followed by a chunk of data.
     *
     * For full UR (Uniform Resources) support, a CBOR library would be needed.
     * This simplified version works for basic use cases.
     */

    /* Maximum data per QR code (Version 10-M can hold ~213 bytes binary) */
    const size_t MAX_CHUNK_SIZE = 200;

    size_t total_frames;
    size_t offset = 0;
    int frame = 0;

    if (data == NULL || data_len == 0 || frame_callback == NULL) {
        return -1;
    }

    /* Calculate number of frames needed */
    total_frames = (data_len + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;

    while (offset < data_len) {
        size_t chunk_size = data_len - offset;
        if (chunk_size > MAX_CHUNK_SIZE) {
            chunk_size = MAX_CHUNK_SIZE;
        }

        /* Build frame with header: "p<frame>of<total>:" + data */
        char header[32];
        snprintf(header, sizeof(header), "p%dof%zu:", frame + 1, total_frames);
        size_t header_len = strlen(header);

        /* Create frame buffer */
        size_t frame_len = header_len + chunk_size;
        uint8_t *frame_data = malloc(frame_len + 1);
        if (frame_data == NULL) {
            return -1;
        }

        memcpy(frame_data, header, header_len);
        memcpy(frame_data + header_len, data + offset, chunk_size);
        frame_data[frame_len] = '\0';

        /* Encode as QR */
        qr_code_t qr;
        if (qr_encode((const char *)frame_data, &qr) == 0) {
            frame_callback(&qr, frame, (int)total_frames, user_data);
            qr_free(&qr);
        }

        free(frame_data);

        offset += chunk_size;
        frame++;
    }

    return 0;
}

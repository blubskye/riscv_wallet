/*
 * Hardware Abstraction Layer (HAL)
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "hal.h"
#include "hwconfig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef HAVE_LIBGPIOD
#include <gpiod.h>
#endif

/* ============================================================================
 * Error Messages
 * ============================================================================ */

static const char *error_messages[] = {
    [0] = "Success",
    [1] = "Not initialized",
    [2] = "Not supported",
    [3] = "Hardware error",
    [4] = "Device busy",
    [5] = "Timeout",
    [6] = "Invalid parameter",
};

/* ============================================================================
 * Terminal Display Backend
 * ============================================================================ */

static int term_display_init(void)
{
    return HAL_OK;
}

static void term_display_shutdown(void)
{
    /* Nothing to do */
}

static int term_display_get_caps(hal_display_caps_t *caps)
{
    if (!caps) return HAL_ERR_INVALID;

    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        caps->width = ws.ws_col;
        caps->height = ws.ws_row;
    } else {
        caps->width = 80;
        caps->height = 24;
    }
    caps->bpp = 0;  /* Text mode */
    caps->supports_color = 1;
    caps->supports_touch = 0;
    caps->supports_backlight = 0;

    return HAL_OK;
}

static int term_display_clear(void)
{
    printf("\033[2J\033[H");
    fflush(stdout);
    return HAL_OK;
}

static int term_display_draw_pixel(int x, int y, uint32_t color)
{
    (void)color;
    printf("\033[%d;%dH*", y + 1, x + 1);
    return HAL_OK;
}

static int term_display_draw_rect(int x, int y, int w, int h, uint32_t color)
{
    (void)color;
    for (int row = 0; row < h; row++) {
        printf("\033[%d;%dH", y + row + 1, x + 1);
        for (int col = 0; col < w; col++) {
            putchar('#');
        }
    }
    return HAL_OK;
}

static int term_display_draw_text(int x, int y, const char *text,
                                   uint32_t fg, uint32_t bg)
{
    (void)fg;
    (void)bg;
    printf("\033[%d;%dH%s", y + 1, x + 1, text);
    return HAL_OK;
}

static int term_display_draw_bitmap(int x, int y, int w, int h,
                                     const uint8_t *data)
{
    (void)x;
    (void)y;
    (void)w;
    (void)h;
    (void)data;
    return HAL_ERR_NOT_SUPPORTED;
}

static int term_display_refresh(void)
{
    fflush(stdout);
    return HAL_OK;
}

static int term_display_set_backlight(uint8_t level)
{
    (void)level;
    return HAL_ERR_NOT_SUPPORTED;
}

static hal_display_ops_t terminal_display_ops = {
    .init = term_display_init,
    .shutdown = term_display_shutdown,
    .get_caps = term_display_get_caps,
    .clear = term_display_clear,
    .draw_pixel = term_display_draw_pixel,
    .draw_rect = term_display_draw_rect,
    .draw_text = term_display_draw_text,
    .draw_bitmap = term_display_draw_bitmap,
    .refresh = term_display_refresh,
    .set_backlight = term_display_set_backlight,
};

/* ============================================================================
 * Framebuffer Display Backend
 * ============================================================================ */

static int fb_fd = -1;
static uint8_t *fb_mem = NULL;
static uint16_t fb_width = 0;
static uint16_t fb_height = 0;
static uint16_t fb_bpp = 0;
static size_t fb_size = 0;

static int fb_display_init(void)
{
    const char *fb_path = g_hwconfig.display.fb_device;
    if (fb_path[0] == '\0') {
        fb_path = "/dev/fb0";
    }

    fb_fd = open(fb_path, O_RDWR);
    if (fb_fd < 0) {
        return HAL_ERR_HARDWARE;
    }

    /* Get framebuffer info via ioctl would go here */
    /* For now, use config values or defaults */
    fb_width = g_hwconfig.display.width > 0 ? g_hwconfig.display.width : 320;
    fb_height = g_hwconfig.display.height > 0 ? g_hwconfig.display.height : 240;
    fb_bpp = 16;
    fb_size = (size_t)fb_width * fb_height * (fb_bpp / 8);

    /* mmap would go here for real implementation */

    return HAL_OK;
}

static void fb_display_shutdown(void)
{
    if (fb_mem) {
        /* munmap would go here */
        fb_mem = NULL;
    }
    if (fb_fd >= 0) {
        close(fb_fd);
        fb_fd = -1;
    }
}

static int fb_display_get_caps(hal_display_caps_t *caps)
{
    if (!caps) return HAL_ERR_INVALID;

    caps->width = fb_width;
    caps->height = fb_height;
    caps->bpp = fb_bpp;
    caps->supports_color = 1;
    caps->supports_touch = 0;
    caps->supports_backlight = 1;

    return HAL_OK;
}

static int fb_display_clear(void)
{
    if (fb_fd < 0) return HAL_ERR_NOT_INIT;

    /* Clear framebuffer memory */
    if (fb_mem) {
        memset(fb_mem, 0, fb_size);
    }

    return HAL_OK;
}

static int fb_display_draw_pixel(int x, int y, uint32_t color)
{
    if (fb_fd < 0 || !fb_mem) return HAL_ERR_NOT_INIT;
    if (x < 0 || x >= fb_width || y < 0 || y >= fb_height) return HAL_OK;

    size_t offset = ((size_t)y * fb_width + (size_t)x) * (fb_bpp / 8);
    if (fb_bpp == 16) {
        uint16_t *pixel = (uint16_t *)(fb_mem + offset);
        /* Convert RGB888 to RGB565 */
        *pixel = (uint16_t)(((color >> 8) & 0xF800) |
                           ((color >> 5) & 0x07E0) |
                           ((color >> 3) & 0x001F));
    }

    return HAL_OK;
}

static int fb_display_draw_rect(int x, int y, int w, int h, uint32_t color)
{
    for (int row = 0; row < h; row++) {
        for (int col = 0; col < w; col++) {
            fb_display_draw_pixel(x + col, y + row, color);
        }
    }
    return HAL_OK;
}

static int fb_display_draw_text(int x, int y, const char *text,
                                 uint32_t fg, uint32_t bg)
{
    /* Simple 8x8 font rendering would go here */
    (void)x;
    (void)y;
    (void)text;
    (void)fg;
    (void)bg;
    return HAL_ERR_NOT_SUPPORTED;  /* Needs font data */
}

static int fb_display_draw_bitmap(int x, int y, int w, int h,
                                   const uint8_t *data)
{
    if (fb_fd < 0 || !fb_mem || !data) return HAL_ERR_NOT_INIT;

    for (int row = 0; row < h; row++) {
        for (int col = 0; col < w; col++) {
            size_t src_offset = ((size_t)row * (size_t)w + (size_t)col) * (fb_bpp / 8);
            uint32_t color = 0;
            if (fb_bpp == 16) {
                color = *(uint16_t *)(data + src_offset);
            }
            fb_display_draw_pixel(x + col, y + row, color);
        }
    }
    return HAL_OK;
}

static int fb_display_refresh(void)
{
    /* Sync/flush framebuffer */
    if (fb_fd >= 0) {
        fsync(fb_fd);
    }
    return HAL_OK;
}

static int fb_display_set_backlight(uint8_t level)
{
    /* Write to sysfs backlight brightness control */
    FILE *f = fopen("/sys/class/backlight/backlight/brightness", "w");
    if (!f) {
        /* Try alternate path */
        f = fopen("/sys/class/backlight/10-0045/brightness", "w");
    }
    if (f) {
        fprintf(f, "%d", (int)level);
        fclose(f);
        return HAL_OK;
    }
    return HAL_ERR_NOT_SUPPORTED;
}

static hal_display_ops_t framebuffer_display_ops = {
    .init = fb_display_init,
    .shutdown = fb_display_shutdown,
    .get_caps = fb_display_get_caps,
    .clear = fb_display_clear,
    .draw_pixel = fb_display_draw_pixel,
    .draw_rect = fb_display_draw_rect,
    .draw_text = fb_display_draw_text,
    .draw_bitmap = fb_display_draw_bitmap,
    .refresh = fb_display_refresh,
    .set_backlight = fb_display_set_backlight,
};

/* ============================================================================
 * DRM/KMS Display Backend (Linux Direct Rendering Manager)
 * ============================================================================ */

#ifdef HAVE_LIBDRM
#include <xf86drm.h>
#include <xf86drmMode.h>
#include <sys/mman.h>
#include <errno.h>

/* DRM state */
static int drm_fd = -1;
static drmModeConnector *drm_connector = NULL;
static drmModeEncoder *drm_encoder = NULL;
static drmModeCrtc *drm_crtc = NULL;
static drmModeCrtc *drm_saved_crtc = NULL;

/* DRM framebuffer */
static uint32_t drm_fb_id = 0;
static uint32_t drm_handle = 0;
static uint8_t *drm_fb_mem = NULL;
static uint32_t drm_fb_stride = 0;
static uint64_t drm_fb_size = 0;
static uint16_t drm_width = 0;
static uint16_t drm_height = 0;
static uint16_t drm_bpp = 32;

/* Find a connected connector */
static drmModeConnector *drm_find_connector(int fd, drmModeRes *res,
                                             uint32_t preferred_id)
{
    for (int i = 0; i < res->count_connectors; i++) {
        drmModeConnector *conn = drmModeGetConnector(fd, res->connectors[i]);
        if (!conn) continue;

        /* If preferred ID specified, use that */
        if (preferred_id != 0 && conn->connector_id == preferred_id) {
            if (conn->connection == DRM_MODE_CONNECTED && conn->count_modes > 0) {
                return conn;
            }
        }

        /* Otherwise find first connected */
        if (preferred_id == 0 && conn->connection == DRM_MODE_CONNECTED &&
            conn->count_modes > 0) {
            return conn;
        }

        drmModeFreeConnector(conn);
    }
    return NULL;
}

/* Find encoder for connector */
static drmModeEncoder *drm_find_encoder(int fd, drmModeConnector *conn)
{
    if (conn->encoder_id) {
        return drmModeGetEncoder(fd, conn->encoder_id);
    }

    /* Try to find a compatible encoder */
    drmModeRes *res = drmModeGetResources(fd);
    if (!res) return NULL;

    for (int i = 0; i < conn->count_encoders; i++) {
        drmModeEncoder *enc = drmModeGetEncoder(fd, conn->encoders[i]);
        if (!enc) continue;

        /* Check if encoder is available */
        for (int j = 0; j < res->count_crtcs; j++) {
            if (enc->possible_crtcs & (1 << j)) {
                drmModeFreeResources(res);
                return enc;
            }
        }
        drmModeFreeEncoder(enc);
    }

    drmModeFreeResources(res);
    return NULL;
}

/* Create a dumb buffer for the framebuffer */
static int drm_create_dumb_buffer(int fd, uint32_t width, uint32_t height,
                                   uint32_t *handle, uint32_t *stride,
                                   uint64_t *size)
{
    struct drm_mode_create_dumb create = {0};
    create.width = width;
    create.height = height;
    create.bpp = 32;

    if (drmIoctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &create) < 0) {
        return -1;
    }

    *handle = create.handle;
    *stride = create.pitch;
    *size = create.size;
    return 0;
}

/* Map the dumb buffer to userspace */
static int drm_map_dumb_buffer(int fd, uint32_t handle, uint64_t size,
                                uint8_t **map)
{
    struct drm_mode_map_dumb map_req = {0};
    map_req.handle = handle;

    if (drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &map_req) < 0) {
        return -1;
    }

    *map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                fd, map_req.offset);
    if (*map == MAP_FAILED) {
        *map = NULL;
        return -1;
    }

    return 0;
}

/* Destroy dumb buffer */
static void drm_destroy_dumb_buffer(int fd, uint32_t handle)
{
    struct drm_mode_destroy_dumb destroy = {0};
    destroy.handle = handle;
    drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &destroy);
}

static int drm_display_init(void)
{
    const char *drm_path = g_hwconfig.display.drm_device;
    if (drm_path[0] == '\0') {
        drm_path = "/dev/dri/card0";
    }

    /* Open DRM device */
    drm_fd = open(drm_path, O_RDWR | O_CLOEXEC);
    if (drm_fd < 0) {
        fprintf(stderr, "[drm] Failed to open %s: %s\n",
                drm_path, strerror(errno));
        return HAL_ERR_HARDWARE;
    }

    /* Get DRM resources */
    drmModeRes *res = drmModeGetResources(drm_fd);
    if (!res) {
        fprintf(stderr, "[drm] Failed to get resources\n");
        close(drm_fd);
        drm_fd = -1;
        return HAL_ERR_HARDWARE;
    }

    /* Find a connected connector */
    drm_connector = drm_find_connector(drm_fd, res,
                                        g_hwconfig.display.drm_connector_id);
    if (!drm_connector) {
        fprintf(stderr, "[drm] No connected display found\n");
        drmModeFreeResources(res);
        close(drm_fd);
        drm_fd = -1;
        return HAL_ERR_HARDWARE;
    }

    /* Use first mode (usually native resolution) or config override */
    drmModeModeInfo *mode = &drm_connector->modes[0];
    drm_width = (g_hwconfig.display.width > 0) ?
                g_hwconfig.display.width : mode->hdisplay;
    drm_height = (g_hwconfig.display.height > 0) ?
                 g_hwconfig.display.height : mode->vdisplay;

    /* Find encoder */
    drm_encoder = drm_find_encoder(drm_fd, drm_connector);
    if (!drm_encoder) {
        fprintf(stderr, "[drm] No encoder found\n");
        drmModeFreeConnector(drm_connector);
        drm_connector = NULL;
        drmModeFreeResources(res);
        close(drm_fd);
        drm_fd = -1;
        return HAL_ERR_HARDWARE;
    }

    /* Get CRTC */
    drm_crtc = drmModeGetCrtc(drm_fd, drm_encoder->crtc_id);

    /* Save current CRTC for restoration */
    drm_saved_crtc = drmModeGetCrtc(drm_fd, drm_encoder->crtc_id);

    drmModeFreeResources(res);

    /* Create dumb buffer */
    if (drm_create_dumb_buffer(drm_fd, drm_width, drm_height,
                               &drm_handle, &drm_fb_stride, &drm_fb_size) < 0) {
        fprintf(stderr, "[drm] Failed to create dumb buffer\n");
        goto cleanup;
    }

    /* Map buffer */
    if (drm_map_dumb_buffer(drm_fd, drm_handle, drm_fb_size, &drm_fb_mem) < 0) {
        fprintf(stderr, "[drm] Failed to map dumb buffer\n");
        drm_destroy_dumb_buffer(drm_fd, drm_handle);
        goto cleanup;
    }

    /* Create framebuffer object */
    if (drmModeAddFB(drm_fd, drm_width, drm_height, 24, 32,
                     drm_fb_stride, drm_handle, &drm_fb_id) < 0) {
        fprintf(stderr, "[drm] Failed to create framebuffer\n");
        munmap(drm_fb_mem, drm_fb_size);
        drm_fb_mem = NULL;
        drm_destroy_dumb_buffer(drm_fd, drm_handle);
        goto cleanup;
    }

    /* Set mode */
    if (drmModeSetCrtc(drm_fd, drm_encoder->crtc_id, drm_fb_id, 0, 0,
                       &drm_connector->connector_id, 1, mode) < 0) {
        fprintf(stderr, "[drm] Failed to set CRTC\n");
        drmModeRmFB(drm_fd, drm_fb_id);
        drm_fb_id = 0;
        munmap(drm_fb_mem, drm_fb_size);
        drm_fb_mem = NULL;
        drm_destroy_dumb_buffer(drm_fd, drm_handle);
        goto cleanup;
    }

    /* Clear the framebuffer to black */
    memset(drm_fb_mem, 0, drm_fb_size);

    fprintf(stderr, "[drm] Initialized %dx%d display\n", drm_width, drm_height);
    return HAL_OK;

cleanup:
    if (drm_crtc) {
        drmModeFreeCrtc(drm_crtc);
        drm_crtc = NULL;
    }
    if (drm_saved_crtc) {
        drmModeFreeCrtc(drm_saved_crtc);
        drm_saved_crtc = NULL;
    }
    if (drm_encoder) {
        drmModeFreeEncoder(drm_encoder);
        drm_encoder = NULL;
    }
    if (drm_connector) {
        drmModeFreeConnector(drm_connector);
        drm_connector = NULL;
    }
    close(drm_fd);
    drm_fd = -1;
    return HAL_ERR_HARDWARE;
}

static void drm_display_shutdown(void)
{
    if (drm_fd < 0) return;

    /* Restore saved CRTC */
    if (drm_saved_crtc) {
        drmModeSetCrtc(drm_fd, drm_saved_crtc->crtc_id,
                       drm_saved_crtc->buffer_id,
                       drm_saved_crtc->x, drm_saved_crtc->y,
                       &drm_connector->connector_id, 1,
                       &drm_saved_crtc->mode);
        drmModeFreeCrtc(drm_saved_crtc);
        drm_saved_crtc = NULL;
    }

    if (drm_fb_id) {
        drmModeRmFB(drm_fd, drm_fb_id);
        drm_fb_id = 0;
    }

    if (drm_fb_mem) {
        munmap(drm_fb_mem, drm_fb_size);
        drm_fb_mem = NULL;
    }

    if (drm_handle) {
        drm_destroy_dumb_buffer(drm_fd, drm_handle);
        drm_handle = 0;
    }

    if (drm_crtc) {
        drmModeFreeCrtc(drm_crtc);
        drm_crtc = NULL;
    }

    if (drm_encoder) {
        drmModeFreeEncoder(drm_encoder);
        drm_encoder = NULL;
    }

    if (drm_connector) {
        drmModeFreeConnector(drm_connector);
        drm_connector = NULL;
    }

    close(drm_fd);
    drm_fd = -1;
}

static int drm_display_get_caps(hal_display_caps_t *caps)
{
    if (!caps) return HAL_ERR_INVALID;

    caps->width = drm_width;
    caps->height = drm_height;
    caps->bpp = drm_bpp;
    caps->supports_color = 1;
    caps->supports_touch = 0;
    caps->supports_backlight = 1;

    return HAL_OK;
}

static int drm_display_clear(void)
{
    if (drm_fd < 0 || !drm_fb_mem) return HAL_ERR_NOT_INIT;
    memset(drm_fb_mem, 0, drm_fb_size);
    return HAL_OK;
}

static int drm_display_draw_pixel(int x, int y, uint32_t color)
{
    if (drm_fd < 0 || !drm_fb_mem) return HAL_ERR_NOT_INIT;
    if (x < 0 || x >= drm_width || y < 0 || y >= drm_height) return HAL_OK;

    /* DRM uses ARGB8888 format (or XRGB8888) */
    uint32_t *pixel = (uint32_t *)(drm_fb_mem + y * drm_fb_stride + x * 4);
    *pixel = color | 0xFF000000;  /* Set alpha to opaque */

    return HAL_OK;
}

static int drm_display_draw_rect(int x, int y, int w, int h, uint32_t color)
{
    if (drm_fd < 0 || !drm_fb_mem) return HAL_ERR_NOT_INIT;

    uint32_t argb = color | 0xFF000000;

    for (int row = 0; row < h; row++) {
        int py = y + row;
        if (py < 0 || py >= drm_height) continue;

        for (int col = 0; col < w; col++) {
            int px = x + col;
            if (px < 0 || px >= drm_width) continue;

            uint32_t *pixel = (uint32_t *)(drm_fb_mem + py * drm_fb_stride + px * 4);
            *pixel = argb;
        }
    }
    return HAL_OK;
}

static int drm_display_draw_text(int x, int y, const char *text,
                                  uint32_t fg, uint32_t bg)
{
    /* Simple text rendering would go here - needs font data */
    (void)x;
    (void)y;
    (void)text;
    (void)fg;
    (void)bg;
    return HAL_ERR_NOT_SUPPORTED;  /* Needs font data */
}

static int drm_display_draw_bitmap(int x, int y, int w, int h,
                                    const uint8_t *data)
{
    if (drm_fd < 0 || !drm_fb_mem || !data) return HAL_ERR_NOT_INIT;

    /* Assume input is RGB888 (3 bytes per pixel) */
    for (int row = 0; row < h; row++) {
        int py = y + row;
        if (py < 0 || py >= drm_height) continue;

        for (int col = 0; col < w; col++) {
            int px = x + col;
            if (px < 0 || px >= drm_width) continue;

            /* Source pixel (RGB888) */
            size_t src_off = (row * w + col) * 3;
            uint32_t r = data[src_off + 0];
            uint32_t g = data[src_off + 1];
            uint32_t b = data[src_off + 2];
            uint32_t argb = 0xFF000000 | (r << 16) | (g << 8) | b;

            /* Destination pixel */
            uint32_t *pixel = (uint32_t *)(drm_fb_mem + py * drm_fb_stride + px * 4);
            *pixel = argb;
        }
    }
    return HAL_OK;
}

static int drm_display_refresh(void)
{
    if (drm_fd < 0) return HAL_ERR_NOT_INIT;

    /* For simple dumb buffers, just do a page flip or nothing
     * The changes are visible immediately since we wrote to mapped memory */

    /* Optional: request page flip for vsync */
    /* drmModePageFlip(drm_fd, drm_encoder->crtc_id, drm_fb_id,
                       DRM_MODE_PAGE_FLIP_EVENT, NULL); */

    return HAL_OK;
}

static int drm_display_set_backlight(uint8_t level)
{
    /* Try standard backlight paths */
    const char *paths[] = {
        "/sys/class/backlight/backlight/brightness",
        "/sys/class/backlight/10-0045/brightness",
        "/sys/class/backlight/rpi_backlight/brightness",
        NULL
    };

    for (const char **path = paths; *path; path++) {
        FILE *f = fopen(*path, "w");
        if (f) {
            fprintf(f, "%d", (int)level);
            fclose(f);
            return HAL_OK;
        }
    }

    return HAL_ERR_NOT_SUPPORTED;
}

static hal_display_ops_t drm_display_ops = {
    .init = drm_display_init,
    .shutdown = drm_display_shutdown,
    .get_caps = drm_display_get_caps,
    .clear = drm_display_clear,
    .draw_pixel = drm_display_draw_pixel,
    .draw_rect = drm_display_draw_rect,
    .draw_text = drm_display_draw_text,
    .draw_bitmap = drm_display_draw_bitmap,
    .refresh = drm_display_refresh,
    .set_backlight = drm_display_set_backlight,
};
#endif /* HAVE_LIBDRM */

/* ============================================================================
 * Terminal Input Backend
 * ============================================================================ */

static struct termios orig_termios;
static int term_input_initialized = 0;

static int term_input_init(void)
{
    if (term_input_initialized) return HAL_OK;

    /* Save original terminal settings */
    if (tcgetattr(STDIN_FILENO, &orig_termios) < 0) {
        return HAL_ERR_HARDWARE;
    }

    /* Set raw mode for non-blocking input */
    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0) {
        return HAL_ERR_HARDWARE;
    }

    term_input_initialized = 1;
    return HAL_OK;
}

static void term_input_shutdown(void)
{
    if (term_input_initialized) {
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
        term_input_initialized = 0;
    }
}

static int term_input_poll(hal_input_event_t *event, int timeout_ms)
{
    if (!event) return HAL_ERR_INVALID;

    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(STDIN_FILENO + 1, &fds, NULL, NULL,
                     timeout_ms >= 0 ? &tv : NULL);

    if (ret > 0 && FD_ISSET(STDIN_FILENO, &fds)) {
        char c;
        if (read(STDIN_FILENO, &c, 1) == 1) {
            event->type = HAL_INPUT_KEY_PRESS;
            event->timestamp = (uint32_t)time(NULL);
            event->key.code = c;

            /* Map common keys to actions */
            switch (c) {
                case 'w': case 'W': case 'k': case 'K':
                    event->key.action = HWBTN_UP;
                    break;
                case 's': case 'S': case 'j': case 'J':
                    event->key.action = HWBTN_DOWN;
                    break;
                case 'a': case 'A': case 'h': case 'H':
                    event->key.action = HWBTN_LEFT;
                    break;
                case 'd': case 'D': case 'l': case 'L':
                    event->key.action = HWBTN_RIGHT;
                    break;
                case '\n': case '\r': case ' ':
                    event->key.action = HWBTN_ENTER;
                    break;
                case 'q': case 'Q': case 27:  /* ESC */
                    event->key.action = HWBTN_BACK;
                    break;
                case 'm': case 'M':
                    event->key.action = HWBTN_MENU;
                    break;
                default:
                    event->key.action = HWBTN_NONE;
                    break;
            }

            return HAL_OK;
        }
    }

    event->type = HAL_INPUT_NONE;
    return HAL_ERR_TIMEOUT;
}

static int term_input_has_pending(void)
{
    fd_set fds;
    struct timeval tv = {0, 0};

    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);

    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
}

static int term_input_get_button_state(int button)
{
    (void)button;
    return 0;  /* Can't get state in terminal mode */
}

static int term_input_wait_any_button(int timeout_ms)
{
    hal_input_event_t event;
    return term_input_poll(&event, timeout_ms) == HAL_OK ? event.key.action : -1;
}

static hal_input_ops_t terminal_input_ops = {
    .init = term_input_init,
    .shutdown = term_input_shutdown,
    .poll = term_input_poll,
    .has_pending = term_input_has_pending,
    .get_button_state = term_input_get_button_state,
    .wait_any_button = term_input_wait_any_button,
};

/* ============================================================================
 * GPIO Input Backend (libgpiod)
 * ============================================================================ */

#ifdef HAVE_LIBGPIOD
static struct gpiod_chip *gpio_chip = NULL;
static struct gpiod_line_request *gpio_lines[MAX_BUTTONS] = {NULL};
static int gpio_pins[MAX_BUTTONS] = {0};
static int gpio_num_buttons = 0;

static int gpio_input_init(void)
{
    const char *chip_path = g_hwconfig.input.device;
    if (chip_path[0] == '\0') {
        chip_path = "/dev/gpiochip0";
    }

    gpio_chip = gpiod_chip_open(chip_path);
    if (!gpio_chip) {
        return HAL_ERR_HARDWARE;
    }

    gpio_num_buttons = g_hwconfig.input.num_buttons;
    if (gpio_num_buttons > MAX_BUTTONS) {
        gpio_num_buttons = MAX_BUTTONS;
    }

    for (int i = 0; i < gpio_num_buttons; i++) {
        gpio_pins[i] = g_hwconfig.input.buttons[i].code;

        struct gpiod_line_settings *settings = gpiod_line_settings_new();
        if (!settings) continue;

        gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_INPUT);
        if (g_hwconfig.input.buttons[i].active_low) {
            gpiod_line_settings_set_active_low(settings, true);
        }

        struct gpiod_line_config *line_cfg = gpiod_line_config_new();
        if (line_cfg) {
            unsigned int offset = (unsigned int)gpio_pins[i];
            gpiod_line_config_add_line_settings(line_cfg, &offset, 1, settings);

            struct gpiod_request_config *req_cfg = gpiod_request_config_new();
            if (req_cfg) {
                gpiod_request_config_set_consumer(req_cfg, "wallet_input");
                gpio_lines[i] = gpiod_chip_request_lines(gpio_chip, req_cfg, line_cfg);
                gpiod_request_config_free(req_cfg);
            }
            gpiod_line_config_free(line_cfg);
        }
        gpiod_line_settings_free(settings);
    }

    return HAL_OK;
}

static void gpio_input_shutdown(void)
{
    for (int i = 0; i < MAX_BUTTONS; i++) {
        if (gpio_lines[i]) {
            gpiod_line_request_release(gpio_lines[i]);
            gpio_lines[i] = NULL;
        }
    }
    if (gpio_chip) {
        gpiod_chip_close(gpio_chip);
        gpio_chip = NULL;
    }
}

static int gpio_input_poll(hal_input_event_t *event, int timeout_ms)
{
    if (!event) return HAL_ERR_INVALID;

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (1) {
        for (int i = 0; i < gpio_num_buttons; i++) {
            if (!gpio_lines[i]) continue;

            enum gpiod_line_value val = gpiod_line_request_get_value(
                gpio_lines[i], (unsigned int)gpio_pins[i]);

            if (val == GPIOD_LINE_VALUE_ACTIVE) {
                event->type = HAL_INPUT_KEY_PRESS;
                event->timestamp = (uint32_t)time(NULL);
                event->key.code = gpio_pins[i];
                event->key.action = g_hwconfig.input.buttons[i].action;
                return HAL_OK;
            }
        }

        if (timeout_ms == 0) break;

        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
                         (now.tv_nsec - start.tv_nsec) / 1000000;
        if (timeout_ms > 0 && elapsed_ms >= timeout_ms) break;

        usleep(10000);  /* 10ms poll interval */
    }

    event->type = HAL_INPUT_NONE;
    return HAL_ERR_TIMEOUT;
}

static int gpio_input_has_pending(void)
{
    for (int i = 0; i < gpio_num_buttons; i++) {
        if (!gpio_lines[i]) continue;

        enum gpiod_line_value val = gpiod_line_request_get_value(
            gpio_lines[i], (unsigned int)gpio_pins[i]);

        if (val == GPIOD_LINE_VALUE_ACTIVE) {
            return 1;
        }
    }
    return 0;
}

static int gpio_input_get_button_state(int button)
{
    for (int i = 0; i < gpio_num_buttons; i++) {
        if ((int)g_hwconfig.input.buttons[i].action == button && gpio_lines[i]) {
            enum gpiod_line_value val = gpiod_line_request_get_value(
                gpio_lines[i], (unsigned int)gpio_pins[i]);
            return (val == GPIOD_LINE_VALUE_ACTIVE) ? 1 : 0;
        }
    }
    return 0;
}

static int gpio_input_wait_any_button(int timeout_ms)
{
    hal_input_event_t event;
    if (gpio_input_poll(&event, timeout_ms) == HAL_OK) {
        return event.key.action;
    }
    return -1;
}

static hal_input_ops_t gpio_input_ops = {
    .init = gpio_input_init,
    .shutdown = gpio_input_shutdown,
    .poll = gpio_input_poll,
    .has_pending = gpio_input_has_pending,
    .get_button_state = gpio_input_get_button_state,
    .wait_any_button = gpio_input_wait_any_button,
};
#endif /* HAVE_LIBGPIOD */

/* ============================================================================
 * evdev Input Backend (Linux input subsystem)
 * ============================================================================ */

#ifdef __linux__
#include <linux/input.h>
#include <dirent.h>
#include <errno.h>

static int evdev_fd = -1;
static int evdev_initialized = 0;

/* Map Linux keycodes to wallet actions */
static int evdev_keycode_to_action(int keycode)
{
    switch (keycode) {
        case KEY_UP:
        case KEY_W:
        case KEY_K:
            return HWBTN_UP;
        case KEY_DOWN:
        case KEY_S:
        case KEY_J:
            return HWBTN_DOWN;
        case KEY_LEFT:
        case KEY_A:
        case KEY_H:
            return HWBTN_LEFT;
        case KEY_RIGHT:
        case KEY_D:
        case KEY_L:
            return HWBTN_RIGHT;
        case KEY_ENTER:
        case KEY_SPACE:
        case KEY_KPENTER:
            return HWBTN_ENTER;
        case KEY_ESC:
        case KEY_BACKSPACE:
        case KEY_Q:
            return HWBTN_BACK;
        case KEY_M:
        case KEY_F1:
            return HWBTN_MENU;
        case KEY_POWER:
            return HWBTN_POWER;
        /* Additional keys for hardware buttons */
        case BTN_0:
        case BTN_TRIGGER:
            return HWBTN_ENTER;
        case BTN_1:
        case BTN_THUMB:
            return HWBTN_BACK;
        default:
            return HWBTN_NONE;
    }
}

/* Find an input device that supports keys */
static int evdev_find_device(char *path, size_t path_len)
{
    DIR *dir = opendir("/dev/input");
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "event", 5) != 0) continue;

        snprintf(path, path_len, "/dev/input/%s", entry->d_name);

        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;

        /* Check if device supports EV_KEY events */
        unsigned long evbits = 0;
        if (ioctl(fd, EVIOCGBIT(0, sizeof(evbits)), &evbits) >= 0) {
            if (evbits & (1 << EV_KEY)) {
                close(fd);
                closedir(dir);
                return 0;  /* Found suitable device */
            }
        }
        close(fd);
    }

    closedir(dir);
    return -1;  /* No suitable device found */
}

static int evdev_input_init(void)
{
    if (evdev_initialized) return HAL_OK;

    char device_path[280];  /* /dev/input/ (11) + d_name (255) + null */

    /* Use configured device or auto-detect */
    if (g_hwconfig.input.device[0] != '\0') {
        strncpy(device_path, g_hwconfig.input.device, sizeof(device_path) - 1);
        device_path[sizeof(device_path) - 1] = '\0';
    } else {
        /* Try to auto-detect a suitable input device */
        if (evdev_find_device(device_path, sizeof(device_path)) < 0) {
            /* Fallback to default */
            strncpy(device_path, "/dev/input/event0", sizeof(device_path));
        }
    }

    evdev_fd = open(device_path, O_RDONLY | O_NONBLOCK);
    if (evdev_fd < 0) {
        fprintf(stderr, "[evdev] Failed to open %s: %s\n",
                device_path, strerror(errno));
        return HAL_ERR_HARDWARE;
    }

    /* Optionally grab exclusive access */
    /* ioctl(evdev_fd, EVIOCGRAB, 1); */

    evdev_initialized = 1;
    return HAL_OK;
}

static void evdev_input_shutdown(void)
{
    if (evdev_fd >= 0) {
        /* Release exclusive access if grabbed */
        /* ioctl(evdev_fd, EVIOCGRAB, 0); */
        close(evdev_fd);
        evdev_fd = -1;
    }
    evdev_initialized = 0;
}

static int evdev_input_poll(hal_input_event_t *event, int timeout_ms)
{
    if (!event) return HAL_ERR_INVALID;
    if (evdev_fd < 0) return HAL_ERR_NOT_INIT;

    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(evdev_fd, &fds);

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(evdev_fd + 1, &fds, NULL, NULL,
                     timeout_ms >= 0 ? &tv : NULL);

    if (ret > 0 && FD_ISSET(evdev_fd, &fds)) {
        struct input_event ev;
        ssize_t n = read(evdev_fd, &ev, sizeof(ev));

        if (n == sizeof(ev)) {
            if (ev.type == EV_KEY && ev.value == 1) {  /* Key press */
                event->type = HAL_INPUT_KEY_PRESS;
                event->timestamp = (uint32_t)(ev.time.tv_sec & 0xFFFFFFFF);
                event->key.code = ev.code;
                event->key.action = evdev_keycode_to_action(ev.code);
                return HAL_OK;
            } else if (ev.type == EV_KEY && ev.value == 0) {  /* Key release */
                event->type = HAL_INPUT_KEY_RELEASE;
                event->timestamp = (uint32_t)(ev.time.tv_sec & 0xFFFFFFFF);
                event->key.code = ev.code;
                event->key.action = evdev_keycode_to_action(ev.code);
                return HAL_OK;
            } else if (ev.type == EV_ABS) {  /* Touch/absolute input */
                /* Handle touchscreen events */
                if (ev.code == ABS_X || ev.code == ABS_MT_POSITION_X) {
                    event->type = HAL_INPUT_TOUCH_MOVE;
                    event->touch.x = ev.value;
                } else if (ev.code == ABS_Y || ev.code == ABS_MT_POSITION_Y) {
                    event->type = HAL_INPUT_TOUCH_MOVE;
                    event->touch.y = ev.value;
                }
                /* BTN_TOUCH events indicate touch down/up */
            } else if (ev.type == EV_KEY && ev.code == BTN_TOUCH) {
                event->type = ev.value ? HAL_INPUT_TOUCH_DOWN : HAL_INPUT_TOUCH_UP;
                event->timestamp = (uint32_t)(ev.time.tv_sec & 0xFFFFFFFF);
                return HAL_OK;
            }
        }
    }

    event->type = HAL_INPUT_NONE;
    return HAL_ERR_TIMEOUT;
}

static int evdev_input_has_pending(void)
{
    if (evdev_fd < 0) return 0;

    fd_set fds;
    struct timeval tv = {0, 0};

    FD_ZERO(&fds);
    FD_SET(evdev_fd, &fds);

    return select(evdev_fd + 1, &fds, NULL, NULL, &tv) > 0;
}

static int evdev_input_get_button_state(int button)
{
    if (evdev_fd < 0) return 0;

    /* Map action back to a key code (reverse of evdev_keycode_to_action) */
    int keycode = KEY_RESERVED;
    switch (button) {
        case HWBTN_UP:    keycode = KEY_UP; break;
        case HWBTN_DOWN:  keycode = KEY_DOWN; break;
        case HWBTN_LEFT:  keycode = KEY_LEFT; break;
        case HWBTN_RIGHT: keycode = KEY_RIGHT; break;
        case HWBTN_ENTER: keycode = KEY_ENTER; break;
        case HWBTN_BACK:  keycode = KEY_ESC; break;
        case HWBTN_MENU:  keycode = KEY_M; break;
        default: return 0;
    }

    /* Query key state */
    unsigned long key_bits[(KEY_MAX + 7) / 8 / sizeof(unsigned long) + 1] = {0};
    if (ioctl(evdev_fd, EVIOCGKEY(sizeof(key_bits)), key_bits) >= 0) {
        return (key_bits[keycode / (sizeof(unsigned long) * 8)] >>
                (keycode % (sizeof(unsigned long) * 8))) & 1;
    }

    return 0;
}

static int evdev_input_wait_any_button(int timeout_ms)
{
    hal_input_event_t event;
    if (evdev_input_poll(&event, timeout_ms) == HAL_OK) {
        return event.key.action;
    }
    return -1;
}

static hal_input_ops_t evdev_input_ops = {
    .init = evdev_input_init,
    .shutdown = evdev_input_shutdown,
    .poll = evdev_input_poll,
    .has_pending = evdev_input_has_pending,
    .get_button_state = evdev_input_get_button_state,
    .wait_any_button = evdev_input_wait_any_button,
};
#endif /* __linux__ */

/* ============================================================================
 * Simulated Sensor Backend
 * ============================================================================ */

static int sim_sensor_init(void) { return HAL_OK; }
static void sim_sensor_shutdown(void) { }

static int sim_sensor_is_available(hal_sensor_type_t type)
{
    (void)type;
    return 1;  /* All simulated sensors "available" */
}

static int sim_sensor_read_accel(hal_accel_data_t *data)
{
    if (!data) return HAL_ERR_INVALID;
    data->x = 0;
    data->y = 0;
    data->z = 1000;  /* 1g down */
    return HAL_OK;
}

static int sim_sensor_read_light(uint16_t *lux)
{
    if (!lux) return HAL_ERR_INVALID;
    *lux = 0;  /* Dark (case closed) */
    return HAL_OK;
}

static int sim_sensor_read_temperature(int16_t *temp)
{
    if (!temp) return HAL_ERR_INVALID;
    *temp = 250;  /* 25.0°C */
    return HAL_OK;
}

static int sim_sensor_read_tamper(int *triggered)
{
    if (!triggered) return HAL_ERR_INVALID;
    *triggered = 0;  /* Not tampered */
    return HAL_OK;
}

static hal_sensor_ops_t simulated_sensor_ops = {
    .init = sim_sensor_init,
    .shutdown = sim_sensor_shutdown,
    .is_available = sim_sensor_is_available,
    .read_accel = sim_sensor_read_accel,
    .read_light = sim_sensor_read_light,
    .read_temperature = sim_sensor_read_temperature,
    .read_tamper = sim_sensor_read_tamper,
};

/* ============================================================================
 * Software RNG Backend
 * ============================================================================ */

static int hw_rng_fd = -1;

static int sw_rng_init(void)
{
    /* Try to open hardware RNG if configured */
    if (g_hwconfig.has_hardware_rng && g_hwconfig.rng_device[0] != '\0') {
        hw_rng_fd = open(g_hwconfig.rng_device, O_RDONLY);
    }
    if (hw_rng_fd < 0) {
        hw_rng_fd = open("/dev/hwrng", O_RDONLY);
    }

    return HAL_OK;
}

static void sw_rng_shutdown(void)
{
    if (hw_rng_fd >= 0) {
        close(hw_rng_fd);
        hw_rng_fd = -1;
    }
}

static int sw_rng_has_hardware(void)
{
    return hw_rng_fd >= 0;
}

static int sw_rng_get_random(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) return HAL_ERR_INVALID;

    /* Try hardware RNG first */
    if (hw_rng_fd >= 0) {
        ssize_t n = read(hw_rng_fd, buf, len);
        if (n == (ssize_t)len) {
            return HAL_OK;
        }
    }

    /* Fall back to /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return HAL_ERR_HARDWARE;
    }

    ssize_t n = read(fd, buf, len);
    close(fd);

    return (n == (ssize_t)len) ? HAL_OK : HAL_ERR_HARDWARE;
}

static int sw_rng_get_entropy(uint8_t *buf, size_t len)
{
    /* Mix hardware and software entropy */
    uint8_t hw_buf[64];
    uint8_t sw_buf[64];

    int ret = sw_rng_get_random(sw_buf, sizeof(sw_buf));
    if (ret != HAL_OK) return ret;

    if (hw_rng_fd >= 0) {
        if (read(hw_rng_fd, hw_buf, sizeof(hw_buf)) > 0) {
            /* XOR mix */
            for (size_t i = 0; i < sizeof(sw_buf); i++) {
                sw_buf[i] ^= hw_buf[i];
            }
        }
    }

    /* Fill output buffer */
    for (size_t i = 0; i < len; i++) {
        buf[i] = sw_buf[i % sizeof(sw_buf)];
    }

    return HAL_OK;
}

static hal_rng_ops_t software_rng_ops = {
    .init = sw_rng_init,
    .shutdown = sw_rng_shutdown,
    .has_hardware_rng = sw_rng_has_hardware,
    .get_random = sw_rng_get_random,
    .get_entropy = sw_rng_get_entropy,
};

/* ============================================================================
 * File-based Secure Storage Backend
 * ============================================================================ */

#define STORAGE_SLOT_COUNT      16
#define STORAGE_SLOT_SIZE       256
#define STORAGE_BASE_PATH       "/var/lib/riscv-wallet"
#define DEVICE_ID_PATH          STORAGE_BASE_PATH "/device_id"

static int storage_initialized = 0;
static uint8_t cached_device_id[16] = {0};
static int device_id_loaded = 0;

static int file_storage_init(void)
{
    if (storage_initialized) {
        return HAL_OK;
    }

    /* Ensure storage directory exists */
    if (access(STORAGE_BASE_PATH, F_OK) != 0) {
        /* Try to create directory - may fail without root, that's okay */
        (void)mkdir(STORAGE_BASE_PATH, 0700);
    }

    storage_initialized = 1;
    return HAL_OK;
}

static void file_storage_shutdown(void)
{
    storage_initialized = 0;
    device_id_loaded = 0;
}

static int file_storage_has_secure_element(void)
{
    /*
     * Check for hardware secure element presence.
     * On Linux, look for common secure element interfaces:
     * - /dev/tpm0 or /dev/tpmrm0 (TPM 2.0)
     * - /dev/optiga_trust* (Infineon OPTIGA)
     * - /dev/atecc* (Microchip ATECC608)
     */
    if (access("/dev/tpm0", F_OK) == 0 ||
        access("/dev/tpmrm0", F_OK) == 0) {
        return 1;  /* TPM present */
    }

    /* No hardware secure element detected */
    return 0;
}

static int file_storage_read(uint8_t slot, uint8_t *data, size_t *len)
{
    if (!storage_initialized) return HAL_ERR_NOT_INIT;
    if (slot >= STORAGE_SLOT_COUNT || !data || !len) return HAL_ERR_INVALID;

    char path[256];
    snprintf(path, sizeof(path), STORAGE_BASE_PATH "/slot_%02u.dat", slot);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        *len = 0;
        return HAL_ERR_HARDWARE;  /* Slot empty or error */
    }

    ssize_t n = read(fd, data, *len);
    close(fd);

    if (n < 0) {
        *len = 0;
        return HAL_ERR_HARDWARE;
    }

    *len = (size_t)n;
    return HAL_OK;
}

static int file_storage_write(uint8_t slot, const uint8_t *data, size_t len)
{
    if (!storage_initialized) return HAL_ERR_NOT_INIT;
    if (slot >= STORAGE_SLOT_COUNT || !data) return HAL_ERR_INVALID;
    if (len > STORAGE_SLOT_SIZE) return HAL_ERR_INVALID;

    char path[256];
    snprintf(path, sizeof(path), STORAGE_BASE_PATH "/slot_%02u.dat", slot);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return HAL_ERR_HARDWARE;
    }

    ssize_t n = write(fd, data, len);
    if (fsync(fd) != 0) {
        close(fd);
        return HAL_ERR_HARDWARE;
    }
    close(fd);

    return (n == (ssize_t)len) ? HAL_OK : HAL_ERR_HARDWARE;
}

static int file_storage_erase(uint8_t slot)
{
    if (!storage_initialized) return HAL_ERR_NOT_INIT;
    if (slot >= STORAGE_SLOT_COUNT) return HAL_ERR_INVALID;

    char path[256];
    snprintf(path, sizeof(path), STORAGE_BASE_PATH "/slot_%02u.dat", slot);

    /* Overwrite with zeros before unlinking for secure erasure */
    int fd = open(path, O_WRONLY);
    if (fd >= 0) {
        uint8_t zeros[STORAGE_SLOT_SIZE] = {0};
        ssize_t written = write(fd, zeros, sizeof(zeros));
        (void)written;  /* Best effort secure erase */
        fsync(fd);
        close(fd);
    }

    if (unlink(path) != 0 && errno != ENOENT) {
        return HAL_ERR_HARDWARE;
    }

    return HAL_OK;
}

/**
 * Generate or retrieve a unique device ID
 *
 * Priority:
 * 1. Cached device ID (if already loaded)
 * 2. Existing device ID file
 * 3. Hardware-derived ID (machine-id, CPU serial, MAC address)
 * 4. Randomly generated ID (persisted for consistency)
 */
static int file_storage_get_device_id(uint8_t id[16])
{
    if (!id) return HAL_ERR_INVALID;

    /* Return cached ID if available */
    if (device_id_loaded) {
        memcpy(id, cached_device_id, 16);
        return HAL_OK;
    }

    /* Try to load existing device ID */
    int fd = open(DEVICE_ID_PATH, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, cached_device_id, 16);
        close(fd);
        if (n == 16) {
            device_id_loaded = 1;
            memcpy(id, cached_device_id, 16);
            return HAL_OK;
        }
    }

    /*
     * Generate new device ID from hardware identifiers.
     * We combine multiple sources for uniqueness and persistence.
     */
    uint8_t seed[64] = {0};
    size_t seed_len = 0;

    /* Source 1: /etc/machine-id (systemd persistent ID) */
    fd = open("/etc/machine-id", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, seed + seed_len, 32);
        close(fd);
        if (n > 0) seed_len += (size_t)n;
    }

    /* Source 2: /sys/class/dmi/id/product_serial (if accessible) */
    fd = open("/sys/class/dmi/id/product_serial", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, seed + seed_len, 16);
        close(fd);
        if (n > 0) seed_len += (size_t)n;
    }

    /* Source 3: CPU serial from /proc/cpuinfo (ARM/RISC-V) */
    FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo) {
        char line[256];
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strncmp(line, "Serial", 6) == 0) {
                char *colon = strchr(line, ':');
                if (colon && seed_len < 48) {
                    size_t to_copy = strlen(colon + 1);
                    if (to_copy > 16) to_copy = 16;
                    memcpy(seed + seed_len, colon + 1, to_copy);
                    seed_len += to_copy;
                }
                break;
            }
        }
        fclose(cpuinfo);
    }

    /* Source 4: Add some random entropy for uniqueness */
    if (seed_len < 48) {
        int rng_fd = open("/dev/urandom", O_RDONLY);
        if (rng_fd >= 0) {
            ssize_t n = read(rng_fd, seed + seed_len, 16);
            close(rng_fd);
            if (n > 0) seed_len += (size_t)n;
        }
    }

    /*
     * Hash the seed material to produce the device ID.
     * Using simple hash mixing - for production would use proper KDF.
     */
    uint32_t hash = 0x811c9dc5;  /* FNV-1a offset basis */
    for (size_t i = 0; i < seed_len; i++) {
        hash ^= seed[i];
        hash *= 0x01000193;  /* FNV-1a prime */
    }

    /* Fill device ID with hash-based mixing */
    for (int i = 0; i < 16; i++) {
        hash ^= seed[i % seed_len];
        hash *= 0x01000193;
        cached_device_id[i] = (uint8_t)(hash >> ((i % 4) * 8));
    }

    /* Version and variant bits (UUID v4-like format) */
    cached_device_id[6] = (cached_device_id[6] & 0x0F) | 0x40;  /* Version 4 */
    cached_device_id[8] = (cached_device_id[8] & 0x3F) | 0x80;  /* Variant 1 */

    /* Persist the generated device ID */
    fd = open(DEVICE_ID_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        ssize_t written = write(fd, cached_device_id, 16);
        (void)written;  /* Best effort persistence */
        fsync(fd);
        close(fd);
    }

    device_id_loaded = 1;
    memcpy(id, cached_device_id, 16);
    return HAL_OK;
}

static hal_storage_ops_t file_storage_ops = {
    .init = file_storage_init,
    .shutdown = file_storage_shutdown,
    .has_secure_element = file_storage_has_secure_element,
    .read = file_storage_read,
    .write = file_storage_write,
    .erase = file_storage_erase,
    .get_device_id = file_storage_get_device_id,
};

/* ============================================================================
 * HAL State and Current Backend
 * ============================================================================ */

static int hal_initialized = 0;
static hal_backend_t current_backend = {
    .name = "default",
    .display = &terminal_display_ops,
    .input = &terminal_input_ops,
    .sensor = &simulated_sensor_ops,
    .storage = &file_storage_ops,
    .rng = &software_rng_ops,
};

/* ============================================================================
 * HAL Core Functions
 * ============================================================================ */

int hal_init(const hwconfig_t *config)
{
    if (hal_initialized) {
        return HAL_OK;
    }

    /* Use provided config or global */
    const hwconfig_t *cfg = config ? config : &g_hwconfig;

    /* Select display backend based on config */
    switch (cfg->display.mode) {
        case DISPLAY_MODE_FRAMEBUFFER:
            current_backend.display = &framebuffer_display_ops;
            current_backend.name = "framebuffer";
            break;
#ifdef HAVE_LIBDRM
        case DISPLAY_MODE_DRM:
            current_backend.display = &drm_display_ops;
            current_backend.name = "drm";
            break;
#endif
        case DISPLAY_MODE_TERMINAL:
        default:
            current_backend.display = &terminal_display_ops;
            current_backend.name = "terminal";
            break;
    }

    /* Select input backend based on config */
    switch (cfg->input.mode) {
#ifdef HAVE_LIBGPIOD
        case INPUT_MODE_GPIOD:
            current_backend.input = &gpio_input_ops;
            break;
#endif
#ifdef __linux__
        case INPUT_MODE_EVDEV:
            current_backend.input = &evdev_input_ops;
            break;
#endif
        case INPUT_MODE_TERMINAL:
        default:
            current_backend.input = &terminal_input_ops;
            break;
    }

    /* Initialize all backends */
    if (current_backend.display && current_backend.display->init) {
        current_backend.display->init();
    }
    if (current_backend.input && current_backend.input->init) {
        current_backend.input->init();
    }
    if (current_backend.sensor && current_backend.sensor->init) {
        current_backend.sensor->init();
    }
    if (current_backend.rng && current_backend.rng->init) {
        current_backend.rng->init();
    }

    hal_initialized = 1;
    return HAL_OK;
}

void hal_shutdown(void)
{
    if (!hal_initialized) return;

    if (current_backend.rng && current_backend.rng->shutdown) {
        current_backend.rng->shutdown();
    }
    if (current_backend.sensor && current_backend.sensor->shutdown) {
        current_backend.sensor->shutdown();
    }
    if (current_backend.input && current_backend.input->shutdown) {
        current_backend.input->shutdown();
    }
    if (current_backend.display && current_backend.display->shutdown) {
        current_backend.display->shutdown();
    }

    hal_initialized = 0;
}

int hal_is_initialized(void)
{
    return hal_initialized;
}

const hal_backend_t *hal_get_backend(void)
{
    return &current_backend;
}

const char *hal_error_string(int err)
{
    if (err < 0) err = -err;
    if (err < (int)(sizeof(error_messages) / sizeof(error_messages[0]))) {
        return error_messages[err];
    }
    return "Unknown error";
}

/* ============================================================================
 * Convenience Functions
 * ============================================================================ */

int hal_display_init(void)
{
    if (current_backend.display && current_backend.display->init) {
        return current_backend.display->init();
    }
    return HAL_ERR_NOT_SUPPORTED;
}

void hal_display_shutdown(void)
{
    if (current_backend.display && current_backend.display->shutdown) {
        current_backend.display->shutdown();
    }
}

int hal_display_clear(void)
{
    if (current_backend.display && current_backend.display->clear) {
        return current_backend.display->clear();
    }
    return HAL_ERR_NOT_SUPPORTED;
}

int hal_display_text(int x, int y, const char *text)
{
    if (current_backend.display && current_backend.display->draw_text) {
        return current_backend.display->draw_text(x, y, text, 0xFFFFFF, 0);
    }
    return HAL_ERR_NOT_SUPPORTED;
}

int hal_display_refresh(void)
{
    if (current_backend.display && current_backend.display->refresh) {
        return current_backend.display->refresh();
    }
    return HAL_ERR_NOT_SUPPORTED;
}

int hal_input_init(void)
{
    if (current_backend.input && current_backend.input->init) {
        return current_backend.input->init();
    }
    return HAL_ERR_NOT_SUPPORTED;
}

void hal_input_shutdown(void)
{
    if (current_backend.input && current_backend.input->shutdown) {
        current_backend.input->shutdown();
    }
}

int hal_input_poll(hal_input_event_t *event, int timeout_ms)
{
    if (current_backend.input && current_backend.input->poll) {
        return current_backend.input->poll(event, timeout_ms);
    }
    return HAL_ERR_NOT_SUPPORTED;
}

int hal_input_wait_button(int timeout_ms)
{
    if (current_backend.input && current_backend.input->wait_any_button) {
        return current_backend.input->wait_any_button(timeout_ms);
    }
    return HAL_ERR_NOT_SUPPORTED;
}

int hal_sensor_init(void)
{
    if (current_backend.sensor && current_backend.sensor->init) {
        return current_backend.sensor->init();
    }
    return HAL_ERR_NOT_SUPPORTED;
}

void hal_sensor_shutdown(void)
{
    if (current_backend.sensor && current_backend.sensor->shutdown) {
        current_backend.sensor->shutdown();
    }
}

int hal_sensor_available(hal_sensor_type_t type)
{
    if (current_backend.sensor && current_backend.sensor->is_available) {
        return current_backend.sensor->is_available(type);
    }
    return 0;
}

int hal_sensor_read_accel(hal_accel_data_t *data)
{
    if (current_backend.sensor && current_backend.sensor->read_accel) {
        return current_backend.sensor->read_accel(data);
    }
    return HAL_ERR_NOT_SUPPORTED;
}

int hal_sensor_read_temp(int16_t *temp)
{
    if (current_backend.sensor && current_backend.sensor->read_temperature) {
        return current_backend.sensor->read_temperature(temp);
    }
    return HAL_ERR_NOT_SUPPORTED;
}

int hal_rng_init(void)
{
    if (current_backend.rng && current_backend.rng->init) {
        return current_backend.rng->init();
    }
    return HAL_ERR_NOT_SUPPORTED;
}

int hal_rng_get_random(uint8_t *buf, size_t len)
{
    if (current_backend.rng && current_backend.rng->get_random) {
        return current_backend.rng->get_random(buf, len);
    }
    return HAL_ERR_NOT_SUPPORTED;
}

/* ============================================================================
 * Backend Registration
 * ============================================================================ */

void hal_register_display(display_mode_t mode, hal_display_ops_t *ops)
{
    if (mode == DISPLAY_MODE_FRAMEBUFFER) {
        framebuffer_display_ops = *ops;
    }
    /* Could extend with a registry for more modes */
}

void hal_register_input(input_mode_t mode, hal_input_ops_t *ops)
{
    (void)mode;
    (void)ops;
    /* Could extend with a registry */
}

void hal_register_sensor(const char *name, hal_sensor_ops_t *ops)
{
    (void)name;
    (void)ops;
    /* Could extend with a registry */
}

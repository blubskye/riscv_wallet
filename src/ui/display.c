/*
 * Display Interface with Linux Framebuffer Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _GNU_SOURCE

#include "display.h"
#include "qr.h"
#include "../hw/hwconfig.h"
#include "../hw/hal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/fb.h>

/* Built-in 8x16 font (subset of ASCII printable characters) */
#include "font8x16.h"

/* Default framebuffer device */
#define DEFAULT_FB_DEVICE "/dev/fb0"

/* Display state */
static int g_initialized = 0;
static display_info_t g_info;

/* Framebuffer state */
static int g_fb_fd = -1;
static uint8_t *g_framebuffer = NULL;
static size_t g_fb_size = 0;
static struct fb_var_screeninfo g_vinfo;
static struct fb_fix_screeninfo g_finfo;

/* Double buffer for flicker-free updates */
static uint16_t *g_backbuffer = NULL;

/* Forward declarations */
static int fb_init(const char *device);
static void fb_cleanup(void);
static void fb_set_pixel_internal(int x, int y, uint16_t color);
static void terminal_set_pixel(int x, int y, uint16_t color);

/*
 * Framebuffer initialization
 */
static int fb_init(const char *device)
{
    const char *fb_dev = device ? device : DEFAULT_FB_DEVICE;

    /* Open framebuffer device */
    g_fb_fd = open(fb_dev, O_RDWR);
    if (g_fb_fd < 0) {
        perror("[display] Failed to open framebuffer");
        return -1;
    }

    /* Get fixed screen info */
    if (ioctl(g_fb_fd, FBIOGET_FSCREENINFO, &g_finfo) < 0) {
        perror("[display] Failed to get fixed screen info");
        close(g_fb_fd);
        g_fb_fd = -1;
        return -1;
    }

    /* Get variable screen info */
    if (ioctl(g_fb_fd, FBIOGET_VSCREENINFO, &g_vinfo) < 0) {
        perror("[display] Failed to get variable screen info");
        close(g_fb_fd);
        g_fb_fd = -1;
        return -1;
    }

    /* Store display info */
    g_info.backend = DISPLAY_BACKEND_FRAMEBUFFER;
    g_info.width = g_vinfo.xres;
    g_info.height = g_vinfo.yres;
    g_info.bpp = g_vinfo.bits_per_pixel;
    g_info.stride = g_finfo.line_length;
    g_info.device = fb_dev;

    /* Calculate framebuffer size */
    g_fb_size = g_finfo.line_length * g_vinfo.yres;

    /* Memory map the framebuffer */
    g_framebuffer = mmap(NULL, g_fb_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, g_fb_fd, 0);
    if (g_framebuffer == MAP_FAILED) {
        perror("[display] Failed to mmap framebuffer");
        g_framebuffer = NULL;
        close(g_fb_fd);
        g_fb_fd = -1;
        return -1;
    }

    /* Allocate back buffer for double buffering */
    g_backbuffer = malloc(g_info.width * g_info.height * sizeof(uint16_t));
    if (g_backbuffer == NULL) {
        fprintf(stderr, "[display] Failed to allocate back buffer\n");
        munmap(g_framebuffer, g_fb_size);
        g_framebuffer = NULL;
        close(g_fb_fd);
        g_fb_fd = -1;
        return -1;
    }

    printf("[display] Framebuffer initialized: %dx%d @ %d bpp\n",
           g_info.width, g_info.height, g_info.bpp);

    return 0;
}

static void fb_cleanup(void)
{
    if (g_backbuffer != NULL) {
        free(g_backbuffer);
        g_backbuffer = NULL;
    }

    if (g_framebuffer != NULL) {
        munmap(g_framebuffer, g_fb_size);
        g_framebuffer = NULL;
    }

    if (g_fb_fd >= 0) {
        close(g_fb_fd);
        g_fb_fd = -1;
    }
}

/*
 * Set pixel in framebuffer (handles different bpp)
 */
static void fb_set_pixel_internal(int x, int y, uint16_t color)
{
    if (g_framebuffer == NULL) return;
    if (x < 0 || x >= g_info.width || y < 0 || y >= g_info.height) return;

    /* Store in back buffer (always RGB565) */
    if (g_backbuffer != NULL) {
        g_backbuffer[y * g_info.width + x] = color;
    }

    /* Calculate pixel offset */
    size_t offset = y * g_finfo.line_length + x * (g_info.bpp / 8);

    switch (g_info.bpp) {
    case 16:
        /* RGB565 - direct write */
        *((uint16_t *)(g_framebuffer + offset)) = color;
        break;

    case 24: {
        /* RGB888 - expand from RGB565 */
        uint8_t r = ((color >> 11) & 0x1F) << 3;
        uint8_t g = ((color >> 5) & 0x3F) << 2;
        uint8_t b = (color & 0x1F) << 3;
        g_framebuffer[offset] = b;
        g_framebuffer[offset + 1] = g;
        g_framebuffer[offset + 2] = r;
        break;
    }

    case 32: {
        /* ARGB8888 - expand from RGB565 */
        uint8_t r = ((color >> 11) & 0x1F) << 3;
        uint8_t g = ((color >> 5) & 0x3F) << 2;
        uint8_t b = (color & 0x1F) << 3;
        *((uint32_t *)(g_framebuffer + offset)) = (0xFF << 24) | (r << 16) | (g << 8) | b;
        break;
    }

    default:
        break;
    }
}

/*
 * Terminal backend (ASCII art)
 */
static void terminal_set_pixel(int x, int y, uint16_t color)
{
    /* Terminal backend doesn't support pixel operations */
    (void)x;
    (void)y;
    (void)color;
}

/*
 * Public API
 */
int display_init(void)
{
    /* Load hardware config */
    hwconfig_load(&g_hwconfig);

    /* Check display mode from config */
    if (g_hwconfig.display.mode == DISPLAY_MODE_FRAMEBUFFER) {
        const char *device = (g_hwconfig.display.fb_device[0] != '\0')
                             ? g_hwconfig.display.fb_device : NULL;
        return display_init_backend(DISPLAY_BACKEND_FRAMEBUFFER, device);
    }

    /* Default to terminal */
    return display_init_backend(DISPLAY_BACKEND_TERMINAL, NULL);
}

int display_init_backend(display_backend_t backend, const char *device)
{
    if (g_initialized) {
        return 0;
    }

    memset(&g_info, 0, sizeof(g_info));

    switch (backend) {
    case DISPLAY_BACKEND_FRAMEBUFFER:
        if (fb_init(device) == 0) {
            g_initialized = 1;
            return 0;
        }
        /* Fall through to terminal if framebuffer fails */
        printf("[display] Framebuffer not available, falling back to terminal\n");
        /* fallthrough */

    case DISPLAY_BACKEND_TERMINAL:
        g_info.backend = DISPLAY_BACKEND_TERMINAL;
        g_info.width = DISPLAY_WIDTH;
        g_info.height = DISPLAY_HEIGHT;
        g_info.bpp = 16;
        g_info.stride = DISPLAY_WIDTH * 2;
        g_info.device = "terminal";
        printf("[display] Terminal backend initialized (%dx%d)\n",
               g_info.width, g_info.height);
        g_initialized = 1;
        return 0;

    case DISPLAY_BACKEND_DRM:
        /* DRM/KMS backend not implemented yet */
        fprintf(stderr, "[display] DRM backend not implemented\n");
        return -1;

    default:
        return -1;
    }
}

void display_cleanup(void)
{
    if (!g_initialized) {
        return;
    }

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        fb_cleanup();
    }

    memset(&g_info, 0, sizeof(g_info));
    g_initialized = 0;
    printf("[display] Cleaned up\n");
}

const display_info_t *display_get_info(void)
{
    return g_initialized ? &g_info : NULL;
}

int display_is_available(void)
{
    return g_initialized;
}

void display_clear(uint16_t color)
{
    if (!g_initialized) return;

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER && g_framebuffer != NULL) {
        /* Clear back buffer */
        if (g_backbuffer != NULL) {
            for (int i = 0; i < g_info.width * g_info.height; i++) {
                g_backbuffer[i] = color;
            }
        }

        /* Clear framebuffer based on bpp */
        switch (g_info.bpp) {
        case 16:
            for (int y = 0; y < g_info.height; y++) {
                uint16_t *line = (uint16_t *)(g_framebuffer + y * g_finfo.line_length);
                for (int x = 0; x < g_info.width; x++) {
                    line[x] = color;
                }
            }
            break;

        case 24:
        case 32:
            for (int y = 0; y < g_info.height; y++) {
                for (int x = 0; x < g_info.width; x++) {
                    fb_set_pixel_internal(x, y, color);
                }
            }
            break;
        }
    } else {
        /* Terminal backend */
        printf("[display] Cleared with color 0x%04X\n", color);
    }
}

void display_update(void)
{
    if (!g_initialized) return;

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        /* For simple framebuffer, updates are immediate */
        /* Could implement vsync here if needed */
    }
}

void display_set_pixel(int x, int y, uint16_t color)
{
    if (!g_initialized) return;

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        fb_set_pixel_internal(x, y, color);
    } else {
        terminal_set_pixel(x, y, color);
    }
}

void display_draw_hline(int x, int y, int length, uint16_t color)
{
    if (!g_initialized) return;

    for (int i = 0; i < length; i++) {
        display_set_pixel(x + i, y, color);
    }
}

void display_draw_vline(int x, int y, int length, uint16_t color)
{
    if (!g_initialized) return;

    for (int i = 0; i < length; i++) {
        display_set_pixel(x, y + i, color);
    }
}

void display_draw_rect(int x, int y, int w, int h, uint16_t color)
{
    if (!g_initialized) return;

    display_draw_hline(x, y, w, color);
    display_draw_hline(x, y + h - 1, w, color);
    display_draw_vline(x, y, h, color);
    display_draw_vline(x + w - 1, y, h, color);
}

void display_fill_rect(int x, int y, int w, int h, uint16_t color)
{
    if (!g_initialized) return;

    for (int j = 0; j < h; j++) {
        for (int i = 0; i < w; i++) {
            display_set_pixel(x + i, y + j, color);
        }
    }
}

void display_draw_text(int x, int y, const char *text, uint16_t fg, uint16_t bg)
{
    if (!g_initialized || text == NULL) return;

    int transparent = (fg == bg);
    int cx = x;

    while (*text) {
        unsigned char c = (unsigned char)*text;

        /* Only handle printable ASCII */
        if (c >= 32 && c < 128) {
            int font_idx = c - 32;

            /* Draw character from font */
            for (int row = 0; row < 16; row++) {
                uint8_t bits = font8x16[font_idx * 16 + row];
                for (int col = 0; col < 8; col++) {
                    if (bits & (0x80 >> col)) {
                        display_set_pixel(cx + col, y + row, fg);
                    } else if (!transparent) {
                        display_set_pixel(cx + col, y + row, bg);
                    }
                }
            }
        }

        cx += 8;
        text++;
    }
}

void display_draw_text_centered(int y, const char *text, uint16_t fg, uint16_t bg)
{
    if (!g_initialized || text == NULL) return;

    int len = strlen(text);
    int x = (g_info.width - len * 8) / 2;
    if (x < 0) x = 0;

    display_draw_text(x, y, text, fg, bg);
}

void display_draw_bitmap(int x, int y, int w, int h, const uint16_t *data)
{
    if (!g_initialized || data == NULL) return;

    for (int j = 0; j < h; j++) {
        for (int i = 0; i < w; i++) {
            display_set_pixel(x + i, y + j, data[j * w + i]);
        }
    }
}

/*
 * High-level UI functions
 */
void display_show_lock_screen(void)
{
    if (!g_initialized) return;

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        display_clear(COLOR_BLACK);

        /* Draw title */
        display_draw_text_centered(40, "RISC-V COLD WALLET", COLOR_WHITE, COLOR_BLACK);

        /* Draw lock icon (simple rectangle) */
        display_fill_rect(140, 80, 40, 50, COLOR_GRAY);
        display_fill_rect(145, 90, 30, 35, COLOR_DARKGRAY);

        /* Draw status */
        display_draw_text_centered(150, "[ LOCKED ]", COLOR_YELLOW, COLOR_BLACK);
        display_draw_text_centered(180, "Place finger on sensor", COLOR_LIGHTGRAY, COLOR_BLACK);
        display_draw_text_centered(196, "to unlock", COLOR_LIGHTGRAY, COLOR_BLACK);

        display_update();
    } else {
        /* Terminal fallback */
        printf("\n");
        printf("+---------------------------------+\n");
        printf("|                                 |\n");
        printf("|      RISC-V COLD WALLET         |\n");
        printf("|                                 |\n");
        printf("|        [ LOCKED ]               |\n");
        printf("|                                 |\n");
        printf("|   Place finger on sensor        |\n");
        printf("|   to unlock                     |\n");
        printf("|                                 |\n");
        printf("+---------------------------------+\n");
        printf("\n");
    }
}

void display_show_main_menu(void)
{
    if (!g_initialized) return;

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        display_clear(COLOR_BLACK);

        /* Header */
        display_fill_rect(0, 0, g_info.width, 24, COLOR_BLUE);
        display_draw_text_centered(4, "RISC-V COLD WALLET", COLOR_WHITE, COLOR_BLUE);

        /* Menu items */
        display_draw_text(20, 40, "> 1. View Accounts", COLOR_WHITE, COLOR_BLACK);
        display_draw_text(20, 60, "  2. Receive", COLOR_LIGHTGRAY, COLOR_BLACK);
        display_draw_text(20, 80, "  3. Sign Transaction", COLOR_LIGHTGRAY, COLOR_BLACK);
        display_draw_text(20, 100, "  4. Settings", COLOR_LIGHTGRAY, COLOR_BLACK);

        /* Footer */
        display_draw_hline(0, g_info.height - 24, g_info.width, COLOR_GRAY);
        display_draw_text(10, g_info.height - 18, "[UP/DOWN] Select", COLOR_LIGHTGRAY, COLOR_BLACK);
        display_draw_text(180, g_info.height - 18, "[OK] Enter", COLOR_LIGHTGRAY, COLOR_BLACK);

        display_update();
    } else {
        printf("\n");
        printf("+---------------------------------+\n");
        printf("|      RISC-V COLD WALLET         |\n");
        printf("+---------------------------------+\n");
        printf("|  > 1. View Accounts             |\n");
        printf("|    2. Receive                   |\n");
        printf("|    3. Sign Transaction          |\n");
        printf("|    4. Settings                  |\n");
        printf("|                                 |\n");
        printf("|  [UP/DOWN] Select  [OK] Enter   |\n");
        printf("+---------------------------------+\n");
        printf("\n");
    }
}

void display_show_account(int account_index)
{
    if (!g_initialized) return;

    char title[32];
    snprintf(title, sizeof(title), "Account #%d", account_index);

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        display_clear(COLOR_BLACK);

        /* Header */
        display_fill_rect(0, 0, g_info.width, 24, COLOR_BLUE);
        display_draw_text_centered(4, title, COLOR_WHITE, COLOR_BLUE);

        /* Account details */
        display_draw_text(20, 40, "Chain: Bitcoin", COLOR_WHITE, COLOR_BLACK);
        display_draw_text(20, 60, "Type:  Native SegWit", COLOR_WHITE, COLOR_BLACK);
        display_draw_text(20, 100, "Balance:", COLOR_LIGHTGRAY, COLOR_BLACK);
        display_draw_text(20, 120, "0.00000000 BTC", COLOR_GREEN, COLOR_BLACK);

        /* Footer */
        display_draw_hline(0, g_info.height - 24, g_info.width, COLOR_GRAY);
        display_draw_text(10, g_info.height - 18, "[BACK] Menu", COLOR_LIGHTGRAY, COLOR_BLACK);
        display_draw_text(200, g_info.height - 18, "[OK] Details", COLOR_LIGHTGRAY, COLOR_BLACK);

        display_update();
    } else {
        printf("\n");
        printf("+---------------------------------+\n");
        printf("|  %s                    |\n", title);
        printf("+---------------------------------+\n");
        printf("|  Chain: Bitcoin                 |\n");
        printf("|  Type:  Native SegWit           |\n");
        printf("|                                 |\n");
        printf("|  Balance: 0.00000000 BTC        |\n");
        printf("|                                 |\n");
        printf("|  [BACK] Menu  [OK] Details      |\n");
        printf("+---------------------------------+\n");
        printf("\n");
    }
}

void display_show_address(const char *address, const char *label)
{
    if (!g_initialized) return;

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        display_clear(COLOR_BLACK);

        /* Header */
        display_fill_rect(0, 0, g_info.width, 24, COLOR_GREEN);
        display_draw_text_centered(4, "RECEIVE", COLOR_WHITE, COLOR_GREEN);

        /* Label if provided */
        int qr_y = 30;
        if (label != NULL && label[0] != '\0') {
            display_draw_text_centered(30, label, COLOR_LIGHTGRAY, COLOR_BLACK);
            qr_y = 46;
        }

        /* Draw QR code */
        if (address != NULL) {
            display_draw_qr(address, (g_info.width - 120) / 2, qr_y, 3);
        }

        /* Address text (truncated) */
        if (address != NULL) {
            char truncated[40];
            size_t len = strlen(address);
            if (len > 32) {
                snprintf(truncated, sizeof(truncated), "%.14s...%.14s",
                         address, address + len - 14);
            } else {
                snprintf(truncated, sizeof(truncated), "%s", address);
            }
            display_draw_text_centered(g_info.height - 44, truncated,
                                        COLOR_WHITE, COLOR_BLACK);
        }

        /* Footer */
        display_draw_hline(0, g_info.height - 24, g_info.width, COLOR_GRAY);
        display_draw_text(10, g_info.height - 18, "[BACK] Menu", COLOR_LIGHTGRAY, COLOR_BLACK);
        display_draw_text(180, g_info.height - 18, "[OK] New Addr", COLOR_LIGHTGRAY, COLOR_BLACK);

        display_update();
    } else {
        printf("\n");
        printf("+---------------------------------+\n");
        printf("|  RECEIVE                        |\n");
        printf("+---------------------------------+\n");
        if (label != NULL && label[0] != '\0') {
            printf("|  %s\n", label);
        }
        printf("|                                 |\n");
        printf("|  [QR CODE WOULD APPEAR HERE]    |\n");
        printf("|                                 |\n");
        if (address != NULL) {
            printf("|  %.32s...\n", address);
        }
        printf("|                                 |\n");
        printf("|  [BACK] Menu  [OK] New Addr     |\n");
        printf("+---------------------------------+\n");
        printf("\n");
    }
}

void display_show_transaction(const char *to_address, const char *amount,
                              const char *fee, const char *chain)
{
    if (!g_initialized) return;

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        display_clear(COLOR_BLACK);

        /* Header */
        display_fill_rect(0, 0, g_info.width, 24, COLOR_ORANGE);
        display_draw_text_centered(4, "CONFIRM TRANSACTION", COLOR_BLACK, COLOR_ORANGE);

        /* Transaction details */
        char chain_str[32];
        snprintf(chain_str, sizeof(chain_str), "Chain: %s", chain ? chain : "Unknown");
        display_draw_text(10, 35, chain_str, COLOR_WHITE, COLOR_BLACK);

        display_draw_text(10, 60, "To:", COLOR_LIGHTGRAY, COLOR_BLACK);
        if (to_address != NULL) {
            char truncated[36];
            snprintf(truncated, sizeof(truncated), "%.32s...", to_address);
            display_draw_text(10, 76, truncated, COLOR_WHITE, COLOR_BLACK);
        }

        char amount_str[48];
        snprintf(amount_str, sizeof(amount_str), "Amount: %s", amount ? amount : "0");
        display_draw_text(10, 100, amount_str, COLOR_GREEN, COLOR_BLACK);

        char fee_str[48];
        snprintf(fee_str, sizeof(fee_str), "Fee:    %s", fee ? fee : "0");
        display_draw_text(10, 120, fee_str, COLOR_YELLOW, COLOR_BLACK);

        /* Buttons */
        display_fill_rect(20, g_info.height - 40, 80, 30, COLOR_RED);
        display_draw_text(35, g_info.height - 34, "CANCEL", COLOR_WHITE, COLOR_RED);

        display_fill_rect(g_info.width - 100, g_info.height - 40, 80, 30, COLOR_GREEN);
        display_draw_text(g_info.width - 90, g_info.height - 34, "CONFIRM", COLOR_BLACK, COLOR_GREEN);

        display_update();
    } else {
        printf("\n");
        printf("+---------------------------------+\n");
        printf("|  CONFIRM TRANSACTION            |\n");
        printf("+---------------------------------+\n");
        printf("|  Chain: %s\n", chain ? chain : "Unknown");
        printf("|                                 |\n");
        printf("|  To: %.20s...\n", to_address ? to_address : "");
        printf("|                                 |\n");
        printf("|  Amount: %s\n", amount ? amount : "0");
        printf("|  Fee:    %s\n", fee ? fee : "0");
        printf("|                                 |\n");
        printf("|  [CANCEL]           [CONFIRM]   |\n");
        printf("+---------------------------------+\n");
        printf("\n");
    }
}

void display_show_message(const char *title, const char *message)
{
    if (!g_initialized) return;

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        display_clear(COLOR_BLACK);

        /* Title */
        display_fill_rect(0, 0, g_info.width, 24, COLOR_BLUE);
        display_draw_text_centered(4, title ? title : "Message", COLOR_WHITE, COLOR_BLUE);

        /* Message */
        if (message != NULL) {
            display_draw_text_centered(100, message, COLOR_WHITE, COLOR_BLACK);
        }

        /* OK button */
        display_fill_rect((g_info.width - 60) / 2, g_info.height - 50, 60, 30, COLOR_BLUE);
        display_draw_text((g_info.width - 16) / 2, g_info.height - 44, "OK", COLOR_WHITE, COLOR_BLUE);

        display_update();
    } else {
        printf("\n");
        printf("+---------------------------------+\n");
        printf("|  %s\n", title ? title : "Message");
        printf("+---------------------------------+\n");
        printf("|  %s\n", message ? message : "");
        printf("|                                 |\n");
        printf("|              [OK]               |\n");
        printf("+---------------------------------+\n");
        printf("\n");
    }
}

void display_show_error(const char *error)
{
    if (!g_initialized) return;

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        display_clear(COLOR_BLACK);

        /* Header */
        display_fill_rect(0, 0, g_info.width, 24, COLOR_RED);
        display_draw_text_centered(4, "ERROR", COLOR_WHITE, COLOR_RED);

        /* Error message */
        if (error != NULL) {
            display_draw_text_centered(100, error, COLOR_RED, COLOR_BLACK);
        }

        /* OK button */
        display_fill_rect((g_info.width - 60) / 2, g_info.height - 50, 60, 30, COLOR_RED);
        display_draw_text((g_info.width - 16) / 2, g_info.height - 44, "OK", COLOR_WHITE, COLOR_RED);

        display_update();
    } else {
        printf("\n");
        printf("+---------------------------------+\n");
        printf("|  ERROR                          |\n");
        printf("+---------------------------------+\n");
        printf("|  %s\n", error ? error : "Unknown error");
        printf("|                                 |\n");
        printf("|              [OK]               |\n");
        printf("+---------------------------------+\n");
        printf("\n");
    }
}

void display_draw_qr(const char *data, int x, int y, int scale)
{
    qr_code_t qr;

    if (!g_initialized || data == NULL) return;

    /* Generate QR code */
    if (qr_encode(data, &qr) != 0) {
        printf("[display] Failed to generate QR code\n");
        return;
    }

    if (g_info.backend == DISPLAY_BACKEND_FRAMEBUFFER) {
        /* Draw QR code with scaling */
        for (int qy = 0; qy < qr.width; qy++) {
            for (int qx = 0; qx < qr.width; qx++) {
                uint16_t color = qr_get_module(&qr, qx, qy) ? COLOR_BLACK : COLOR_WHITE;
                display_fill_rect(x + qx * scale, y + qy * scale, scale, scale, color);
            }
        }
    } else {
        /* Terminal ASCII QR */
        printf("\n");
        for (int qy = 0; qy < qr.width; qy++) {
            printf("  ");
            for (int qx = 0; qx < qr.width; qx++) {
                printf(qr_get_module(&qr, qx, qy) ? "██" : "  ");
            }
            printf("\n");
        }
        printf("\n");
    }

    qr_free(&qr);
}

int display_set_brightness(int brightness)
{
    /* Use HAL for brightness control if available */
    const hal_backend_t *hal = hal_get_backend();
    if (hal && hal->display && hal->display->set_backlight) {
        uint8_t level = (brightness < 0) ? 0 :
                        (brightness > 255) ? 255 : (uint8_t)brightness;
        return hal->display->set_backlight(level);
    }

    return -1;
}

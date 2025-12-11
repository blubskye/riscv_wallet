/*
 * Display Interface
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdint.h>
#include <stddef.h>

/* Display dimensions (target: 320x240 TFT) */
#define DISPLAY_WIDTH   320
#define DISPLAY_HEIGHT  240

/* Colors (RGB565) */
#define COLOR_BLACK     0x0000
#define COLOR_WHITE     0xFFFF
#define COLOR_RED       0xF800
#define COLOR_GREEN     0x07E0
#define COLOR_BLUE      0x001F
#define COLOR_YELLOW    0xFFE0
#define COLOR_CYAN      0x07FF
#define COLOR_MAGENTA   0xF81F
#define COLOR_ORANGE    0xFD20
#define COLOR_GRAY      0x8410
#define COLOR_DARKGRAY  0x4208
#define COLOR_LIGHTGRAY 0xC618

/* Display backend type */
typedef enum {
    DISPLAY_BACKEND_NONE = 0,
    DISPLAY_BACKEND_TERMINAL,     /* ASCII art to stdout */
    DISPLAY_BACKEND_FRAMEBUFFER,  /* Linux /dev/fb0 */
    DISPLAY_BACKEND_DRM           /* Linux DRM/KMS */
} display_backend_t;

/* Display info structure */
typedef struct {
    display_backend_t backend;
    int width;
    int height;
    int bpp;              /* Bits per pixel */
    int stride;           /* Bytes per line */
    const char *device;   /* Device path (e.g., /dev/fb0) */
} display_info_t;

/**
 * Initialize display subsystem
 *
 * @return 0 on success, -1 on error
 */
int display_init(void);

/**
 * Initialize display with specific backend
 *
 * @param backend Backend type to use
 * @param device Optional device path (NULL for default)
 * @return 0 on success, -1 on error
 */
int display_init_backend(display_backend_t backend, const char *device);

/**
 * Cleanup display subsystem
 */
void display_cleanup(void);

/**
 * Get display information
 *
 * @return Pointer to display info, or NULL if not initialized
 */
const display_info_t *display_get_info(void);

/**
 * Check if display is available
 *
 * @return 1 if available, 0 if not
 */
int display_is_available(void);

/**
 * Clear display with specified color
 *
 * @param color Fill color (RGB565)
 */
void display_clear(uint16_t color);

/**
 * Update display (flush buffer to screen)
 */
void display_update(void);

/**
 * Set a single pixel
 *
 * @param x X coordinate
 * @param y Y coordinate
 * @param color Pixel color (RGB565)
 */
void display_set_pixel(int x, int y, uint16_t color);

/**
 * Draw a horizontal line
 *
 * @param x Start X
 * @param y Start Y
 * @param length Line length
 * @param color Line color
 */
void display_draw_hline(int x, int y, int length, uint16_t color);

/**
 * Draw a vertical line
 *
 * @param x Start X
 * @param y Start Y
 * @param length Line length
 * @param color Line color
 */
void display_draw_vline(int x, int y, int length, uint16_t color);

/**
 * Draw a rectangle outline
 *
 * @param x Top-left X
 * @param y Top-left Y
 * @param w Width
 * @param h Height
 * @param color Line color
 */
void display_draw_rect(int x, int y, int w, int h, uint16_t color);

/**
 * Draw a filled rectangle
 *
 * @param x Top-left X
 * @param y Top-left Y
 * @param w Width
 * @param h Height
 * @param color Fill color
 */
void display_fill_rect(int x, int y, int w, int h, uint16_t color);

/**
 * Draw text at position
 *
 * @param x X coordinate
 * @param y Y coordinate
 * @param text Text string
 * @param fg Foreground color
 * @param bg Background color (use same as fg for transparent)
 */
void display_draw_text(int x, int y, const char *text, uint16_t fg, uint16_t bg);

/**
 * Draw text centered horizontally
 *
 * @param y Y coordinate
 * @param text Text string
 * @param fg Foreground color
 * @param bg Background color
 */
void display_draw_text_centered(int y, const char *text, uint16_t fg, uint16_t bg);

/**
 * Draw a bitmap image
 *
 * @param x Top-left X
 * @param y Top-left Y
 * @param w Width
 * @param h Height
 * @param data RGB565 pixel data
 */
void display_draw_bitmap(int x, int y, int w, int h, const uint16_t *data);

/**
 * Show lock screen
 */
void display_show_lock_screen(void);

/**
 * Show main menu
 */
void display_show_main_menu(void);

/**
 * Show account details
 *
 * @param account_index Index of account to display
 */
void display_show_account(int account_index);

/**
 * Show address with QR code
 *
 * @param address Address string
 * @param label Optional label
 */
void display_show_address(const char *address, const char *label);

/**
 * Show transaction for confirmation
 *
 * @param to_address Recipient address
 * @param amount Amount as string
 * @param fee Fee as string
 * @param chain Chain name
 */
void display_show_transaction(const char *to_address, const char *amount,
                              const char *fee, const char *chain);

/**
 * Show message to user
 *
 * @param title Message title
 * @param message Message body
 */
void display_show_message(const char *title, const char *message);

/**
 * Show error message
 *
 * @param error Error message
 */
void display_show_error(const char *error);

/**
 * Draw QR code on display
 *
 * @param data Data to encode
 * @param x X position
 * @param y Y position
 * @param scale Pixel scale factor
 */
void display_draw_qr(const char *data, int x, int y, int scale);

/**
 * Set display brightness (0-100)
 *
 * @param brightness Brightness percentage
 * @return 0 on success, -1 if not supported
 */
int display_set_brightness(int brightness);

/**
 * Convert RGB to RGB565
 *
 * @param r Red (0-255)
 * @param g Green (0-255)
 * @param b Blue (0-255)
 * @return RGB565 color
 */
static inline uint16_t display_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3);
}

#endif /* DISPLAY_H */

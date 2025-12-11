/*
 * Hardware Configuration System
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Simple configuration for Linux kernel-managed hardware.
 *
 * Displays: Uses the Linux framebuffer interface (/dev/fb*).
 *   The kernel's fbtft, drm, or other drivers handle the actual
 *   SPI/I2C/HDMI hardware. Configure via device tree overlays.
 *
 * Buttons: Uses either Linux input events (/dev/input/event*)
 *   via gpio-keys driver, or direct GPIO via libgpiod.
 *   Configure gpio-keys in device tree for best integration.
 */

#ifndef HWCONFIG_H
#define HWCONFIG_H

#include <stdint.h>
#include <stddef.h>

/* Configuration file path */
#define HWCONFIG_PATH_ENV       "RISCV_WALLET_HWCONFIG"
#define HWCONFIG_DEFAULT_PATH   "/etc/riscv_wallet/hardware.conf"
#define HWCONFIG_USER_PATH      "~/.config/riscv_wallet/hardware.conf"

/* Maximum string lengths */
#define HWCONFIG_MAX_PATH       256

/*
 * Display Mode
 */
typedef enum {
    DISPLAY_MODE_TERMINAL = 0,  /* Terminal/console output (default) */
    DISPLAY_MODE_FRAMEBUFFER,   /* Linux framebuffer (/dev/fb*) */
    DISPLAY_MODE_DRM,           /* Linux DRM/KMS (/dev/dri/card*) */
} display_mode_t;

/*
 * Display Configuration
 */
typedef struct {
    display_mode_t mode;
    char fb_device[HWCONFIG_MAX_PATH];   /* e.g., "/dev/fb0" */
    char drm_device[HWCONFIG_MAX_PATH];  /* e.g., "/dev/dri/card0" */
    uint32_t drm_connector_id;           /* DRM connector ID (0 = first available) */
    uint16_t width;                       /* Display width (0 = auto-detect) */
    uint16_t height;                      /* Display height (0 = auto-detect) */
    uint8_t rotation;                     /* UI rotation: 0, 90, 180, 270 */
} display_config_t;

/*
 * Button Actions (config file buttons - use HWBTN_ prefix to avoid conflict
 * with linux/input.h BTN_* macros and input.h wallet button enums)
 */
typedef enum {
    HWBTN_NONE = 0,
    HWBTN_UP,
    HWBTN_DOWN,
    HWBTN_LEFT,
    HWBTN_RIGHT,
    HWBTN_ENTER,
    HWBTN_BACK,
    HWBTN_MENU,
    HWBTN_POWER,
    HWBTN_ACTION_COUNT
} button_action_t;

/*
 * Input Mode
 */
typedef enum {
    INPUT_MODE_TERMINAL = 0,    /* Keyboard input from terminal */
    INPUT_MODE_EVDEV,           /* Linux input events (/dev/input/event*) */
    INPUT_MODE_GPIOD,           /* Direct GPIO via libgpiod */
} input_mode_t;

/*
 * Button Mapping
 */
typedef struct {
    button_action_t action;
    int code;                   /* Key code (evdev) or GPIO pin (gpiod) */
    int active_low;             /* For gpiod: 1 if active low */
    char label[32];
} button_map_t;

#define MAX_BUTTONS 8

/*
 * Input Configuration
 */
typedef struct {
    input_mode_t mode;
    char device[HWCONFIG_MAX_PATH];      /* Event device or GPIO chip */
    int debounce_ms;                      /* For gpiod mode */
    int num_buttons;
    button_map_t buttons[MAX_BUTTONS];
} input_config_t;

/*
 * Complete Hardware Configuration
 */
typedef struct {
    char board_name[64];
    char config_path[HWCONFIG_MAX_PATH];
    int config_loaded;

    display_config_t display;
    input_config_t input;

    /* Hardware RNG */
    int has_hardware_rng;
    char rng_device[HWCONFIG_MAX_PATH];
} hwconfig_t;

/* Global configuration instance */
extern hwconfig_t g_hwconfig;

/*
 * Core Functions
 */

/** Initialize with defaults (terminal mode) */
void hwconfig_init_defaults(hwconfig_t *config);

/** Load from config file (searches standard paths) */
int hwconfig_load(hwconfig_t *config);

/** Save to config file */
int hwconfig_save(const hwconfig_t *config, const char *path);

/** Auto-detect available hardware */
int hwconfig_autodetect(hwconfig_t *config);

/*
 * Helper Functions
 */

const char *hwconfig_display_mode_name(display_mode_t mode);
display_mode_t hwconfig_parse_display_mode(const char *name);

const char *hwconfig_input_mode_name(input_mode_t mode);
input_mode_t hwconfig_parse_input_mode(const char *name);

const char *hwconfig_button_action_name(button_action_t action);
button_action_t hwconfig_parse_button_action(const char *name);

/** Find button mapping by action */
const button_map_t *hwconfig_find_button(const input_config_t *input,
                                          button_action_t action);

/*
 * Device Detection
 */

/** List available framebuffer devices */
int hwconfig_detect_framebuffers(char devices[][HWCONFIG_MAX_PATH], int max);

/** List available input event devices */
int hwconfig_detect_input_devices(char devices[][HWCONFIG_MAX_PATH], int max);

/** List available GPIO chips */
int hwconfig_detect_gpio_chips(char devices[][HWCONFIG_MAX_PATH], int max);

/** Check if hardware RNG is available */
int hwconfig_detect_hwrng(char *device, size_t device_len);

#endif /* HWCONFIG_H */

/*
 * Input Handling - Hardware GPIO and Input Event Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef INPUT_H
#define INPUT_H

#include <stdint.h>

/* Error codes */
#define INPUT_OK             0
#define INPUT_ERR_INIT      -1
#define INPUT_ERR_NO_DEVICE -2
#define INPUT_ERR_IO        -3
#define INPUT_ERR_TIMEOUT   -4
#define INPUT_ERR_CANCELLED -5

/* Input backend type */
typedef enum {
    INPUT_BACKEND_NONE = 0,
    INPUT_BACKEND_TERMINAL,    /* Keyboard via terminal */
    INPUT_BACKEND_EVDEV,       /* Linux input events (/dev/input/event*) */
    INPUT_BACKEND_GPIO         /* Direct GPIO (/dev/gpiochip*) */
} input_backend_t;

/* Button definitions */
typedef enum {
    WALLET_BTN_NONE = 0,
    WALLET_BTN_UP,
    WALLET_BTN_DOWN,
    WALLET_BTN_LEFT,
    WALLET_BTN_RIGHT,
    WALLET_BTN_SELECT,
    WALLET_BTN_BACK,
    WALLET_BTN_CONFIRM,
    WALLET_BTN_CANCEL,
    WALLET_BTN_COUNT       /* Number of buttons */
} button_t;

/* Convenience aliases (avoid name collision with linux/input.h BTN_* macros) */
#define BTN_NONE    WALLET_BTN_NONE
#define BTN_UP      WALLET_BTN_UP
#define BTN_DOWN    WALLET_BTN_DOWN
#define BTN_LEFT    WALLET_BTN_LEFT
#define BTN_RIGHT   WALLET_BTN_RIGHT
#define BTN_SELECT  WALLET_BTN_SELECT
#define BTN_BACK    WALLET_BTN_BACK
#define BTN_CONFIRM WALLET_BTN_CONFIRM
#define BTN_CANCEL  WALLET_BTN_CANCEL
#define BTN_COUNT   WALLET_BTN_COUNT

/* Input event */
typedef struct {
    button_t button;
    uint8_t pressed;    /* 1 = press, 0 = release */
    uint32_t timestamp; /* Milliseconds since init */
} input_event_t;

/* Input info structure */
typedef struct {
    input_backend_t backend;
    const char *device;       /* Device path */
    int num_buttons;          /* Number of available buttons */
    const char *backend_name; /* Human-readable backend name */
} input_info_t;

/* GPIO pin configuration */
typedef struct {
    int chip;           /* GPIO chip number (0 for /dev/gpiochip0) */
    int line;           /* GPIO line number */
    int active_low;     /* 1 if button is active-low */
} gpio_pin_config_t;

/* Callback for input events (for async mode) */
typedef void (*input_callback_t)(const input_event_t *event, void *user_data);

/**
 * Initialize input subsystem (auto-detect best backend)
 *
 * @return INPUT_OK on success, error code on failure
 */
int input_init(void);

/**
 * Initialize with specific backend
 *
 * @param backend Backend type to use
 * @param device Optional device path (NULL for auto-detect)
 * @return INPUT_OK on success, error code on failure
 */
int input_init_backend(input_backend_t backend, const char *device);

/**
 * Cleanup input subsystem
 */
void input_cleanup(void);

/**
 * Get input subsystem information
 *
 * @return Pointer to info struct, or NULL if not initialized
 */
const input_info_t *input_get_info(void);

/**
 * Check if input is available
 *
 * @return 1 if available, 0 if not
 */
int input_is_available(void);

/**
 * Poll for input event (non-blocking)
 *
 * @param event Output event structure
 * @return 1 if event available, 0 if no event
 */
int input_poll(input_event_t *event);

/**
 * Wait for input event (blocking)
 *
 * @param event Output event structure
 * @param timeout_ms Timeout in milliseconds (0 = infinite)
 * @return 1 if event received, 0 on timeout, -1 on error
 */
int input_wait(input_event_t *event, uint32_t timeout_ms);

/**
 * Get current button state
 *
 * @param button Button to check
 * @return 1 if pressed, 0 if not
 */
int input_is_pressed(button_t button);

/**
 * Wait for any button press
 *
 * @param timeout_ms Timeout in milliseconds (0 = infinite)
 * @return Button that was pressed, BTN_NONE on timeout
 */
button_t input_wait_any(uint32_t timeout_ms);

/**
 * Wait for specific button
 *
 * @param button Button to wait for
 * @param timeout_ms Timeout in milliseconds (0 = infinite)
 * @return 1 if button pressed, 0 on timeout
 */
int input_wait_button(button_t button, uint32_t timeout_ms);

/**
 * Read PIN input from user
 *
 * @param pin Output buffer for PIN
 * @param max_len Maximum PIN length
 * @return Length of entered PIN, INPUT_ERR_CANCELLED on cancel
 */
int input_read_pin(char *pin, int max_len);

/**
 * Read PIN with visual feedback on display
 *
 * @param pin Output buffer for PIN
 * @param max_len Maximum PIN length
 * @param title Title to show on display
 * @return Length of entered PIN, INPUT_ERR_CANCELLED on cancel
 */
int input_read_pin_display(char *pin, int max_len, const char *title);

/**
 * Get user confirmation (yes/no)
 *
 * @param prompt Prompt to display
 * @return 1 for yes, 0 for no
 */
int input_confirm(const char *prompt);

/**
 * Get user confirmation with display UI
 *
 * @param title Title for confirmation dialog
 * @param message Message to display
 * @return 1 for confirm, 0 for cancel
 */
int input_confirm_display(const char *title, const char *message);

/**
 * Menu selection with buttons
 *
 * @param items Array of menu item strings
 * @param count Number of items
 * @param selected Initially selected index
 * @return Selected index, -1 on cancel
 */
int input_menu_select(const char **items, int count, int selected);

/**
 * Configure GPIO pin mapping for a button
 *
 * @param button Button to configure
 * @param config GPIO configuration
 * @return INPUT_OK on success, error code on failure
 */
int input_configure_gpio(button_t button, const gpio_pin_config_t *config);

/**
 * Set debounce time for GPIO buttons
 *
 * @param debounce_ms Debounce time in milliseconds
 */
void input_set_debounce(uint32_t debounce_ms);

/**
 * Register callback for async input events
 *
 * @param callback Callback function
 * @param user_data User data passed to callback
 * @return INPUT_OK on success, error code on failure
 */
int input_set_callback(input_callback_t callback, void *user_data);

/**
 * Clear registered callback
 */
void input_clear_callback(void);

/**
 * Get button name as string
 *
 * @param button Button code
 * @return Static string with button name
 */
const char *input_button_name(button_t button);

/**
 * Simulate button press (for testing)
 *
 * @param button Button to simulate
 * @param pressed 1 for press, 0 for release
 */
void input_simulate(button_t button, int pressed);

/**
 * Get uptime in milliseconds
 *
 * @return Milliseconds since input_init()
 */
uint32_t input_get_time_ms(void);

#endif /* INPUT_H */

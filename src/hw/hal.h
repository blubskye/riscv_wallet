/*
 * Hardware Abstraction Layer (HAL)
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Dynamic hardware abstraction that selects implementations
 * based on detected/configured hardware. Provides unified APIs
 * for display, input, sensors, and secure storage that work
 * across different hardware configurations.
 */

#ifndef HAL_H
#define HAL_H

#include <stdint.h>
#include <stddef.h>
#include "hwconfig.h"

/* ============================================================================
 * HAL Error Codes
 * ============================================================================ */

#define HAL_OK                   0
#define HAL_ERR_NOT_INIT        -1
#define HAL_ERR_NOT_SUPPORTED   -2
#define HAL_ERR_HARDWARE        -3
#define HAL_ERR_BUSY            -4
#define HAL_ERR_TIMEOUT         -5
#define HAL_ERR_INVALID         -6

/* ============================================================================
 * Display HAL
 * ============================================================================ */

/* Display capabilities */
typedef struct {
    uint16_t width;
    uint16_t height;
    uint8_t  bpp;              /* Bits per pixel */
    uint8_t  supports_color;
    uint8_t  supports_touch;
    uint8_t  supports_backlight;
} hal_display_caps_t;

/* Display operations vtable */
typedef struct {
    int (*init)(void);
    void (*shutdown)(void);
    int (*get_caps)(hal_display_caps_t *caps);
    int (*clear)(void);
    int (*draw_pixel)(int x, int y, uint32_t color);
    int (*draw_rect)(int x, int y, int w, int h, uint32_t color);
    int (*draw_text)(int x, int y, const char *text, uint32_t fg, uint32_t bg);
    int (*draw_bitmap)(int x, int y, int w, int h, const uint8_t *data);
    int (*refresh)(void);      /* Flush to screen */
    int (*set_backlight)(uint8_t level);
} hal_display_ops_t;

/* ============================================================================
 * Input HAL
 * ============================================================================ */

/* Input event types */
typedef enum {
    HAL_INPUT_NONE = 0,
    HAL_INPUT_KEY_PRESS,
    HAL_INPUT_KEY_RELEASE,
    HAL_INPUT_TOUCH_DOWN,
    HAL_INPUT_TOUCH_UP,
    HAL_INPUT_TOUCH_MOVE,
} hal_input_type_t;

/* Input event */
typedef struct {
    hal_input_type_t type;
    uint32_t timestamp;
    union {
        struct {
            int code;          /* Key/button code */
            int action;        /* Mapped action (button_action_t) */
        } key;
        struct {
            int x;
            int y;
            int pressure;
        } touch;
    };
} hal_input_event_t;

/* Input operations vtable */
typedef struct {
    int (*init)(void);
    void (*shutdown)(void);
    int (*poll)(hal_input_event_t *event, int timeout_ms);
    int (*has_pending)(void);
    int (*get_button_state)(int button);  /* Returns 1 if pressed */
    int (*wait_any_button)(int timeout_ms);
} hal_input_ops_t;

/* ============================================================================
 * Sensor HAL
 * ============================================================================ */

/* Sensor types */
typedef enum {
    HAL_SENSOR_ACCELEROMETER = 0,
    HAL_SENSOR_LIGHT,
    HAL_SENSOR_TEMPERATURE,
    HAL_SENSOR_TAMPER_SWITCH,
    HAL_SENSOR_COUNT
} hal_sensor_type_t;

/* Accelerometer data */
typedef struct {
    int16_t x, y, z;           /* In milli-g */
} hal_accel_data_t;

/* Sensor operations vtable */
typedef struct {
    int (*init)(void);
    void (*shutdown)(void);
    int (*is_available)(hal_sensor_type_t type);
    int (*read_accel)(hal_accel_data_t *data);
    int (*read_light)(uint16_t *lux);
    int (*read_temperature)(int16_t *temp_c10);  /* Celsius * 10 */
    int (*read_tamper)(int *triggered);
} hal_sensor_ops_t;

/* ============================================================================
 * Secure Storage HAL
 * ============================================================================ */

/* Secure storage operations vtable */
typedef struct {
    int (*init)(void);
    void (*shutdown)(void);
    int (*has_secure_element)(void);
    int (*read)(uint8_t slot, uint8_t *data, size_t *len);
    int (*write)(uint8_t slot, const uint8_t *data, size_t len);
    int (*erase)(uint8_t slot);
    int (*get_device_id)(uint8_t id[16]);
} hal_storage_ops_t;

/* ============================================================================
 * RNG HAL
 * ============================================================================ */

/* RNG operations vtable */
typedef struct {
    int (*init)(void);
    void (*shutdown)(void);
    int (*has_hardware_rng)(void);
    int (*get_random)(uint8_t *buf, size_t len);
    int (*get_entropy)(uint8_t *buf, size_t len);  /* Mix hardware + software */
} hal_rng_ops_t;

/* ============================================================================
 * Complete HAL Interface
 * ============================================================================ */

typedef struct {
    const char *name;          /* Backend name */
    hal_display_ops_t *display;
    hal_input_ops_t *input;
    hal_sensor_ops_t *sensor;
    hal_storage_ops_t *storage;
    hal_rng_ops_t *rng;
} hal_backend_t;

/* ============================================================================
 * HAL Functions
 * ============================================================================ */

/**
 * Initialize HAL with hardware configuration
 * Selects appropriate backends based on detected hardware
 *
 * @param config Hardware configuration (NULL for auto-detect)
 * @return HAL_OK on success
 */
int hal_init(const hwconfig_t *config);

/**
 * Shutdown HAL and release resources
 */
void hal_shutdown(void);

/**
 * Check if HAL is initialized
 *
 * @return 1 if initialized, 0 if not
 */
int hal_is_initialized(void);

/**
 * Get current backend info
 *
 * @return Pointer to backend structure
 */
const hal_backend_t *hal_get_backend(void);

/**
 * Get HAL error string
 *
 * @param err Error code
 * @return Error message
 */
const char *hal_error_string(int err);

/* ============================================================================
 * Convenience Macros (dispatch to current backend)
 * ============================================================================ */

/* Display */
int hal_display_init(void);
void hal_display_shutdown(void);
int hal_display_clear(void);
int hal_display_text(int x, int y, const char *text);
int hal_display_refresh(void);

/* Input */
int hal_input_init(void);
void hal_input_shutdown(void);
int hal_input_poll(hal_input_event_t *event, int timeout_ms);
int hal_input_wait_button(int timeout_ms);

/* Sensors */
int hal_sensor_init(void);
void hal_sensor_shutdown(void);
int hal_sensor_available(hal_sensor_type_t type);
int hal_sensor_read_accel(hal_accel_data_t *data);
int hal_sensor_read_temp(int16_t *temp);

/* RNG */
int hal_rng_init(void);
int hal_rng_get_random(uint8_t *buf, size_t len);

/* ============================================================================
 * Backend Registration (for adding new hardware support)
 * ============================================================================ */

/**
 * Register a display backend
 *
 * @param mode Display mode this backend handles
 * @param ops Operations vtable
 */
void hal_register_display(display_mode_t mode, hal_display_ops_t *ops);

/**
 * Register an input backend
 *
 * @param mode Input mode this backend handles
 * @param ops Operations vtable
 */
void hal_register_input(input_mode_t mode, hal_input_ops_t *ops);

/**
 * Register a sensor backend
 *
 * @param name Backend name (e.g., "i2c-sensors")
 * @param ops Operations vtable
 */
void hal_register_sensor(const char *name, hal_sensor_ops_t *ops);

#endif /* HAL_H */

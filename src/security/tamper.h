/*
 * Tamper Detection Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Physical tamper detection using GPIO sensors, accelerometers,
 * light sensors, and mesh integrity checks.
 */

#ifndef TAMPER_H
#define TAMPER_H

#include <stdint.h>
#include <stddef.h>

/* Tamper detection types */
#define TAMPER_TYPE_CASE_OPEN    (1 << 0)   /* Case open switch triggered */
#define TAMPER_TYPE_MESH_BREAK   (1 << 1)   /* Protective mesh broken */
#define TAMPER_TYPE_GLITCH       (1 << 2)   /* Voltage/clock glitch detected */
#define TAMPER_TYPE_TEMPERATURE  (1 << 3)   /* Temperature out of range */
#define TAMPER_TYPE_LIGHT        (1 << 4)   /* Light sensor triggered */
#define TAMPER_TYPE_MOTION       (1 << 5)   /* Unexpected motion detected */
#define TAMPER_TYPE_VOLTAGE      (1 << 6)   /* Voltage anomaly */
#define TAMPER_TYPE_PROBE        (1 << 7)   /* Probe attempt detected */

/* Tamper response actions */
#define TAMPER_ACTION_LOG        (1 << 0)   /* Log the event */
#define TAMPER_ACTION_ALERT      (1 << 1)   /* Display alert to user */
#define TAMPER_ACTION_LOCK       (1 << 2)   /* Lock wallet immediately */
#define TAMPER_ACTION_WIPE_KEYS  (1 << 3)   /* Wipe cryptographic keys */
#define TAMPER_ACTION_WIPE_ALL   (1 << 4)   /* Wipe all data */
#define TAMPER_ACTION_SHUTDOWN   (1 << 5)   /* Shutdown device */
#define TAMPER_ACTION_BRICK      (1 << 6)   /* Permanently disable device */

/* Error codes */
#define TAMPER_OK                0
#define TAMPER_ERR_INIT          -1
#define TAMPER_ERR_SENSOR        -2
#define TAMPER_ERR_GPIO          -3
#define TAMPER_ERR_CONFIG        -4
#define TAMPER_ERR_INTERNAL      -5

/* Sensor status */
typedef enum {
    SENSOR_STATUS_UNKNOWN = 0,
    SENSOR_STATUS_OK,
    SENSOR_STATUS_TRIGGERED,
    SENSOR_STATUS_FAULT,
    SENSOR_STATUS_DISABLED
} tamper_sensor_status_t;

/* Tamper event */
typedef struct {
    uint32_t timestamp;          /* Unix timestamp */
    uint32_t type;               /* TAMPER_TYPE_* bitmask */
    uint8_t  sensor_id;          /* Which sensor triggered */
    uint8_t  severity;           /* 0-255 severity level */
    uint16_t raw_value;          /* Raw sensor value */
    char     description[64];    /* Human-readable description */
} tamper_event_t;

/* Sensor configuration */
typedef struct {
    uint8_t  enabled;            /* Sensor enabled */
    uint8_t  gpio_pin;           /* GPIO pin number */
    uint8_t  active_low;         /* Active low trigger */
    uint8_t  debounce_ms;        /* Debounce time in ms */
    uint16_t threshold;          /* Trigger threshold */
    uint32_t response;           /* TAMPER_ACTION_* bitmask */
} tamper_sensor_config_t;

/* Overall tamper configuration */
#define TAMPER_MAX_SENSORS       8

typedef struct {
    uint32_t version;
    uint8_t  enabled;            /* Global tamper detection enable */
    uint8_t  paranoid_mode;      /* Extra sensitive detection */
    uint8_t  log_events;         /* Log tamper events */
    uint8_t  reserved;
    tamper_sensor_config_t sensors[TAMPER_MAX_SENSORS];
    uint32_t global_response;    /* Default response for all sensors */
} tamper_config_t;

/* Tamper state */
typedef struct {
    uint32_t status;             /* Current tamper status (TAMPER_TYPE_* bitmask) */
    uint32_t event_count;        /* Total tamper events */
    uint32_t last_event_time;    /* Timestamp of last event */
    uint32_t boot_count;         /* Boot counter (increases on tamper) */
    uint8_t  tampered;           /* Device has been tampered */
    uint8_t  locked;             /* Device is locked due to tamper */
    uint8_t  wiped;              /* Keys have been wiped */
} tamper_state_t;

/* Accelerometer data */
typedef struct {
    int16_t x;
    int16_t y;
    int16_t z;
} tamper_accel_t;

/* ============================================================================
 * Initialization
 * ============================================================================ */

/**
 * Initialize tamper detection subsystem
 *
 * @param config Configuration (NULL for defaults)
 * @return TAMPER_OK on success, error code on failure
 */
int tamper_init(const tamper_config_t *config);

/**
 * Shutdown tamper detection
 */
void tamper_shutdown(void);

/**
 * Check if tamper detection is enabled
 *
 * @return 1 if enabled, 0 if disabled
 */
int tamper_is_enabled(void);

/* ============================================================================
 * Sensor Management
 * ============================================================================ */

/**
 * Configure a tamper sensor
 *
 * @param sensor_id Sensor ID (0 to TAMPER_MAX_SENSORS-1)
 * @param config Sensor configuration
 * @return TAMPER_OK on success, error code on failure
 */
int tamper_configure_sensor(uint8_t sensor_id, const tamper_sensor_config_t *config);

/**
 * Enable or disable a sensor
 *
 * @param sensor_id Sensor ID
 * @param enable 1 to enable, 0 to disable
 * @return TAMPER_OK on success
 */
int tamper_enable_sensor(uint8_t sensor_id, int enable);

/**
 * Get sensor status
 *
 * @param sensor_id Sensor ID
 * @return Sensor status
 */
tamper_sensor_status_t tamper_get_sensor_status(uint8_t sensor_id);

/**
 * Read raw sensor value
 *
 * @param sensor_id Sensor ID
 * @param value Output value
 * @return TAMPER_OK on success
 */
int tamper_read_sensor(uint8_t sensor_id, uint16_t *value);

/* ============================================================================
 * Detection and Monitoring
 * ============================================================================ */

/**
 * Poll all sensors (should be called periodically)
 *
 * @return Number of tamper events detected
 */
int tamper_poll(void);

/**
 * Check for active tamper condition
 *
 * @return TAMPER_TYPE_* bitmask of active conditions
 */
uint32_t tamper_check(void);

/**
 * Get current tamper state
 *
 * @param state Output state structure
 * @return TAMPER_OK on success
 */
int tamper_get_state(tamper_state_t *state);

/**
 * Check if device has been tampered
 *
 * @return 1 if tampered, 0 if clean
 */
int tamper_was_detected(void);

/**
 * Clear tamper flag (requires authentication)
 *
 * @return TAMPER_OK on success
 */
int tamper_clear_flag(void);

/* ============================================================================
 * Event Handling
 * ============================================================================ */

/**
 * Register tamper event callback
 *
 * @param callback Function to call on tamper event
 * @param user_data User data passed to callback
 * @return TAMPER_OK on success
 */
typedef void (*tamper_callback_t)(const tamper_event_t *event, void *user_data);
int tamper_register_callback(tamper_callback_t callback, void *user_data);

/**
 * Get last tamper event
 *
 * @param event Output event structure
 * @return TAMPER_OK if event available, error if no events
 */
int tamper_get_last_event(tamper_event_t *event);

/**
 * Get tamper event log
 *
 * @param events Output event array
 * @param max_events Maximum events to return
 * @return Number of events returned
 */
int tamper_get_event_log(tamper_event_t *events, size_t max_events);

/**
 * Clear tamper event log
 *
 * @return TAMPER_OK on success
 */
int tamper_clear_log(void);

/* ============================================================================
 * Response Actions
 * ============================================================================ */

/**
 * Execute tamper response
 *
 * @param actions TAMPER_ACTION_* bitmask
 * @return TAMPER_OK on success
 */
int tamper_execute_response(uint32_t actions);

/**
 * Lock device due to tamper
 *
 * @return TAMPER_OK on success
 */
int tamper_lock_device(void);

/**
 * Perform emergency key wipe
 *
 * @return TAMPER_OK on success
 */
int tamper_wipe_keys(void);

/* ============================================================================
 * Special Sensors
 * ============================================================================ */

/**
 * Initialize accelerometer for motion detection
 *
 * @param threshold Motion threshold (sensitivity)
 * @return TAMPER_OK on success
 */
int tamper_init_accelerometer(uint16_t threshold);

/**
 * Read accelerometer data
 *
 * @param data Output accelerometer data
 * @return TAMPER_OK on success
 */
int tamper_read_accelerometer(tamper_accel_t *data);

/**
 * Initialize light sensor
 *
 * @param threshold Light threshold
 * @return TAMPER_OK on success
 */
int tamper_init_light_sensor(uint16_t threshold);

/**
 * Read light sensor
 *
 * @param lux Output lux value
 * @return TAMPER_OK on success
 */
int tamper_read_light_sensor(uint16_t *lux);

/**
 * Initialize temperature monitoring
 *
 * @param min_temp Minimum allowed temperature (Celsius * 10)
 * @param max_temp Maximum allowed temperature (Celsius * 10)
 * @return TAMPER_OK on success
 */
int tamper_init_temperature(int16_t min_temp, int16_t max_temp);

/**
 * Read temperature
 *
 * @param temp Output temperature (Celsius * 10)
 * @return TAMPER_OK on success
 */
int tamper_read_temperature(int16_t *temp);

/* ============================================================================
 * Configuration
 * ============================================================================ */

/**
 * Save tamper configuration
 *
 * @param config Configuration to save
 * @return TAMPER_OK on success
 */
int tamper_save_config(const tamper_config_t *config);

/**
 * Load tamper configuration
 *
 * @param config Output configuration
 * @return TAMPER_OK on success
 */
int tamper_load_config(tamper_config_t *config);

/**
 * Reset configuration to defaults
 */
void tamper_default_config(tamper_config_t *config);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Get error message
 *
 * @param err Error code
 * @return Human-readable error message
 */
const char *tamper_error_string(int err);

/**
 * Get tamper type name
 *
 * @param type TAMPER_TYPE_* value
 * @return Type name string
 */
const char *tamper_type_string(uint32_t type);

/**
 * Get sensor status name
 *
 * @param status Sensor status
 * @return Status name string
 */
const char *tamper_status_string(tamper_sensor_status_t status);

#endif /* TAMPER_H */

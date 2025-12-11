/*
 * Tamper Detection Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L

#include "tamper.h"
#include "storage.h"
#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#ifdef HAVE_LIBGPIOD
#include <gpiod.h>
/* Use line_request for libgpiod v2 */
#endif

/* Configuration and state file names */
#define TAMPER_CONFIG_FILE    "tamper.cfg"
#define TAMPER_STATE_FILE     "tamper.state"
#define TAMPER_LOG_FILE       "tamper.log"

/* Maximum events in log */
#define TAMPER_MAX_LOG_EVENTS  256

/* Internal state */
static struct {
    tamper_config_t config;
    tamper_state_t state;
    tamper_sensor_status_t sensor_status[TAMPER_MAX_SENSORS];
    tamper_event_t last_event;
    int has_last_event;
    tamper_callback_t callback;
    void *callback_data;
    int initialized;
#ifdef HAVE_LIBGPIOD
    struct gpiod_chip *gpio_chip;
    struct gpiod_line_request *gpio_lines[TAMPER_MAX_SENSORS];
#endif
} g_tamper;

/* Error messages */
static const char *error_messages[] = {
    [0] = "Success",
    [1] = "Initialization error",
    [2] = "Sensor error",
    [3] = "GPIO error",
    [4] = "Configuration error",
    [5] = "Internal error",
};

/* Type names */
static const char *type_names[] = {
    "Case Open",
    "Mesh Break",
    "Glitch",
    "Temperature",
    "Light",
    "Motion",
    "Voltage",
    "Probe",
};

/* Status names */
static const char *status_names[] = {
    [SENSOR_STATUS_UNKNOWN]   = "Unknown",
    [SENSOR_STATUS_OK]        = "OK",
    [SENSOR_STATUS_TRIGGERED] = "Triggered",
    [SENSOR_STATUS_FAULT]     = "Fault",
    [SENSOR_STATUS_DISABLED]  = "Disabled",
};

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static void trigger_event(uint32_t type, uint8_t sensor_id,
                         uint8_t severity, uint16_t raw_value,
                         const char *description)
{
    tamper_event_t event = {0};
    event.timestamp = (uint32_t)time(NULL);
    event.type = type;
    event.sensor_id = sensor_id;
    event.severity = severity;
    event.raw_value = raw_value;

    if (description) {
        strncpy(event.description, description, sizeof(event.description) - 1);
    }

    /* Update state */
    g_tamper.state.status |= type;
    g_tamper.state.event_count++;
    g_tamper.state.last_event_time = event.timestamp;
    g_tamper.state.tampered = 1;

    /* Save event */
    memcpy(&g_tamper.last_event, &event, sizeof(tamper_event_t));
    g_tamper.has_last_event = 1;

    /* Log event */
    if (g_tamper.config.log_events) {
        char log_path[256];
        const char *storage_dir = storage_get_path();
        snprintf(log_path, sizeof(log_path), "%s/%s", storage_dir, TAMPER_LOG_FILE);

        FILE *f = fopen(log_path, "ab");
        if (f) {
            fwrite(&event, sizeof(event), 1, f);
            fclose(f);
        }
    }

    /* Execute response */
    uint32_t response = g_tamper.config.global_response;
    if (sensor_id < TAMPER_MAX_SENSORS) {
        response |= g_tamper.config.sensors[sensor_id].response;
    }
    tamper_execute_response(response);

    /* Call callback */
    if (g_tamper.callback) {
        g_tamper.callback(&event, g_tamper.callback_data);
    }
}

static int save_state(void)
{
    char state_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(state_path, sizeof(state_path), "%s/%s", storage_dir, TAMPER_STATE_FILE);

    FILE *f = fopen(state_path, "wb");
    if (!f) {
        return TAMPER_ERR_INTERNAL;
    }

    fwrite(&g_tamper.state, sizeof(g_tamper.state), 1, f);
    fclose(f);

    return TAMPER_OK;
}

static int load_state(void)
{
    char state_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(state_path, sizeof(state_path), "%s/%s", storage_dir, TAMPER_STATE_FILE);

    FILE *f = fopen(state_path, "rb");
    if (!f) {
        return TAMPER_ERR_INTERNAL;
    }

    if (fread(&g_tamper.state, sizeof(g_tamper.state), 1, f) != 1) {
        fclose(f);
        return TAMPER_ERR_INTERNAL;
    }

    fclose(f);
    return TAMPER_OK;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

int tamper_init(const tamper_config_t *config)
{
    if (g_tamper.initialized) {
        return TAMPER_OK;
    }

    memset(&g_tamper, 0, sizeof(g_tamper));

    /* Load or set configuration */
    if (config) {
        memcpy(&g_tamper.config, config, sizeof(tamper_config_t));
    } else if (tamper_load_config(&g_tamper.config) != TAMPER_OK) {
        tamper_default_config(&g_tamper.config);
    }

    /* Load existing state */
    if (load_state() != TAMPER_OK) {
        memset(&g_tamper.state, 0, sizeof(g_tamper.state));
    }

    /* Increment boot counter */
    g_tamper.state.boot_count++;

    /* Initialize GPIO for sensors */
#ifdef HAVE_LIBGPIOD
    if (g_tamper.config.enabled) {
        g_tamper.gpio_chip = gpiod_chip_open("/dev/gpiochip0");
        if (g_tamper.gpio_chip) {
            for (int i = 0; i < TAMPER_MAX_SENSORS; i++) {
                if (g_tamper.config.sensors[i].enabled) {
                    /* libgpiod v2 API: use line request */
                    struct gpiod_line_settings *settings = gpiod_line_settings_new();
                    if (settings) {
                        gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_INPUT);

                        struct gpiod_line_config *line_cfg = gpiod_line_config_new();
                        if (line_cfg) {
                            unsigned int offset = g_tamper.config.sensors[i].gpio_pin;
                            gpiod_line_config_add_line_settings(line_cfg, &offset, 1, settings);

                            struct gpiod_request_config *req_cfg = gpiod_request_config_new();
                            if (req_cfg) {
                                gpiod_request_config_set_consumer(req_cfg, "tamper_detect");
                                g_tamper.gpio_lines[i] = gpiod_chip_request_lines(
                                    g_tamper.gpio_chip, req_cfg, line_cfg);
                                gpiod_request_config_free(req_cfg);
                            }
                            gpiod_line_config_free(line_cfg);
                        }
                        gpiod_line_settings_free(settings);
                    }

                    if (g_tamper.gpio_lines[i]) {
                        g_tamper.sensor_status[i] = SENSOR_STATUS_OK;
                    } else {
                        g_tamper.sensor_status[i] = SENSOR_STATUS_FAULT;
                    }
                } else {
                    g_tamper.sensor_status[i] = SENSOR_STATUS_DISABLED;
                }
            }
        }
    }
#endif

    /* Set all sensors to unknown if GPIO not available */
    for (int i = 0; i < TAMPER_MAX_SENSORS; i++) {
        if (g_tamper.sensor_status[i] == SENSOR_STATUS_UNKNOWN) {
            if (g_tamper.config.sensors[i].enabled) {
                g_tamper.sensor_status[i] = SENSOR_STATUS_OK;  /* Simulated */
            } else {
                g_tamper.sensor_status[i] = SENSOR_STATUS_DISABLED;
            }
        }
    }

    g_tamper.initialized = 1;
    save_state();

    return TAMPER_OK;
}

void tamper_shutdown(void)
{
    if (!g_tamper.initialized) {
        return;
    }

#ifdef HAVE_LIBGPIOD
    for (int i = 0; i < TAMPER_MAX_SENSORS; i++) {
        if (g_tamper.gpio_lines[i]) {
            gpiod_line_request_release(g_tamper.gpio_lines[i]);
            g_tamper.gpio_lines[i] = NULL;
        }
    }
    if (g_tamper.gpio_chip) {
        gpiod_chip_close(g_tamper.gpio_chip);
        g_tamper.gpio_chip = NULL;
    }
#endif

    save_state();
    g_tamper.initialized = 0;
}

int tamper_is_enabled(void)
{
    return g_tamper.config.enabled;
}

/* ============================================================================
 * Sensor Management
 * ============================================================================ */

int tamper_configure_sensor(uint8_t sensor_id, const tamper_sensor_config_t *config)
{
    if (sensor_id >= TAMPER_MAX_SENSORS || config == NULL) {
        return TAMPER_ERR_CONFIG;
    }

    memcpy(&g_tamper.config.sensors[sensor_id], config, sizeof(tamper_sensor_config_t));

    if (config->enabled) {
        g_tamper.sensor_status[sensor_id] = SENSOR_STATUS_OK;
    } else {
        g_tamper.sensor_status[sensor_id] = SENSOR_STATUS_DISABLED;
    }

    return TAMPER_OK;
}

int tamper_enable_sensor(uint8_t sensor_id, int enable)
{
    if (sensor_id >= TAMPER_MAX_SENSORS) {
        return TAMPER_ERR_SENSOR;
    }

    g_tamper.config.sensors[sensor_id].enabled = enable ? 1 : 0;
    g_tamper.sensor_status[sensor_id] = enable ? SENSOR_STATUS_OK : SENSOR_STATUS_DISABLED;

    return TAMPER_OK;
}

tamper_sensor_status_t tamper_get_sensor_status(uint8_t sensor_id)
{
    if (sensor_id >= TAMPER_MAX_SENSORS) {
        return SENSOR_STATUS_UNKNOWN;
    }
    return g_tamper.sensor_status[sensor_id];
}

int tamper_read_sensor(uint8_t sensor_id, uint16_t *value)
{
    if (sensor_id >= TAMPER_MAX_SENSORS || value == NULL) {
        return TAMPER_ERR_SENSOR;
    }

    if (!g_tamper.config.sensors[sensor_id].enabled) {
        return TAMPER_ERR_SENSOR;
    }

#ifdef HAVE_LIBGPIOD
    if (g_tamper.gpio_lines[sensor_id]) {
        enum gpiod_line_value gpio_val = gpiod_line_request_get_value(
            g_tamper.gpio_lines[sensor_id],
            g_tamper.config.sensors[sensor_id].gpio_pin);

        if (gpio_val == GPIOD_LINE_VALUE_ERROR) {
            g_tamper.sensor_status[sensor_id] = SENSOR_STATUS_FAULT;
            return TAMPER_ERR_GPIO;
        }

        int gpio_value = (gpio_val == GPIOD_LINE_VALUE_ACTIVE) ? 1 : 0;

        /* Handle active low */
        if (g_tamper.config.sensors[sensor_id].active_low) {
            gpio_value = !gpio_value;
        }

        *value = (uint16_t)(gpio_value ? 1 : 0);
        return TAMPER_OK;
    }
#endif

    /* Simulated: return 0 (no tamper) */
    *value = 0;
    return TAMPER_OK;
}

/* ============================================================================
 * Detection and Monitoring
 * ============================================================================ */

int tamper_poll(void)
{
    if (!g_tamper.initialized || !g_tamper.config.enabled) {
        return 0;
    }

    int events_detected = 0;

    for (uint8_t i = 0; i < TAMPER_MAX_SENSORS; i++) {
        if (!g_tamper.config.sensors[i].enabled) {
            continue;
        }

        uint16_t value;
        if (tamper_read_sensor(i, &value) != TAMPER_OK) {
            continue;
        }

        /* Check threshold */
        if (value >= g_tamper.config.sensors[i].threshold) {
            uint32_t type = (1U << i);  /* Map sensor ID to type */
            g_tamper.sensor_status[i] = SENSOR_STATUS_TRIGGERED;
            trigger_event(type, i, (uint8_t)(value > 127 ? 255 : value * 2),
                         value, "Sensor threshold exceeded");
            events_detected++;
        }
    }

    return events_detected;
}

uint32_t tamper_check(void)
{
    tamper_poll();
    return g_tamper.state.status;
}

int tamper_get_state(tamper_state_t *state)
{
    if (state == NULL) {
        return TAMPER_ERR_INTERNAL;
    }

    memcpy(state, &g_tamper.state, sizeof(tamper_state_t));
    return TAMPER_OK;
}

int tamper_was_detected(void)
{
    return g_tamper.state.tampered;
}

int tamper_clear_flag(void)
{
    g_tamper.state.status = 0;
    g_tamper.state.tampered = 0;
    g_tamper.state.locked = 0;

    /* Reset sensor status */
    for (int i = 0; i < TAMPER_MAX_SENSORS; i++) {
        if (g_tamper.sensor_status[i] == SENSOR_STATUS_TRIGGERED) {
            g_tamper.sensor_status[i] = SENSOR_STATUS_OK;
        }
    }

    return save_state();
}

/* ============================================================================
 * Event Handling
 * ============================================================================ */

int tamper_register_callback(tamper_callback_t callback, void *user_data)
{
    g_tamper.callback = callback;
    g_tamper.callback_data = user_data;
    return TAMPER_OK;
}

int tamper_get_last_event(tamper_event_t *event)
{
    if (event == NULL || !g_tamper.has_last_event) {
        return TAMPER_ERR_INTERNAL;
    }

    memcpy(event, &g_tamper.last_event, sizeof(tamper_event_t));
    return TAMPER_OK;
}

int tamper_get_event_log(tamper_event_t *events, size_t max_events)
{
    if (events == NULL || max_events == 0) {
        return 0;
    }

    char log_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(log_path, sizeof(log_path), "%s/%s", storage_dir, TAMPER_LOG_FILE);

    FILE *f = fopen(log_path, "rb");
    if (!f) {
        return 0;
    }

    int count = 0;
    while ((size_t)count < max_events) {
        if (fread(&events[count], sizeof(tamper_event_t), 1, f) != 1) {
            break;
        }
        count++;
    }

    fclose(f);
    return count;
}

int tamper_clear_log(void)
{
    char log_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(log_path, sizeof(log_path), "%s/%s", storage_dir, TAMPER_LOG_FILE);

    remove(log_path);
    return TAMPER_OK;
}

/* ============================================================================
 * Response Actions
 * ============================================================================ */

int tamper_execute_response(uint32_t actions)
{
    if (actions & TAMPER_ACTION_LOG) {
        /* Already logged in trigger_event */
    }

    if (actions & TAMPER_ACTION_ALERT) {
        printf("\n[TAMPER ALERT] Security breach detected!\n");
    }

    if (actions & TAMPER_ACTION_LOCK) {
        tamper_lock_device();
    }

    if (actions & TAMPER_ACTION_WIPE_KEYS) {
        tamper_wipe_keys();
    }

    if (actions & TAMPER_ACTION_WIPE_ALL) {
        /* Wipe wallet and all storage */
        storage_wipe_wallet();
    }

    if (actions & TAMPER_ACTION_SHUTDOWN) {
        printf("[TAMPER] Device shutting down...\n");
        /* In real implementation: trigger system shutdown */
    }

    if (actions & TAMPER_ACTION_BRICK) {
        printf("[TAMPER] Device permanently disabled!\n");
        /* In real implementation: fuse blow or permanent lockout */
        g_tamper.state.wiped = 1;
        save_state();
    }

    return TAMPER_OK;
}

int tamper_lock_device(void)
{
    g_tamper.state.locked = 1;
    save_state();
    return TAMPER_OK;
}

int tamper_wipe_keys(void)
{
    printf("[TAMPER] Emergency key wipe initiated!\n");

    /* Wipe wallet data */
    const char *storage_dir = storage_get_path();
    char path[256];

    /* Remove wallet file */
    snprintf(path, sizeof(path), "%s/wallet.enc", storage_dir);
    /* Overwrite with zeros before removal */
    FILE *f = fopen(path, "r+b");
    if (f) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t zeros[4096] = {0};
        while (size > 0) {
            size_t chunk = (size_t)size > sizeof(zeros) ? sizeof(zeros) : (size_t)size;
            fwrite(zeros, 1, chunk, f);
            size -= (long)chunk;
        }
        fclose(f);
        remove(path);
    }

    g_tamper.state.wiped = 1;
    save_state();

    return TAMPER_OK;
}

/* ============================================================================
 * Special Sensors (simulated for now)
 * ============================================================================ */

int tamper_init_accelerometer(uint16_t threshold)
{
    /* In real implementation: initialize I2C accelerometer */
    (void)threshold;
    return TAMPER_OK;
}

int tamper_read_accelerometer(tamper_accel_t *data)
{
    if (data == NULL) {
        return TAMPER_ERR_INTERNAL;
    }

    /* Simulated: return static values */
    data->x = 0;
    data->y = 0;
    data->z = 1000;  /* 1g down */

    return TAMPER_OK;
}

int tamper_init_light_sensor(uint16_t threshold)
{
    (void)threshold;
    return TAMPER_OK;
}

int tamper_read_light_sensor(uint16_t *lux)
{
    if (lux == NULL) {
        return TAMPER_ERR_INTERNAL;
    }

    /* Simulated: dark (case closed) */
    *lux = 0;

    return TAMPER_OK;
}

int tamper_init_temperature(int16_t min_temp, int16_t max_temp)
{
    (void)min_temp;
    (void)max_temp;
    return TAMPER_OK;
}

int tamper_read_temperature(int16_t *temp)
{
    if (temp == NULL) {
        return TAMPER_ERR_INTERNAL;
    }

    /* Simulated: 25°C */
    *temp = 250;

    return TAMPER_OK;
}

/* ============================================================================
 * Configuration
 * ============================================================================ */

int tamper_save_config(const tamper_config_t *config)
{
    if (config == NULL) {
        return TAMPER_ERR_CONFIG;
    }

    char config_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(config_path, sizeof(config_path), "%s/%s", storage_dir, TAMPER_CONFIG_FILE);

    FILE *f = fopen(config_path, "wb");
    if (!f) {
        return TAMPER_ERR_INTERNAL;
    }

    fwrite(config, sizeof(tamper_config_t), 1, f);
    fclose(f);

    memcpy(&g_tamper.config, config, sizeof(tamper_config_t));

    return TAMPER_OK;
}

int tamper_load_config(tamper_config_t *config)
{
    if (config == NULL) {
        return TAMPER_ERR_CONFIG;
    }

    char config_path[256];
    const char *storage_dir = storage_get_path();
    snprintf(config_path, sizeof(config_path), "%s/%s", storage_dir, TAMPER_CONFIG_FILE);

    FILE *f = fopen(config_path, "rb");
    if (!f) {
        return TAMPER_ERR_INTERNAL;
    }

    if (fread(config, sizeof(tamper_config_t), 1, f) != 1) {
        fclose(f);
        return TAMPER_ERR_INTERNAL;
    }

    fclose(f);
    return TAMPER_OK;
}

void tamper_default_config(tamper_config_t *config)
{
    if (config == NULL) {
        return;
    }

    memset(config, 0, sizeof(tamper_config_t));
    config->version = 1;
    config->enabled = 0;  /* Disabled by default */
    config->paranoid_mode = 0;
    config->log_events = 1;
    config->global_response = TAMPER_ACTION_LOG | TAMPER_ACTION_ALERT | TAMPER_ACTION_LOCK;

    /* Configure default sensors */
    /* Sensor 0: Case open switch */
    config->sensors[0].enabled = 0;
    config->sensors[0].gpio_pin = 17;
    config->sensors[0].active_low = 1;
    config->sensors[0].debounce_ms = 50;
    config->sensors[0].threshold = 1;
    config->sensors[0].response = TAMPER_ACTION_LOG | TAMPER_ACTION_ALERT;

    /* Sensor 1: Motion detection */
    config->sensors[1].enabled = 0;
    config->sensors[1].gpio_pin = 27;
    config->sensors[1].active_low = 0;
    config->sensors[1].debounce_ms = 100;
    config->sensors[1].threshold = 1;
    config->sensors[1].response = TAMPER_ACTION_LOG;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char *tamper_error_string(int err)
{
    if (err < 0) {
        err = -err;
    }
    if (err < (int)(sizeof(error_messages) / sizeof(error_messages[0]))) {
        return error_messages[err];
    }
    return "Unknown error";
}

const char *tamper_type_string(uint32_t type)
{
    /* Find first set bit */
    for (int i = 0; i < 8; i++) {
        if (type & (1U << i)) {
            return type_names[i];
        }
    }
    return "Unknown";
}

const char *tamper_status_string(tamper_sensor_status_t status)
{
    if (status < sizeof(status_names) / sizeof(status_names[0])) {
        return status_names[status];
    }
    return "Unknown";
}

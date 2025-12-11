/*
 * Hardware Setup Wizard
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Interactive setup wizard for configuring hardware:
 * - Display (terminal, framebuffer, DRM)
 * - Input (terminal keyboard, evdev, GPIO buttons)
 * - Camera (V4L2 devices for QR scanning)
 * - Fingerprint reader
 */

#ifndef SETUP_H
#define SETUP_H

#include <stdint.h>
#include "../hw/hwconfig.h"

/* Setup wizard result */
typedef enum {
    SETUP_OK = 0,
    SETUP_CANCELLED,
    SETUP_ERROR,
    SETUP_SKIP
} setup_result_t;

/* Device info for selection */
typedef struct {
    char path[256];
    char name[128];
    char description[256];
} setup_device_t;

#define SETUP_MAX_DEVICES 16

/* ============================================================================
 * Main Setup Functions
 * ============================================================================ */

/**
 * Run the complete setup wizard
 *
 * Guides user through configuring all hardware components.
 * Saves configuration to file when complete.
 *
 * @param config Configuration to populate
 * @return SETUP_OK on success
 */
setup_result_t setup_run_wizard(hwconfig_t *config);

/**
 * Run setup wizard for first-time setup only
 *
 * Checks if configuration exists, runs wizard if not.
 *
 * @param config Configuration to populate
 * @return SETUP_OK if configured, SETUP_SKIP if already configured
 */
setup_result_t setup_first_time(hwconfig_t *config);

/* ============================================================================
 * Individual Setup Steps
 * ============================================================================ */

/**
 * Setup display configuration
 *
 * @param config Configuration to update
 * @return SETUP_OK on success
 */
setup_result_t setup_display(hwconfig_t *config);

/**
 * Setup input/button configuration
 *
 * Allows user to:
 * - Select input mode (terminal, evdev, GPIO)
 * - Select input device
 * - Map physical buttons to actions
 *
 * @param config Configuration to update
 * @return SETUP_OK on success
 */
setup_result_t setup_input(hwconfig_t *config);

/**
 * Setup camera for QR scanning
 *
 * @param camera_device Output: selected camera device path
 * @param device_len Size of camera_device buffer
 * @return SETUP_OK on success, SETUP_SKIP if no camera
 */
setup_result_t setup_camera(char *camera_device, size_t device_len);

/**
 * Setup fingerprint reader
 *
 * @return SETUP_OK on success, SETUP_SKIP if no reader
 */
setup_result_t setup_fingerprint(void);

/**
 * Button mapping wizard
 *
 * Prompts user to press each button to map it to an action.
 *
 * @param config Configuration to update
 * @return SETUP_OK on success
 */
setup_result_t setup_button_mapping(hwconfig_t *config);

/* ============================================================================
 * Device Detection
 * ============================================================================ */

/**
 * Detect available displays
 *
 * @param devices Output array of detected devices
 * @param max_devices Maximum devices to return
 * @return Number of devices found
 */
int setup_detect_displays(setup_device_t *devices, int max_devices);

/**
 * Detect available input devices
 *
 * @param devices Output array of detected devices
 * @param max_devices Maximum devices to return
 * @return Number of devices found
 */
int setup_detect_inputs(setup_device_t *devices, int max_devices);

/**
 * Detect available cameras
 *
 * @param devices Output array of detected devices
 * @param max_devices Maximum devices to return
 * @return Number of devices found
 */
int setup_detect_cameras(setup_device_t *devices, int max_devices);

/**
 * Detect fingerprint readers
 *
 * @param devices Output array of detected devices
 * @param max_devices Maximum devices to return
 * @return Number of devices found
 */
int setup_detect_fingerprint(setup_device_t *devices, int max_devices);

/* ============================================================================
 * Test Functions
 * ============================================================================ */

/**
 * Test display configuration
 *
 * Shows test pattern on selected display.
 *
 * @param config Configuration to test
 * @return SETUP_OK if display works
 */
setup_result_t setup_test_display(const hwconfig_t *config);

/**
 * Test button input
 *
 * Waits for button press and shows which button was pressed.
 *
 * @param config Configuration to test
 * @return SETUP_OK if buttons work
 */
setup_result_t setup_test_buttons(const hwconfig_t *config);

/**
 * Test camera
 *
 * Captures a frame and tries to decode QR code.
 *
 * @param device Camera device path
 * @return SETUP_OK if camera works
 */
setup_result_t setup_test_camera(const char *device);

/**
 * Test fingerprint reader
 *
 * Prompts for fingerprint scan.
 *
 * @return SETUP_OK if reader works
 */
setup_result_t setup_test_fingerprint(void);

#endif /* SETUP_H */

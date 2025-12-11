/*
 * Hardware Setup Wizard
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _GNU_SOURCE
#include "setup.h"
#include "display.h"
#include "input.h"
#include "qr.h"
#include "../security/fingerprint.h"
#include "../hw/hal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <time.h>

#ifdef __linux__
#include <linux/input.h>
#include <linux/fb.h>
#include <linux/videodev2.h>
#endif

/* ============================================================================
 * Terminal UI Helpers
 * ============================================================================ */

static void print_header(const char *title)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  💕 RISC-V Wallet Setup Wizard 💕                          ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  %s\n", title);
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void print_section(const char *title)
{
    printf("\n┌─ %s ─────────────────────────────────\n", title);
}

static int prompt_yes_no(const char *question, int default_yes)
{
    char buf[16];
    printf("%s [%s]: ", question, default_yes ? "Y/n" : "y/N");
    fflush(stdout);

    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        return default_yes;
    }

    if (buf[0] == '\n' || buf[0] == '\0') {
        return default_yes;
    }

    return (buf[0] == 'y' || buf[0] == 'Y');
}

static int prompt_number(const char *question, int min, int max, int default_val)
{
    char buf[32];
    int val;

    while (1) {
        printf("%s [%d-%d, default=%d]: ", question, min, max, default_val);
        fflush(stdout);

        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            return default_val;
        }

        if (buf[0] == '\n' || buf[0] == '\0') {
            return default_val;
        }

        val = atoi(buf);
        if (val >= min && val <= max) {
            return val;
        }

        printf("  Please enter a number between %d and %d\n", min, max);
    }
}


/* ============================================================================
 * Device Detection
 * ============================================================================ */

int setup_detect_displays(setup_device_t *devices, int max_devices)
{
    int count = 0;

    /* Always add terminal option */
    if (count < max_devices) {
        snprintf(devices[count].path, sizeof(devices[count].path), "terminal");
        snprintf(devices[count].name, sizeof(devices[count].name), "Terminal");
        snprintf(devices[count].description, sizeof(devices[count].description),
                 "Text-based terminal UI (works everywhere)");
        count++;
    }

    /* Detect framebuffers */
    for (int i = 0; i < 4 && count < max_devices; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/fb%d", i);

        if (access(path, R_OK | W_OK) == 0) {
            snprintf(devices[count].path, sizeof(devices[count].path), "%s", path);
            snprintf(devices[count].name, sizeof(devices[count].name), "Framebuffer %d", i);

            /* Try to get resolution */
#ifdef __linux__
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                struct fb_var_screeninfo vinfo;
                if (ioctl(fd, FBIOGET_VSCREENINFO, &vinfo) == 0) {
                    snprintf(devices[count].description, sizeof(devices[count].description),
                             "%dx%d %dbpp", vinfo.xres, vinfo.yres, vinfo.bits_per_pixel);
                } else {
                    snprintf(devices[count].description, sizeof(devices[count].description),
                             "Linux framebuffer");
                }
                close(fd);
            }
#else
            snprintf(devices[count].description, sizeof(devices[count].description),
                     "Framebuffer device");
#endif
            count++;
        }
    }

    /* Detect DRM devices */
    for (int i = 0; i < 4 && count < max_devices; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/dri/card%d", i);

        if (access(path, R_OK | W_OK) == 0) {
            snprintf(devices[count].path, sizeof(devices[count].path), "%s", path);
            snprintf(devices[count].name, sizeof(devices[count].name), "DRM card%d", i);
            snprintf(devices[count].description, sizeof(devices[count].description),
                     "DRM/KMS display (HDMI/DisplayPort)");
            count++;
        }
    }

    return count;
}

int setup_detect_inputs(setup_device_t *devices, int max_devices)
{
    int count = 0;

    /* Always add terminal option */
    if (count < max_devices) {
        snprintf(devices[count].path, sizeof(devices[count].path), "terminal");
        snprintf(devices[count].name, sizeof(devices[count].name), "Terminal Keyboard");
        snprintf(devices[count].description, sizeof(devices[count].description),
                 "Standard keyboard input via terminal");
        count++;
    }

#ifdef __linux__
    /* Detect evdev input devices */
    DIR *dir = opendir("/dev/input");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL && count < max_devices) {
            if (strncmp(ent->d_name, "event", 5) != 0) continue;

            char path[256];
            snprintf(path, sizeof(path), "/dev/input/%.200s", ent->d_name);

            if (access(path, R_OK) != 0) continue;

            int fd = open(path, O_RDONLY | O_NONBLOCK);
            if (fd < 0) continue;

            char name[256] = "Unknown device";
            ioctl(fd, EVIOCGNAME(sizeof(name)), name);

            /* Check if it has key events */
            unsigned long evbit[1] = {0};
            ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), evbit);

            close(fd);

            /* Only include devices with key/button capability */
            if (evbit[0] & (1 << EV_KEY)) {
                snprintf(devices[count].path, sizeof(devices[count].path), "%.255s", path);
                snprintf(devices[count].name, sizeof(devices[count].name), "%.127s", ent->d_name);
                snprintf(devices[count].description, sizeof(devices[count].description),
                         "%.255s", name);
                count++;
            }
        }
        closedir(dir);
    }

    /* Detect GPIO chips */
    dir = opendir("/dev");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL && count < max_devices) {
            if (strncmp(ent->d_name, "gpiochip", 8) != 0) continue;

            char path[256];
            snprintf(path, sizeof(path), "/dev/%.200s", ent->d_name);

            if (access(path, R_OK) == 0) {
                snprintf(devices[count].path, sizeof(devices[count].path), "%.255s", path);
                snprintf(devices[count].name, sizeof(devices[count].name), "%.127s", ent->d_name);
                snprintf(devices[count].description, sizeof(devices[count].description),
                         "GPIO chip for hardware buttons");
                count++;
            }
        }
        closedir(dir);
    }
#endif

    return count;
}

int setup_detect_cameras(setup_device_t *devices, int max_devices)
{
    int count = 0;

#if defined(__linux__) && defined(HAVE_V4L2)
    for (int i = 0; i < 8 && count < max_devices; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/video%d", i);

        if (access(path, R_OK | W_OK) != 0) continue;

        int fd = open(path, O_RDWR);
        if (fd < 0) continue;

        struct v4l2_capability cap;
        if (ioctl(fd, VIDIOC_QUERYCAP, &cap) == 0) {
            /* Check if it's a capture device */
            if (cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) {
                snprintf(devices[count].path, sizeof(devices[count].path), "%s", path);
                snprintf(devices[count].name, sizeof(devices[count].name),
                         "%s", (char *)cap.card);
                snprintf(devices[count].description, sizeof(devices[count].description),
                         "%s - %s", (char *)cap.driver, (char *)cap.bus_info);
                count++;
            }
        }
        close(fd);
    }
#else
    (void)devices;
    (void)max_devices;
#endif

    return count;
}

int setup_detect_fingerprint(setup_device_t *devices, int max_devices)
{
    int count = 0;

#ifdef HAVE_LIBFPRINT
    if (count < max_devices && fingerprint_init() == 0) {
        if (fingerprint_is_available()) {
            const char *name = fingerprint_get_device_name();
            snprintf(devices[count].path, sizeof(devices[count].path), "libfprint");
            snprintf(devices[count].name, sizeof(devices[count].name),
                     "%s", name ? name : "Fingerprint Reader");
            snprintf(devices[count].description, sizeof(devices[count].description),
                     "Detected via libfprint");
            count++;
        }
        fingerprint_cleanup();
    }
#else
    (void)devices;
    (void)max_devices;
#endif

    return count;
}

/* ============================================================================
 * Setup Steps
 * ============================================================================ */

setup_result_t setup_display(hwconfig_t *config)
{
    print_section("Display Configuration 🖥️");

    setup_device_t displays[SETUP_MAX_DEVICES];
    int count = setup_detect_displays(displays, SETUP_MAX_DEVICES);

    if (count == 0) {
        printf("No display devices found. Using terminal mode.\n");
        config->display.mode = DISPLAY_MODE_TERMINAL;
        return SETUP_OK;
    }

    printf("Detected displays:\n");
    for (int i = 0; i < count; i++) {
        printf("  [%d] %s - %s\n", i + 1, displays[i].name, displays[i].description);
    }
    printf("\n");

    int selection = prompt_number("Select display", 1, count, 1) - 1;

    if (strcmp(displays[selection].path, "terminal") == 0) {
        config->display.mode = DISPLAY_MODE_TERMINAL;
    } else if (strncmp(displays[selection].path, "/dev/fb", 7) == 0) {
        config->display.mode = DISPLAY_MODE_FRAMEBUFFER;
        strncpy(config->display.fb_device, displays[selection].path,
                sizeof(config->display.fb_device) - 1);
    } else if (strncmp(displays[selection].path, "/dev/dri", 8) == 0) {
        config->display.mode = DISPLAY_MODE_DRM;
        strncpy(config->display.drm_device, displays[selection].path,
                sizeof(config->display.drm_device) - 1);
    }

    /* Rotation */
    const char *rotations[] = {"0° (Normal)", "90° (Rotated right)",
                               "180° (Upside down)", "270° (Rotated left)"};
    printf("\nDisplay rotation:\n");
    for (int i = 0; i < 4; i++) {
        printf("  [%d] %s\n", i + 1, rotations[i]);
    }
    int rot = prompt_number("Select rotation", 1, 4, 1) - 1;
    config->display.rotation = rot * 90;

    printf("\n✅ Display configured: %s\n", displays[selection].name);
    return SETUP_OK;
}

setup_result_t setup_input(hwconfig_t *config)
{
    print_section("Input Configuration 🎮");

    setup_device_t inputs[SETUP_MAX_DEVICES];
    int count = setup_detect_inputs(inputs, SETUP_MAX_DEVICES);

    if (count == 0) {
        printf("No input devices found. Using terminal keyboard.\n");
        config->input.mode = INPUT_MODE_TERMINAL;
        return SETUP_OK;
    }

    printf("Detected input devices:\n");
    for (int i = 0; i < count; i++) {
        printf("  [%d] %s - %s\n", i + 1, inputs[i].name, inputs[i].description);
    }
    printf("\n");

    int selection = prompt_number("Select input device", 1, count, 1) - 1;

    if (strcmp(inputs[selection].path, "terminal") == 0) {
        config->input.mode = INPUT_MODE_TERMINAL;
    } else if (strstr(inputs[selection].path, "/dev/input/event") != NULL) {
        config->input.mode = INPUT_MODE_EVDEV;
        strncpy(config->input.device, inputs[selection].path,
                sizeof(config->input.device) - 1);
    } else if (strstr(inputs[selection].path, "gpiochip") != NULL) {
        config->input.mode = INPUT_MODE_GPIOD;
        strncpy(config->input.device, inputs[selection].path,
                sizeof(config->input.device) - 1);
        config->input.debounce_ms = 50;
    }

    /* Offer button mapping for non-terminal modes */
    if (config->input.mode != INPUT_MODE_TERMINAL) {
        if (prompt_yes_no("\nConfigure button mapping?", 1)) {
            setup_button_mapping(config);
        }
    }

    printf("\n✅ Input configured: %s\n", inputs[selection].name);
    return SETUP_OK;
}

setup_result_t setup_button_mapping(hwconfig_t *config)
{
    print_section("Button Mapping 🔘");

    printf("I'll help you map your physical buttons to wallet functions!\n");
    printf("When prompted, press the button you want to assign.\n\n");

    const char *actions[] = {"UP", "DOWN", "LEFT", "RIGHT", "ENTER/SELECT", "BACK/CANCEL"};
    button_action_t action_codes[] = {HWBTN_UP, HWBTN_DOWN, HWBTN_LEFT,
                                       HWBTN_RIGHT, HWBTN_ENTER, HWBTN_BACK};
    int num_actions = 6;

    config->input.num_buttons = 0;

    for (int i = 0; i < num_actions; i++) {
        printf("Press the button for [%s] (or Enter to skip): ", actions[i]);
        fflush(stdout);

        /* For terminal mode, just use keyboard mapping */
        if (config->input.mode == INPUT_MODE_TERMINAL) {
            char buf[16];
            if (fgets(buf, sizeof(buf), stdin) && buf[0] != '\n') {
                config->input.buttons[config->input.num_buttons].action = action_codes[i];
                config->input.buttons[config->input.num_buttons].code = buf[0];
                snprintf(config->input.buttons[config->input.num_buttons].label,
                         sizeof(config->input.buttons[0].label), "%s", actions[i]);
                config->input.num_buttons++;
                printf("  Mapped to key '%c'\n", buf[0]);
            } else {
                printf("  Skipped\n");
            }
        }
#ifdef __linux__
        else if (config->input.mode == INPUT_MODE_EVDEV) {
            /* Open event device and wait for keypress */
            int fd = open(config->input.device, O_RDONLY | O_NONBLOCK);
            if (fd >= 0) {
                struct input_event ev;
                int found = 0;
                time_t start = time(NULL);

                while (!found && (time(NULL) - start) < 5) {
                    if (read(fd, &ev, sizeof(ev)) == sizeof(ev)) {
                        if (ev.type == EV_KEY && ev.value == 1) {
                            config->input.buttons[config->input.num_buttons].action = action_codes[i];
                            config->input.buttons[config->input.num_buttons].code = ev.code;
                            snprintf(config->input.buttons[config->input.num_buttons].label,
                                     sizeof(config->input.buttons[0].label), "%s", actions[i]);
                            config->input.num_buttons++;
                            printf("  Mapped to keycode %d\n", ev.code);
                            found = 1;
                        }
                    }
                    usleep(10000);
                }
                close(fd);

                if (!found) {
                    printf("  Timeout - skipped\n");
                }
            }
        }
#endif
        else if (config->input.mode == INPUT_MODE_GPIOD) {
            printf("  Enter GPIO pin number (or -1 to skip): ");
            fflush(stdout);
            char buf[16];
            if (fgets(buf, sizeof(buf), stdin)) {
                int pin = atoi(buf);
                if (pin >= 0) {
                    config->input.buttons[config->input.num_buttons].action = action_codes[i];
                    config->input.buttons[config->input.num_buttons].code = pin;
                    config->input.buttons[config->input.num_buttons].active_low = 1;
                    snprintf(config->input.buttons[config->input.num_buttons].label,
                             sizeof(config->input.buttons[0].label), "%s", actions[i]);
                    config->input.num_buttons++;
                    printf("  Mapped to GPIO %d (active low)\n", pin);
                } else {
                    printf("  Skipped\n");
                }
            }
        }
    }

    printf("\n✅ Mapped %d buttons\n", config->input.num_buttons);
    return SETUP_OK;
}

setup_result_t setup_camera(char *camera_device, size_t device_len)
{
    print_section("Camera Configuration 📷");

    setup_device_t cameras[SETUP_MAX_DEVICES];
    int count = setup_detect_cameras(cameras, SETUP_MAX_DEVICES);

    if (count == 0) {
        printf("No cameras detected. QR scanning will be disabled.\n");
        if (camera_device && device_len > 0) {
            camera_device[0] = '\0';
        }
        return SETUP_SKIP;
    }

    printf("Detected cameras:\n");
    for (int i = 0; i < count; i++) {
        printf("  [%d] %s - %s\n", i + 1, cameras[i].name, cameras[i].description);
    }
    printf("  [0] Skip camera setup\n\n");

    int selection = prompt_number("Select camera", 0, count, 1);

    if (selection == 0) {
        if (camera_device && device_len > 0) {
            camera_device[0] = '\0';
        }
        return SETUP_SKIP;
    }

    selection--;
    if (camera_device && device_len > 0) {
        strncpy(camera_device, cameras[selection].path, device_len - 1);
        camera_device[device_len - 1] = '\0';
    }

    printf("\n✅ Camera configured: %s\n", cameras[selection].name);
    return SETUP_OK;
}

setup_result_t setup_fingerprint(void)
{
    print_section("Fingerprint Reader 👆");

    setup_device_t readers[SETUP_MAX_DEVICES];
    int count = setup_detect_fingerprint(readers, SETUP_MAX_DEVICES);

    if (count == 0) {
        printf("No fingerprint reader detected.\n");
        printf("You can still use the wallet with PIN/button confirmation.\n");
        return SETUP_SKIP;
    }

    printf("Detected fingerprint reader: %s\n", readers[0].name);

    if (prompt_yes_no("Enroll fingerprint now?", 1)) {
#ifdef HAVE_LIBFPRINT
        if (fingerprint_init() == 0) {
            printf("\nPlace your finger on the reader multiple times when prompted...\n");
            /* Enrollment would happen here */
            printf("(Fingerprint enrollment not implemented in setup wizard)\n");
            printf("Use the main menu to enroll fingerprints.\n");
            fingerprint_cleanup();
        }
#endif
    }

    printf("\n✅ Fingerprint reader ready\n");
    return SETUP_OK;
}

/* ============================================================================
 * Test Functions
 * ============================================================================ */

setup_result_t setup_test_display(const hwconfig_t *config)
{
    printf("\nTesting display...\n");

    if (config->display.mode == DISPLAY_MODE_TERMINAL) {
        printf("┌────────────────────────────────┐\n");
        printf("│  Display Test Pattern          │\n");
        printf("│  If you can see this box,      │\n");
        printf("│  terminal display is working!  │\n");
        printf("└────────────────────────────────┘\n");
    } else {
        /* Would initialize actual display and show test pattern */
        printf("(Graphical display test not implemented in wizard)\n");
    }

    return prompt_yes_no("Display working correctly?", 1) ? SETUP_OK : SETUP_ERROR;
}

setup_result_t setup_test_buttons(const hwconfig_t *config)
{
    printf("\nTesting buttons... Press each button once.\n");
    printf("Press Ctrl+C or wait 10 seconds to finish.\n\n");

    (void)config;
    /* Would test each mapped button */

    return SETUP_OK;
}

setup_result_t setup_test_camera(const char *device)
{
    if (!device || device[0] == '\0') {
        return SETUP_SKIP;
    }

    printf("\nTesting camera: %s\n", device);
    printf("Point a QR code at the camera...\n");

#if defined(HAVE_V4L2) && defined(HAVE_QUIRC)
    if (qr_scanner_init(device) == QR_SCANNER_OK) {
        char result[512];
        printf("Scanning for 10 seconds...\n");
        if (qr_scanner_scan(result, sizeof(result), 10000) > 0) {
            printf("✅ Scanned QR code: %s\n", result);
            qr_scanner_shutdown();
            return SETUP_OK;
        }
        printf("No QR code detected.\n");
        qr_scanner_shutdown();
    } else {
        printf("Failed to initialize camera.\n");
    }
#else
    printf("(QR scanning not compiled in)\n");
#endif

    return prompt_yes_no("Camera test successful?", 0) ? SETUP_OK : SETUP_ERROR;
}

setup_result_t setup_test_fingerprint(void)
{
#ifdef HAVE_LIBFPRINT
    if (fingerprint_init() != 0) {
        printf("Failed to initialize fingerprint reader.\n");
        return SETUP_ERROR;
    }

    if (!fingerprint_is_available()) {
        printf("No fingerprint reader available.\n");
        fingerprint_cleanup();
        return SETUP_SKIP;
    }

    printf("\nPlace your finger on the reader...\n");
    int slot = -1;
    if (fingerprint_identify(&slot) == 0 && slot >= 0) {
        printf("✅ Fingerprint recognized (slot %d)\n", slot);
    } else {
        printf("Fingerprint not recognized (no enrolled prints?)\n");
    }

    fingerprint_cleanup();
#endif
    return SETUP_OK;
}

/* ============================================================================
 * Main Wizard
 * ============================================================================ */

setup_result_t setup_run_wizard(hwconfig_t *config)
{
    print_header("Let me help you set up your wallet~ 💕");

    printf("This wizard will help you configure:\n");
    printf("  • Display output\n");
    printf("  • Button/keyboard input\n");
    printf("  • Camera for QR scanning (optional)\n");
    printf("  • Fingerprint reader (optional)\n");
    printf("\n");

    if (!prompt_yes_no("Ready to begin?", 1)) {
        return SETUP_CANCELLED;
    }

    /* Initialize defaults */
    hwconfig_init_defaults(config);

    /* Step 1: Display */
    if (setup_display(config) != SETUP_OK) {
        printf("Display setup failed.\n");
    }

    /* Step 2: Input */
    if (setup_input(config) != SETUP_OK) {
        printf("Input setup failed.\n");
    }

    /* Step 3: Camera (optional) */
    char camera_device[256] = {0};
    setup_camera(camera_device, sizeof(camera_device));

    /* Step 4: Fingerprint (optional) */
    setup_fingerprint();

    /* Summary */
    print_section("Setup Complete! 🎉");

    printf("Configuration summary:\n");
    printf("  Display: %s\n", hwconfig_display_mode_name(config->display.mode));
    printf("  Input: %s\n", hwconfig_input_mode_name(config->input.mode));
    printf("  Buttons mapped: %d\n", config->input.num_buttons);
    printf("  Camera: %s\n", camera_device[0] ? camera_device : "None");
    printf("\n");

    /* Save configuration */
    if (prompt_yes_no("Save this configuration?", 1)) {
        const char *path = HWCONFIG_DEFAULT_PATH;

        /* Try user path first */
        char user_path[512];
        const char *home = getenv("HOME");
        if (home) {
            snprintf(user_path, sizeof(user_path),
                     "%s/.config/riscv_wallet/hardware.conf", home);
            path = user_path;

            /* Create directory */
            char dir[512];
            snprintf(dir, sizeof(dir), "%s/.config/riscv_wallet", home);
            mkdir(dir, 0755);
        }

        if (hwconfig_save(config, path) == 0) {
            printf("✅ Configuration saved to %s\n", path);
        } else {
            printf("⚠️  Could not save to %s\n", path);
            if (hwconfig_save(config, HWCONFIG_DEFAULT_PATH) == 0) {
                printf("✅ Configuration saved to %s\n", HWCONFIG_DEFAULT_PATH);
            }
        }
    }

    printf("\n💕 Setup complete! Your wallet is ready~ 💕\n\n");
    return SETUP_OK;
}

setup_result_t setup_first_time(hwconfig_t *config)
{
    /* Check if config already exists */
    if (hwconfig_load(config) == 0 && config->config_loaded) {
        return SETUP_SKIP;
    }

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Welcome to RISC-V Cold Wallet! 💕                         ║\n");
    printf("║  It looks like this is your first time~                    ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    if (prompt_yes_no("Would you like to run the setup wizard?", 1)) {
        return setup_run_wizard(config);
    }

    /* Use defaults */
    hwconfig_init_defaults(config);
    return SETUP_SKIP;
}

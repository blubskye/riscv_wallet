/*
 * Hardware Configuration System
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fb.h>
#include "hwconfig.h"

/* Global configuration instance */
hwconfig_t g_hwconfig;

/* Mode name tables */
static const char *display_mode_names[] = {
    [DISPLAY_MODE_TERMINAL]    = "terminal",
    [DISPLAY_MODE_FRAMEBUFFER] = "framebuffer",
    [DISPLAY_MODE_DRM]         = "drm",
};

static const char *input_mode_names[] = {
    [INPUT_MODE_TERMINAL] = "terminal",
    [INPUT_MODE_EVDEV]    = "evdev",
    [INPUT_MODE_GPIOD]    = "gpiod",
};

static const char *button_action_names[] = {
    [HWBTN_NONE]  = "none",
    [HWBTN_UP]    = "up",
    [HWBTN_DOWN]  = "down",
    [HWBTN_LEFT]  = "left",
    [HWBTN_RIGHT] = "right",
    [HWBTN_ENTER] = "enter",
    [HWBTN_BACK]  = "back",
    [HWBTN_MENU]  = "menu",
    [HWBTN_POWER] = "power",
};

/*
 * Initialize with defaults
 */
void hwconfig_init_defaults(hwconfig_t *config)
{
    memset(config, 0, sizeof(*config));

    strcpy(config->board_name, "unknown");
    config->config_loaded = 0;

    /* Default to terminal mode */
    config->display.mode = DISPLAY_MODE_TERMINAL;
    config->display.width = 80;
    config->display.height = 24;
    config->display.rotation = 0;
    strcpy(config->display.fb_device, "/dev/fb0");
    strcpy(config->display.drm_device, "/dev/dri/card0");
    config->display.drm_connector_id = 0;  /* Auto-detect */

    /* Default to terminal input */
    config->input.mode = INPUT_MODE_TERMINAL;
    config->input.debounce_ms = 50;
    strcpy(config->input.device, "/dev/input/event0");

    /* Check for hardware RNG */
    config->has_hardware_rng = (access("/dev/hwrng", R_OK) == 0);
    strcpy(config->rng_device, "/dev/hwrng");
}

/*
 * Helper: expand ~ in paths
 */
static void expand_home(const char *path, char *expanded, size_t len)
{
    if (path[0] == '~' && path[1] == '/') {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(expanded, len, "%s%s", home, path + 1);
            return;
        }
    }
    snprintf(expanded, len, "%s", path);
}

/*
 * Helper: trim whitespace
 */
static char *trim(char *str)
{
    while (isspace((unsigned char)*str)) str++;
    if (*str == '\0') return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

/*
 * Parse configuration file
 */
static int parse_config_file(hwconfig_t *config, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    char section[64] = "";
    int button_idx = -1;

    while (fgets(line, sizeof(line), fp)) {
        char *p = trim(line);

        /* Skip empty lines and comments */
        if (*p == '\0' || *p == '#' || *p == ';') continue;

        /* Section header */
        if (*p == '[') {
            char *end = strchr(p, ']');
            if (end) {
                *end = '\0';
                snprintf(section, sizeof(section), "%s", p + 1);

                /* Check for button section */
                if (strncmp(section, "button.", 7) == 0) {
                    button_idx = atoi(section + 7);
                    if (button_idx >= 0 && button_idx < MAX_BUTTONS) {
                        if (button_idx >= config->input.num_buttons) {
                            config->input.num_buttons = button_idx + 1;
                        }
                    }
                } else {
                    button_idx = -1;
                }
            }
            continue;
        }

        /* Key=value */
        char *eq = strchr(p, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = trim(p);
        char *value = trim(eq + 1);

        /* Remove quotes */
        size_t vlen = strlen(value);
        if (vlen >= 2 && ((value[0] == '"' && value[vlen-1] == '"') ||
                          (value[0] == '\'' && value[vlen-1] == '\''))) {
            value[vlen-1] = '\0';
            value++;
        }

        /* Handle sections */
        if (strcmp(section, "general") == 0) {
            if (strcmp(key, "board_name") == 0) {
                snprintf(config->board_name, sizeof(config->board_name), "%s", value);
            }
        }
        else if (strcmp(section, "display") == 0) {
            if (strcmp(key, "mode") == 0) {
                config->display.mode = hwconfig_parse_display_mode(value);
            } else if (strcmp(key, "device") == 0 || strcmp(key, "fb_device") == 0) {
                snprintf(config->display.fb_device, sizeof(config->display.fb_device), "%s", value);
            } else if (strcmp(key, "width") == 0) {
                config->display.width = (uint16_t)atoi(value);
            } else if (strcmp(key, "height") == 0) {
                config->display.height = (uint16_t)atoi(value);
            } else if (strcmp(key, "rotation") == 0) {
                config->display.rotation = (uint8_t)atoi(value);
            }
        }
        else if (strcmp(section, "input") == 0) {
            if (strcmp(key, "mode") == 0) {
                config->input.mode = hwconfig_parse_input_mode(value);
            } else if (strcmp(key, "device") == 0) {
                snprintf(config->input.device, sizeof(config->input.device), "%s", value);
            } else if (strcmp(key, "debounce_ms") == 0) {
                config->input.debounce_ms = atoi(value);
            }
        }
        else if (button_idx >= 0 && button_idx < MAX_BUTTONS) {
            button_map_t *btn = &config->input.buttons[button_idx];
            if (strcmp(key, "action") == 0) {
                btn->action = hwconfig_parse_button_action(value);
            } else if (strcmp(key, "code") == 0 || strcmp(key, "pin") == 0) {
                btn->code = atoi(value);
            } else if (strcmp(key, "active_low") == 0) {
                btn->active_low = (strcasecmp(value, "true") == 0 ||
                                   strcasecmp(value, "yes") == 0 ||
                                   strcmp(value, "1") == 0);
            } else if (strcmp(key, "label") == 0) {
                snprintf(btn->label, sizeof(btn->label), "%s", value);
            }
        }
        else if (strcmp(section, "hardware") == 0) {
            if (strcmp(key, "hardware_rng") == 0) {
                config->has_hardware_rng = (strcasecmp(value, "true") == 0 ||
                                            strcasecmp(value, "yes") == 0);
            } else if (strcmp(key, "rng_device") == 0) {
                snprintf(config->rng_device, sizeof(config->rng_device), "%s", value);
            }
        }
    }

    fclose(fp);
    snprintf(config->config_path, sizeof(config->config_path), "%s", path);
    config->config_loaded = 1;
    return 0;
}

/*
 * Load configuration
 */
int hwconfig_load(hwconfig_t *config)
{
    char path[HWCONFIG_MAX_PATH];

    hwconfig_init_defaults(config);

    /* Try environment variable first */
    const char *env_path = getenv(HWCONFIG_PATH_ENV);
    if (env_path && parse_config_file(config, env_path) == 0) {
        return 0;
    }

    /* Try user config */
    expand_home(HWCONFIG_USER_PATH, path, sizeof(path));
    if (parse_config_file(config, path) == 0) {
        return 0;
    }

    /* Try system config */
    if (parse_config_file(config, HWCONFIG_DEFAULT_PATH) == 0) {
        return 0;
    }

    /* No config found, use defaults */
    return -1;
}

/*
 * Save configuration
 */
int hwconfig_save(const hwconfig_t *config, const char *path)
{
    char filepath[HWCONFIG_MAX_PATH];

    if (path) {
        expand_home(path, filepath, sizeof(filepath));
    } else {
        expand_home(HWCONFIG_USER_PATH, filepath, sizeof(filepath));
    }

    /* Create directory if needed */
    char *dir = strdup(filepath);
    if (dir) {
        char *last_slash = strrchr(dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            char cmd[HWCONFIG_MAX_PATH + 16];
            snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", dir);
            int ret = system(cmd);
            (void)ret;
        }
        free(dir);
    }

    FILE *fp = fopen(filepath, "w");
    if (!fp) return -1;

    fprintf(fp, "# RISC-V Wallet Hardware Configuration\n\n");

    fprintf(fp, "[general]\n");
    fprintf(fp, "board_name = %s\n\n", config->board_name);

    fprintf(fp, "[display]\n");
    fprintf(fp, "mode = %s\n", hwconfig_display_mode_name(config->display.mode));
    if (config->display.mode == DISPLAY_MODE_FRAMEBUFFER) {
        fprintf(fp, "device = %s\n", config->display.fb_device);
    }
    fprintf(fp, "width = %u\n", config->display.width);
    fprintf(fp, "height = %u\n", config->display.height);
    fprintf(fp, "rotation = %u\n\n", config->display.rotation);

    fprintf(fp, "[input]\n");
    fprintf(fp, "mode = %s\n", hwconfig_input_mode_name(config->input.mode));
    fprintf(fp, "device = %s\n", config->input.device);
    if (config->input.mode == INPUT_MODE_GPIOD) {
        fprintf(fp, "debounce_ms = %d\n", config->input.debounce_ms);
    }
    fprintf(fp, "\n");

    for (int i = 0; i < config->input.num_buttons; i++) {
        const button_map_t *btn = &config->input.buttons[i];
        if (btn->action == HWBTN_NONE) continue;

        fprintf(fp, "[button.%d]\n", i);
        fprintf(fp, "action = %s\n", hwconfig_button_action_name(btn->action));
        fprintf(fp, "code = %d\n", btn->code);
        if (config->input.mode == INPUT_MODE_GPIOD) {
            fprintf(fp, "active_low = %s\n", btn->active_low ? "true" : "false");
        }
        if (btn->label[0]) {
            fprintf(fp, "label = %s\n", btn->label);
        }
        fprintf(fp, "\n");
    }

    fprintf(fp, "[hardware]\n");
    fprintf(fp, "hardware_rng = %s\n", config->has_hardware_rng ? "true" : "false");
    fprintf(fp, "rng_device = %s\n", config->rng_device);

    fclose(fp);
    return 0;
}

/*
 * Mode name helpers
 */
const char *hwconfig_display_mode_name(display_mode_t mode)
{
    if (mode < sizeof(display_mode_names) / sizeof(display_mode_names[0])) {
        return display_mode_names[mode];
    }
    return "unknown";
}

display_mode_t hwconfig_parse_display_mode(const char *name)
{
    for (size_t i = 0; i < sizeof(display_mode_names) / sizeof(display_mode_names[0]); i++) {
        if (display_mode_names[i] && strcasecmp(name, display_mode_names[i]) == 0) {
            return (display_mode_t)i;
        }
    }
    /* Also accept shorthands */
    if (strcasecmp(name, "fb") == 0) return DISPLAY_MODE_FRAMEBUFFER;
    if (strcasecmp(name, "kms") == 0) return DISPLAY_MODE_DRM;
    return DISPLAY_MODE_TERMINAL;
}

const char *hwconfig_input_mode_name(input_mode_t mode)
{
    if (mode < sizeof(input_mode_names) / sizeof(input_mode_names[0])) {
        return input_mode_names[mode];
    }
    return "unknown";
}

input_mode_t hwconfig_parse_input_mode(const char *name)
{
    for (size_t i = 0; i < sizeof(input_mode_names) / sizeof(input_mode_names[0]); i++) {
        if (input_mode_names[i] && strcasecmp(name, input_mode_names[i]) == 0) {
            return (input_mode_t)i;
        }
    }
    /* Also accept "gpio" as shorthand */
    if (strcasecmp(name, "gpio") == 0) return INPUT_MODE_GPIOD;
    return INPUT_MODE_TERMINAL;
}

const char *hwconfig_button_action_name(button_action_t action)
{
    if (action < sizeof(button_action_names) / sizeof(button_action_names[0])) {
        return button_action_names[action];
    }
    return "unknown";
}

button_action_t hwconfig_parse_button_action(const char *name)
{
    for (size_t i = 0; i < sizeof(button_action_names) / sizeof(button_action_names[0]); i++) {
        if (button_action_names[i] && strcasecmp(name, button_action_names[i]) == 0) {
            return (button_action_t)i;
        }
    }
    /* Common aliases */
    if (strcasecmp(name, "select") == 0 || strcasecmp(name, "ok") == 0) return HWBTN_ENTER;
    if (strcasecmp(name, "cancel") == 0 || strcasecmp(name, "escape") == 0) return HWBTN_BACK;
    return HWBTN_NONE;
}

/*
 * Find button by action
 */
const button_map_t *hwconfig_find_button(const input_config_t *input,
                                          button_action_t action)
{
    for (int i = 0; i < input->num_buttons; i++) {
        if (input->buttons[i].action == action) {
            return &input->buttons[i];
        }
    }
    return NULL;
}

/*
 * Device detection helpers
 */
int hwconfig_detect_framebuffers(char devices[][HWCONFIG_MAX_PATH], int max)
{
    int count = 0;

    for (int i = 0; i < 8 && count < max; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/fb%d", i);
        if (access(path, R_OK | W_OK) == 0) {
            snprintf(devices[count], HWCONFIG_MAX_PATH, "%s", path);
            count++;
        }
    }

    return count;
}

int hwconfig_detect_input_devices(char devices[][HWCONFIG_MAX_PATH], int max)
{
    DIR *dir = opendir("/dev/input");
    if (!dir) return 0;

    int count = 0;
    struct dirent *ent;

    while ((ent = readdir(dir)) != NULL && count < max) {
        if (strncmp(ent->d_name, "event", 5) == 0) {
            /* Limit d_name to avoid truncation (prefix is 11 chars + null) */
            size_t name_len = strnlen(ent->d_name, sizeof(ent->d_name));
            if (name_len < HWCONFIG_MAX_PATH - 12) {
                int ret = snprintf(devices[count], HWCONFIG_MAX_PATH,
                                   "/dev/input/%.*s", (int)name_len, ent->d_name);
                if (ret > 0 && (size_t)ret < HWCONFIG_MAX_PATH) {
                    count++;
                }
            }
        }
    }

    closedir(dir);
    return count;
}

int hwconfig_detect_gpio_chips(char devices[][HWCONFIG_MAX_PATH], int max)
{
    DIR *dir = opendir("/dev");
    if (!dir) return 0;

    int count = 0;
    struct dirent *ent;

    while ((ent = readdir(dir)) != NULL && count < max) {
        if (strncmp(ent->d_name, "gpiochip", 8) == 0) {
            /* Limit d_name to avoid truncation (prefix is 5 chars + null) */
            size_t name_len = strnlen(ent->d_name, sizeof(ent->d_name));
            if (name_len < HWCONFIG_MAX_PATH - 6) {
                int ret = snprintf(devices[count], HWCONFIG_MAX_PATH,
                                   "/dev/%.*s", (int)name_len, ent->d_name);
                if (ret > 0 && (size_t)ret < HWCONFIG_MAX_PATH) {
                    count++;
                }
            }
        }
    }

    closedir(dir);
    return count;
}

int hwconfig_detect_hwrng(char *device, size_t device_len)
{
    if (access("/dev/hwrng", R_OK) == 0) {
        snprintf(device, device_len, "/dev/hwrng");
        return 1;
    }
    return 0;
}

/*
 * Auto-detect hardware
 */
int hwconfig_autodetect(hwconfig_t *config)
{
    int detected = 0;
    char devices[8][HWCONFIG_MAX_PATH];

    /* Detect framebuffers */
    int fb_count = hwconfig_detect_framebuffers(devices, 8);
    if (fb_count > 0) {
        config->display.mode = DISPLAY_MODE_FRAMEBUFFER;
        snprintf(config->display.fb_device, sizeof(config->display.fb_device),
                 "%s", devices[0]);

        /* Try to get actual dimensions from framebuffer */
        int fd = open(devices[0], O_RDONLY);
        if (fd >= 0) {
            struct fb_var_screeninfo vinfo;
            if (ioctl(fd, FBIOGET_VSCREENINFO, &vinfo) == 0) {
                config->display.width = (uint16_t)vinfo.xres;
                config->display.height = (uint16_t)vinfo.yres;
            }
            close(fd);
        }
        detected++;
    }

    /* Detect input devices */
    int input_count = hwconfig_detect_input_devices(devices, 8);
    if (input_count > 0) {
        config->input.mode = INPUT_MODE_EVDEV;
        snprintf(config->input.device, sizeof(config->input.device),
                 "%s", devices[0]);
        detected++;
    }

    /* Detect GPIO chips (if no evdev found) */
    if (config->input.mode == INPUT_MODE_TERMINAL) {
        int gpio_count = hwconfig_detect_gpio_chips(devices, 8);
        if (gpio_count > 0) {
            config->input.mode = INPUT_MODE_GPIOD;
            snprintf(config->input.device, sizeof(config->input.device),
                     "%s", devices[0]);
            detected++;
        }
    }

    /* Detect hardware RNG */
    if (hwconfig_detect_hwrng(config->rng_device, sizeof(config->rng_device))) {
        config->has_hardware_rng = 1;
        detected++;
    }

    return detected;
}

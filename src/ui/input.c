/*
 * Input Handling - Hardware GPIO and Input Event Support
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/* Include input.h first to define our button enum before linux/input.h */
#include "input.h"
#include "display.h"
#include "../security/memory.h"
#include "../hw/hwconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

/* Linux input event support - use fully qualified names to avoid conflicts */
#ifdef __linux__
#include <linux/input.h>
/* Undefine conflicting BTN_* macros from linux/input.h, we use our own */
#undef BTN_LEFT
#undef BTN_RIGHT
#undef BTN_SELECT
#undef BTN_BACK
/* Restore our definitions */
#define BTN_LEFT    WALLET_BTN_LEFT
#define BTN_RIGHT   WALLET_BTN_RIGHT
#define BTN_SELECT  WALLET_BTN_SELECT
#define BTN_BACK    WALLET_BTN_BACK
#endif

/* libgpiod support (optional) */
#ifdef HAVE_LIBGPIOD
#include <gpiod.h>
#endif

/* ============================================================================
 * Constants and Configuration
 * ============================================================================ */

#define MAX_INPUT_DEVICES    8
#define EVENT_QUEUE_SIZE     32
#define DEFAULT_DEBOUNCE_MS  50

/* Default GPIO mapping (typical hardware wallet setup)
 * These can be reconfigured at runtime */
static gpio_pin_config_t g_default_gpio_map[WALLET_BTN_COUNT] = {
    [WALLET_BTN_NONE]    = { -1, -1, 0 },      /* Not used */
    [WALLET_BTN_UP]      = { 0, 17, 1 },       /* GPIO17, active-low */
    [WALLET_BTN_DOWN]    = { 0, 27, 1 },       /* GPIO27, active-low */
    [WALLET_BTN_LEFT]    = { 0, 22, 1 },       /* GPIO22, active-low */
    [WALLET_BTN_RIGHT]   = { 0, 23, 1 },       /* GPIO23, active-low */
    [WALLET_BTN_SELECT]  = { 0, 24, 1 },       /* GPIO24, active-low */
    [WALLET_BTN_BACK]    = { 0, 25, 1 },       /* GPIO25, active-low */
    [WALLET_BTN_CONFIRM] = { 0,  5, 1 },       /* GPIO5, active-low */
    [WALLET_BTN_CANCEL]  = { 0,  6, 1 },       /* GPIO6, active-low */
};

/* Button names for display/debug */
static const char *g_button_names[WALLET_BTN_COUNT] = {
    [WALLET_BTN_NONE]    = "NONE",
    [WALLET_BTN_UP]      = "UP",
    [WALLET_BTN_DOWN]    = "DOWN",
    [WALLET_BTN_LEFT]    = "LEFT",
    [WALLET_BTN_RIGHT]   = "RIGHT",
    [WALLET_BTN_SELECT]  = "SELECT",
    [WALLET_BTN_BACK]    = "BACK",
    [WALLET_BTN_CONFIRM] = "CONFIRM",
    [WALLET_BTN_CANCEL]  = "CANCEL",
};

/* ============================================================================
 * State Variables
 * ============================================================================ */

static int g_initialized = 0;
static input_info_t g_info = { 0 };
static struct termios g_orig_termios;
static int g_terminal_modified = 0;

/* Button state tracking */
static uint8_t g_button_state[WALLET_BTN_COUNT] = { 0 };
static uint32_t g_button_last_change[WALLET_BTN_COUNT] = { 0 };
static uint32_t g_debounce_ms = DEFAULT_DEBOUNCE_MS;

/* Event queue for buffering */
static input_event_t g_event_queue[EVENT_QUEUE_SIZE];
static int g_queue_head = 0;
static int g_queue_tail = 0;

/* Time tracking */
static struct timespec g_start_time;

/* Callback for async events */
static input_callback_t g_callback = NULL;
static void *g_callback_data = NULL;

/* Evdev state */
#ifdef __linux__
static int g_evdev_fds[MAX_INPUT_DEVICES];
static int g_evdev_count = 0;
#endif

/* GPIO state - libgpiod v2 API */
#ifdef HAVE_LIBGPIOD
static struct gpiod_chip *g_gpio_chip = NULL;
static struct gpiod_line_request *g_gpio_request = NULL;
static unsigned int g_gpio_offsets[WALLET_BTN_COUNT];
static int g_gpio_line_count = 0;
#endif

/* Simulated button state for testing */
static uint8_t g_simulated_buttons[WALLET_BTN_COUNT] = { 0 };

/* ============================================================================
 * Time Functions
 * ============================================================================ */

uint32_t input_get_time_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint64_t ms = (now.tv_sec - g_start_time.tv_sec) * 1000;
    ms += (now.tv_nsec - g_start_time.tv_nsec) / 1000000;

    return (uint32_t)ms;
}

/* ============================================================================
 * Event Queue Functions
 * ============================================================================ */

static int queue_is_empty(void)
{
    return g_queue_head == g_queue_tail;
}

static int queue_is_full(void)
{
    return ((g_queue_tail + 1) % EVENT_QUEUE_SIZE) == g_queue_head;
}

/* Used by GPIO polling to queue events for later processing */
__attribute__((unused))
static void queue_push(const input_event_t *event)
{
    if (queue_is_full()) {
        return;  /* Drop event if queue full */
    }

    g_event_queue[g_queue_tail] = *event;
    g_queue_tail = (g_queue_tail + 1) % EVENT_QUEUE_SIZE;

    /* Call async callback if registered */
    if (g_callback) {
        g_callback(event, g_callback_data);
    }
}

static int queue_pop(input_event_t *event)
{
    if (queue_is_empty()) {
        return 0;
    }

    *event = g_event_queue[g_queue_head];
    g_queue_head = (g_queue_head + 1) % EVENT_QUEUE_SIZE;

    return 1;
}

/* ============================================================================
 * Terminal Backend
 * ============================================================================ */

static void terminal_save_settings(void)
{
    if (!g_terminal_modified) {
        tcgetattr(STDIN_FILENO, &g_orig_termios);
    }
}

static void terminal_restore_settings(void)
{
    if (g_terminal_modified) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
        g_terminal_modified = 0;
    }
}

static int terminal_getch_nonblocking(void)
{
    struct termios new_termios;
    int ch;

    tcgetattr(STDIN_FILENO, &new_termios);
    new_termios.c_lflag &= ~(ICANON | ECHO);
    new_termios.c_cc[VMIN] = 0;
    new_termios.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);
    g_terminal_modified = 1;

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
    g_terminal_modified = 0;

    return ch;
}

static int terminal_getch_blocking(void)
{
    struct termios new_termios;
    int ch;

    tcgetattr(STDIN_FILENO, &new_termios);
    new_termios.c_lflag &= ~(ICANON | ECHO);
    new_termios.c_cc[VMIN] = 1;
    new_termios.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);
    g_terminal_modified = 1;

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
    g_terminal_modified = 0;

    return ch;
}

static int terminal_getch_timeout(uint32_t timeout_ms)
{
    struct pollfd pfd;
    int ret;

    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;

    struct termios new_termios;
    tcgetattr(STDIN_FILENO, &new_termios);
    new_termios.c_lflag &= ~(ICANON | ECHO);
    new_termios.c_cc[VMIN] = 0;
    new_termios.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);
    g_terminal_modified = 1;

    ret = poll(&pfd, 1, timeout_ms > 0 ? (int)timeout_ms : -1);

    int ch = EOF;
    if (ret > 0 && (pfd.revents & POLLIN)) {
        ch = getchar();
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
    g_terminal_modified = 0;

    return ch;
}

static button_t terminal_map_key(int ch)
{
    /* Handle escape sequences for arrow keys */
    if (ch == 27) {  /* ESC */
        int next = terminal_getch_nonblocking();
        if (next == '[' || next == 'O') {
            int arrow = terminal_getch_nonblocking();
            switch (arrow) {
            case 'A': return BTN_UP;
            case 'B': return BTN_DOWN;
            case 'C': return BTN_RIGHT;
            case 'D': return BTN_LEFT;
            }
        }
        return BTN_CANCEL;  /* Plain ESC */
    }

    switch (ch) {
    /* WASD / vim keys for navigation */
    case 'w': case 'W': case 'k': case 'K':
        return BTN_UP;
    case 's': case 'S': case 'j': case 'J':
        return BTN_DOWN;
    case 'a': case 'A': case 'h': case 'H':
        return BTN_LEFT;
    case 'd': case 'D': case 'l': case 'L':
        return BTN_RIGHT;

    /* Action keys */
    case '\n': case '\r': case ' ':
        return BTN_SELECT;
    case 'y': case 'Y':
        return BTN_CONFIRM;
    case 'n': case 'N':
        return BTN_CANCEL;
    case 'b': case 'B': case 'q': case 'Q':
        return BTN_BACK;

    default:
        return BTN_NONE;
    }
}

static int terminal_init(void)
{
    terminal_save_settings();

    g_info.backend = INPUT_BACKEND_TERMINAL;
    g_info.device = "stdin";
    g_info.num_buttons = WALLET_BTN_COUNT - 1;
    g_info.backend_name = "Terminal (keyboard)";

    return INPUT_OK;
}

static void terminal_cleanup(void)
{
    terminal_restore_settings();
}

static int terminal_poll(input_event_t *event)
{
    int ch = terminal_getch_nonblocking();
    if (ch == EOF || ch == -1) {
        return 0;
    }

    button_t btn = terminal_map_key(ch);
    if (btn == BTN_NONE) {
        return 0;
    }

    event->button = btn;
    event->pressed = 1;
    event->timestamp = input_get_time_ms();

    return 1;
}

/* ============================================================================
 * Linux Evdev Backend
 * ============================================================================ */

#ifdef __linux__

/* Map Linux key codes to our button enum */
static button_t evdev_map_keycode(int code)
{
    switch (code) {
    case KEY_UP:
        return BTN_UP;
    case KEY_DOWN:
        return BTN_DOWN;
    case KEY_LEFT:
        return BTN_LEFT;
    case KEY_RIGHT:
        return BTN_RIGHT;
    case KEY_ENTER:
    case KEY_KPENTER:
        return BTN_SELECT;
    case KEY_BACKSPACE:
    case KEY_ESC:
        return BTN_BACK;
    case KEY_Y:
        return BTN_CONFIRM;
    case KEY_N:
        return BTN_CANCEL;
    default:
        return BTN_NONE;
    }
}

static int evdev_is_keyboard(int fd)
{
    unsigned long evbit[2] = { 0 };

    if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), evbit) < 0) {
        return 0;
    }

    /* Check for EV_KEY capability */
    return (evbit[0] & (1 << EV_KEY)) != 0;
}

static int evdev_init(const char *device)
{
    char path[280];  /* /dev/input/ (11) + d_name (256 max) + null */
    DIR *dir;
    struct dirent *ent;

    g_evdev_count = 0;

    if (device) {
        /* Use specific device */
        int fd = open(device, O_RDONLY | O_NONBLOCK);
        if (fd >= 0 && evdev_is_keyboard(fd)) {
            g_evdev_fds[g_evdev_count++] = fd;
        } else if (fd >= 0) {
            close(fd);
        }
    } else {
        /* Scan /dev/input for event devices */
        dir = opendir("/dev/input");
        if (dir) {
            while ((ent = readdir(dir)) != NULL && g_evdev_count < MAX_INPUT_DEVICES) {
                if (strncmp(ent->d_name, "event", 5) != 0) {
                    continue;
                }

                snprintf(path, sizeof(path), "/dev/input/%s", ent->d_name);
                int fd = open(path, O_RDONLY | O_NONBLOCK);
                if (fd >= 0 && evdev_is_keyboard(fd)) {
                    g_evdev_fds[g_evdev_count++] = fd;
                } else if (fd >= 0) {
                    close(fd);
                }
            }
            closedir(dir);
        }
    }

    if (g_evdev_count == 0) {
        return INPUT_ERR_NO_DEVICE;
    }

    g_info.backend = INPUT_BACKEND_EVDEV;
    g_info.device = "/dev/input/event*";
    g_info.num_buttons = WALLET_BTN_COUNT - 1;
    g_info.backend_name = "Linux evdev";

    return INPUT_OK;
}

static void evdev_cleanup(void)
{
    for (int i = 0; i < g_evdev_count; i++) {
        if (g_evdev_fds[i] >= 0) {
            close(g_evdev_fds[i]);
            g_evdev_fds[i] = -1;
        }
    }
    g_evdev_count = 0;
}

static int evdev_poll(input_event_t *event)
{
    struct input_event ev;

    for (int i = 0; i < g_evdev_count; i++) {
        ssize_t n = read(g_evdev_fds[i], &ev, sizeof(ev));
        if (n == sizeof(ev) && ev.type == EV_KEY) {
            button_t btn = evdev_map_keycode(ev.code);
            if (btn != BTN_NONE) {
                event->button = btn;
                event->pressed = (ev.value != 0) ? 1 : 0;
                event->timestamp = input_get_time_ms();
                return 1;
            }
        }
    }

    return 0;
}

static int evdev_wait(input_event_t *event, uint32_t timeout_ms)
{
    struct pollfd pfds[MAX_INPUT_DEVICES];

    for (int i = 0; i < g_evdev_count; i++) {
        pfds[i].fd = g_evdev_fds[i];
        pfds[i].events = POLLIN;
    }

    int ret = poll(pfds, g_evdev_count, timeout_ms > 0 ? (int)timeout_ms : -1);
    if (ret <= 0) {
        return 0;
    }

    return evdev_poll(event);
}

#endif /* __linux__ */

/* ============================================================================
 * GPIO Backend (libgpiod v2 API)
 * ============================================================================ */

#ifdef HAVE_LIBGPIOD

static int gpio_init(const char *device)
{
    const char *chip_path = device ? device : "/dev/gpiochip0";
    struct gpiod_line_settings *settings = NULL;
    struct gpiod_line_config *line_cfg = NULL;
    struct gpiod_request_config *req_cfg = NULL;
    int ret = INPUT_ERR_NO_DEVICE;

    /* Open GPIO chip */
    g_gpio_chip = gpiod_chip_open(chip_path);
    if (!g_gpio_chip) {
        return INPUT_ERR_NO_DEVICE;
    }

    /* Create line settings for input with pull-up and active-low */
    settings = gpiod_line_settings_new();
    if (!settings) {
        goto cleanup;
    }

    gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_INPUT);
    gpiod_line_settings_set_bias(settings, GPIOD_LINE_BIAS_PULL_UP);
    gpiod_line_settings_set_active_low(settings, true);

    /* Create line config */
    line_cfg = gpiod_line_config_new();
    if (!line_cfg) {
        goto cleanup;
    }

    /* Collect all valid GPIO offsets */
    g_gpio_line_count = 0;
    for (int i = 1; i < WALLET_BTN_COUNT; i++) {
        gpio_pin_config_t *cfg = &g_default_gpio_map[i];
        if (cfg->line >= 0) {
            g_gpio_offsets[g_gpio_line_count++] = (unsigned int)cfg->line;
        }
    }

    if (g_gpio_line_count == 0) {
        goto cleanup;
    }

    /* Add all lines to the config */
    if (gpiod_line_config_add_line_settings(line_cfg, g_gpio_offsets,
                                             g_gpio_line_count, settings) < 0) {
        goto cleanup;
    }

    /* Create request config */
    req_cfg = gpiod_request_config_new();
    if (!req_cfg) {
        goto cleanup;
    }
    gpiod_request_config_set_consumer(req_cfg, "riscv_wallet");

    /* Request the lines */
    g_gpio_request = gpiod_chip_request_lines(g_gpio_chip, req_cfg, line_cfg);
    if (!g_gpio_request) {
        goto cleanup;
    }

    g_info.backend = INPUT_BACKEND_GPIO;
    g_info.device = chip_path;
    g_info.num_buttons = g_gpio_line_count;
    g_info.backend_name = "GPIO (libgpiod v2)";

    ret = INPUT_OK;

cleanup:
    if (req_cfg) gpiod_request_config_free(req_cfg);
    if (line_cfg) gpiod_line_config_free(line_cfg);
    if (settings) gpiod_line_settings_free(settings);

    if (ret != INPUT_OK) {
        if (g_gpio_chip) {
            gpiod_chip_close(g_gpio_chip);
            g_gpio_chip = NULL;
        }
        g_gpio_line_count = 0;
    }

    return ret;
}

static void gpio_cleanup(void)
{
    if (g_gpio_request) {
        gpiod_line_request_release(g_gpio_request);
        g_gpio_request = NULL;
    }
    if (g_gpio_chip) {
        gpiod_chip_close(g_gpio_chip);
        g_gpio_chip = NULL;
    }
    g_gpio_line_count = 0;
}

static int gpio_poll(input_event_t *event)
{
    uint32_t now = input_get_time_ms();
    enum gpiod_line_value values[WALLET_BTN_COUNT];

    if (!g_gpio_request || g_gpio_line_count == 0) {
        return 0;
    }

    /* Read all GPIO lines at once */
    if (gpiod_line_request_get_values(g_gpio_request, values) < 0) {
        return 0;
    }

    /* Check each button for state changes */
    int line_idx = 0;
    for (int btn = 1; btn < WALLET_BTN_COUNT; btn++) {
        gpio_pin_config_t *cfg = &g_default_gpio_map[btn];
        if (cfg->line < 0) {
            continue;
        }

        /* Active-low is handled by libgpiod, so ACTIVE = pressed */
        uint8_t pressed = (values[line_idx] == GPIOD_LINE_VALUE_ACTIVE) ? 1 : 0;
        line_idx++;

        /* Check for state change with debouncing */
        if (pressed != g_button_state[btn]) {
            if ((now - g_button_last_change[btn]) >= g_debounce_ms) {
                g_button_state[btn] = pressed;
                g_button_last_change[btn] = now;

                event->button = (button_t)btn;
                event->pressed = pressed;
                event->timestamp = now;

                return 1;
            }
        }
    }

    return 0;
}

static int gpio_wait(input_event_t *event, uint32_t timeout_ms)
{
    uint32_t start = input_get_time_ms();
    uint32_t elapsed = 0;
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };  /* 10ms */

    while (timeout_ms == 0 || elapsed < timeout_ms) {
        if (gpio_poll(event)) {
            return 1;
        }

        /* Small delay to avoid busy-waiting */
        nanosleep(&ts, NULL);
        elapsed = input_get_time_ms() - start;
    }

    return 0;
}

#endif /* HAVE_LIBGPIOD */

/* ============================================================================
 * Helper: Map hwconfig button action to input button
 * ============================================================================ */

static button_t hwconfig_action_to_button(button_action_t action)
{
    switch (action) {
    case HWBTN_UP:     return WALLET_BTN_UP;
    case HWBTN_DOWN:   return WALLET_BTN_DOWN;
    case HWBTN_LEFT:   return WALLET_BTN_LEFT;
    case HWBTN_RIGHT:  return WALLET_BTN_RIGHT;
    case HWBTN_ENTER:  return WALLET_BTN_SELECT;
    case HWBTN_BACK:   return WALLET_BTN_BACK;
    case HWBTN_MENU:   return WALLET_BTN_CONFIRM;
    case HWBTN_POWER:  return WALLET_BTN_CANCEL;
    default:          return WALLET_BTN_NONE;
    }
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

int input_init(void)
{
    /* Load hardware config */
    hwconfig_load(&g_hwconfig);

    /* Apply button mappings from config */
    for (int i = 0; i < g_hwconfig.input.num_buttons; i++) {
        const button_map_t *map = &g_hwconfig.input.buttons[i];
        button_t btn = hwconfig_action_to_button(map->action);
        if (btn != WALLET_BTN_NONE) {
            g_default_gpio_map[btn].chip = 0;
            g_default_gpio_map[btn].line = map->code;
            g_default_gpio_map[btn].active_low = map->active_low;
        }
    }

    /* Set debounce from config */
    if (g_hwconfig.input.debounce_ms > 0) {
        g_debounce_ms = (uint32_t)g_hwconfig.input.debounce_ms;
    }

    /* Select backend based on config */
    const char *device = (g_hwconfig.input.device[0] != '\0')
                         ? g_hwconfig.input.device : NULL;

    switch (g_hwconfig.input.mode) {
    case INPUT_MODE_EVDEV:
        return input_init_backend(INPUT_BACKEND_EVDEV, device);
    case INPUT_MODE_GPIOD:
        return input_init_backend(INPUT_BACKEND_GPIO, device);
    case INPUT_MODE_TERMINAL:
    default:
        return input_init_backend(INPUT_BACKEND_TERMINAL, NULL);
    }
}

int input_init_backend(input_backend_t backend, const char *device)
{
    int ret = INPUT_ERR_NO_DEVICE;

    if (g_initialized) {
        return INPUT_OK;
    }

    /* Initialize timing */
    clock_gettime(CLOCK_MONOTONIC, &g_start_time);

    /* Clear state */
    memset(g_button_state, 0, sizeof(g_button_state));
    memset(g_button_last_change, 0, sizeof(g_button_last_change));
    g_queue_head = 0;
    g_queue_tail = 0;

    /* Auto-detect or use specified backend */
    if (backend == INPUT_BACKEND_NONE) {
#ifdef HAVE_LIBGPIOD
        /* Try GPIO first (hardware wallet) */
        ret = gpio_init(device);
        if (ret == INPUT_OK) {
            goto done;
        }
#endif

#ifdef __linux__
        /* Try evdev */
        ret = evdev_init(device);
        if (ret == INPUT_OK) {
            goto done;
        }
#endif

        /* Fall back to terminal */
        ret = terminal_init();
    } else {
        switch (backend) {
        case INPUT_BACKEND_TERMINAL:
            ret = terminal_init();
            break;

#ifdef __linux__
        case INPUT_BACKEND_EVDEV:
            ret = evdev_init(device);
            break;
#endif

#ifdef HAVE_LIBGPIOD
        case INPUT_BACKEND_GPIO:
            ret = gpio_init(device);
            break;
#endif

        default:
            ret = INPUT_ERR_NO_DEVICE;
            break;
        }
    }

#if defined(HAVE_LIBGPIOD) || defined(__linux__)
done:
#endif
    if (ret == INPUT_OK) {
        g_initialized = 1;
        printf("[input] Initialized: %s\n", g_info.backend_name);
    }

    return ret;
}

void input_cleanup(void)
{
    if (!g_initialized) {
        return;
    }

    switch (g_info.backend) {
    case INPUT_BACKEND_TERMINAL:
        terminal_cleanup();
        break;

#ifdef __linux__
    case INPUT_BACKEND_EVDEV:
        evdev_cleanup();
        break;
#endif

#ifdef HAVE_LIBGPIOD
    case INPUT_BACKEND_GPIO:
        gpio_cleanup();
        break;
#endif

    default:
        break;
    }

    g_callback = NULL;
    g_callback_data = NULL;

    printf("[input] Cleaned up\n");
    g_initialized = 0;
}

const input_info_t *input_get_info(void)
{
    return g_initialized ? &g_info : NULL;
}

int input_is_available(void)
{
    return g_initialized;
}

int input_poll(input_event_t *event)
{
    if (!g_initialized || event == NULL) {
        return 0;
    }

    /* Check simulated buttons first */
    for (int i = 1; i < WALLET_BTN_COUNT; i++) {
        if (g_simulated_buttons[i]) {
            event->button = (button_t)i;
            event->pressed = 1;
            event->timestamp = input_get_time_ms();
            g_simulated_buttons[i] = 0;
            return 1;
        }
    }

    /* Check queued events */
    if (queue_pop(event)) {
        return 1;
    }

    /* Poll backend */
    switch (g_info.backend) {
    case INPUT_BACKEND_TERMINAL:
        return terminal_poll(event);

#ifdef __linux__
    case INPUT_BACKEND_EVDEV:
        return evdev_poll(event);
#endif

#ifdef HAVE_LIBGPIOD
    case INPUT_BACKEND_GPIO:
        return gpio_poll(event);
#endif

    default:
        return 0;
    }
}

int input_wait(input_event_t *event, uint32_t timeout_ms)
{
    if (!g_initialized || event == NULL) {
        return -1;
    }

    /* Check queued events first */
    if (queue_pop(event)) {
        return 1;
    }

    switch (g_info.backend) {
    case INPUT_BACKEND_TERMINAL: {
        int ch = terminal_getch_timeout(timeout_ms);
        if (ch == EOF || ch == -1) {
            return 0;
        }
        button_t btn = terminal_map_key(ch);
        if (btn == BTN_NONE) {
            return 0;
        }
        event->button = btn;
        event->pressed = 1;
        event->timestamp = input_get_time_ms();
        return 1;
    }

#ifdef __linux__
    case INPUT_BACKEND_EVDEV:
        return evdev_wait(event, timeout_ms);
#endif

#ifdef HAVE_LIBGPIOD
    case INPUT_BACKEND_GPIO:
        return gpio_wait(event, timeout_ms);
#endif

    default:
        return -1;
    }
}

int input_is_pressed(button_t button)
{
    if (!g_initialized || button <= WALLET_BTN_NONE || button >= WALLET_BTN_COUNT) {
        return 0;
    }

    /* For GPIO, we track state continuously */
    if (g_info.backend == INPUT_BACKEND_GPIO) {
        return g_button_state[button];
    }

    /* For other backends, we can only detect edges */
    return 0;
}

button_t input_wait_any(uint32_t timeout_ms)
{
    input_event_t event;

    if (input_wait(&event, timeout_ms) > 0 && event.pressed) {
        return event.button;
    }

    return BTN_NONE;
}

int input_wait_button(button_t button, uint32_t timeout_ms)
{
    uint32_t start = input_get_time_ms();
    uint32_t elapsed = 0;
    input_event_t event;

    while (timeout_ms == 0 || elapsed < timeout_ms) {
        uint32_t remaining = timeout_ms > 0 ? (timeout_ms - elapsed) : 0;

        if (input_wait(&event, remaining) > 0) {
            if (event.button == button && event.pressed) {
                return 1;
            }
        }

        elapsed = input_get_time_ms() - start;
    }

    return 0;
}

int input_read_pin(char *pin, int max_len)
{
    int i = 0;
    int ch;

    if (!g_initialized || pin == NULL || max_len <= 0) {
        return INPUT_ERR_INIT;
    }

    printf("Enter PIN: ");
    fflush(stdout);

    while (i < max_len - 1) {
        ch = terminal_getch_blocking();

        if (ch == '\n' || ch == '\r') {
            break;
        }

        if (ch == 27) {  /* ESC to cancel */
            secure_wipe(pin, max_len);
            printf("\nCancelled\n");
            return INPUT_ERR_CANCELLED;
        }

        if (ch == 127 || ch == 8) {  /* Backspace */
            if (i > 0) {
                i--;
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }

        if (ch >= '0' && ch <= '9') {
            pin[i++] = (char)ch;
            printf("*");
            fflush(stdout);
        }
    }

    pin[i] = '\0';
    printf("\n");

    return i;
}

int input_read_pin_display(char *pin, int max_len, const char *title)
{
    int len = 0;
    char display_pin[32] = "";
    input_event_t event;
    int digit = 5;  /* Start in middle (0-9) */

    if (!g_initialized || pin == NULL || max_len <= 0) {
        return INPUT_ERR_INIT;
    }

    /* Check if display is available */
    if (!display_is_available()) {
        return input_read_pin(pin, max_len);
    }

    while (len < max_len - 1) {
        /* Build masked display string */
        memset(display_pin, '*', len);
        display_pin[len] = '0' + digit;
        display_pin[len + 1] = '\0';

        /* Update display */
        display_clear(COLOR_BLACK);
        display_draw_text_centered(40, title ? title : "Enter PIN", COLOR_WHITE, COLOR_BLACK);
        display_draw_text_centered(100, display_pin, COLOR_GREEN, COLOR_BLACK);
        display_draw_text_centered(180, "UP/DOWN: Change  SELECT: Confirm", COLOR_GRAY, COLOR_BLACK);
        display_draw_text_centered(200, "BACK: Delete     CANCEL: Abort", COLOR_GRAY, COLOR_BLACK);
        display_update();

        /* Wait for input */
        if (input_wait(&event, 0) <= 0) {
            continue;
        }

        if (!event.pressed) {
            continue;
        }

        switch (event.button) {
        case BTN_UP:
            digit = (digit + 1) % 10;
            break;

        case BTN_DOWN:
            digit = (digit + 9) % 10;
            break;

        case BTN_SELECT:
        case BTN_CONFIRM:
            pin[len++] = '0' + digit;
            digit = 5;
            break;

        case BTN_BACK:
            if (len > 0) {
                len--;
            }
            break;

        case BTN_CANCEL:
            secure_wipe(pin, max_len);
            display_show_message("Cancelled", "PIN entry cancelled");
            return INPUT_ERR_CANCELLED;

        case BTN_RIGHT:
            /* Finish entry */
            if (len > 0) {
                pin[len] = '\0';
                return len;
            }
            break;

        default:
            break;
        }
    }

    pin[len] = '\0';
    return len;
}

int input_confirm(const char *prompt)
{
    int ch;

    if (!g_initialized) {
        return 0;
    }

    printf("%s (y/n): ", prompt);
    fflush(stdout);

    ch = terminal_getch_blocking();
    printf("%c\n", ch);

    return (ch == 'y' || ch == 'Y') ? 1 : 0;
}

int input_confirm_display(const char *title, const char *message)
{
    input_event_t event;

    if (!g_initialized) {
        return 0;
    }

    if (!display_is_available()) {
        return input_confirm(message ? message : title);
    }

    /* Show confirmation dialog */
    display_clear(COLOR_BLACK);
    display_draw_text_centered(40, title, COLOR_WHITE, COLOR_BLACK);

    if (message) {
        display_draw_text_centered(100, message, COLOR_LIGHTGRAY, COLOR_BLACK);
    }

    display_fill_rect(40, 180, 100, 40, COLOR_GREEN);
    display_draw_text(60, 192, "CONFIRM", COLOR_WHITE, COLOR_GREEN);

    display_fill_rect(180, 180, 100, 40, COLOR_RED);
    display_draw_text(205, 192, "CANCEL", COLOR_WHITE, COLOR_RED);

    display_update();

    /* Wait for response */
    while (1) {
        if (input_wait(&event, 0) <= 0) {
            continue;
        }

        if (!event.pressed) {
            continue;
        }

        if (event.button == BTN_CONFIRM || event.button == BTN_SELECT) {
            return 1;
        }

        if (event.button == BTN_CANCEL || event.button == BTN_BACK) {
            return 0;
        }
    }
}

int input_menu_select(const char **items, int count, int selected)
{
    input_event_t event;
    int visible_start = 0;
    const int visible_count = 6;  /* Items visible at once */

    if (!g_initialized || items == NULL || count <= 0) {
        return -1;
    }

    if (selected < 0 || selected >= count) {
        selected = 0;
    }

    while (1) {
        /* Adjust visible window */
        if (selected < visible_start) {
            visible_start = selected;
        } else if (selected >= visible_start + visible_count) {
            visible_start = selected - visible_count + 1;
        }

        if (display_is_available()) {
            display_clear(COLOR_BLACK);
            display_draw_text_centered(10, "Select Option", COLOR_WHITE, COLOR_BLACK);

            for (int i = 0; i < visible_count && (visible_start + i) < count; i++) {
                int idx = visible_start + i;
                int y = 50 + i * 28;

                if (idx == selected) {
                    display_fill_rect(10, y - 2, 300, 24, COLOR_BLUE);
                    display_draw_text(20, y, items[idx], COLOR_WHITE, COLOR_BLUE);
                } else {
                    display_draw_text(20, y, items[idx], COLOR_LIGHTGRAY, COLOR_BLACK);
                }
            }

            /* Scroll indicators */
            if (visible_start > 0) {
                display_draw_text(150, 35, "^", COLOR_GRAY, COLOR_BLACK);
            }
            if (visible_start + visible_count < count) {
                display_draw_text(150, 220, "v", COLOR_GRAY, COLOR_BLACK);
            }

            display_update();
        } else {
            /* Terminal fallback */
            printf("\n--- Select Option ---\n");
            for (int i = 0; i < count; i++) {
                printf("%c [%d] %s\n", (i == selected) ? '>' : ' ', i + 1, items[i]);
            }
            printf("Use UP/DOWN, ENTER to select, ESC to cancel\n");
        }

        /* Wait for input */
        if (input_wait(&event, 0) <= 0) {
            continue;
        }

        if (!event.pressed) {
            continue;
        }

        switch (event.button) {
        case BTN_UP:
            if (selected > 0) {
                selected--;
            }
            break;

        case BTN_DOWN:
            if (selected < count - 1) {
                selected++;
            }
            break;

        case BTN_SELECT:
        case BTN_CONFIRM:
            return selected;

        case BTN_CANCEL:
        case BTN_BACK:
            return -1;

        default:
            break;
        }
    }
}

int input_configure_gpio(button_t button, const gpio_pin_config_t *config)
{
    if (button <= WALLET_BTN_NONE || button >= WALLET_BTN_COUNT || config == NULL) {
        return INPUT_ERR_INIT;
    }

    g_default_gpio_map[button] = *config;

    return INPUT_OK;
}

void input_set_debounce(uint32_t debounce_ms)
{
    g_debounce_ms = debounce_ms;
}

int input_set_callback(input_callback_t callback, void *user_data)
{
    g_callback = callback;
    g_callback_data = user_data;
    return INPUT_OK;
}

void input_clear_callback(void)
{
    g_callback = NULL;
    g_callback_data = NULL;
}

const char *input_button_name(button_t button)
{
    if (button >= 0 && button < WALLET_BTN_COUNT) {
        return g_button_names[button];
    }
    return "UNKNOWN";
}

void input_simulate(button_t button, int pressed)
{
    if (button > WALLET_BTN_NONE && button < WALLET_BTN_COUNT) {
        if (pressed) {
            g_simulated_buttons[button] = 1;
        }

        /* Also update state tracking */
        g_button_state[button] = pressed ? 1 : 0;
    }
}

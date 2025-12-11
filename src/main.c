/*
 * RISC-V Cold Wallet - Main Entry Point
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "ui/cli.h"
#include "security/memory.h"
#include "crypto/random.h"

static volatile sig_atomic_t g_running = 1;

/* Signal handler for clean shutdown */
static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    printf("\nInterrupted. Cleaning up...\n");
}

static void print_version(void)
{
    printf("RISC-V Cold Wallet v0.1.0\n");
    printf("Copyright (C) 2025 blubskye\n");
    printf("License: AGPL-3.0-or-later\n");
    printf("Source:  https://github.com/blubskye/riscv_wallet\n");
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -h, --help      Show this help message\n");
    printf("  -v, --version   Show version and license information\n");
    printf("  --source        Show source code URL (AGPL compliance)\n");
}

int main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;

    /* Handle command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "--source") == 0) {
            printf("https://github.com/blubskye/riscv_wallet\n");
            return EXIT_SUCCESS;
        }
    }

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize secure memory handling */
    if (secure_memory_init() != 0) {
        fprintf(stderr, "Failed to initialize secure memory\n");
        return EXIT_FAILURE;
    }

    /* Initialize random number generator (uses hardware RNG if available) */
    if (random_init() != 0) {
        fprintf(stderr, "Failed to initialize random subsystem\n");
        secure_memory_cleanup();
        return EXIT_FAILURE;
    }

    /* Initialize CLI subsystem */
    if (cli_init() != 0) {
        fprintf(stderr, "Failed to initialize CLI\n");
        random_cleanup();
        secure_memory_cleanup();
        return EXIT_FAILURE;
    }

    /* Run CLI */
    ret = cli_run();

    /* Cleanup */
    cli_cleanup();
    random_cleanup();
    secure_memory_cleanup();

    /* Final secure memory wipe */
    secure_memory_wipe_all();

    return ret;
}

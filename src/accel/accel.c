/*
 * Hardware Acceleration Implementation
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Runtime CPU feature detection and accelerated crypto dispatch.
 */

#define _POSIX_C_SOURCE 200809L

#include "accel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <sys/auxv.h>
#endif

#ifdef ACCEL_HOTLOAD
#include <dlfcn.h>
#endif

/* External generic implementations (from crypto/) */
extern void crypto_hash_sha256(unsigned char *out, const unsigned char *in, unsigned long long len);
extern void crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long len);
extern void ripemd160(const uint8_t *data, size_t len, uint8_t digest[20]);
extern void keccak256(const uint8_t *data, size_t len, uint8_t *hash);

/* Forward declarations for wrappers */
static void generic_sha256(const uint8_t *data, size_t len, uint8_t hash[32]);
static void generic_sha512(const uint8_t *data, size_t len, uint8_t hash[64]);
static void generic_ripemd160(const uint8_t *data, size_t len, uint8_t hash[20]);
static void generic_keccak256(const uint8_t *data, size_t len, uint8_t hash[32]);

/* Detected extensions */
static uint64_t g_extensions = 0;
static int g_initialized = 0;

/* Current dispatch table */
static accel_dispatch_t g_dispatch;

/* Loaded module handle */
#ifdef ACCEL_HOTLOAD
static void *g_module_handle = NULL;
static accel_module_t *g_module = NULL;
#endif

/*
 * Generic (fallback) dispatch table
 */
static const accel_dispatch_t g_generic_dispatch = {
    .type = ACCEL_IMPL_GENERIC,
    .name = "Generic C",
    .required_extensions = 0,
    .sha256 = generic_sha256,
    .sha256_init = NULL,  /* Use libsodium streaming API */
    .sha256_update = NULL,
    .sha256_final = NULL,
    .sha512 = generic_sha512,
    .ripemd160 = generic_ripemd160,
    .keccak256 = generic_keccak256,
    .ecdsa_sign = NULL,   /* Use libsecp256k1 */
    .ecdsa_verify = NULL,
    .pubkey_create = NULL,
    .pubkey_tweak = NULL,
    .schnorr_sign = NULL,
};

/*
 * Wrapper functions to adapt existing implementations
 */
static void generic_sha256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    crypto_hash_sha256(hash, data, len);
}

static void generic_sha512(const uint8_t *data, size_t len, uint8_t hash[64])
{
    crypto_hash_sha512(hash, data, len);
}

static void generic_ripemd160(const uint8_t *data, size_t len, uint8_t hash[20])
{
    ripemd160(data, len, hash);
}

static void generic_keccak256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    keccak256(data, len, hash);
}

/*
 * RISC-V CPU Feature Detection
 *
 * On Linux, we use getauxval(AT_HWCAP) to read the hardware capabilities.
 * The HWCAP bits correspond to single-letter extensions where bit N = extension (N + 'A').
 * For multi-letter extensions, we check /proc/cpuinfo or use hwprobe syscall.
 */

#ifdef __riscv

/* HWCAP bit positions for single-letter extensions */
#define HWCAP_ISA_V     (1UL << ('V' - 'A'))  /* Vector */

#ifdef __linux__
static uint64_t detect_riscv_extensions(void)
{
    uint64_t extensions = 0;
    unsigned long hwcap = 0;

    /* Get basic HWCAP */
    hwcap = getauxval(AT_HWCAP);

    /* Check for vector extension */
    if (hwcap & HWCAP_ISA_V) {
        extensions |= RISCV_EXT_V;
    }

    /*
     * For multi-letter extensions (Zk*, Zvk*), we need to parse
     * /proc/cpuinfo or use the newer hwprobe mechanism.
     *
     * /proc/cpuinfo format:
     *   isa : rv64imafdc_zba_zbb_zbc_zbs_zkn_zvk...
     */
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "isa", 3) == 0) {
                /* Parse ISA string */
                char *isa = strchr(line, ':');
                if (isa) {
                    isa++;  /* Skip ':' */

                    /* Check for scalar crypto extensions */
                    if (strstr(isa, "_zbkb") || strstr(isa, "_Zbkb"))
                        extensions |= RISCV_EXT_ZBKB;
                    if (strstr(isa, "_zbkc") || strstr(isa, "_Zbkc"))
                        extensions |= RISCV_EXT_ZBKC;
                    if (strstr(isa, "_zbkx") || strstr(isa, "_Zbkx"))
                        extensions |= RISCV_EXT_ZBKX;
                    if (strstr(isa, "_zknd") || strstr(isa, "_Zknd"))
                        extensions |= RISCV_EXT_ZKND;
                    if (strstr(isa, "_zkne") || strstr(isa, "_Zkne"))
                        extensions |= RISCV_EXT_ZKNE;
                    if (strstr(isa, "_zknh") || strstr(isa, "_Zknh"))
                        extensions |= RISCV_EXT_ZKNH;
                    if (strstr(isa, "_zkr") || strstr(isa, "_Zkr"))
                        extensions |= RISCV_EXT_ZKR;
                    if (strstr(isa, "_zkt") || strstr(isa, "_Zkt"))
                        extensions |= RISCV_EXT_ZKT;

                    /* Check for Zkn/Zks shorthand */
                    if (strstr(isa, "_zkn") || strstr(isa, "_Zkn"))
                        extensions |= RISCV_EXT_ZKN;
                    if (strstr(isa, "_zks") || strstr(isa, "_Zks"))
                        extensions |= RISCV_EXT_ZKS;

                    /* Check for vector crypto extensions */
                    if (strstr(isa, "_zvbb") || strstr(isa, "_Zvbb"))
                        extensions |= RISCV_EXT_ZVBB;
                    if (strstr(isa, "_zvbc") || strstr(isa, "_Zvbc"))
                        extensions |= RISCV_EXT_ZVBC;
                    if (strstr(isa, "_zvkg") || strstr(isa, "_Zvkg"))
                        extensions |= RISCV_EXT_ZVKG;
                    if (strstr(isa, "_zvkned") || strstr(isa, "_Zvkned"))
                        extensions |= RISCV_EXT_ZVKNED;
                    if (strstr(isa, "_zvknha") || strstr(isa, "_Zvknha"))
                        extensions |= RISCV_EXT_ZVKNHA;
                    if (strstr(isa, "_zvknhb") || strstr(isa, "_Zvknhb"))
                        extensions |= RISCV_EXT_ZVKNHB;
                    if (strstr(isa, "_zvksed") || strstr(isa, "_Zvksed"))
                        extensions |= RISCV_EXT_ZVKSED;
                    if (strstr(isa, "_zvksh") || strstr(isa, "_Zvksh"))
                        extensions |= RISCV_EXT_ZVKSH;

                    /* Bit manipulation */
                    if (strstr(isa, "_zba") || strstr(isa, "_Zba"))
                        extensions |= RISCV_EXT_ZBA;
                    if (strstr(isa, "_zbb") || strstr(isa, "_Zbb"))
                        extensions |= RISCV_EXT_ZBB;
                    if (strstr(isa, "_zbc") || strstr(isa, "_Zbc"))
                        extensions |= RISCV_EXT_ZBC;
                    if (strstr(isa, "_zbs") || strstr(isa, "_Zbs"))
                        extensions |= RISCV_EXT_ZBS;
                }
                break;
            }
        }
        fclose(f);
    }

    return extensions;
}
#else
static uint64_t detect_riscv_extensions(void)
{
    /* No detection available on non-Linux RISC-V */
    return 0;
}
#endif /* __linux__ */

#else /* !__riscv */

static uint64_t detect_riscv_extensions(void)
{
    /* Not running on RISC-V */
    return 0;
}

#endif /* __riscv */

/*
 * Select best implementation based on detected extensions
 */
static void select_implementation(void)
{
    /* Start with generic */
    memcpy(&g_dispatch, &g_generic_dispatch, sizeof(g_dispatch));

    /*
     * Priority order (highest to lowest):
     * 1. External hotloaded module (if loaded and compatible)
     * 2. Vector crypto (Zvk) - best performance for bulk operations
     * 3. Scalar crypto (Zk) - good for single operations
     * 4. Vector (V) - can help with some operations
     * 5. Generic C fallback
     *
     * Note: Actual accelerated implementations would be compiled
     * conditionally with appropriate intrinsics/assembly.
     */

#ifdef ACCEL_HOTLOAD
    if (g_module && g_module->dispatch) {
        /* Check if module's requirements are met */
        if ((g_extensions & g_module->required_extensions) ==
            g_module->required_extensions) {
            memcpy(&g_dispatch, g_module->dispatch, sizeof(g_dispatch));
            g_dispatch.type = ACCEL_IMPL_EXTERNAL;
            return;
        }
    }
#endif

    /* Check for vector crypto (Zvknha for SHA-256) */
    if ((g_extensions & RISCV_EXT_V) && (g_extensions & RISCV_EXT_ZVKNHA)) {
        g_dispatch.type = ACCEL_IMPL_VECTOR_CRYPTO;
        g_dispatch.name = "RISC-V Vector Crypto (Zvk)";
        /* Would set accelerated function pointers here */
        return;
    }

    /* Check for scalar crypto (Zknh for SHA-256) */
    if (g_extensions & RISCV_EXT_ZKNH) {
        g_dispatch.type = ACCEL_IMPL_SCALAR_CRYPTO;
        g_dispatch.name = "RISC-V Scalar Crypto (Zknh)";
        /* Would set accelerated function pointers here */
        return;
    }

    /* Check for basic vector extension */
    if (g_extensions & RISCV_EXT_V) {
        g_dispatch.type = ACCEL_IMPL_VECTOR;
        g_dispatch.name = "RISC-V Vector (V)";
        /* Would set accelerated function pointers here */
        return;
    }

    /* Fallback to generic */
    g_dispatch.type = ACCEL_IMPL_GENERIC;
    g_dispatch.name = "Generic C";
}

/*
 * Public API
 */

int accel_init(void)
{
    if (g_initialized) {
        return 0;
    }

    /* Detect CPU features */
    g_extensions = detect_riscv_extensions();

    /* Select best implementation */
    select_implementation();

    g_initialized = 1;
    return 0;
}

void accel_cleanup(void)
{
    if (!g_initialized) {
        return;
    }

#ifdef ACCEL_HOTLOAD
    accel_unload_module();
#endif

    g_extensions = 0;
    g_initialized = 0;
}

uint64_t accel_get_extensions(void)
{
    return g_extensions;
}

int accel_get_extension_string(char *buf, size_t buf_len)
{
    if (!buf || buf_len == 0) {
        return -1;
    }

    buf[0] = '\0';
    size_t pos = 0;

    struct {
        uint64_t flag;
        const char *name;
    } exts[] = {
        { RISCV_EXT_V,      "V" },
        { RISCV_EXT_ZBA,    "Zba" },
        { RISCV_EXT_ZBB,    "Zbb" },
        { RISCV_EXT_ZBC,    "Zbc" },
        { RISCV_EXT_ZBS,    "Zbs" },
        { RISCV_EXT_ZBKB,   "Zbkb" },
        { RISCV_EXT_ZBKC,   "Zbkc" },
        { RISCV_EXT_ZBKX,   "Zbkx" },
        { RISCV_EXT_ZKND,   "Zknd" },
        { RISCV_EXT_ZKNE,   "Zkne" },
        { RISCV_EXT_ZKNH,   "Zknh" },
        { RISCV_EXT_ZKR,    "Zkr" },
        { RISCV_EXT_ZKT,    "Zkt" },
        { RISCV_EXT_ZVBB,   "Zvbb" },
        { RISCV_EXT_ZVBC,   "Zvbc" },
        { RISCV_EXT_ZVKG,   "Zvkg" },
        { RISCV_EXT_ZVKNED, "Zvkned" },
        { RISCV_EXT_ZVKNHA, "Zvknha" },
        { RISCV_EXT_ZVKNHB, "Zvknhb" },
        { RISCV_EXT_ZVKSED, "Zvksed" },
        { RISCV_EXT_ZVKSH,  "Zvksh" },
        { 0, NULL }
    };

    for (size_t i = 0; exts[i].name; i++) {
        if (g_extensions & exts[i].flag) {
            int written;
            if (pos > 0) {
                written = snprintf(buf + pos, buf_len - pos, " %s", exts[i].name);
            } else {
                written = snprintf(buf + pos, buf_len - pos, "%s", exts[i].name);
            }
            if (written < 0 || (size_t)written >= buf_len - pos) {
                break;
            }
            pos += (size_t)written;
        }
    }

    if (pos == 0) {
        snprintf(buf, buf_len, "(none)");
    }

    return (int)pos;
}

accel_impl_t accel_get_impl_type(void)
{
    return g_dispatch.type;
}

const char *accel_get_impl_name(void)
{
    return g_dispatch.name;
}

#ifdef ACCEL_HOTLOAD
int accel_load_module(const char *path)
{
    if (!path) {
        return -1;
    }

    /* Unload any existing module */
    accel_unload_module();

    /* Load shared library */
    g_module_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!g_module_handle) {
        fprintf(stderr, "accel: failed to load module: %s\n", dlerror());
        return -1;
    }

    /* Get module descriptor */
    g_module = dlsym(g_module_handle, "accel_module");
    if (!g_module) {
        fprintf(stderr, "accel: module missing accel_module symbol\n");
        dlclose(g_module_handle);
        g_module_handle = NULL;
        return -1;
    }

    /* Validate module */
    if (g_module->magic != ACCEL_MODULE_MAGIC) {
        fprintf(stderr, "accel: invalid module magic\n");
        dlclose(g_module_handle);
        g_module_handle = NULL;
        g_module = NULL;
        return -1;
    }

    if (g_module->version != ACCEL_MODULE_VERSION) {
        fprintf(stderr, "accel: module version mismatch (got %u, expected %u)\n",
                g_module->version, ACCEL_MODULE_VERSION);
        dlclose(g_module_handle);
        g_module_handle = NULL;
        g_module = NULL;
        return -1;
    }

    /* Check required extensions */
    if ((g_extensions & g_module->required_extensions) !=
        g_module->required_extensions) {
        fprintf(stderr, "accel: module requires extensions not available\n");
        dlclose(g_module_handle);
        g_module_handle = NULL;
        g_module = NULL;
        return -1;
    }

    /* Initialize module */
    if (g_module->init && g_module->init() != 0) {
        fprintf(stderr, "accel: module initialization failed\n");
        dlclose(g_module_handle);
        g_module_handle = NULL;
        g_module = NULL;
        return -1;
    }

    /* Re-select implementation (will pick up module) */
    select_implementation();

    return 0;
}

void accel_unload_module(void)
{
    if (g_module) {
        if (g_module->cleanup) {
            g_module->cleanup();
        }
        g_module = NULL;
    }

    if (g_module_handle) {
        dlclose(g_module_handle);
        g_module_handle = NULL;
    }

    /* Revert to built-in implementation */
    select_implementation();
}
#else
int accel_load_module(const char *path)
{
    (void)path;
    fprintf(stderr, "accel: hotloading not enabled (compile with ACCEL_HOTLOAD)\n");
    return -1;
}

void accel_unload_module(void)
{
    /* No-op when hotloading disabled */
}
#endif /* ACCEL_HOTLOAD */

const accel_dispatch_t *accel_get_dispatch(void)
{
    return &g_dispatch;
}

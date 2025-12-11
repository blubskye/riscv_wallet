/*
 * Hardware Acceleration Interface
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Runtime CPU feature detection and accelerated crypto dispatch.
 * Supports hotloadable modules for RISC-V vector/crypto extensions.
 */

#ifndef ACCEL_H
#define ACCEL_H

#include <stdint.h>
#include <stddef.h>

/*
 * RISC-V Extension Flags
 * Based on ratified extensions as of 2024
 */

/* Base extensions */
#define RISCV_EXT_V         (1ULL << 0)   /* Vector Extension 1.0 */
#define RISCV_EXT_ZBA       (1ULL << 1)   /* Address generation */
#define RISCV_EXT_ZBB       (1ULL << 2)   /* Basic bit-manipulation */
#define RISCV_EXT_ZBC       (1ULL << 3)   /* Carry-less multiplication */
#define RISCV_EXT_ZBS       (1ULL << 4)   /* Single-bit instructions */

/* Scalar Cryptography (Zk) */
#define RISCV_EXT_ZBKB      (1ULL << 8)   /* Bit-manip for crypto */
#define RISCV_EXT_ZBKC      (1ULL << 9)   /* Carry-less mul for crypto */
#define RISCV_EXT_ZBKX      (1ULL << 10)  /* Crossbar permutations */
#define RISCV_EXT_ZKND      (1ULL << 11)  /* AES Decryption */
#define RISCV_EXT_ZKNE      (1ULL << 12)  /* AES Encryption */
#define RISCV_EXT_ZKNH      (1ULL << 13)  /* SHA2 Hash (SHA-256/512) */
#define RISCV_EXT_ZKSED     (1ULL << 14)  /* SM4 Block Cipher */
#define RISCV_EXT_ZKSH      (1ULL << 15)  /* SM3 Hash */
#define RISCV_EXT_ZKR       (1ULL << 16)  /* Entropy Source */
#define RISCV_EXT_ZKT       (1ULL << 17)  /* Data-independent timing */

/* Vector Cryptography (Zvk) */
#define RISCV_EXT_ZVBB      (1ULL << 24)  /* Vector bit-manip */
#define RISCV_EXT_ZVBC      (1ULL << 25)  /* Vector carry-less mul */
#define RISCV_EXT_ZVKG      (1ULL << 26)  /* Vector GCM/GMAC */
#define RISCV_EXT_ZVKNED    (1ULL << 27)  /* Vector AES */
#define RISCV_EXT_ZVKNHA    (1ULL << 28)  /* Vector SHA-256 */
#define RISCV_EXT_ZVKNHB    (1ULL << 29)  /* Vector SHA-512 */
#define RISCV_EXT_ZVKSED    (1ULL << 30)  /* Vector SM4 */
#define RISCV_EXT_ZVKSH     (1ULL << 31)  /* Vector SM3 */

/* Shorthand extension groups */
#define RISCV_EXT_ZKN       (RISCV_EXT_ZBKB | RISCV_EXT_ZBKC | RISCV_EXT_ZBKX | \
                             RISCV_EXT_ZKND | RISCV_EXT_ZKNE | RISCV_EXT_ZKNH)
#define RISCV_EXT_ZKS       (RISCV_EXT_ZBKB | RISCV_EXT_ZBKC | RISCV_EXT_ZBKX | \
                             RISCV_EXT_ZKSED | RISCV_EXT_ZKSH)
#define RISCV_EXT_ZK        (RISCV_EXT_ZKN | RISCV_EXT_ZKT | RISCV_EXT_ZKR)

/*
 * Acceleration Implementation Types
 */
typedef enum {
    ACCEL_IMPL_GENERIC = 0,     /* Pure C fallback */
    ACCEL_IMPL_SCALAR_CRYPTO,   /* RISC-V Zk scalar crypto */
    ACCEL_IMPL_VECTOR,          /* RISC-V V vector */
    ACCEL_IMPL_VECTOR_CRYPTO,   /* RISC-V Zvk vector crypto */
    ACCEL_IMPL_EXTERNAL,        /* External hotloaded module */
} accel_impl_t;

/*
 * Function pointer types for accelerated operations
 */

/* SHA-256 */
typedef void (*sha256_fn)(const uint8_t *data, size_t len, uint8_t hash[32]);
typedef void (*sha256_init_fn)(void *state);
typedef void (*sha256_update_fn)(void *state, const uint8_t *data, size_t len);
typedef void (*sha256_final_fn)(void *state, uint8_t hash[32]);

/* SHA-512 */
typedef void (*sha512_fn)(const uint8_t *data, size_t len, uint8_t hash[64]);

/* RIPEMD-160 */
typedef void (*ripemd160_fn)(const uint8_t *data, size_t len, uint8_t hash[20]);

/* Keccak-256 (for Ethereum) */
typedef void (*keccak256_fn)(const uint8_t *data, size_t len, uint8_t hash[32]);

/* secp256k1 operations */
typedef int (*ecdsa_sign_fn)(const uint8_t privkey[32], const uint8_t hash[32],
                             uint8_t sig[64]);
typedef int (*ecdsa_verify_fn)(const uint8_t pubkey[33], const uint8_t hash[32],
                               const uint8_t sig[64]);
typedef int (*pubkey_create_fn)(const uint8_t privkey[32], uint8_t pubkey[33]);
typedef int (*pubkey_tweak_fn)(uint8_t pubkey[33], const uint8_t tweak[32]);

/* Schnorr signatures (BIP-340) */
typedef int (*schnorr_sign_fn)(const uint8_t privkey[32], const uint8_t hash[32],
                               uint8_t sig[64]);

/*
 * Acceleration dispatch table
 */
typedef struct {
    /* Implementation info */
    accel_impl_t type;
    const char *name;
    uint64_t required_extensions;

    /* Hash functions */
    sha256_fn sha256;
    sha256_init_fn sha256_init;
    sha256_update_fn sha256_update;
    sha256_final_fn sha256_final;
    sha512_fn sha512;
    ripemd160_fn ripemd160;
    keccak256_fn keccak256;

    /* Elliptic curve operations */
    ecdsa_sign_fn ecdsa_sign;
    ecdsa_verify_fn ecdsa_verify;
    pubkey_create_fn pubkey_create;
    pubkey_tweak_fn pubkey_tweak;
    schnorr_sign_fn schnorr_sign;
} accel_dispatch_t;

/*
 * Hotloadable module interface
 */
typedef struct {
    uint32_t magic;             /* ACCEL_MODULE_MAGIC */
    uint32_t version;           /* Module ABI version */
    uint64_t required_extensions;
    const char *name;
    const char *description;

    /* Module lifecycle */
    int (*init)(void);
    void (*cleanup)(void);

    /* Dispatch table provided by module */
    const accel_dispatch_t *dispatch;
} accel_module_t;

#define ACCEL_MODULE_MAGIC      0x41434345  /* "ACCE" */
#define ACCEL_MODULE_VERSION    1

/*
 * API Functions
 */

/**
 * Initialize acceleration subsystem
 * Detects CPU features and selects best implementation
 * @return 0 on success, -1 on error
 */
int accel_init(void);

/**
 * Cleanup acceleration subsystem
 */
void accel_cleanup(void);

/**
 * Get detected RISC-V extensions
 * @return Bitmask of RISCV_EXT_* flags
 */
uint64_t accel_get_extensions(void);

/**
 * Get human-readable extension string
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @return Length written, or -1 on error
 */
int accel_get_extension_string(char *buf, size_t buf_len);

/**
 * Get current implementation info
 * @return Implementation type
 */
accel_impl_t accel_get_impl_type(void);

/**
 * Get implementation name
 * @return Human-readable name
 */
const char *accel_get_impl_name(void);

/**
 * Load external acceleration module
 * @param path Path to shared library
 * @return 0 on success, -1 on error
 */
int accel_load_module(const char *path);

/**
 * Unload external module and revert to built-in
 */
void accel_unload_module(void);

/**
 * Get current dispatch table
 * @return Pointer to dispatch table (never NULL after init)
 */
const accel_dispatch_t *accel_get_dispatch(void);

/*
 * Convenience macros for calling accelerated functions
 */
#define ACCEL_SHA256(data, len, hash) \
    accel_get_dispatch()->sha256((data), (len), (hash))

#define ACCEL_SHA512(data, len, hash) \
    accel_get_dispatch()->sha512((data), (len), (hash))

#define ACCEL_RIPEMD160(data, len, hash) \
    accel_get_dispatch()->ripemd160((data), (len), (hash))

#define ACCEL_KECCAK256(data, len, hash) \
    accel_get_dispatch()->keccak256((data), (len), (hash))

#endif /* ACCEL_H */

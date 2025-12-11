/*
 * RISC-V Optimization Primitives
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Inline functions using RISC-V extensions for improved performance.
 * Falls back to portable C when extensions not available.
 */

#ifndef RISCV_OPT_H
#define RISCV_OPT_H

#include <stdint.h>

/*
 * Compiler/Architecture Detection
 */
#if defined(__riscv) && defined(__riscv_zbb)
#define RISCV_HAS_ZBB 1
#else
#define RISCV_HAS_ZBB 0
#endif

#if defined(__riscv) && defined(__riscv_zba)
#define RISCV_HAS_ZBA 1
#else
#define RISCV_HAS_ZBA 0
#endif

#if defined(__riscv) && defined(__riscv_zbs)
#define RISCV_HAS_ZBS 1
#else
#define RISCV_HAS_ZBS 0
#endif

#if defined(__riscv) && defined(__riscv_zbkb)
#define RISCV_HAS_ZBKB 1
#else
#define RISCV_HAS_ZBKB 0
#endif

#if defined(__riscv) && defined(__riscv_zknh)
#define RISCV_HAS_ZKNH 1
#else
#define RISCV_HAS_ZKNH 0
#endif

/*
 * Bit Manipulation Operations (Zbb)
 */

/**
 * Count leading zeros (clz)
 * Returns number of leading zero bits in x
 */
static inline int riscv_clz32(uint32_t x)
{
#if RISCV_HAS_ZBB
    int result;
    __asm__ volatile("clzw %0, %1" : "=r"(result) : "r"(x));
    return result;
#else
    if (x == 0) return 32;
    int n = 0;
    if ((x & 0xFFFF0000) == 0) { n += 16; x <<= 16; }
    if ((x & 0xFF000000) == 0) { n += 8;  x <<= 8;  }
    if ((x & 0xF0000000) == 0) { n += 4;  x <<= 4;  }
    if ((x & 0xC0000000) == 0) { n += 2;  x <<= 2;  }
    if ((x & 0x80000000) == 0) { n += 1; }
    return n;
#endif
}

static inline int riscv_clz64(uint64_t x)
{
#if RISCV_HAS_ZBB && __riscv_xlen == 64
    int result;
    __asm__ volatile("clz %0, %1" : "=r"(result) : "r"(x));
    return result;
#else
    if (x == 0) return 64;
    int n = 0;
    if ((x & 0xFFFFFFFF00000000ULL) == 0) { n += 32; x <<= 32; }
    if ((x & 0xFFFF000000000000ULL) == 0) { n += 16; x <<= 16; }
    if ((x & 0xFF00000000000000ULL) == 0) { n += 8;  x <<= 8;  }
    if ((x & 0xF000000000000000ULL) == 0) { n += 4;  x <<= 4;  }
    if ((x & 0xC000000000000000ULL) == 0) { n += 2;  x <<= 2;  }
    if ((x & 0x8000000000000000ULL) == 0) { n += 1; }
    return n;
#endif
}

/**
 * Count trailing zeros (ctz)
 */
static inline int riscv_ctz32(uint32_t x)
{
#if RISCV_HAS_ZBB
    int result;
    __asm__ volatile("ctzw %0, %1" : "=r"(result) : "r"(x));
    return result;
#else
    if (x == 0) return 32;
    int n = 0;
    if ((x & 0x0000FFFF) == 0) { n += 16; x >>= 16; }
    if ((x & 0x000000FF) == 0) { n += 8;  x >>= 8;  }
    if ((x & 0x0000000F) == 0) { n += 4;  x >>= 4;  }
    if ((x & 0x00000003) == 0) { n += 2;  x >>= 2;  }
    if ((x & 0x00000001) == 0) { n += 1; }
    return n;
#endif
}

/**
 * Population count (popcnt) - count set bits
 */
static inline int riscv_popcount32(uint32_t x)
{
#if RISCV_HAS_ZBB
    int result;
    __asm__ volatile("cpopw %0, %1" : "=r"(result) : "r"(x));
    return result;
#else
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x + (x >> 4)) & 0x0F0F0F0F;
    return (x * 0x01010101) >> 24;
#endif
}

static inline int riscv_popcount64(uint64_t x)
{
#if RISCV_HAS_ZBB && __riscv_xlen == 64
    int result;
    __asm__ volatile("cpop %0, %1" : "=r"(result) : "r"(x));
    return result;
#else
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (x * 0x0101010101010101ULL) >> 56;
#endif
}

/**
 * Rotate left
 */
static inline uint32_t riscv_rol32(uint32_t x, int n)
{
#if RISCV_HAS_ZBB
    uint32_t result;
    __asm__ volatile("rolw %0, %1, %2" : "=r"(result) : "r"(x), "r"(n));
    return result;
#else
    n &= 31;
    return (x << n) | (x >> (32 - n));
#endif
}

static inline uint64_t riscv_rol64(uint64_t x, int n)
{
#if RISCV_HAS_ZBB && __riscv_xlen == 64
    uint64_t result;
    __asm__ volatile("rol %0, %1, %2" : "=r"(result) : "r"(x), "r"(n));
    return result;
#else
    n &= 63;
    return (x << n) | (x >> (64 - n));
#endif
}

/**
 * Rotate right
 */
static inline uint32_t riscv_ror32(uint32_t x, int n)
{
#if RISCV_HAS_ZBB
    uint32_t result;
    __asm__ volatile("rorw %0, %1, %2" : "=r"(result) : "r"(x), "r"(n));
    return result;
#else
    n &= 31;
    return (x >> n) | (x << (32 - n));
#endif
}

static inline uint64_t riscv_ror64(uint64_t x, int n)
{
#if RISCV_HAS_ZBB && __riscv_xlen == 64
    uint64_t result;
    __asm__ volatile("ror %0, %1, %2" : "=r"(result) : "r"(x), "r"(n));
    return result;
#else
    n &= 63;
    return (x >> n) | (x << (64 - n));
#endif
}

/**
 * Byte-reverse (bswap/rev8)
 * Used for endianness conversion
 */
static inline uint32_t riscv_bswap32(uint32_t x)
{
#if RISCV_HAS_ZBB || RISCV_HAS_ZBKB
    uint32_t result;
    /* rev8 reverses bytes - need to shift for 32-bit on RV64 */
#if __riscv_xlen == 64
    __asm__ volatile("rev8 %0, %1" : "=r"(result) : "r"((uint64_t)x));
    result >>= 32;
#else
    __asm__ volatile("rev8 %0, %1" : "=r"(result) : "r"(x));
#endif
    return result;
#else
    return ((x >> 24) & 0x000000FF) |
           ((x >>  8) & 0x0000FF00) |
           ((x <<  8) & 0x00FF0000) |
           ((x << 24) & 0xFF000000);
#endif
}

static inline uint64_t riscv_bswap64(uint64_t x)
{
#if (RISCV_HAS_ZBB || RISCV_HAS_ZBKB) && __riscv_xlen == 64
    uint64_t result;
    __asm__ volatile("rev8 %0, %1" : "=r"(result) : "r"(x));
    return result;
#else
    return ((x >> 56) & 0x00000000000000FFULL) |
           ((x >> 40) & 0x000000000000FF00ULL) |
           ((x >> 24) & 0x0000000000FF0000ULL) |
           ((x >>  8) & 0x00000000FF000000ULL) |
           ((x <<  8) & 0x000000FF00000000ULL) |
           ((x << 24) & 0x0000FF0000000000ULL) |
           ((x << 40) & 0x00FF000000000000ULL) |
           ((x << 56) & 0xFF00000000000000ULL);
#endif
}

/*
 * Address Generation (Zba)
 * These help with array indexing: base + (index << shift)
 */

/**
 * Shift-add for array indexing (sh1add, sh2add, sh3add)
 */
static inline uintptr_t riscv_sh1add(uintptr_t index, uintptr_t base)
{
#if RISCV_HAS_ZBA
    uintptr_t result;
    __asm__ volatile("sh1add %0, %1, %2" : "=r"(result) : "r"(index), "r"(base));
    return result;
#else
    return base + (index << 1);
#endif
}

static inline uintptr_t riscv_sh2add(uintptr_t index, uintptr_t base)
{
#if RISCV_HAS_ZBA
    uintptr_t result;
    __asm__ volatile("sh2add %0, %1, %2" : "=r"(result) : "r"(index), "r"(base));
    return result;
#else
    return base + (index << 2);
#endif
}

static inline uintptr_t riscv_sh3add(uintptr_t index, uintptr_t base)
{
#if RISCV_HAS_ZBA
    uintptr_t result;
    __asm__ volatile("sh3add %0, %1, %2" : "=r"(result) : "r"(index), "r"(base));
    return result;
#else
    return base + (index << 3);
#endif
}

/*
 * Single-Bit Operations (Zbs)
 */

/**
 * Set single bit: x | (1 << shamt)
 */
static inline uint64_t riscv_bset(uint64_t x, int shamt)
{
#if RISCV_HAS_ZBS && __riscv_xlen == 64
    uint64_t result;
    __asm__ volatile("bset %0, %1, %2" : "=r"(result) : "r"(x), "r"(shamt));
    return result;
#else
    return x | (1ULL << (shamt & 63));
#endif
}

/**
 * Clear single bit: x & ~(1 << shamt)
 */
static inline uint64_t riscv_bclr(uint64_t x, int shamt)
{
#if RISCV_HAS_ZBS && __riscv_xlen == 64
    uint64_t result;
    __asm__ volatile("bclr %0, %1, %2" : "=r"(result) : "r"(x), "r"(shamt));
    return result;
#else
    return x & ~(1ULL << (shamt & 63));
#endif
}

/**
 * Invert single bit: x ^ (1 << shamt)
 */
static inline uint64_t riscv_binv(uint64_t x, int shamt)
{
#if RISCV_HAS_ZBS && __riscv_xlen == 64
    uint64_t result;
    __asm__ volatile("binv %0, %1, %2" : "=r"(result) : "r"(x), "r"(shamt));
    return result;
#else
    return x ^ (1ULL << (shamt & 63));
#endif
}

/**
 * Extract single bit: (x >> shamt) & 1
 */
static inline int riscv_bext(uint64_t x, int shamt)
{
#if RISCV_HAS_ZBS && __riscv_xlen == 64
    uint64_t result;
    __asm__ volatile("bext %0, %1, %2" : "=r"(result) : "r"(x), "r"(shamt));
    return (int)result;
#else
    return (x >> (shamt & 63)) & 1;
#endif
}

/*
 * Crypto-specific Operations (Zbkb)
 */

/**
 * AND-NOT: x & ~y (andn instruction)
 * Useful in cryptographic algorithms
 */
static inline uint64_t riscv_andn(uint64_t x, uint64_t y)
{
#if RISCV_HAS_ZBB || RISCV_HAS_ZBKB
    uint64_t result;
    __asm__ volatile("andn %0, %1, %2" : "=r"(result) : "r"(x), "r"(y));
    return result;
#else
    return x & ~y;
#endif
}

/**
 * OR-NOT: x | ~y (orn instruction)
 */
static inline uint64_t riscv_orn(uint64_t x, uint64_t y)
{
#if RISCV_HAS_ZBB || RISCV_HAS_ZBKB
    uint64_t result;
    __asm__ volatile("orn %0, %1, %2" : "=r"(result) : "r"(x), "r"(y));
    return result;
#else
    return x | ~y;
#endif
}

/**
 * XOR-NOT (XNOR): ~(x ^ y) (xnor instruction)
 */
static inline uint64_t riscv_xnor(uint64_t x, uint64_t y)
{
#if RISCV_HAS_ZBB || RISCV_HAS_ZBKB
    uint64_t result;
    __asm__ volatile("xnor %0, %1, %2" : "=r"(result) : "r"(x), "r"(y));
    return result;
#else
    return ~(x ^ y);
#endif
}

/*
 * Min/Max Operations (Zbb)
 */

static inline int64_t riscv_max(int64_t a, int64_t b)
{
#if RISCV_HAS_ZBB && __riscv_xlen == 64
    int64_t result;
    __asm__ volatile("max %0, %1, %2" : "=r"(result) : "r"(a), "r"(b));
    return result;
#else
    return (a > b) ? a : b;
#endif
}

static inline int64_t riscv_min(int64_t a, int64_t b)
{
#if RISCV_HAS_ZBB && __riscv_xlen == 64
    int64_t result;
    __asm__ volatile("min %0, %1, %2" : "=r"(result) : "r"(a), "r"(b));
    return result;
#else
    return (a < b) ? a : b;
#endif
}

static inline uint64_t riscv_maxu(uint64_t a, uint64_t b)
{
#if RISCV_HAS_ZBB && __riscv_xlen == 64
    uint64_t result;
    __asm__ volatile("maxu %0, %1, %2" : "=r"(result) : "r"(a), "r"(b));
    return result;
#else
    return (a > b) ? a : b;
#endif
}

static inline uint64_t riscv_minu(uint64_t a, uint64_t b)
{
#if RISCV_HAS_ZBB && __riscv_xlen == 64
    uint64_t result;
    __asm__ volatile("minu %0, %1, %2" : "=r"(result) : "r"(a), "r"(b));
    return result;
#else
    return (a < b) ? a : b;
#endif
}

/*
 * Utility macros for SHA-256/SHA-512
 * These use optimized rotate operations when available
 */

/* SHA-256 uses 32-bit rotations */
#define SHA256_ROTR(x, n)   riscv_ror32((x), (n))
#define SHA256_SHR(x, n)    ((x) >> (n))

/* SHA-256 functions */
#define SHA256_CH(x, y, z)  (((x) & (y)) ^ (riscv_andn((z), (x))))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x)       (SHA256_ROTR(x, 2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22))
#define SHA256_EP1(x)       (SHA256_ROTR(x, 6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25))
#define SHA256_SIG0(x)      (SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ SHA256_SHR(x, 3))
#define SHA256_SIG1(x)      (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ SHA256_SHR(x, 10))

/* SHA-512 uses 64-bit rotations */
#define SHA512_ROTR(x, n)   riscv_ror64((x), (n))
#define SHA512_SHR(x, n)    ((x) >> (n))

/* SHA-512 functions */
#define SHA512_CH(x, y, z)  (((x) & (y)) ^ (riscv_andn((z), (x))))
#define SHA512_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_EP0(x)       (SHA512_ROTR(x, 28) ^ SHA512_ROTR(x, 34) ^ SHA512_ROTR(x, 39))
#define SHA512_EP1(x)       (SHA512_ROTR(x, 14) ^ SHA512_ROTR(x, 18) ^ SHA512_ROTR(x, 41))
#define SHA512_SIG0(x)      (SHA512_ROTR(x, 1) ^ SHA512_ROTR(x, 8) ^ SHA512_SHR(x, 7))
#define SHA512_SIG1(x)      (SHA512_ROTR(x, 19) ^ SHA512_ROTR(x, 61) ^ SHA512_SHR(x, 6))

#endif /* RISCV_OPT_H */

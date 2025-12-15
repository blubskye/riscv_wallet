# C/C++ Optimization Guide for Embedded Systems

A comprehensive guide to writing efficient C code, understanding compiler optimizations, and the relationship between C and modern hardware.

## Table of Contents

1. [The Reality: C is Not a Low-Level Language](#the-reality-c-is-not-a-low-level-language)
2. [C to Assembly Translation](#c-to-assembly-translation)
3. [Compiler Optimization Categories](#compiler-optimization-categories)
4. [Practical Optimization Examples](#practical-optimization-examples)
5. [Embedded Systems Best Practices](#embedded-systems-best-practices)
6. [Compiler Flags and Tools](#compiler-flags-and-tools)

---

## The Reality: C is Not a Low-Level Language

Modern processors are vastly more complex than C's abstract machine model suggests:

### The Abstract Machine Mismatch

- **C assumes**: Flat memory model, serial instruction execution
- **Reality**: Speculative execution, branch prediction, multi-level caches, out-of-order processing
- **Consequence**: Code that appears efficient in C's model may perform poorly on real hardware

### Key Insights

> "The features that led to [Meltdown and Spectre] vulnerabilities were added to let C programmers continue to believe they were programming in a low-level language, when this hasn't been the case for decades."

- A modern Intel processor has up to **180 instructions in flight** at a time
- Processors inspect adjacent instructions and execute them in parallel if independent
- C's theoretical model hasn't fundamentally changed to acknowledge these realities

### Implications for Optimization

1. **Don't assume C maps directly to hardware** - compilers perform extensive transformations
2. **Trust the compiler** for most optimizations - it knows the target architecture better
3. **Profile before optimizing** - intuitions about performance are often wrong
4. **Understand memory hierarchy** - cache behavior often dominates performance

---

## C to Assembly Translation

### Function Calling Convention

Functions establish stack frames through these steps:
1. Save the caller's frame pointer
2. Copy the stack pointer into the frame pointer
3. Decrement the stack pointer for local variables

Parameters are accessed at **positive offsets** from the frame pointer; local variables at **negative offsets**.

### Control Flow Translation

#### Loops
While and for loops generate conditional jumps and branch instructions:

```c
for (int i = 0; i < 100; ++i) {
    func(i * 1234);
}
```

Compiler rewrites using **strength reduction** (replacing multiplication with addition):

```c
// Compiler transforms to:
for (int iTimes1234 = 0; iTimes1234 < 100 * 1234; iTimes1234 += 1234) {
    func(iTimes1234);
}
```

#### Switch Statements

Implementation varies based on case value distribution:

| Pattern | Implementation | Complexity |
|---------|---------------|------------|
| Narrow range | Jump table | O(1) |
| Wide range | Cascading comparisons | O(n) |
| Large distributed | Binary search | O(log n) |

### Array Indexing Optimization

- Compilers optimize loops by **incrementing pointers directly** rather than recalculating indices
- Making struct sizes **powers of 2** enables shift instructions instead of multiplication
- This significantly improves loop performance

```c
// Instead of array[i], compiler uses pointer arithmetic:
// ptr++; *ptr;
```

---

## Compiler Optimization Categories

### Strength Reduction
Taking expensive operations and transforming them to use less expensive ones.

**Example**: Loop multiplication → addition (shown above)

### Inlining
Replacing function calls with function bodies:
- Removes call overhead
- Unlocks further optimizations
- Allows optimization of combined code as single unit

### Constant Folding
Expressions calculable at compile time are replaced with results:

```c
int x = 3 * 4 + 5;  // Compiler computes: int x = 17;
```

### Constant Propagation
Compiler tracks value provenance and exploits known constants:

```c
int x = 5;
int y = x * 2;  // Compiler knows y = 10
```

### Common Subexpression Elimination
Duplicated calculations computed once:

```c
// Before:
a = b * c + d;
e = b * c + f;

// After optimization:
temp = b * c;
a = temp + d;
e = temp + f;
```

### Dead Code Removal
Unreachable or ineffective code is eliminated:
- Unused loads and stores
- Unused functions
- Code after unconditional returns

### Loop Invariant Code Movement
Expressions constant within a loop are moved outside:

```c
// Before:
for (int i = 0; i < n; i++) {
    result[i] = data[i] * (a + b);  // a + b computed every iteration
}

// After optimization:
int temp = a + b;
for (int i = 0; i < n; i++) {
    result[i] = data[i] * temp;
}
```

### Tail Call Removal
Recursive functions ending in self-calls can be rewritten as loops:
- Reduces call overhead
- Prevents stack overflow

---

## Practical Optimization Examples

### Integer Division by Constant

Division is expensive (~50x slower than addition). Compilers use **multiplication by reciprocal**:

```c
unsigned divideByThree(unsigned x) {
    return x / 3;
}
```

Compiles to:
```asm
mov eax, edi
mov edi, 2863311531      ; 0xaaaaaaab (reciprocal of 3)
imul rax, rdi
shr rax, 33              ; Fixed point at bit 33
ret
```

**No divide instruction!** Just shift and multiply.

### Counting Set Bits (Population Count)

```c
int countSetBits(unsigned a) {
    int count = 0;
    while (a != 0) {
        count++;
        a &= (a - 1);  // Clears bottom set bit
    }
    return count;
}
```

Clang recognizes this pattern and emits a single instruction:
```asm
popcnt eax, edi    ; Hardware instruction for bit counting
ret
```

### Chained Conditionals → Lookup Table

```c
bool isWhitespace(char c) {
    return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}
```

Compiler creates a **33-bit lookup table**:
```asm
cmp dil, 32
ja .L4                    ; Quick exit if c > 32
movabs rax, 4294977024    ; Lookup table as magic constant
shrx rax, rax, rdi        ; rax >>= c
and eax, 1                ; Extract bit
```

### Vectorization (SIMD)

```c
int sumSquared(const vector<int> &v) {
    int res = 0;
    for (auto i : v) {
        res += i * i;
    }
    return res;
}
```

Compiler vectorizes to process **8 values at once**:
```asm
vmovdqu ymm2, [rax]       ; Read 32 bytes (8 ints)
vpmulld ymm0, ymm2, ymm2  ; Square all 8
vpaddd ymm1, ymm1, ymm0   ; Add to 8 subtotals
```

---

## Embedded Systems Best Practices

### Data Type Selection

Choose the smallest data type that fits:

```c
// Prefer:
uint8_t counter;    // If 0-255 is sufficient

// Over:
int counter;        // Uses 4 bytes, slower on some architectures
```

### Struct Alignment

Keep struct sizes as **powers of 2** for efficient array indexing:

```c
struct Optimized {
    uint32_t a;
    uint32_t b;
    // Total: 8 bytes (power of 2)
};

struct NotOptimized {
    uint32_t a;
    uint16_t b;
    uint8_t c;
    // Total: 7 bytes (requires multiplication for array indexing)
};
```

### Bit Manipulation

Bit operations are often faster and more memory-efficient:

```c
// Use bit flags instead of separate bools
#define FLAG_A (1 << 0)
#define FLAG_B (1 << 1)
#define FLAG_C (1 << 2)

uint8_t flags = FLAG_A | FLAG_C;

// Check flag
if (flags & FLAG_A) { /* ... */ }

// Clear bottom set bit (useful trick)
x &= (x - 1);
```

### Loop Optimization

```c
// Avoid function calls in loop conditions
// Bad:
for (int i = 0; i < strlen(str); i++) { }

// Good:
size_t len = strlen(str);
for (int i = 0; i < len; i++) { }

// Best (for known-length arrays):
for (int i = 0; i < ARRAY_SIZE; i++) { }
```

### Memory Access Patterns

Access memory sequentially when possible (cache-friendly):

```c
// Good: Sequential access
for (int i = 0; i < rows; i++)
    for (int j = 0; j < cols; j++)
        sum += matrix[i][j];

// Bad: Strided access (cache-unfriendly)
for (int j = 0; j < cols; j++)
    for (int i = 0; i < rows; i++)
        sum += matrix[i][j];
```

### The 80/20 Rule

> "80% of a program's execution time is spent executing 20% of the code."

**Profile first**, then optimize hot spots:
- Use profilers to identify critical areas
- Don't optimize code that isn't performance-critical
- Premature optimization is the root of all evil (Knuth)

---

## Compiler Flags and Tools

### GCC/Clang Optimization Levels

| Flag | Description |
|------|-------------|
| `-O0` | No optimization (debugging) |
| `-O1` | Basic optimization |
| `-O2` | Standard optimization (recommended) |
| `-O3` | Aggressive optimization (may increase code size) |
| `-Os` | Optimize for size |
| `-Ofast` | `-O3` + fast-math (breaks IEEE compliance) |

### Architecture-Specific Flags

```bash
# Target specific CPU
-march=native          # Optimize for build machine
-march=rv32imac        # RISC-V 32-bit with extensions
-mtune=cortex-m4       # Tune for Cortex-M4

# Enable specific features
-msse4.2               # SSE 4.2 instructions
-mavx2                 # AVX2 instructions
```

### Link-Time Optimization (LTO)

```bash
gcc -flto -O2 file1.c file2.c -o program
```

Benefits:
- Allows inlining across translation units
- Enables whole-program optimization
- Can significantly improve performance

### Viewing Assembly Output

```bash
# GCC: Generate assembly
gcc -S -O2 -masm=intel file.c -o file.s

# View with Compiler Explorer
# https://godbolt.org
```

### Function Attributes

```c
// Mark function as pure (no side effects)
__attribute__((pure))
int computeHash(const char *str);

// Force inlining
__attribute__((always_inline))
inline int fastFunc(int x) { return x * 2; }

// Prevent inlining
__attribute__((noinline))
int slowPath(int x);

// Hot/cold hints
__attribute__((hot))
void frequentlyCalledFunc(void);

__attribute__((cold))
void errorHandler(void);
```

---

## Key Takeaways

1. **Trust the compiler** - Modern compilers perform sophisticated transformations
2. **Profile before optimizing** - Don't guess where bottlenecks are
3. **Give the compiler information** - Use `const`, `restrict`, pure attributes
4. **Enable LTO** - Whole-program optimization can unlock significant gains
5. **Target your architecture** - Use `-march` for best instruction selection
6. **Understand memory hierarchy** - Cache behavior often dominates performance
7. **Read the assembly** - Use Compiler Explorer to understand what your code becomes

---

## Sources

- [C to Assembly Translation - EventHelix](https://www.eventhelix.com/embedded/c-to-assembly-translation/)
- [Optimizations in C++ Compilers - ACM Queue (Matt Godbolt)](https://queue.acm.org/detail.cfm?id=3372264)
- [C Is Not a Low-level Language - ACM Queue (David Chisnall)](https://queue.acm.org/detail.cfm?id=3212479)
- [Embedded C Programming Best Practices - EmbeddedXpress](https://embeddedxpress.com/blog/2024/11/17/embedded-c-programming-best-practices-optimization-techniques-and-tools/)
- [Optimizing C and C++ Code - EventHelix](https://www.eventhelix.com/embedded/optimizing-c-and-cpp-code/)
- [Compiler Explorer](https://godbolt.org) - Interactive tool to view compiler output

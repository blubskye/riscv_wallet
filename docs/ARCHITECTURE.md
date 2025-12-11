# RISC-V Cold Wallet Architecture

## Overview

This document describes the architecture for an open-source RISC-V based cold cryptocurrency wallet. The wallet is designed to securely store private keys offline and sign transactions without exposing keys to networked devices.

## Design Principles

1. **Air-gapped Security**: The wallet operates completely offline
2. **Open Source**: All hardware and software is fully open and auditable
3. **Multi-chain Support**: Support for Bitcoin, Ethereum, and other major cryptocurrencies
4. **Hardware Security**: Fingerprint authentication and secure key storage
5. **Minimal Attack Surface**: Small, auditable codebase in C

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface                            │
│                   (LCD Display + Buttons)                        │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Wallet     │  │  Transaction │  │      QR Code         │  │
│  │   Manager    │  │    Signer    │  │   Encoder/Decoder    │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                      Cryptography Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   BIP-39     │  │   BIP-32     │  │    Chain-specific    │  │
│  │  Mnemonic    │  │   HD Keys    │  │   (secp256k1, etc)   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                       Security Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Fingerprint │  │   Secure     │  │      Memory          │  │
│  │    Auth      │  │   Storage    │  │     Protection       │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                       Hardware Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  RISC-V CPU  │  │    NVMe/SD   │  │   Fingerprint        │  │
│  │   (RV64GC)   │  │   Storage    │  │     Sensor           │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Hardware Layer

#### RISC-V Board Requirements
- **Architecture**: RV64GC (64-bit with standard extensions)
- **Minimum RAM**: 512MB (1GB recommended)
- **Secure Boot**: Support for verified boot chain
- **Random Number Generator**: Hardware TRNG required for key generation

**Recommended Boards:**
| Board | CPU | RAM | Price Range | Notes |
|-------|-----|-----|-------------|-------|
| VisionFive 2 | JH7110 | 2-8GB | $55-100 | Good Linux support |
| Milk-V Mars | JH7110 | 1-8GB | $40-70 | Compact form factor |
| LicheePi 4A | TH1520 | 4-16GB | $120-200 | High performance |
| BeagleV-Ahead | TH1520 | 4GB | $150 | Good community |

#### Storage
- **Primary**: NVMe SSD with hardware encryption support
- **Backup**: MicroSD card slot for recovery
- **Power Backup**: Battery/supercapacitor to prevent data loss on NVMe

#### Fingerprint Sensor
- Must be supported by libfprint
- Recommended: sensors with Match-on-Chip for additional security
- See: https://fprint.freedesktop.org/supported-devices.html

### 2. Security Layer

#### Key Storage Architecture
```
┌─────────────────────────────────────┐
│         Encrypted Storage           │
│  ┌─────────────────────────────┐   │
│  │    Master Seed (encrypted)   │   │
│  │    + Fingerprint binding     │   │
│  │    + PIN/passphrase layer    │   │
│  └─────────────────────────────┘   │
│                                     │
│  Encryption: AES-256-GCM            │
│  KDF: Argon2id                      │
│  Integrity: HMAC-SHA256             │
└─────────────────────────────────────┘
```

#### Authentication Flow
1. Device powers on → shows locked screen
2. User presents fingerprint
3. System verifies fingerprint via libfprint
4. User enters PIN/passphrase
5. Key derived using Argon2id(fingerprint_template || pin)
6. Master seed decrypted
7. Session begins with timeout

#### Memory Protection
- Sensitive data stored in secure memory regions
- Memory wiped (zeroed) after use
- No swap enabled
- Stack canaries enabled
- ASLR enabled

### 3. Cryptography Layer

#### Supported Standards
| Standard | Purpose |
|----------|---------|
| BIP-39 | Mnemonic seed phrases (12/24 words) |
| BIP-32 | Hierarchical Deterministic (HD) wallets |
| BIP-44 | Multi-account hierarchy |
| BIP-84 | Native SegWit derivation (Bitcoin) |
| BIP-141 | SegWit transaction format |
| EIP-155 | Ethereum chain ID for replay protection |

#### Supported Curves
| Curve | Used By |
|-------|---------|
| secp256k1 | Bitcoin, Ethereum, most chains |
| ed25519 | Solana, Cardano, others |
| secp256r1 (P-256) | Some newer chains |

#### Key Derivation Paths
```
Bitcoin (Legacy):     m/44'/0'/0'/0/x
Bitcoin (SegWit):     m/84'/0'/0'/0/x
Ethereum:             m/44'/60'/0'/0/x
Solana:               m/44'/501'/0'/0'
Litecoin:             m/84'/2'/0'/0/x
```

### 4. Application Layer

#### Wallet Manager
- Create new wallet (generate mnemonic)
- Restore wallet from mnemonic
- Multiple account support
- Address generation and display
- Balance tracking (via QR code import from companion app)

#### Transaction Signer
- Parse unsigned transaction (from QR code)
- Display transaction details for verification
- Sign transaction after user confirmation
- Output signed transaction (as QR code)

#### QR Code Interface
- Primary method of data transfer (air-gapped)
- Animated QR codes for large data (UR format)
- Camera input for receiving unsigned transactions
- Display output for signed transactions

### 5. User Interface

#### Hardware Interface
- LCD Display: 2.8" - 3.5" TFT (320x240 minimum)
- Navigation: 5-way button or touch screen
- Confirmation buttons: Physical buttons for transaction approval

#### UI Screens
1. **Lock Screen**: Fingerprint prompt
2. **Home**: Account list, total balance
3. **Account**: Address, balance, transaction history
4. **Receive**: Display address + QR code
5. **Sign**: Transaction details, confirm/cancel
6. **Settings**: PIN change, backup, wipe device

## Software Components

### Operating System
**Primary Choice: Linux**
- Better RISC-V support currently
- Rich driver ecosystem
- Can be hardened (SELinux, minimal install)

**Alternative: OpenBSD**
- Superior security defaults
- Limited RISC-V support currently
- Consider for future versions

### Directory Structure
```
riscv_wallet/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── HARDWARE.md
│   └── SECURITY.md
├── src/
│   ├── main.c                 # Entry point
│   ├── wallet/
│   │   ├── wallet.c           # Wallet management
│   │   ├── wallet.h
│   │   ├── account.c          # Account handling
│   │   └── account.h
│   ├── crypto/
│   │   ├── bip39.c            # Mnemonic generation
│   │   ├── bip39.h
│   │   ├── bip32.c            # HD key derivation
│   │   ├── bip32.h
│   │   ├── secp256k1.c        # Elliptic curve ops
│   │   └── secp256k1.h
│   ├── chains/
│   │   ├── bitcoin.c          # Bitcoin transaction handling
│   │   ├── bitcoin.h
│   │   ├── ethereum.c         # Ethereum transaction handling
│   │   ├── ethereum.h
│   │   └── ...                # Other chains
│   ├── security/
│   │   ├── fingerprint.c      # Fingerprint auth via libfprint
│   │   ├── fingerprint.h
│   │   ├── storage.c          # Encrypted storage
│   │   ├── storage.h
│   │   ├── memory.c           # Secure memory handling
│   │   └── memory.h
│   ├── ui/
│   │   ├── display.c          # LCD driver interface
│   │   ├── display.h
│   │   ├── input.c            # Button/touch handling
│   │   ├── input.h
│   │   ├── qr.c               # QR code encode/decode
│   │   └── qr.h
│   └── util/
│       ├── base58.c           # Base58 encoding
│       ├── base58.h
│       ├── hex.c              # Hex utilities
│       └── hex.h
├── lib/                       # Third-party libraries
│   ├── libsecp256k1/
│   ├── libqrencode/
│   └── ...
├── tests/
│   ├── test_bip39.c
│   ├── test_bip32.c
│   └── ...
├── tools/
│   ├── mnemonic_gen.c         # Standalone mnemonic generator
│   └── ...
├── Makefile
├── CMakeLists.txt
├── LICENSE
└── README.md
```

### Dependencies
| Library | Purpose | License |
|---------|---------|---------|
| libsecp256k1 | Elliptic curve operations | MIT |
| libfprint | Fingerprint authentication | LGPL-2.1 |
| libqrencode | QR code generation | LGPL-2.1 |
| quirc | QR code decoding | ISC |
| libsodium | Crypto primitives (Argon2, etc) | ISC |
| tiny-AES-c | AES encryption (optional) | Public Domain |

## Security Considerations

### Threat Model
| Threat | Mitigation |
|--------|------------|
| Physical theft | Fingerprint + PIN required |
| Evil maid attack | Secure boot, tamper detection |
| Side-channel attacks | Constant-time crypto operations |
| Supply chain attack | Open source, reproducible builds |
| Memory extraction | Encrypted storage, memory wiping |
| Social engineering | Clear transaction display, confirmation flow |

### Secure Development Practices
1. All crypto operations use vetted libraries (libsecp256k1, libsodium)
2. No dynamic memory allocation in critical paths
3. All buffers bounds-checked
4. Static analysis with clang-analyzer, cppcheck
5. Fuzzing of all input parsing
6. Code review required for all changes

## Build and Deployment

### Cross-Compilation
```bash
# Install RISC-V toolchain
sudo apt install gcc-riscv64-linux-gnu

# Build
make CROSS_COMPILE=riscv64-linux-gnu-
```

### Target System Setup
1. Install minimal Linux (Debian/Alpine)
2. Disable networking permanently
3. Configure auto-login to wallet application
4. Enable read-only root filesystem
5. Configure secure boot if available

## Future Enhancements

1. **Hardware Security Module (HSM)**: Integrate dedicated secure element
2. **Multi-signature Support**: Require multiple devices for signing
3. **Shamir Secret Sharing**: Split seed across multiple backups
4. **Additional Chains**: Monero, Cardano, Polkadot, etc.
5. **NFC Interface**: Alternative to QR codes
6. **Companion Mobile App**: For balance checking and transaction creation

## References

- [BIP-39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
- [libfprint](https://fprint.freedesktop.org/)
- [RISC-V Specifications](https://riscv.org/technical/specifications/)

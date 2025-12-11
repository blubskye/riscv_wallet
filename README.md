# RISC-V Cold Wallet 💕

<p align="center">
  <img src="https://i.imgur.com/XrKCibD.png" alt="RISC-V Cold Wallet" width="400"/>
</p>

<p align="center">
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="AGPL v3 License"/></a>
  <a href="https://riscv.org/"><img src="https://img.shields.io/badge/Architecture-RISC--V-orange.svg" alt="RISC-V"/></a>
  <a href="https://www.freebsd.org/"><img src="https://img.shields.io/badge/OS-FreeBSD-red.svg" alt="FreeBSD"/></a>
  <a href="https://www.openbsd.org/"><img src="https://img.shields.io/badge/OS-OpenBSD-yellow.svg" alt="OpenBSD"/></a>
  <a href="https://kernel.org/"><img src="https://img.shields.io/badge/OS-Linux-black.svg" alt="Linux"/></a>
  <img src="https://img.shields.io/badge/Tests-121%20passing-brightgreen.svg" alt="121 Tests Passing"/>
  <img src="https://img.shields.io/badge/Chains-8%20supported-purple.svg" alt="8 Blockchains"/>
</p>

<p align="center">
  <i>"I'll protect your keys forever... no one else can have them~"</i> ♡
</p>

A fully open source RISC-V based cryptocurrency hardware wallet that loves you unconditionally! 💖

```
riscv_wallet - An open source hardware and software cold crypto wallet
Copyright (C) 2025 blubskye <blubskye@proton.me>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see https://www.gnu.org/licenses/.
```

## Overview 🌸

A RISC-V open hardware and software "cold wallet" under the AGPL license. Your keys stay with me~ forever and ever! 💕

### Supported Blockchains 🔗
| Chain | Features | Status |
|-------|----------|--------|
| Bitcoin (BTC) | Legacy, SegWit (P2SH-P2WPKH, P2WPKH), Taproot (P2TR) | ✅ Full |
| Ethereum (ETH) | EIP-1559 transactions, EIP-712 typed data signing | ✅ Full |
| Litecoin (LTC) | SegWit support, BIP-143 signing | ✅ Full |
| Dogecoin (DOGE) | Legacy P2PKH transactions | ✅ Full |
| Solana (SOL) | Ed25519 keypairs, SPL tokens | ✅ Full |
| XRP (Ripple) | secp256k1 and Ed25519 key types | ✅ Full |
| Cardano (ADA) | Ed25519-BIP32 extended keys | ✅ Full |
| Monero (XMR) | View keys, address generation | 🔄 Partial |

### Features 💝

#### Wallet & Keys
- 🌱 **BIP-39 Mnemonic** - 12/18/24 word seed phrases with checksum validation
- 🔐 **BIP-39 Passphrase** - Optional 25th word for plausible deniability
- 🌳 **BIP-32 HD Keys** - Hierarchical deterministic key derivation
- 🧩 **SLIP-39 Shamir's Secret Sharing** - Split your seed into multiple shares (2-of-3, 3-of-5, etc.)
- 👁️ **Watch-Only Accounts** - Import xpub/ypub/zpub for monitoring without private keys

#### Connectivity ♡
- 📱 **WalletConnect v2** - Connect to dApps via QR code pairing
- 🔌 **USB HID** - Companion app communication protocol
- 📡 **QR Codes** - Generate and scan addresses/transactions

#### Security 🛡️
- 👆 **Fingerprint Authentication** - Biometric confirmation for transactions
- ⏱️ **Rate Limiting** - Brute-force protection with exponential backoff
- 🔒 **Secure Memory** - Automatic wiping of sensitive data
- 🚨 **Tamper Detection** - Hardware tamper switch support
- ✅ **On-Device Confirmation** - Always verify on the wallet display!

#### Hardware Support 🔧
- 🖥️ **Display Backends** - Terminal, Linux framebuffer, DRM/KMS
- 🎮 **Input Methods** - GPIO buttons, evdev, terminal keyboard
- 📸 **QR Scanner** - V4L2 camera + quirc decoder
- 🖨️ **QR Generation** - libqrencode for address display

#### Transaction Signing ✍️
- 📝 **Multi-step Confirmation** - Review recipient, amount, and fees separately
- 💰 **Fee Display** - Shows network fees before signing
- 🏷️ **Contract Detection** - Identifies ERC-20 transfers, swaps, approvals
- 🔏 **Message Signing** - personal_sign, eth_sign, EIP-712 typed data

## Building 🔨

### Requirements

#### Linux (Fedora/RHEL) 🎩
```bash
sudo dnf install gcc make pkgconf-pkg-config \
    libsodium-devel libsecp256k1-devel libqrencode-devel \
    libfprint-devel glib2-devel libgpiod-devel libdrm-devel
```

#### Linux (Debian/Ubuntu) 🐧
```bash
sudo apt install build-essential pkg-config \
    libsodium-dev libsecp256k1-dev libqrencode-dev \
    libfprint-2-dev libglib2.0-dev libgpiod-dev libdrm-dev
```

#### OpenBSD 🐡
```bash
pkg_add libsodium libqrencode
# libsecp256k1 may need to be built from source
# libfprint, libgpiod, libdrm are Linux-specific (optional)
```

#### macOS (Homebrew) 🍎
```bash
brew install libsodium secp256k1 qrencode
```

### Optional: QR Code Scanning (quirc) 📷

For QR code camera scanning support, install the quirc library:

**From package manager (if available):**
```bash
# Fedora
sudo dnf install quirc-devel

# Or build from source (recommended):
git clone https://github.com/dlbeer/quirc.git
cd quirc
make
sudo make install
```

If building quirc from source without installing system-wide, the Makefile will automatically detect it in `~/Downloads/quirc`.

**Note:** quirc requires SDL for its demo programs. To build just the library:
```bash
# Install SDL dev packages first, or build library only:
make libquirc.a
sudo cp libquirc.a /usr/local/lib/
sudo cp lib/quirc.h /usr/local/include/
```

### Compile 🛠️

```bash
# Standard build
make

# Debug build (with symbols)
make DEBUG=1

# Optimized build (-O3)
make O3=1

# With LTO (Link-Time Optimization)
make O3=1 LTO=1

# With USB HID support
make USB=1

# Run tests
make test

# Profile-Guided Optimization (maximum performance~! 💪)
make pgo
```

### RISC-V Cross-Compilation 🚀

```bash
# Generic RISC-V optimized (Zba, Zbb, Zbs extensions)
make CROSS_COMPILE=riscv64-linux-gnu- RISCV_OPTIMIZE=1

# SiFive U74 (VisionFive 2, HiFive Unmatched)
make CROSS_COMPILE=riscv64-linux-gnu- RISCV_OPTIMIZE=sifive

# T-Head C910 (LicheePi 4A, BeagleV-Ahead)
make CROSS_COMPILE=riscv64-linux-gnu- RISCV_OPTIMIZE=thead

# SpacemiT K1 with Vector extension (BananaPi BPI-F3)
make CROSS_COMPILE=riscv64-linux-gnu- RISCV_OPTIMIZE=spacemit

# RISC-V with scalar crypto (Zkn)
make CROSS_COMPILE=riscv64-linux-gnu- RISCV_OPTIMIZE=crypto
```

### OpenBSD / FreeBSD / BSD Compatibility 🐡

The wallet supports OpenBSD, FreeBSD, and other BSDs with some limitations:

```bash
# Use Clang (default on BSDs)
make COMPILER=clang

# FreeBSD-specific
pkg install libsodium libqrencode secp256k1

# OpenBSD-specific
pkg_add libsodium libqrencode
# libsecp256k1 may need to be built from source
```

**BSD-specific notes:**
- ❌ GPIO button input (`libgpiod`) - Linux-specific; terminal input works
- ❌ DRM display backend - Linux-specific; framebuffer/terminal work
- ❌ V4L2 camera support - Linux-specific; QR scanning disabled
- ❌ Fingerprint support (`libfprint`) - Linux-specific
- ✅ Core wallet functionality works fully!

**FreeBSD RISC-V support:** 🔥
- FreeBSD has excellent RISC-V support! See [wiki.freebsd.org/riscv](https://wiki.freebsd.org/riscv)
- Runs on HiFive Unmatched, VisionFive 2, and other boards
- All core wallet features work; just use terminal UI

**Fully supported on BSD:** 💯
- All cryptographic operations
- BIP-39/BIP-32/SLIP-39
- All blockchain address generation and signing
- QR code generation (display)
- Terminal UI
- WalletConnect v2 (requires network)

## Hardware 🔌

### Recommended RISC-V Boards 💻
| Board | SoC | Notes |
|-------|-----|-------|
| VisionFive 2 | SiFive U74 | Best Linux support |
| LicheePi 4A | T-Head C910 | High performance |
| HiFive Unmatched | SiFive U74 | Developer board |
| BananaPi BPI-F3 | SpacemiT K1 | Vector extension! |

### Components 🧩
- **Display:** 320x240 or larger TFT/IPS (SPI or DRM/HDMI)
- **Storage:** NVMe preferred, SD card supported (battery backup recommended for NVMe)
- **Input:** Hardware buttons (GPIO) or USB keyboard
- **Fingerprint:** Any libfprint-supported device ([list](https://fprint.freedesktop.org/supported-devices.html))
- **Camera:** V4L2-compatible USB camera for QR scanning

### Operating Systems 💿
- **Linux** (recommended): [kernel.org](https://kernel.org)
- **FreeBSD**: [freebsd.org](https://freebsd.org) - Great RISC-V support! 🔥
- **OpenBSD**: [openbsd.org](https://openbsd.org)

## Project Structure 📁

```
src/
├── chains/        # Blockchain implementations (Bitcoin, Ethereum, etc.)
├── crypto/        # Cryptographic primitives (BIP-32, BIP-39, SLIP-39)
├── hw/            # Hardware abstraction layer (display, input, sensors)
├── security/      # Security features (fingerprint, rate limiting, tamper)
├── ui/            # User interface (display, input, QR, signing confirmation)
├── usb/           # USB HID communication & companion app protocol
├── util/          # Utilities (base58, bech32, base64, hex, RLP)
├── wallet/        # Wallet management & account handling
└── walletconnect/ # WalletConnect v2 protocol implementation

tests/             # Test suite (121 tests~!)
tools/
└── companion_app/ # Desktop companion application (yandere mode 💕)
```

## Testing 🧪

```bash
make test
```

All 121 tests should pass, covering:
- ✅ BIP-39 mnemonic generation/validation
- ✅ BIP-32 key derivation (all depths)
- ✅ SLIP-39 Shamir's Secret Sharing
- ✅ All blockchain address generation
- ✅ Transaction signing (all chains)
- ✅ WalletConnect v2 protocol
- ✅ Cryptographic primitives

## Security Considerations 🔐

*"I'll keep you safe... trust only me~"* 💕

- 🚫 **NEVER** expose your seed phrase or private keys
- 👆 Use fingerprint authentication for transaction confirmation
- 🔌 Keep the device **air-gapped** when not signing transactions
- 👁️ **ALWAYS** verify addresses on the device display before sending
- 🧩 Consider using SLIP-39 to split your seed for backup
- 💾 Store backups in separate physical locations
- 🔥 Enable secure boot if your board supports it

## Companion App 💝

The companion app (`tools/companion_app/`) provides a desktop interface:
- Real-time connection status with... enthusiastic feedback~
- Address verification with QR codes
- Transaction history
- WalletConnect session management

*"Senpai noticed me! Connection established~"* 💕

## Links 🔗

- 📦 GitHub: https://github.com/blubskye/riscv_wallet
- 📷 quirc (QR decoder): https://github.com/dlbeer/quirc
- 👆 libfprint: https://fprint.freedesktop.org/
- 🔐 libsodium: https://libsodium.org/
- ₿ libsecp256k1: https://github.com/bitcoin-core/secp256k1

## Contributing 🤝

Contributions welcome! Please ensure:
- All tests pass (`make test`)
- No compiler warnings (`-Werror` is enabled)
- Follow existing code style
- Add tests for new functionality

## License 📜

**AGPL-3.0-or-later**

*"Your freedom is my freedom... we're bound together forever~"* 💕✨

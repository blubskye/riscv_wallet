#!/bin/bash
#
# RISC-V Wallet Hardware Setup Script
# Copyright (C) 2025 blubskye
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Interactive script to configure display and GPIO buttons for the wallet.
#

set -e

CONFIG_DIR="${HOME}/.config/riscv_wallet"
CONFIG_FILE="${CONFIG_DIR}/hardware.conf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Display types
DISPLAY_TYPES=(
    "terminal:Terminal/Console Output (default)"
    "spi_ili9341:ILI9341 240x320 SPI TFT"
    "spi_st7789:ST7789 240x240/320 SPI TFT"
    "spi_st7735:ST7735 128x160 SPI TFT"
    "spi_ssd1306:SSD1306 128x64 OLED (SPI)"
    "i2c_ssd1306:SSD1306 128x64 OLED (I2C)"
    "i2c_sh1106:SH1106 128x64 OLED (I2C)"
    "hdmi:HDMI/Framebuffer Output"
    "custom:Custom Driver"
)

# Button actions
BUTTON_ACTIONS=(
    "up:Navigate Up"
    "down:Navigate Down"
    "left:Navigate Left"
    "right:Navigate Right"
    "enter:Select/Confirm"
    "back:Cancel/Back"
    "menu:Menu/Options"
    "power:Power Button"
)

echo_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect available devices
detect_devices() {
    echo_header "Detecting Hardware"

    # GPIO chips
    echo_info "Scanning for GPIO chips..."
    GPIO_CHIPS=($(ls /dev/gpiochip* 2>/dev/null || true))
    if [ ${#GPIO_CHIPS[@]} -gt 0 ]; then
        echo_info "Found GPIO chips: ${GPIO_CHIPS[*]}"
    else
        echo_warn "No GPIO chips found"
    fi

    # SPI devices
    echo_info "Scanning for SPI devices..."
    SPI_DEVICES=($(ls /dev/spidev* 2>/dev/null || true))
    if [ ${#SPI_DEVICES[@]} -gt 0 ]; then
        echo_info "Found SPI devices: ${SPI_DEVICES[*]}"
    else
        echo_warn "No SPI devices found"
    fi

    # I2C devices
    echo_info "Scanning for I2C buses..."
    I2C_DEVICES=($(ls /dev/i2c-* 2>/dev/null || true))
    if [ ${#I2C_DEVICES[@]} -gt 0 ]; then
        echo_info "Found I2C buses: ${I2C_DEVICES[*]}"

        # Scan for common display addresses
        for i2c in "${I2C_DEVICES[@]}"; do
            if command -v i2cdetect &> /dev/null; then
                bus_num=$(echo "$i2c" | grep -o '[0-9]*$')
                echo_info "Scanning I2C bus $bus_num for displays..."
                # Check common OLED addresses (0x3C, 0x3D)
                if i2cdetect -y "$bus_num" 0x3c 0x3c 2>/dev/null | grep -q "3c"; then
                    echo_info "  Found device at 0x3C (likely SSD1306/SH1106 OLED)"
                fi
                if i2cdetect -y "$bus_num" 0x3d 0x3d 2>/dev/null | grep -q "3d"; then
                    echo_info "  Found device at 0x3D (likely SSD1306/SH1106 OLED)"
                fi
            fi
        done
    else
        echo_warn "No I2C buses found"
    fi

    # Hardware RNG
    echo_info "Checking for hardware RNG..."
    if [ -e /dev/hwrng ]; then
        echo_info "Hardware RNG found: /dev/hwrng"
        HAS_HWRNG=1
    else
        echo_warn "No hardware RNG found"
        HAS_HWRNG=0
    fi

    echo ""
}

# Select from menu
select_option() {
    local prompt="$1"
    shift
    local options=("$@")

    echo "$prompt"
    for i in "${!options[@]}"; do
        echo "  $((i+1)). ${options[$i]}"
    done

    while true; do
        read -p "Enter choice [1-${#options[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            SELECTED_INDEX=$((choice-1))
            return 0
        fi
        echo "Invalid choice. Please try again."
    done
}

# Get user input with default
get_input() {
    local prompt="$1"
    local default="$2"

    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " value
        echo "${value:-$default}"
    else
        read -p "$prompt: " value
        echo "$value"
    fi
}

# Configure display
configure_display() {
    echo_header "Display Configuration"

    # Build display options
    local options=()
    for dtype in "${DISPLAY_TYPES[@]}"; do
        options+=("${dtype#*:}")
    done

    select_option "Select display type:" "${options[@]}"
    local dtype_key="${DISPLAY_TYPES[$SELECTED_INDEX]%%:*}"

    DISPLAY_TYPE="$dtype_key"

    case "$dtype_key" in
        terminal)
            DISPLAY_WIDTH=80
            DISPLAY_HEIGHT=24
            ;;
        spi_*)
            echo ""
            echo_info "SPI Display Configuration"

            if [ ${#SPI_DEVICES[@]} -gt 0 ]; then
                select_option "Select SPI device:" "${SPI_DEVICES[@]}"
                SPI_DEVICE="${SPI_DEVICES[$SELECTED_INDEX]}"
            else
                SPI_DEVICE=$(get_input "Enter SPI device path" "/dev/spidev0.0")
            fi

            SPI_SPEED=$(get_input "SPI speed (Hz)" "32000000")
            GPIO_DC=$(get_input "GPIO pin for DC (Data/Command)" "25")
            GPIO_RESET=$(get_input "GPIO pin for Reset (-1 to skip)" "24")
            GPIO_BL=$(get_input "GPIO pin for Backlight (-1 to skip)" "-1")

            case "$dtype_key" in
                spi_ili9341)
                    DISPLAY_WIDTH=$(get_input "Display width" "240")
                    DISPLAY_HEIGHT=$(get_input "Display height" "320")
                    ;;
                spi_st7789)
                    DISPLAY_WIDTH=$(get_input "Display width" "240")
                    DISPLAY_HEIGHT=$(get_input "Display height" "240")
                    ;;
                spi_st7735)
                    DISPLAY_WIDTH=$(get_input "Display width" "128")
                    DISPLAY_HEIGHT=$(get_input "Display height" "160")
                    ;;
                spi_ssd1306)
                    DISPLAY_WIDTH=128
                    DISPLAY_HEIGHT=64
                    ;;
            esac
            ;;
        i2c_*)
            echo ""
            echo_info "I2C Display Configuration"

            if [ ${#I2C_DEVICES[@]} -gt 0 ]; then
                select_option "Select I2C bus:" "${I2C_DEVICES[@]}"
                I2C_DEVICE="${I2C_DEVICES[$SELECTED_INDEX]}"
            else
                I2C_DEVICE=$(get_input "Enter I2C device path" "/dev/i2c-1")
            fi

            I2C_ADDRESS=$(get_input "I2C address (hex)" "0x3c")
            DISPLAY_WIDTH=128
            DISPLAY_HEIGHT=64
            ;;
        hdmi)
            FB_DEVICE=$(get_input "Framebuffer device" "/dev/fb0")
            DISPLAY_WIDTH=$(get_input "Display width" "1920")
            DISPLAY_HEIGHT=$(get_input "Display height" "1080")
            ;;
        custom)
            CUSTOM_DRIVER=$(get_input "Path to custom driver library" "")
            DISPLAY_WIDTH=$(get_input "Display width" "320")
            DISPLAY_HEIGHT=$(get_input "Display height" "240")
            ;;
    esac

    DISPLAY_ROTATION=$(get_input "Display rotation (0, 90, 180, 270)" "0")
}

# Configure GPIO buttons
configure_buttons() {
    echo_header "GPIO Button Configuration"

    if [ ${#GPIO_CHIPS[@]} -eq 0 ]; then
        echo_warn "No GPIO chips detected. Skipping button configuration."
        NUM_BUTTONS=0
        return
    fi

    # Select GPIO chip
    if [ ${#GPIO_CHIPS[@]} -gt 1 ]; then
        select_option "Select GPIO chip:" "${GPIO_CHIPS[@]}"
        GPIO_CHIP="${GPIO_CHIPS[$SELECTED_INDEX]}"
    else
        GPIO_CHIP="${GPIO_CHIPS[0]}"
        echo_info "Using GPIO chip: $GPIO_CHIP"
    fi

    echo ""
    echo "Configure button GPIO pins. Enter -1 to skip a button."
    echo "Common button configurations:"
    echo "  - 5 buttons: Up, Down, Enter, Back, Menu"
    echo "  - 4 buttons: Up, Down, Enter, Back"
    echo "  - 3 buttons: Up, Down, Enter"
    echo ""

    # Initialize button arrays
    declare -a BTN_PINS
    declare -a BTN_ACTIONS
    declare -a BTN_LABELS

    NUM_BUTTONS=0

    for action_def in "${BUTTON_ACTIONS[@]}"; do
        action_key="${action_def%%:*}"
        action_desc="${action_def#*:}"

        pin=$(get_input "GPIO pin for $action_desc" "-1")

        if [ "$pin" != "-1" ]; then
            BTN_PINS[$NUM_BUTTONS]="$pin"
            BTN_ACTIONS[$NUM_BUTTONS]="$action_key"
            BTN_LABELS[$NUM_BUTTONS]="$action_desc"
            ((NUM_BUTTONS++))
        fi
    done

    if [ $NUM_BUTTONS -gt 0 ]; then
        echo ""
        echo_info "Button defaults:"
        BTN_ACTIVE_LOW=$(get_input "Buttons are active low (pressed = GND)" "yes")
        BTN_PULL_UP=$(get_input "Enable internal pull-up resistors" "yes")
        BTN_DEBOUNCE=$(get_input "Debounce time (ms)" "50")
    fi
}

# Generate configuration file
generate_config() {
    echo_header "Generating Configuration"

    mkdir -p "$CONFIG_DIR"

    cat > "$CONFIG_FILE" << EOF
# RISC-V Wallet Hardware Configuration
# Generated by hw-setup.sh on $(date)

[general]
board_name = $(hostname)

[display]
type = $DISPLAY_TYPE
EOF

    case "$DISPLAY_TYPE" in
        spi_*)
            cat >> "$CONFIG_FILE" << EOF
spi_device = $SPI_DEVICE
spi_speed = $SPI_SPEED
gpio_dc = $GPIO_DC
gpio_reset = $GPIO_RESET
gpio_backlight = $GPIO_BL
EOF
            ;;
        i2c_*)
            cat >> "$CONFIG_FILE" << EOF
i2c_device = $I2C_DEVICE
i2c_address = $I2C_ADDRESS
EOF
            ;;
        hdmi)
            cat >> "$CONFIG_FILE" << EOF
fb_device = $FB_DEVICE
EOF
            ;;
        custom)
            cat >> "$CONFIG_FILE" << EOF
custom_driver = $CUSTOM_DRIVER
EOF
            ;;
    esac

    cat >> "$CONFIG_FILE" << EOF
width = $DISPLAY_WIDTH
height = $DISPLAY_HEIGHT
rotation = $DISPLAY_ROTATION

[gpio]
chip = ${GPIO_CHIP:-/dev/gpiochip0}
EOF

    for ((i=0; i<NUM_BUTTONS; i++)); do
        cat >> "$CONFIG_FILE" << EOF

[button.$i]
pin = ${BTN_PINS[$i]}
action = ${BTN_ACTIONS[$i]}
active_low = ${BTN_ACTIVE_LOW:-yes}
pull_up = ${BTN_PULL_UP:-yes}
debounce_ms = ${BTN_DEBOUNCE:-50}
label = ${BTN_LABELS[$i]}
EOF
    done

    cat >> "$CONFIG_FILE" << EOF

[hardware]
hardware_rng = $([ "$HAS_HWRNG" = "1" ] && echo "true" || echo "false")
rng_device = /dev/hwrng
secure_element = false
EOF

    echo_info "Configuration saved to: $CONFIG_FILE"
}

# Show summary
show_summary() {
    echo_header "Configuration Summary"

    echo "Display:"
    echo "  Type: $DISPLAY_TYPE"
    echo "  Resolution: ${DISPLAY_WIDTH}x${DISPLAY_HEIGHT}"
    echo "  Rotation: ${DISPLAY_ROTATION}°"

    case "$DISPLAY_TYPE" in
        spi_*)
            echo "  SPI Device: $SPI_DEVICE"
            echo "  SPI Speed: $SPI_SPEED Hz"
            echo "  GPIO DC: $GPIO_DC"
            echo "  GPIO Reset: $GPIO_RESET"
            ;;
        i2c_*)
            echo "  I2C Device: $I2C_DEVICE"
            echo "  I2C Address: $I2C_ADDRESS"
            ;;
    esac

    echo ""
    echo "Buttons: $NUM_BUTTONS configured"
    for ((i=0; i<NUM_BUTTONS; i++)); do
        echo "  ${BTN_LABELS[$i]}: GPIO ${BTN_PINS[$i]}"
    done

    echo ""
    echo "Hardware RNG: $([ "$HAS_HWRNG" = "1" ] && echo "Available" || echo "Not available")"
}

# Test configuration
test_config() {
    echo_header "Testing Configuration"

    # Test GPIO chip access
    if [ -n "$GPIO_CHIP" ] && [ -e "$GPIO_CHIP" ]; then
        if [ -r "$GPIO_CHIP" ]; then
            echo_info "GPIO chip $GPIO_CHIP: accessible"
        else
            echo_warn "GPIO chip $GPIO_CHIP: permission denied (may need root)"
        fi
    fi

    # Test SPI device access
    if [ -n "$SPI_DEVICE" ] && [ -e "$SPI_DEVICE" ]; then
        if [ -r "$SPI_DEVICE" ]; then
            echo_info "SPI device $SPI_DEVICE: accessible"
        else
            echo_warn "SPI device $SPI_DEVICE: permission denied"
        fi
    fi

    # Test I2C device access
    if [ -n "$I2C_DEVICE" ] && [ -e "$I2C_DEVICE" ]; then
        if [ -r "$I2C_DEVICE" ]; then
            echo_info "I2C device $I2C_DEVICE: accessible"
        else
            echo_warn "I2C device $I2C_DEVICE: permission denied"
        fi
    fi

    echo ""
    echo_info "To grant device access without root, add your user to these groups:"
    echo "  sudo usermod -aG gpio,spi,i2c $USER"
    echo ""
}

# Main
main() {
    echo_header "RISC-V Wallet Hardware Setup"

    echo "This script will help you configure the display and GPIO buttons"
    echo "for your RISC-V wallet hardware."
    echo ""

    # Check for existing config
    if [ -f "$CONFIG_FILE" ]; then
        echo_warn "Existing configuration found at $CONFIG_FILE"
        read -p "Overwrite? [y/N]: " overwrite
        if [[ ! "$overwrite" =~ ^[Yy] ]]; then
            echo "Setup cancelled."
            exit 0
        fi
    fi

    detect_devices
    configure_display
    configure_buttons
    generate_config
    show_summary
    test_config

    echo_header "Setup Complete"
    echo "Your hardware configuration has been saved."
    echo ""
    echo "To use this configuration, run the wallet normally."
    echo "The configuration will be automatically loaded from:"
    echo "  $CONFIG_FILE"
    echo ""
    echo "To override, set the environment variable:"
    echo "  export RISCV_WALLET_HWCONFIG=/path/to/config"
    echo ""
}

main "$@"

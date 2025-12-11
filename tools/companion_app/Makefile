# RISC-V Wallet Companion App Makefile
# Copyright (C) 2025 blubskye
# SPDX-License-Identifier: AGPL-3.0-or-later

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
CFLAGS += $(shell pkg-config --cflags gtk+-3.0)

LDFLAGS = $(shell pkg-config --libs gtk+-3.0)
LDFLAGS += -lpthread

TARGET = companion_app
SOURCES = companion_app.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJECTS)

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

# Development run
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Check dependencies
check-deps:
	@echo "Checking for GTK3..."
	@pkg-config --exists gtk+-3.0 && echo "GTK3: OK" || echo "GTK3: NOT FOUND (install libgtk-3-dev)"

help:
	@echo "RISC-V Wallet Companion App"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build the companion app"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to system"
	@echo "  run        - Build and run"
	@echo "  debug      - Build with debug symbols"
	@echo "  check-deps - Check for required dependencies"
	@echo ""
	@echo "Dependencies:"
	@echo "  - GTK3 (libgtk-3-dev)"

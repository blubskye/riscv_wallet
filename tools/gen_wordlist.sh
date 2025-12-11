#!/bin/bash
# Generate BIP-39 wordlist header from text file
# Usage: ./gen_wordlist.sh /path/to/english.txt

INPUT_FILE="${1:-/home/blubskye/Downloads/bipenglish.txt}"
OUTPUT_FILE="${2:-/home/blubskye/Downloads/riscv_wallet/src/crypto/bip39_wordlist.h}"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file not found: $INPUT_FILE" >&2
    exit 1
fi

{
cat << 'HEADER'
/*
 * BIP-39 English Wordlist
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This file is auto-generated from the official BIP-39 wordlist.
 * Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
 */

#ifndef BIP39_WORDLIST_H
#define BIP39_WORDLIST_H

#define BIP39_WORDLIST_SIZE 2048

static const char *bip39_wordlist[BIP39_WORDLIST_SIZE] = {
HEADER

# Read all words into array
words=()
while IFS= read -r word || [ -n "$word" ]; do
    word=$(echo "$word" | tr -d '\r' | xargs)
    [ -z "$word" ] && continue
    words+=("$word")
done < "$INPUT_FILE"

# Output words, 8 per line
total=${#words[@]}
for ((i=0; i<total; i++)); do
    # Start of line
    if [ $((i % 8)) -eq 0 ]; then
        printf "    "
    fi

    # Print word
    printf '"%s"' "${words[$i]}"

    # Comma if not last
    if [ $i -lt $((total - 1)) ]; then
        printf ","
    fi

    # Newline every 8 words or at end
    if [ $((i % 8)) -eq 7 ] || [ $i -eq $((total - 1)) ]; then
        printf "\n"
    else
        printf " "
    fi
done

cat << 'FOOTER'
};

#endif /* BIP39_WORDLIST_H */
FOOTER
} > "$OUTPUT_FILE"

echo "Generated $OUTPUT_FILE with ${#words[@]} words" >&2

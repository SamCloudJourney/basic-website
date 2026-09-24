#!/usr/bin/env bash
set -euo pipefail
input="$1"
output="$2"
pub="$3"
mkdir -p "$output"
tar -C "$input" -czf "$output/results.tar.gz" .
keyhex="$(openssl rand -hex 32)"
ivhex="$(openssl rand -hex 16)"
openssl enc -aes-256-cbc -K "$keyhex" -iv "$ivhex" -in "$output/results.tar.gz" -out "$output/results.tar.gz.enc"
printf '%s' "$keyhex" | xxd -r -p > "$output/key.bin"
openssl pkeyutl -encrypt -pubin -inkey "$pub" -in "$output/key.bin" -out "$output/key.bin.enc" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
printf '%s\n' "$ivhex" > "$output/iv.hex"
rm -f "$output/results.tar.gz" "$output/key.bin"

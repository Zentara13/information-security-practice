#!/usr/bin/env bash
# scripts/generate_cert.sh — self-signed сертифікат для localhost
set -euo pipefail
CERT_DIR="nginx/certs"
mkdir -p "$CERT_DIR"
MSYS_NO_PATHCONV=1 openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$CERT_DIR/selfsigned.key" -out "$CERT_DIR/selfsigned.crt" \
  -subj "/C=UA/O=University/OU=IT/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 "$CERT_DIR/selfsigned.key"
echo "Сертифікат: $CERT_DIR/selfsigned.crt (для production — Let's Encrypt)"

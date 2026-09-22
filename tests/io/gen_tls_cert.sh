#!/usr/bin/env bash
# Regenerate the self-signed loopback PEMs used by the TLS/WSS/HTTPS
# tests and examples (CN 127.0.0.1, RSA 2048, 365 days).
# Run from the repo root: tests/io/gen_tls_cert.sh
set -eu
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout tls_test_key.pem -out tls_test_cert.pem \
  -days 365 -subj "/CN=127.0.0.1"
chmod 600 tls_test_key.pem
openssl x509 -in tls_test_cert.pem -noout -dates

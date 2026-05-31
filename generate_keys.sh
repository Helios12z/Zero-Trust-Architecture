#!/bin/bash
set -e

# Setup colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}        GENERATING CRYPTOGRAPHIC KEYSETS            ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Create keys directory
mkdir -p keys

echo -e "\n[1/3] Generating RSA 2048-bit Private Key (private.pem)..."
openssl genpkey -algorithm RSA -out keys/private.pem -pkeyopt rsa_keygen_bits:2048

echo -e "\n[2/3] Extracting RSA Public Key (public.pem)..."
openssl rsa -pubout -in keys/private.pem -out keys/public.pem

echo -e "\n[3/3] Generating Self-Signed SSL Certificate for PEP TLS (cert.pem, key.pem)..."
# Generates a self-signed certificate valid for 365 days, skipping prompts with -subj
openssl req -x509 -newkey rsa:2048 -keyout keys/key.pem -out keys/cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost/O=ZTA PoC/C=US"

echo -e "\n${GREEN}✓ Cryptographic assets generated successfully in the './keys' directory:${NC}"
ls -l keys

echo -e "${BLUE}====================================================${NC}"

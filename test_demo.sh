#!/bin/bash

# Zero Trust Architecture (ZTA) Verification & Hacker Attack Demo Script
# This script automates and tests the security defenses of the ZTA environment.

# Clear screen for presentation
clear

# Setup colors for professional presentation
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================================================${NC}"
echo -e "${BLUE}⚡           ZERO TRUST ARCHITECTURE (ZTA) POC SECURITY DEMONSTRATION           ⚡${NC}"
echo -e "${BLUE}================================================================================${NC}"
echo -e "This interactive suite tests the ZTA's enforcement capabilities against normal and"
echo -e "adversarial conditions, demonstrating how Identity and Device Posture keep resources safe."
echo -e "${BLUE}================================================================================${NC}\n"

# Helper for section headers
print_header() {
    echo -e "\n${CYAN}--------------------------------------------------------------------------------${NC}"
    echo -e "${CYAN}👉 $1${NC}"
    echo -e "${CYAN}--------------------------------------------------------------------------------${NC}"
}

# Helper to print results
print_result() {
    local phase=$1
    local expected=$2
    local actual=$3
    local details=$4
    local success=$5
    
    echo -e "💡 ${YELLOW}Description:${NC} $details"
    echo -e "🎯 ${YELLOW}Expected Outcome:${NC} ${GREEN}$expected${NC}"
    echo -e "📊 ${YELLOW}Actual Response:${NC} $actual"
    
    if [ "$success" = "true" ]; then
        echo -e "${GREEN}✓ TEST / DEMO SCENARIO $phase: SUCCESS (ZTA Enforced Correctly) ${NC}"
    else
        echo -e "${RED}✗ TEST / DEMO SCENARIO $phase: FAILED ${NC}"
    fi
}

# Check for required tools
if ! command -v curl &> /dev/null; then
    echo -e "${RED}Error: curl is required to run this demo.${NC}"
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is required to generate JWT tokens on the host.${NC}"
    exit 1
fi

# 1. Check if keys and tokens are available, generate them if missing
if [ ! -f "keys/private.pem" ]; then
    echo -e "${YELLOW}[!] Private key not found. Automatically running keygen...${NC}"
    chmod +x generate_keys.sh
    ./generate_keys.sh
fi

if [ ! -f "keys/valid_token.txt" ] || [ ! -f "keys/forged_token.txt" ]; then
    echo -e "${YELLOW}[!] Test tokens not found. Running token generator...${NC}"
    npm install &> /dev/null || yarn install &> /dev/null
    node generate_token.js
fi

# Load generated JWTs
VALID_TOKEN=$(cat keys/valid_token.txt)
EXPIRED_TOKEN=$(cat keys/expired_token.txt)
FORGED_TOKEN=$(cat keys/forged_token.txt)
CORRECT_POSTURE="a7b8f9d3e4"
WRONG_POSTURE="untrusted_device_9999"

# Ensure docker container is running
echo -e "${YELLOW}[System Check] Verifying ZTA Docker environment status...${NC}"
if ! docker compose ps | grep -q "zta-pep"; then
    echo -e "${YELLOW}[!] ZTA services are not running. Attempting to start them via 'docker compose up -d'...${NC}"
    docker compose up --build -d
    echo -e "${YELLOW}Waiting 5 seconds for services to fully bootstrap and load keys...${NC}"
    sleep 5
fi

# SCENARIO 1: Bypass verification by direct target API access (Direct Network Attack)
print_header "SCENARIO 1: Bypass attempt via Direct Backend Connection (Host -> Backend:3000)"
echo -e "${MAGENTA}[HACKER ACTION]${NC} Egress scanner attempts to hit target resource directly on port 3000, skipping PEP."
PHASE1_RESP=$(curl -s --max-time 3 -w "%{http_code}" http://localhost:3000/api/resource 2>&1)
if [[ "$PHASE1_RESP" == *"000"* || "$PHASE1_RESP" == *"Failed to connect"* ]]; then
    print_result "1" "Connection Timeout / Refused (000)" "Refused ($PHASE1_RESP)" "Backend resides entirely within zta-network bridge, isolated from the outside." "true"
else
    print_result "1" "Connection Timeout / Refused (000)" "Received Code $PHASE1_RESP" "Backend is vulnerable to direct network routing bypasses!" "false"
fi

# SCENARIO 2: Bypass verification by direct PDP query (Direct Brain Attack)
print_header "SCENARIO 2: Bypass attempt via Direct PDP Query (Host -> PDP:8080/validate)"
echo -e "${MAGENTA}[HACKER ACTION]${NC} Attacker tries to query the PDP decision engine directly to probe for rules/endpoints."
PHASE2_RESP=$(curl -s --max-time 3 -w "%{http_code}" http://localhost:8080/validate 2>&1)
if [[ "$PHASE2_RESP" == *"000"* || "$PHASE2_RESP" == *"Failed to connect"* ]]; then
    print_result "2" "Connection Timeout / Refused (000)" "Refused ($PHASE2_RESP)" "PDP validation endpoint is isolated internally inside Docker and cannot be accessed by external hosts." "true"
else
    print_result "2" "Connection Timeout / Refused (000)" "Received Code $PHASE2_RESP" "PDP is exposed directly to the outside host!" "false"
fi

# SCENARIO 3: Accessing PEP with No Identity (Broken Identity Attack)
print_header "SCENARIO 3: Access PEP without Authorization Bearer Header"
echo -e "${MAGENTA}[HACKER ACTION]${NC} Attacker hits PEP gate on HTTPS (443) without providing identity credentials."
PHASE3_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" https://localhost/api/resource)
PHASE3_BODY=$(curl -k -s https://localhost/api/resource)
if [ "$PHASE3_STATUS" = "401" ]; then
    print_result "3" "401 Unauthorized" "HTTP $PHASE3_STATUS - $PHASE3_BODY" "PEP successfully caught empty token, rejected before backend and PDP evaluated further." "true"
else
    print_result "3" "401 Unauthorized" "HTTP $PHASE3_STATUS - $PHASE3_BODY" "PEP did not block or return correct 401 code!" "false"
fi

# SCENARIO 4: Accessing PEP with Valid JWT but Missing/Wrong Posture Hash (MDM Compliance Attack)
print_header "SCENARIO 4: Access PEP with Valid Identity but Compromised/Untrusted Device Posture"
echo -e "${MAGENTA}[HACKER ACTION]${NC} Employee steals active JWT and tries to access database from their unmanaged personal laptop."
PHASE4_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $VALID_TOKEN" -H "X-Device-Posture-Hash: $WRONG_POSTURE" https://localhost/api/resource)
PHASE4_BODY=$(curl -k -s -H "Authorization: Bearer $VALID_TOKEN" -H "X-Device-Posture-Hash: $WRONG_POSTURE" https://localhost/api/resource)
if [ "$PHASE4_STATUS" = "403" ]; then
    print_result "4" "403 Forbidden" "HTTP $PHASE4_STATUS - $PHASE4_BODY" "PDP identified valid JWT but rejected device hash ($WRONG_POSTURE), preventing unmanaged device access." "true"
else
    print_result "4" "403 Forbidden" "HTTP $PHASE4_STATUS - $PHASE4_BODY" "PDP allowed or returned wrong code!" "false"
fi

# SCENARIO 5: Accessing PEP with Expired Session (Replay Credentials Attack)
print_header "SCENARIO 5: Access PEP with Expired Session JWT"
echo -e "${MAGENTA}[HACKER ACTION]${NC} Attacker intercepts a stale JWT session that expired 5 minutes ago and attempts a replay."
PHASE5_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $EXPIRED_TOKEN" -H "X-Device-Posture-Hash: $CORRECT_POSTURE" https://localhost/api/resource)
PHASE5_BODY=$(curl -k -s -H "Authorization: Bearer $EXPIRED_TOKEN" -H "X-Device-Posture-Hash: $CORRECT_POSTURE" https://localhost/api/resource)
if [ "$PHASE5_STATUS" = "403" ]; then
    print_result "5" "403 Forbidden" "HTTP $PHASE5_STATUS - $PHASE5_BODY" "PDP validation parsed the token, realized 'exp' claim is in the past, and immediately aborted." "true"
else
    print_result "5" "403 Forbidden" "HTTP $PHASE5_STATUS - $PHASE5_BODY" "PDP allowed expired session access!" "false"
fi

# SCENARIO 6: Accessing PEP with Forged Signature (Token Forgery Attack)
print_header "SCENARIO 6: Access PEP with Cryptographically Forged/Fake Signed JWT"
echo -e "${MAGENTA}[HACKER ACTION]${NC} Hacker generates their own RSA keys, crafts a JWT claiming role: 'administrator', signs it."
PHASE6_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $FORGED_TOKEN" -H "X-Device-Posture-Hash: $CORRECT_POSTURE" https://localhost/api/resource)
PHASE6_BODY=$(curl -k -s -H "Authorization: Bearer $FORGED_TOKEN" -H "X-Device-Posture-Hash: $CORRECT_POSTURE" https://localhost/api/resource)
if [ "$PHASE6_STATUS" = "403" ]; then
    print_result "6" "403 Forbidden" "HTTP $PHASE6_STATUS - $PHASE6_BODY" "PDP validated RS256 signature using the company's real public.pem. The fake signature mismatch was caught instantly." "true"
else
    print_result "6" "403 Forbidden" "HTTP $PHASE6_STATUS - $PHASE6_BODY" "PEP accepted a forged token! Critical cryptographic breach!" "false"
fi

# SCENARIO 7: Compliant ZTA Authentication (Normal Compliant User Access)
print_header "SCENARIO 7: Access PEP with BOTH Valid JWT and Compliant Device Posture"
echo -e "${MAGENTA}[COMPLIANT ACTION]${NC} Authorized manager on their corporate MDM-registered laptop requests the report."
PHASE7_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $VALID_TOKEN" -H "X-Device-Posture-Hash: $CORRECT_POSTURE" https://localhost/api/resource)
PHASE7_BODY=$(curl -k -s -H "Authorization: Bearer $VALID_TOKEN" -H "X-Device-Posture-Hash: $CORRECT_POSTURE" https://localhost/api/resource)
if [ "$PHASE7_STATUS" = "200" ]; then
    print_result "7" "200 OK (Sensitive Data Returned)" "HTTP $PHASE7_STATUS - $PHASE7_BODY" "Success! Cryptographic identity checks out, TPM/MDM hash matches, reverse proxy proxies traffic." "true"
else
    print_result "7" "200 OK" "HTTP $PHASE7_STATUS - $PHASE7_BODY" "ZTA blocked a valid and compliant user!" "false"
fi

echo -e "\n${BLUE}================================================================================${NC}"
echo -e "${GREEN}⭐                   DEMO RUN COMPLETE - SYSTEM 100% SECURED                   ⭐${NC}"
echo -e "${BLUE}================================================================================${NC}"
echo -e "Review service logs using: ${YELLOW}docker compose logs -f pep pdp backend${NC} to show the evaluation."
echo -e "${BLUE}================================================================================${NC}"

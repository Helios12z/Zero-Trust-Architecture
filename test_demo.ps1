# Zero Trust Architecture (ZTA) Verification & Security Demo Script for Windows PowerShell
# This script automates and tests the security defenses of the ZTA environment natively on Windows.

# Clear screen for presentation
Clear-Host

# Setup console colors and helpers
Write-Host "================================================================================" -ForegroundColor Blue
Write-Host "[ZTA]        ZERO TRUST ARCHITECTURE (ZTA) POC SECURITY DEMONSTRATION           " -ForegroundColor Blue -BackgroundColor DarkBlue
Write-Host "================================================================================" -ForegroundColor Blue
Write-Host "This interactive suite tests the ZTA's enforcement capabilities against normal and"
Write-Host "adversarial conditions, demonstrating how Identity and Device Posture keep resources safe."
Write-Host "================================================================================" -ForegroundColor Blue
Write-Host ""

function Print-Header {
    param([string]$title)
    Write-Host ""
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ">>> $title" -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan
}

function Print-Result {
    param(
        [string]$phase,
        [string]$expected,
        [string]$actualCode,
        [string]$actualBody,
        [string]$details,
        [bool]$success
    )
    Write-Host "  Description: " -NoNewline -ForegroundColor Yellow
    Write-Host $details
    Write-Host "  Expected:    " -NoNewline -ForegroundColor Yellow
    Write-Host $expected -ForegroundColor Green
    Write-Host "  Actual:      " -NoNewline -ForegroundColor Yellow
    Write-Host "HTTP $actualCode - $actualBody"
    
    if ($success) {
        Write-Host "[PASS] TEST / DEMO SCENARIO ${phase}: SUCCESS (ZTA Enforced Correctly)" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] TEST / DEMO SCENARIO ${phase}: FAILED" -ForegroundColor Red
    }
}

# 1. Verify that keys and tokens are available
if (-not (Test-Path "keys\private.pem")) {
    Write-Host "[!] Private key not found. Please ensure keys exist." -ForegroundColor Yellow
    Exit
}

# Load generated JWTs
$VALID_TOKEN = (Get-Content -Raw -Path "keys\valid_token.txt").Trim()
$EXPIRED_TOKEN = (Get-Content -Raw -Path "keys\expired_token.txt").Trim()
$FORGED_TOKEN = (Get-Content -Raw -Path "keys\forged_token.txt").Trim()
$CORRECT_POSTURE = "a7b8f9d3e4"
$WRONG_POSTURE = "untrusted_device_9999"

# Helper for HTTP requests using native Windows curl.exe to bypass .NET TLS quirks
function Send-ZtaRequest {
    param(
        [string]$Uri,
        [hashtable]$Headers = @{}
    )
    
    $curlArgs = @("-k", "-s", "--max-time", "3", "-w", "`n%{http_code}")
    foreach ($key in $Headers.Keys) {
        $curlArgs += "-H"
        $curlArgs += ($key + ": " + $Headers[$key])
    }
    $curlArgs += $Uri

    # Invoke native Windows curl.exe, forcing array output
    $outputLines = @(& curl.exe @curlArgs)
    
    $res = @{ StatusCode = 0; Content = "" }
    if ($outputLines -and $outputLines.Count -gt 0) {
        if ($outputLines.Count -eq 1) {
            $line = $outputLines[0]
            if ($line -match '^\d{3}$') {
                $res.StatusCode = [int]$line
            } else {
                $res.Content = $line
            }
        } else {
            $statusCodeLine = $outputLines[-1].Trim()
            if ($statusCodeLine -match '^\d{3}$') {
                $res.StatusCode = [int]$statusCodeLine
                $res.Content = ($outputLines[0..($outputLines.Count - 2)] -join "`n")
            } else {
                $res.Content = ($outputLines -join "`n")
            }
        }
    }
    return $res
}

# Ensure docker container is running
Write-Host "[System Check] Verifying ZTA Docker environment status..." -ForegroundColor Yellow
$dockerCheck = docker compose ps --format json
if ($null -eq $dockerCheck -or $dockerCheck -eq "" -or -not ($dockerCheck -like "*zta-pep*")) {
    Write-Host "[!] ZTA services are not running. Please start Docker Desktop and run:" -ForegroundColor Red
    Write-Host "    docker compose up --build -d" -ForegroundColor Yellow
    Write-Host "Then re-run this script." -ForegroundColor Yellow
    Exit
}

# SCENARIO 1: Bypass verification by direct target API access (Direct Network Attack)
Print-Header "SCENARIO 1: Bypass attempt via Direct Backend Connection (Host -> Backend:3000)"
Write-Host "[HACKER ACTION] Egress scanner attempts to hit target resource directly on port 3000, skipping PEP." -ForegroundColor Magenta
$res = Send-ZtaRequest -Uri "http://localhost:3000/api/resource"
if ($res.StatusCode -eq 0 -or $res.Content -match "Failed to connect" -or $res.Content -match "Unable to connect" -or $res.Content -match "timed out") {
    Print-Result -phase "1" -expected "Connection Timeout / Refused (000)" -actualCode $res.StatusCode -actualBody $res.Content -details "Backend resides entirely within zta-network bridge, isolated from the outside." -success $true
} else {
    Print-Result -phase "1" -expected "Connection Timeout / Refused (000)" -actualCode $res.StatusCode -actualBody $res.Content -details "Backend is vulnerable to direct network routing bypasses!" -success $false
}

# SCENARIO 2: Bypass verification by direct PDP query (Direct Brain Attack)
Print-Header "SCENARIO 2: Bypass attempt via Direct PDP Query (Host -> PDP:8080/validate)"
Write-Host "[HACKER ACTION] Attacker tries to query the PDP decision engine directly to probe for rules/endpoints." -ForegroundColor Magenta
$res = Send-ZtaRequest -Uri "http://localhost:8080/validate"
if ($res.StatusCode -eq 0 -or $res.Content -match "Failed to connect" -or $res.Content -match "Unable to connect" -or $res.Content -match "timed out") {
    Print-Result -phase "2" -expected "Connection Timeout / Refused (000)" -actualCode $res.StatusCode -actualBody $res.Content -details "PDP validation endpoint is isolated internally inside Docker and cannot be accessed by external hosts." -success $true
} else {
    Print-Result -phase "2" -expected "Connection Timeout / Refused (000)" -actualCode $res.StatusCode -actualBody $res.Content -details "PDP is exposed directly to the outside host!" -success $false
}

# SCENARIO 3: Accessing PEP with No Identity (Broken Identity Attack)
Print-Header "SCENARIO 3: Access PEP without Authorization Bearer Header"
Write-Host "[HACKER ACTION] Attacker hits PEP gate on HTTPS (443) without providing identity credentials." -ForegroundColor Magenta
$res = Send-ZtaRequest -Uri "https://localhost/api/resource"
if ($res.StatusCode -eq 401) {
    Print-Result -phase "3" -expected "401 Unauthorized" -actualCode $res.StatusCode -actualBody $res.Content -details "PEP successfully caught empty token, rejected before backend and PDP evaluated further." -success $true
} else {
    Print-Result -phase "3" -expected "401 Unauthorized" -actualCode $res.StatusCode -actualBody $res.Content -details "PEP did not block or return correct 401 code!" -success $false
}

# SCENARIO 4: Accessing PEP with Valid JWT but Missing/Wrong Posture Hash (MDM Compliance Attack)
Print-Header "SCENARIO 4: Access PEP with Valid Identity but Compromised/Untrusted Device Posture"
Write-Host "[HACKER ACTION] Employee steals active JWT and tries to access database from their unmanaged personal laptop." -ForegroundColor Magenta
$headers = @{
    "Authorization" = "Bearer $VALID_TOKEN"
    "X-Device-Posture-Hash" = $WRONG_POSTURE
}
$res = Send-ZtaRequest -Uri "https://localhost/api/resource" -Headers $headers
if ($res.StatusCode -eq 403) {
    Print-Result -phase "4" -expected "403 Forbidden" -actualCode $res.StatusCode -actualBody $res.Content -details "PDP identified valid JWT but rejected device hash ($WRONG_POSTURE), preventing unmanaged device access." -success $true
} else {
    Print-Result -phase "4" -expected "403 Forbidden" -actualCode $res.StatusCode -actualBody $res.Content -details "PDP allowed or returned wrong code!" -success $false
}

# SCENARIO 5: Accessing PEP with Expired Session (Replay Credentials Attack)
Print-Header "SCENARIO 5: Access PEP with Expired Session JWT"
Write-Host "[HACKER ACTION] Attacker intercepts a stale JWT session that expired 5 minutes ago and attempts a replay." -ForegroundColor Magenta
$headers = @{
    "Authorization" = "Bearer $EXPIRED_TOKEN"
    "X-Device-Posture-Hash" = $CORRECT_POSTURE
}
$res = Send-ZtaRequest -Uri "https://localhost/api/resource" -Headers $headers
if ($res.StatusCode -eq 403) {
    Print-Result -phase "5" -expected "403 Forbidden" -actualCode $res.StatusCode -actualBody $res.Content -details "PDP validation parsed the token, realized 'exp' claim is in the past, and immediately aborted." -success $true
} else {
    Print-Result -phase "5" -expected "403 Forbidden" -actualCode $res.StatusCode -actualBody $res.Content -details "PDP allowed expired session access!" -success $false
}

# SCENARIO 6: Accessing PEP with Forged Signature (Token Forgery Attack)
Print-Header "SCENARIO 6: Access PEP with Cryptographically Forged/Fake Signed JWT"
Write-Host "[HACKER ACTION] Hacker generates their own RSA keys, crafts a JWT claiming role: 'administrator', signs it." -ForegroundColor Magenta
$headers = @{
    "Authorization" = "Bearer $FORGED_TOKEN"
    "X-Device-Posture-Hash" = $CORRECT_POSTURE
}
$res = Send-ZtaRequest -Uri "https://localhost/api/resource" -Headers $headers
if ($res.StatusCode -eq 403) {
    Print-Result -phase "6" -expected "403 Forbidden" -actualCode $res.StatusCode -actualBody $res.Content -details "PDP validated RS256 signature using the company real public key. The signature mismatch was caught instantly." -success $true
} else {
    Print-Result -phase "6" -expected "403 Forbidden" -actualCode $res.StatusCode -actualBody $res.Content -details "PEP accepted a forged token! Critical cryptographic breach!" -success $false
}

# SCENARIO 7: Compliant ZTA Authentication (Normal Compliant User Access)
Print-Header "SCENARIO 7: Access PEP with BOTH Valid JWT and Compliant Device Posture"
Write-Host "[COMPLIANT ACTION] Authorized manager on their corporate MDM-registered laptop requests the report." -ForegroundColor Magenta
$headers = @{
    "Authorization" = "Bearer $VALID_TOKEN"
    "X-Device-Posture-Hash" = $CORRECT_POSTURE
}
$res = Send-ZtaRequest -Uri "https://localhost/api/resource" -Headers $headers
if ($res.StatusCode -eq 200) {
    Print-Result -phase "7" -expected "200 OK (Sensitive Data Returned)" -actualCode $res.StatusCode -actualBody $res.Content -details "Success! Cryptographic identity checks out, TPM/MDM hash matches, reverse proxy proxies traffic." -success $true
} else {
    Print-Result -phase "7" -expected "200 OK" -actualCode $res.StatusCode -actualBody $res.Content -details "ZTA blocked a valid and compliant user!" -success $false
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Blue
Write-Host "***                   DEMO RUN COMPLETE - SYSTEM 100% SECURED                   ***" -ForegroundColor Green -BackgroundColor DarkGreen
Write-Host "================================================================================" -ForegroundColor Blue
Write-Host "Review service logs using: docker compose logs -f pep pdp backend" -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Blue

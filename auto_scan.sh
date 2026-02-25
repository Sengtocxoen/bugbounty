#!/bin/bash
# =============================================================================
# Automated Bug Bounty Scanner - Master Orchestrator
# =============================================================================
# Runs all scanning tools SEQUENTIALLY to avoid overloading the target,
# then aggregates all results into a unified report.
#
# Usage: ./auto_scan.sh <target_ip> [port]
# Example: ./auto_scan.sh 192.168.204.160 3000
# =============================================================================

set -e

TARGET_IP="${1:-192.168.204.160}"
TARGET_PORT="${2:-3000}"
TARGET_URL="http://${TARGET_IP}:${TARGET_PORT}"
BUGBOUNTY_DIR="/home/aitools/Desktop/bugbounty"
RESULTS_DIR="${BUGBOUNTY_DIR}/results/juice-shop"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${RESULTS_DIR}/auto_scan_${TIMESTAMP}.log"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

check_target() {
    for i in $(seq 1 10); do
        if curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/" | grep -q "200\|301\|302"; then
            return 0
        fi
        log "Target not responding, waiting 10s (attempt $i/10)..."
        sleep 10
    done
    log "ERROR: Target $TARGET_URL is not responding after 10 attempts"
    return 1
}

mkdir -p "$RESULTS_DIR"

log "============================================"
log "Automated Bug Bounty Scan Starting"
log "Target: $TARGET_URL"
log "Results: $RESULTS_DIR"
log "============================================"

# Step 0: Health check
log "[Phase 0] Checking target availability..."
check_target || exit 1
log "Target is up!"

# Step 1: Comprehensive vulnerability scanner (custom)
log ""
log "[Phase 1/6] Running comprehensive vulnerability scanner..."
cd "$BUGBOUNTY_DIR"
python3 tools/scanners/vuln_scanner_v2.py "$TARGET_IP" "$TARGET_PORT" 2>&1 | tee -a "$LOG_FILE"
log "Comprehensive scanner complete."

# Wait and verify target is still up
sleep 10
check_target

# Step 2: Nuclei template scanning
log ""
log "[Phase 2/6] Running Nuclei template scanner..."
mkdir -p "${RESULTS_DIR}/nuclei_v2"
echo "$TARGET_URL" > /tmp/nuclei_targets.txt
nuclei -l /tmp/nuclei_targets.txt \
    -severity critical,high,medium,low,info \
    -exclude-tags dos \
    -rate-limit 20 \
    -bulk-size 5 \
    -concurrency 5 \
    -timeout 20 \
    -retries 3 \
    -max-host-error 100 \
    -jsonl \
    -o "${RESULTS_DIR}/nuclei_v2/nuclei_results.jsonl" \
    2>&1 | tee -a "${RESULTS_DIR}/nuclei_v2/nuclei_stdout.log"
log "Nuclei complete."

sleep 10
check_target

# Step 3: Nikto web server scanner
log ""
log "[Phase 3/6] Running Nikto web server scanner..."
mkdir -p "${RESULTS_DIR}/nikto_v2"
nikto -h "$TARGET_URL" \
    -output "${RESULTS_DIR}/nikto_v2/nikto_results.txt" \
    -Format txt \
    -Tuning 123456789abc \
    -maxtime 600 \
    2>&1 | tee -a "${RESULTS_DIR}/nikto_v2/nikto_stdout.log"
log "Nikto complete."

sleep 10
check_target

# Step 4: SQLMap against known injection points
log ""
log "[Phase 4/6] Running SQLMap against injection points..."
mkdir -p "${RESULTS_DIR}/sqlmap_v2"

# Search endpoint
log "  SQLMap: Testing search endpoint..."
sqlmap -u "${TARGET_URL}/rest/products/search?q=test" \
    --batch --level=3 --risk=2 \
    --threads=1 --delay=1 --timeout=30 --retries=3 \
    --tamper=space2comment -p q --technique=BEUSTQ \
    --output-dir="${RESULTS_DIR}/sqlmap_v2/search/" \
    2>&1 | tee -a "${RESULTS_DIR}/sqlmap_v2/sqlmap_search_v2.log" || true

sleep 5

# Login endpoint
log "  SQLMap: Testing login endpoint..."
sqlmap -u "${TARGET_URL}/rest/user/login" \
    --data='email=test@test.com&password=test' \
    --batch --level=3 --risk=2 \
    --threads=1 --delay=1 --timeout=30 --retries=3 \
    --method=POST \
    --output-dir="${RESULTS_DIR}/sqlmap_v2/login/" \
    2>&1 | tee -a "${RESULTS_DIR}/sqlmap_v2/sqlmap_login_v2.log" || true

log "SQLMap complete."

sleep 10
check_target

# Step 5: FFUF directory/endpoint bruteforcing
log ""
log "[Phase 5/6] Running FFUF content discovery..."
mkdir -p "${RESULTS_DIR}/ffuf_v2"

WORDLIST="/usr/share/wordlists/dirb/common.txt"
if [ ! -f "$WORDLIST" ]; then
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
fi

# Root directory brute-force
log "  FFUF: Brute-forcing root directories..."
ffuf -u "${TARGET_URL}/FUZZ" \
    -w "$WORDLIST" \
    -mc all -fc 404 \
    -rate 10 -t 2 -timeout 15 \
    -o "${RESULTS_DIR}/ffuf_v2/ffuf_dirs.json" \
    -of json \
    2>&1 | tee -a "${RESULTS_DIR}/ffuf_v2/ffuf_dirs_stdout.log" || true

sleep 5

# API endpoint brute-force
log "  FFUF: Brute-forcing API endpoints..."
ffuf -u "${TARGET_URL}/api/FUZZ" \
    -w "$WORDLIST" \
    -mc all -fc 404 \
    -rate 10 -t 2 -timeout 15 \
    -o "${RESULTS_DIR}/ffuf_v2/ffuf_api.json" \
    -of json \
    2>&1 | tee -a "${RESULTS_DIR}/ffuf_v2/ffuf_api_stdout.log" || true

log "FFUF complete."

# Step 6: Aggregate all results
log ""
log "[Phase 6/6] Aggregating all results..."
python3 tools/aggregate_results.py 2>&1 | tee -a "$LOG_FILE"

log ""
log "============================================"
log "ALL SCANS COMPLETE"
log "Unified report: ${RESULTS_DIR}/unified_report/"
log "============================================"

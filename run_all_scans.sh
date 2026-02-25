#!/bin/bash
# ==============================================================================
# Comprehensive Scan Runner - Runs all tools in parallel in background
# Target: 192.168.204.160:3000 (Juice Shop, no TLS)
# ==============================================================================

TARGET="192.168.204.160"
PORT="3000"
BASE_URL="http://${TARGET}:${PORT}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="results/juice-shop/full_scan_${TIMESTAMP}"
mkdir -p "${RESULTS_DIR}"

echo "============================================================"
echo "  LAUNCHING ALL SCANS IN BACKGROUND"
echo "  Target: ${BASE_URL}"
echo "  Results: ${RESULTS_DIR}"
echo "  Time: $(date)"
echo "============================================================"

# ---- 1. Custom Comprehensive Scanner ----
echo "[*] Starting comprehensive vulnerability scanner..."
python3 tools/scanners/vuln_scanner_v2.py \
    --host "${TARGET}" --port "${PORT}" \
    --output "${RESULTS_DIR}/comprehensive" \
    > "${RESULTS_DIR}/comprehensive_stdout.log" 2>&1 &
PID_COMPREHENSIVE=$!
echo "    PID: ${PID_COMPREHENSIVE}"

# ---- 2. Nuclei Scanner ----
echo "[*] Starting Nuclei scanner..."
mkdir -p "${RESULTS_DIR}/nuclei"

# First generate target list
echo "${BASE_URL}" > "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/rest/user/login" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/rest/products/search" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/api/Users" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/api/Products" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/api/Feedbacks" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/api/Complaints" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/api/BasketItems" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/api/SecurityQuestions" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/ftp" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/ftp/" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/redirect" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/api-docs" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/metrics" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/administration" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/accounting" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/promotion" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/profile" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/b2b/v2/orders" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/file-upload" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/snippets" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/encryptionkeys" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/dataerasure" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/.well-known/security.txt" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/robots.txt" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/video" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/rest/basket/1" >> "${RESULTS_DIR}/nuclei/targets.txt"
echo "${BASE_URL}/rest/order-history" >> "${RESULTS_DIR}/nuclei/targets.txt"

nuclei -l "${RESULTS_DIR}/nuclei/targets.txt" \
    -severity critical,high,medium,low,info \
    -exclude-tags dos \
    -rate-limit 100 \
    -bulk-size 25 \
    -concurrency 20 \
    -timeout 15 \
    -retries 2 \
    -jsonl -o "${RESULTS_DIR}/nuclei/nuclei_results.jsonl" \
    -markdown-export "${RESULTS_DIR}/nuclei/markdown" \
    > "${RESULTS_DIR}/nuclei/nuclei_stdout.log" 2>&1 &
PID_NUCLEI=$!
echo "    PID: ${PID_NUCLEI}"

# ---- 3. Nikto Scanner ----
echo "[*] Starting Nikto scanner..."
mkdir -p "${RESULTS_DIR}/nikto"
nikto -h "${BASE_URL}" \
    -output "${RESULTS_DIR}/nikto/nikto_results.txt" \
    -Format txt \
    -Tuning 1234567890abcde \
    -timeout 10 \
    -no404 \
    > "${RESULTS_DIR}/nikto/nikto_stdout.log" 2>&1 &
PID_NIKTO=$!
echo "    PID: ${PID_NIKTO}"

# ---- 4. SQLMap on known injection points ----
echo "[*] Starting SQLMap on known injection points..."
mkdir -p "${RESULTS_DIR}/sqlmap"

# Test search endpoint
sqlmap -u "${BASE_URL}/rest/products/search?q=test" \
    --batch --level=3 --risk=2 \
    --threads=5 \
    --output-dir="${RESULTS_DIR}/sqlmap/search" \
    --forms --crawl=2 \
    --random-agent \
    --tamper=space2comment,between \
    > "${RESULTS_DIR}/sqlmap/sqlmap_search_stdout.log" 2>&1 &
PID_SQLMAP1=$!
echo "    PID (search): ${PID_SQLMAP1}"

# Test login endpoint
sqlmap -u "${BASE_URL}/rest/user/login" \
    --data='{"email":"test@test.com","password":"test"}' \
    --batch --level=3 --risk=2 \
    --threads=5 \
    --output-dir="${RESULTS_DIR}/sqlmap/login" \
    --random-agent \
    --method=POST \
    > "${RESULTS_DIR}/sqlmap/sqlmap_login_stdout.log" 2>&1 &
PID_SQLMAP2=$!
echo "    PID (login): ${PID_SQLMAP2}"

# ---- 5. ffuf Directory Bruteforce ----
echo "[*] Starting ffuf directory bruteforce..."
mkdir -p "${RESULTS_DIR}/ffuf"
ffuf -u "${BASE_URL}/FUZZ" \
    -w /usr/share/wordlists/dirb/common.txt \
    -mc 200,201,301,302,307,401,403,405,500 \
    -t 50 \
    -rate 100 \
    -o "${RESULTS_DIR}/ffuf/ffuf_results.json" \
    -of json \
    > "${RESULTS_DIR}/ffuf/ffuf_stdout.log" 2>&1 &
PID_FFUF=$!
echo "    PID: ${PID_FFUF}"

# ---- 6. ffuf API endpoint bruteforce ----
echo "[*] Starting ffuf API bruteforce..."
ffuf -u "${BASE_URL}/api/FUZZ" \
    -w /usr/share/wordlists/dirb/common.txt \
    -mc 200,201,301,302,307,401,403,405,500 \
    -t 50 \
    -rate 100 \
    -o "${RESULTS_DIR}/ffuf/ffuf_api_results.json" \
    -of json \
    > "${RESULTS_DIR}/ffuf/ffuf_api_stdout.log" 2>&1 &
PID_FFUF_API=$!
echo "    PID: ${PID_FFUF_API}"

# ---- 7. Nmap service scan ----
echo "[*] Starting Nmap service scan..."
mkdir -p "${RESULTS_DIR}/nmap"
nmap -sV -sC -p 3000 "${TARGET}" \
    -oA "${RESULTS_DIR}/nmap/nmap_results" \
    > "${RESULTS_DIR}/nmap/nmap_stdout.log" 2>&1 &
PID_NMAP=$!
echo "    PID: ${PID_NMAP}"

# ---- 8. whatweb fingerprinting ----
echo "[*] Starting WhatWeb fingerprinting..."
mkdir -p "${RESULTS_DIR}/whatweb"
whatweb "${BASE_URL}" -a 3 --log-json="${RESULTS_DIR}/whatweb/whatweb_results.json" \
    > "${RESULTS_DIR}/whatweb/whatweb_stdout.log" 2>&1 &
PID_WHATWEB=$!
echo "    PID: ${PID_WHATWEB}"

# Save all PIDs
echo "${PID_COMPREHENSIVE}" > "${RESULTS_DIR}/pids.txt"
echo "${PID_NUCLEI}" >> "${RESULTS_DIR}/pids.txt"
echo "${PID_NIKTO}" >> "${RESULTS_DIR}/pids.txt"
echo "${PID_SQLMAP1}" >> "${RESULTS_DIR}/pids.txt"
echo "${PID_SQLMAP2}" >> "${RESULTS_DIR}/pids.txt"
echo "${PID_FFUF}" >> "${RESULTS_DIR}/pids.txt"
echo "${PID_FFUF_API}" >> "${RESULTS_DIR}/pids.txt"
echo "${PID_NMAP}" >> "${RESULTS_DIR}/pids.txt"
echo "${PID_WHATWEB}" >> "${RESULTS_DIR}/pids.txt"

echo ""
echo "============================================================"
echo "  ALL SCANS LAUNCHED IN BACKGROUND"
echo "  Results will appear in: ${RESULTS_DIR}"
echo ""
echo "  Monitor progress:"
echo "    tail -f ${RESULTS_DIR}/comprehensive/scan_log.txt"
echo "    tail -f ${RESULTS_DIR}/nuclei/nuclei_stdout.log"
echo "    tail -f ${RESULTS_DIR}/nikto/nikto_stdout.log"
echo ""
echo "  Check completion:"
echo "    ls ${RESULTS_DIR}/comprehensive/SCAN_COMPLETE"
echo "    ls ${RESULTS_DIR}/nuclei/nuclei_results.jsonl"
echo ""
echo "  PIDs saved to: ${RESULTS_DIR}/pids.txt"
echo "============================================================"

# Wait for all and report
wait
echo ""
echo "============================================================"
echo "  ALL SCANS COMPLETED at $(date)"
echo "  Results directory: ${RESULTS_DIR}"
echo "============================================================"

# Create completion marker
echo "ALL_COMPLETE at $(date)" > "${RESULTS_DIR}/ALL_SCANS_COMPLETE"

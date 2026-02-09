#!/bin/bash
# =============================================================================
# COMPLETE Bug Bounty Tool Installer
# Installs ALL tools from reNgine + reconftw + custom modules
# Run: chmod +x install_all_tools.sh && sudo ./install_all_tools.sh
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

TOOLS_DIR="$HOME/Tools"
mkdir -p "$TOOLS_DIR"

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_section() { echo -e "\n${CYAN}========================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

install_go_tool() {
    local name="$1"
    local pkg="$2"
    if command -v "$name" &>/dev/null; then
        log_info "$name already installed"
    else
        log_info "Installing $name..."
        go install -v "$pkg" 2>/dev/null || log_warn "Failed to install $name"
    fi
}

install_pip_tool() {
    local name="$1"
    local pkg="${2:-$1}"
    if command -v "$name" &>/dev/null || pip3 show "$pkg" &>/dev/null 2>&1; then
        log_info "$name already installed"
    else
        log_info "Installing $name..."
        pip3 install "$pkg" 2>/dev/null || log_warn "Failed to install $name"
    fi
}

clone_repo() {
    local dir="$1"
    local url="$2"
    if [ -d "$dir" ]; then
        log_info "$(basename $dir) already cloned"
    else
        log_info "Cloning $(basename $dir)..."
        git clone --depth 1 "$url" "$dir" 2>/dev/null || log_warn "Failed to clone $url"
    fi
}

# =============================================================================
log_section "PREREQUISITES"
# =============================================================================

log_info "Updating package lists..."
sudo apt update -qq 2>/dev/null

log_info "Installing system dependencies..."
sudo apt install -y -qq \
    git curl wget jq python3 python3-pip golang-go \
    build-essential libpcap-dev libssl-dev libffi-dev \
    python3-dev chromium-browser dnsutils whois \
    nmap masscan ruby ruby-dev npm nodejs \
    zip unzip tar gzip bzip2 p7zip-full \
    libxml2-dev libxslt1-dev zlib1g-dev \
    cmake pkg-config libgmp-dev 2>/dev/null || true

# Ensure Go is set up
if ! command -v go &>/dev/null; then
    log_info "Installing Go..."
    wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
    rm go1.22.5.linux-amd64.tar.gz
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
grep -q 'go/bin' ~/.bashrc 2>/dev/null || {
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
}

# Ensure Rust is set up (needed for some tools)
if ! command -v cargo &>/dev/null; then
    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>/dev/null || true
    source "$HOME/.cargo/env" 2>/dev/null || true
fi
export PATH=$PATH:$HOME/.cargo/bin

# =============================================================================
log_section "SUBDOMAIN ENUMERATION"
# =============================================================================

install_go_tool "subfinder"     "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "amass"         "github.com/owasp-amass/amass/v4/...@master"
install_go_tool "assetfinder"   "github.com/tomnomnom/assetfinder@latest"
install_go_tool "github-subdomains" "github.com/gwen001/github-subdomains@latest"
install_go_tool "dnsx"          "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "puredns"       "github.com/d3mondev/puredns/v2@latest"
install_go_tool "gotator"       "github.com/Josue87/gotator@latest"
install_go_tool "ripgen"        "github.com/resyncgg/ripgen@latest" 2>/dev/null || true
install_go_tool "dnstake"       "github.com/pwnesia/dnstake/cmd/dnstake@latest"
install_go_tool "tlsx"          "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
install_go_tool "hakip2host"    "github.com/hakluke/hakip2host@latest"
install_go_tool "dsieve"        "github.com/trickest/dsieve@latest"

# MassDNS
if [ ! -f "/usr/local/bin/massdns" ]; then
    log_info "Installing MassDNS..."
    clone_repo "$TOOLS_DIR/massdns" "https://github.com/blechschmidt/massdns.git"
    cd "$TOOLS_DIR/massdns" && make -j$(nproc) 2>/dev/null && sudo cp bin/massdns /usr/local/bin/ || true
fi

# Subjack (subdomain takeover)
install_go_tool "subjack" "github.com/haccer/subjack@latest"

# =============================================================================
log_section "HTTP PROBING & CRAWLING"
# =============================================================================

install_go_tool "httpx"         "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "katana"        "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "gospider"      "github.com/jaeles-project/gospider@latest"
install_go_tool "hakrawler"     "github.com/hakluke/hakrawler@latest"
install_go_tool "waybackurls"   "github.com/tomnomnom/waybackurls@latest"
install_go_tool "gau"           "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "urlfinder"     "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
install_go_tool "subjs"         "github.com/lc/subjs@latest"

# xnLinkFinder
install_pip_tool "xnLinkFinder" "xnLinkFinder"

# jsluice
install_go_tool "jsluice" "github.com/BishopFox/jsluice/cmd/jsluice@latest"

# =============================================================================
log_section "PORT SCANNING"
# =============================================================================

install_go_tool "naabu"         "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
sudo apt install -y -qq nmap 2>/dev/null || true

# smap (passive port scanner via Shodan)
install_go_tool "smap" "github.com/s0md3v/smap/cmd/smap@latest"

# =============================================================================
log_section "VULNERABILITY SCANNERS"
# =============================================================================

# Nuclei
install_go_tool "nuclei"        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
nuclei -update-templates 2>/dev/null || true

# Dalfox (XSS)
install_go_tool "dalfox"        "github.com/hahwul/dalfox/v2@latest"

# SQLMap
sudo apt install -y -qq sqlmap 2>/dev/null || true

# Ghauri (modern SQLi)
install_pip_tool "ghauri" "ghauri"

# Commix (command injection)
clone_repo "$TOOLS_DIR/commix" "https://github.com/commixproject/commix.git"
if [ -d "$TOOLS_DIR/commix" ] && [ ! -f "/usr/local/bin/commix" ]; then
    sudo ln -sf "$TOOLS_DIR/commix/commix.py" /usr/local/bin/commix
fi

# Corsy (CORS)
clone_repo "$TOOLS_DIR/Corsy" "https://github.com/s0md3v/Corsy.git"
if [ -d "$TOOLS_DIR/Corsy" ]; then
    pip3 install -r "$TOOLS_DIR/Corsy/requirements.txt" 2>/dev/null || true
fi

# CRLFuzz
install_go_tool "crlfuzz" "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"

# Oralyzer (open redirect)
clone_repo "$TOOLS_DIR/Oralyzer" "https://github.com/r0075h3ll/Oralyzer.git"
if [ -d "$TOOLS_DIR/Oralyzer" ]; then
    pip3 install -r "$TOOLS_DIR/Oralyzer/requirements.txt" 2>/dev/null || true
fi

# testssl.sh
clone_repo "$TOOLS_DIR/testssl.sh" "https://github.com/drwetter/testssl.sh.git"
if [ -d "$TOOLS_DIR/testssl.sh" ] && [ ! -f "/usr/local/bin/testssl.sh" ]; then
    sudo ln -sf "$TOOLS_DIR/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh
fi

# ppmap (prototype pollution)
clone_repo "$TOOLS_DIR/ppmap" "https://github.com/nicola-io/ppmap.git"

# smuggler (HTTP request smuggling)
clone_repo "$TOOLS_DIR/smuggler" "https://github.com/defparam/smuggler.git"
if [ -d "$TOOLS_DIR/smuggler" ] && [ ! -f "/usr/local/bin/smuggler" ]; then
    sudo ln -sf "$TOOLS_DIR/smuggler/smuggler.py" /usr/local/bin/smuggler
fi

# Web-Cache-Vulnerability-Scanner
clone_repo "$TOOLS_DIR/web-cache-vuln-scanner" "https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git"

# nomore403 (403 bypass)
install_go_tool "nomore403" "github.com/devploit/nomore403@latest"

# XSStrike
clone_repo "$TOOLS_DIR/XSStrike" "https://github.com/s0md3v/XSStrike.git"
if [ -d "$TOOLS_DIR/XSStrike" ]; then
    pip3 install -r "$TOOLS_DIR/XSStrike/requirements.txt" 2>/dev/null || true
fi

# =============================================================================
log_section "CONTENT DISCOVERY & FUZZING"
# =============================================================================

install_go_tool "ffuf"          "github.com/ffuf/ffuf/v2@latest"

# Feroxbuster
if ! command -v feroxbuster &>/dev/null; then
    log_info "Installing Feroxbuster..."
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash 2>/dev/null || true
    [ -f ./feroxbuster ] && sudo mv ./feroxbuster /usr/local/bin/
fi

# IIS shortname scanner
install_go_tool "shortscan" "github.com/bitquark/shortscan/cmd/shortscan@latest"

# =============================================================================
log_section "PARAMETER DISCOVERY"
# =============================================================================

install_pip_tool "arjun" "arjun"
install_go_tool "x8" "github.com/Sh1Yo/x8@latest" 2>/dev/null || true

# ParamSpider
clone_repo "$TOOLS_DIR/ParamSpider" "https://github.com/devanshbatham/ParamSpider.git"
if [ -d "$TOOLS_DIR/ParamSpider" ]; then
    pip3 install -r "$TOOLS_DIR/ParamSpider/requirements.txt" 2>/dev/null || true
fi

# =============================================================================
log_section "OSINT TOOLS"
# =============================================================================

# Trufflehog (secret scanning in repos)
if ! command -v trufflehog &>/dev/null; then
    log_info "Installing Trufflehog..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || true
fi

# Gitleaks
install_go_tool "gitleaks" "github.com/gitleaks/gitleaks/v8@latest"

# Metagoofil (metadata extraction)
install_pip_tool "metagoofil" "metagoofil"

# emailfinder
install_pip_tool "emailfinder" "emailfinder"

# theHarvester
install_pip_tool "theHarvester" "theHarvester"

# spoofcheck (email spoofing)
clone_repo "$TOOLS_DIR/spoofcheck" "https://github.com/BishopFox/spoofcheck.git"
if [ -d "$TOOLS_DIR/spoofcheck" ]; then
    pip3 install -r "$TOOLS_DIR/spoofcheck/requirements.txt" 2>/dev/null || true
fi

# cloud_enum
clone_repo "$TOOLS_DIR/cloud_enum" "https://github.com/initstring/cloud_enum.git"
if [ -d "$TOOLS_DIR/cloud_enum" ]; then
    pip3 install -r "$TOOLS_DIR/cloud_enum/requirements.txt" 2>/dev/null || true
fi

# S3Scanner
install_pip_tool "s3scanner" "s3scanner"

# CloudHunter
clone_repo "$TOOLS_DIR/CloudHunter" "https://github.com/belane/CloudHunter.git"

# porch-pirate (Postman workspace scanner)
install_pip_tool "porch-pirate" "porch-pirate"

# SwaggerSpy
clone_repo "$TOOLS_DIR/SwaggerSpy" "https://github.com/UndeadSec/SwaggerSpy.git"

# dorks_hunter
clone_repo "$TOOLS_DIR/dorks_hunter" "https://github.com/six2dez/dorks_hunter.git"

# misconfig-mapper
install_go_tool "misconfig-mapper" "github.com/intigriti/misconfig-mapper@latest"

# =============================================================================
log_section "WAF & CDN DETECTION"
# =============================================================================

install_pip_tool "wafw00f" "wafw00f"
install_go_tool "cdncheck" "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"

# =============================================================================
log_section "CMS DETECTION"
# =============================================================================

# CMSeeK
clone_repo "$TOOLS_DIR/CMSeeK" "https://github.com/Tuhinshubhra/CMSeeK.git"
if [ -d "$TOOLS_DIR/CMSeeK" ]; then
    pip3 install -r "$TOOLS_DIR/CMSeeK/requirements.txt" 2>/dev/null || true
fi

# WPScan
if ! command -v wpscan &>/dev/null; then
    log_info "Installing WPScan..."
    sudo gem install wpscan 2>/dev/null || true
fi

# =============================================================================
log_section "JAVASCRIPT ANALYSIS"
# =============================================================================

# LinkFinder
clone_repo "$TOOLS_DIR/LinkFinder" "https://github.com/GerbenJavado/LinkFinder.git"
if [ -d "$TOOLS_DIR/LinkFinder" ]; then
    pip3 install -r "$TOOLS_DIR/LinkFinder/requirements.txt" 2>/dev/null || true
fi

# sourcemapper
install_go_tool "sourcemapper" "github.com/nickvdyck/sourcemapper@latest" 2>/dev/null || true

# retire.js
sudo npm install -g retire 2>/dev/null || true

# =============================================================================
log_section "API TESTING"
# =============================================================================

# Kiterunner
if ! command -v kr &>/dev/null; then
    log_info "Installing Kiterunner..."
    wget -q "https://github.com/assetnote/kiterunner/releases/latest/download/kiterunner_1.0.2_linux_amd64.tar.gz" -O /tmp/kr.tar.gz 2>/dev/null || true
    if [ -f /tmp/kr.tar.gz ]; then
        tar -xzf /tmp/kr.tar.gz -C /tmp/ 2>/dev/null || true
        [ -f /tmp/kr ] && sudo mv /tmp/kr /usr/local/bin/
        rm -f /tmp/kr.tar.gz
    fi
fi

# GQLSpection (GraphQL)
clone_repo "$TOOLS_DIR/GQLSpection" "https://github.com/doyensec/GQLSpection.git"

# grpcurl
install_go_tool "grpcurl" "github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"

# =============================================================================
log_section "SSRF & OOB TOOLS"
# =============================================================================

install_go_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

# SSRFmap
clone_repo "$TOOLS_DIR/SSRFmap" "https://github.com/swisskyrepo/SSRFmap.git"
if [ -d "$TOOLS_DIR/SSRFmap" ]; then
    pip3 install -r "$TOOLS_DIR/SSRFmap/requirements.txt" 2>/dev/null || true
fi

# =============================================================================
log_section "SCREENSHOT TOOLS"
# =============================================================================

# gowitness
install_go_tool "gowitness" "github.com/sensepost/gowitness@latest"

# =============================================================================
log_section "FAVICON ANALYSIS"
# =============================================================================

# fav-up
clone_repo "$TOOLS_DIR/fav-up" "https://github.com/pielco11/fav-up.git"
if [ -d "$TOOLS_DIR/fav-up" ]; then
    pip3 install -r "$TOOLS_DIR/fav-up/requirements.txt" 2>/dev/null || true
fi

# =============================================================================
log_section "VHOST FUZZING"
# =============================================================================

# VhostFinder
clone_repo "$TOOLS_DIR/VhostFinder" "https://github.com/wdahlenburg/VhostFinder.git"

# =============================================================================
log_section "UTILITY TOOLS"
# =============================================================================

install_go_tool "anew"        "github.com/tomnomnom/anew@latest"
install_go_tool "unfurl"      "github.com/tomnomnom/unfurl@latest"
install_go_tool "qsreplace"   "github.com/tomnomnom/qsreplace@latest"
install_go_tool "gf"          "github.com/tomnomnom/gf@latest"
install_go_tool "inscope"     "github.com/tomnomnom/hacks/inscope@latest"
install_go_tool "notify"      "github.com/projectdiscovery/notify/cmd/notify@latest"
install_go_tool "interlace"   "github.com/codingo/Interlace@latest" 2>/dev/null || true

# gf patterns
if [ ! -d "$HOME/.gf" ]; then
    log_info "Installing gf patterns..."
    mkdir -p "$HOME/.gf"
    clone_repo "$TOOLS_DIR/Gf-Patterns" "https://github.com/1ndianl33t/Gf-Patterns.git"
    [ -d "$TOOLS_DIR/Gf-Patterns" ] && cp "$TOOLS_DIR/Gf-Patterns"/*.json "$HOME/.gf/" 2>/dev/null || true
fi

sudo apt install -y -qq jq 2>/dev/null || true
install_go_tool "yq" "github.com/mikefarah/yq/v4@latest"

# =============================================================================
log_section "WORDLISTS & RESOLVERS"
# =============================================================================

# SecLists
if [ ! -d "/opt/SecLists" ]; then
    log_info "Cloning SecLists (this may take a while)..."
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists 2>/dev/null || true
fi

# Custom wordlists
sudo mkdir -p /opt/wordlists

# Best DNS wordlist
if [ ! -f "/opt/wordlists/best-dns-wordlist.txt" ]; then
    log_info "Downloading best-dns-wordlist..."
    sudo wget -q "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" \
        -O /opt/wordlists/best-dns-wordlist.txt 2>/dev/null || true
fi

# Fresh resolvers
log_info "Downloading fresh resolvers..."
wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" \
    -O /tmp/resolvers.txt 2>/dev/null || true
if [ -f /tmp/resolvers.txt ] && [ -s /tmp/resolvers.txt ]; then
    sudo mv /tmp/resolvers.txt /opt/wordlists/resolvers.txt
else
    # Fallback: create basic resolvers
    echo -e "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9" | sudo tee /opt/wordlists/resolvers.txt >/dev/null
fi

# Assetnote wordlists
if [ ! -f "/opt/wordlists/httparchive_apiroutes.txt" ]; then
    log_info "Downloading API routes wordlist..."
    sudo wget -q "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024_11_28.txt" \
        -O /opt/wordlists/httparchive_apiroutes.txt 2>/dev/null || true
fi

# =============================================================================
log_section "PYTHON DEPENDENCIES"
# =============================================================================

log_info "Installing Python packages..."
pip3 install --upgrade \
    requests urllib3 pyyaml jinja2 \
    shodan censys beautifulsoup4 lxml \
    aiohttp psutil tqdm colorama \
    python-whois dnspython mmh3 \
    Wappalyzer cloudscraper \
    tabulate rich 2>/dev/null || true

# =============================================================================
log_section "DIRECTORY SETUP"
# =============================================================================

mkdir -p "$HOME/bugbounty/results"
mkdir -p "$HOME/bugbounty/wordlists"
mkdir -p "$HOME/bugbounty/configs"
mkdir -p "$HOME/bugbounty/loot"
sudo ln -sf /opt/SecLists "$HOME/bugbounty/wordlists/SecLists" 2>/dev/null || true
sudo ln -sf /opt/wordlists "$HOME/bugbounty/wordlists/custom" 2>/dev/null || true

# =============================================================================
log_section "VERIFICATION"
# =============================================================================

echo ""
log_info "Checking installed tools..."
echo ""

TOOLS=(
    subfinder amass assetfinder puredns massdns dnsx httpx naabu nmap
    nuclei ffuf feroxbuster katana gospider gau hakrawler waybackurls
    dalfox sqlmap arjun crlfuzz interactsh-client
    gowitness wafw00f cdncheck trufflehog gitleaks
    anew unfurl qsreplace gf notify
    gotator tlsx hakip2host dsieve dnstake subjack
    subjs jsluice grpcurl shortscan nomore403
)

INSTALLED=0
MISSING=0
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} $tool"
        ((INSTALLED++))
    else
        echo -e "  ${RED}[--]${NC} $tool"
        ((MISSING++))
    fi
done

echo ""
echo -e "${GREEN}Installed: $INSTALLED${NC} | ${RED}Missing: $MISSING${NC}"
echo ""

# =============================================================================
log_section "COMPLETE"
# =============================================================================

echo ""
echo -e "${GREEN}All tools installed. Run 'source ~/.bashrc' to update PATH.${NC}"
echo ""
echo "Next steps:"
echo "  1. source ~/.bashrc"
echo "  2. Configure API keys in configs/full_recon.yaml"
echo "  3. Run: python3 scanner.py fullrecon -t target.com -c configs/full_recon.yaml"
echo ""

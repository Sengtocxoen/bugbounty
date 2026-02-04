#!/bin/bash
# Enhanced Bug Bounty Tools Installation Script
# Run this on your Kali Linux machine for optimal bug bounty hunting

set -e  # Exit on error

echo "========================================="
echo "  Bug Bounty Enhanced Tools Installer"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running on Kali/Debian-based system
if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}[!] This script is designed for Debian-based systems (Kali Linux recommended)${NC}"
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[!] Go is not installed. Installing Go...${NC}"
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    source ~/.bashrc
    rm go1.21.5.linux-amd64.tar.gz
    echo -e "${GREEN}[+] Go installed successfully${NC}"
fi

# Ensure Go paths are set
export PATH=$PATH:/usr/local/go/bin:~/go/bin

echo -e "${GREEN}[+] Updating system packages...${NC}"
sudo apt update -qq

echo ""
echo "========================================"
echo "  Installing Reconnaissance Tools"
echo "========================================"

# Subdomain Discovery Tools
echo -e "${GREEN}[+] Installing Subfinder...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo -e "${GREEN}[+] Installing Amass...${NC}"
go install -v github.com/owasp-amass/amass/v4/...@master

echo -e "${GREEN}[+] Installing Assetfinder...${NC}"
go install -v github.com/tomnomnom/assetfinder@latest

echo -e "${GREEN}[+] Installing GitHub Subdomains...${NC}"
go install -v github.com/gwen001/github-subdomains@latest

# DNS Resolution & Validation
echo -e "${GREEN}[+] Installing PureDNS...${NC}"
go install -v github.com/d3mondev/puredns/v2@latest

echo -e "${GREEN}[+] Installing MassDNS...${NC}"
if [ ! -d "/opt/massdns" ]; then
    sudo git clone https://github.com/blechschmidt/massdns.git /opt/massdns
    cd /opt/massdns
    sudo make
    sudo ln -sf /opt/massdns/bin/massdns /usr/local/bin/massdns
fi

# HTTP Probing
echo -e "${GREEN}[+] Installing HTTPX...${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Port Scanning
echo -e "${GREEN}[+] Installing Naabu...${NC}"
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo -e "${GREEN}[+] Installing Nmap (if not present)...${NC}"
sudo apt install -y nmap

echo ""
echo "========================================"
echo "  Installing Vulnerability Scanners"
echo "========================================"

# Nuclei - CRITICAL TOOL
echo -e "${GREEN}[+] Installing Nuclei...${NC}"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo -e "${GREEN}[+] Updating Nuclei templates...${NC}"
nuclei -update-templates -ut

# Additional Vulnerability Scanners
echo -e "${GREEN}[+] Installing Nikto...${NC}"
sudo apt install -y nikto

echo ""
echo "========================================"
echo "  Installing Content Discovery Tools"
echo "========================================"

# High-Performance Fuzzers
echo -e "${GREEN}[+] Installing ffuf...${NC}"
go install -v github.com/ffuf/ffuf/v2@latest

echo -e "${GREEN}[+] Installing Feroxbuster...${NC}"
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
sudo mv ./feroxbuster /usr/local/bin/

# URL Collection
echo -e "${GREEN}[+] Installing Waybackurls...${NC}"
go install -v github.com/tomnomnom/waybackurls@latest

echo -e "${GREEN}[+] Installing gau (GetAllUrls)...${NC}"
go install -v github.com/lc/gau/v2/cmd/gau@latest

echo -e "${GREEN}[+] Installing Hakrawler...${NC}"
go install -v github.com/hakluke/hakrawler@latest

# Crawlers
echo -e "${GREEN}[+] Installing Katana...${NC}"
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo -e "${GREEN}[+] Installing GoSpider...${NC}"
go install -v github.com/jaeles-project/gospider@latest

echo ""
echo "========================================"
echo "  Installing JavaScript Analysis Tools"
echo "========================================"

echo -e "${GREEN}[+] Installing LinkFinder...${NC}"
if [ ! -d "/opt/LinkFinder" ]; then
    sudo git clone https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder
    cd /opt/LinkFinder
    sudo pip3 install -r requirements.txt
    sudo chmod +x linkfinder.py
    sudo ln -sf /opt/LinkFinder/linkfinder.py /usr/local/bin/linkfinder
fi

echo -e "${GREEN}[+] Installing retire.js...${NC}"
sudo npm install -g retire

echo -e "${GREEN}[+] Installing JSScanner...${NC}"
go install -v github.com/0x240x23elu/JSScanner@latest

echo ""
echo "========================================"
echo "  Installing XSS & Injection Tools"
echo "========================================"

echo -e "${GREEN}[+] Installing Dalfox (Advanced XSS)...${NC}"
go install -v github.com/hahwul/dalfox/v2@latest

echo -e "${GREEN}[+] Installing XSStrike...${NC}"
if [ ! -d "/opt/XSStrike" ]; then
    sudo git clone https://github.com/s0md3v/XSStrike.git /opt/XSStrike
    cd /opt/XSStrike
    sudo pip3 install -r requirements.txt
    sudo chmod +x xsstrike.py
fi

echo -e "${GREEN}[+] Installing SQLMap...${NC}"
sudo apt install -y sqlmap

echo -e "${GREEN}[+] Installing NoSQLMap...${NC}"
if [ ! -d "/opt/NoSQLMap" ]; then
    sudo git clone https://github.com/codingo/NoSQLMap.git /opt/NoSQLMap
    cd /opt/NoSQLMap
    sudo pip3 install -r requirements.txt
fi

echo ""
echo "========================================"
echo "  Installing Parameter Discovery Tools"
echo "========================================"

echo -e "${GREEN}[+] Installing Arjun...${NC}"
pip3 install arjun

echo -e "${GREEN}[+] Installing x8 (Hidden Parameters)...${NC}"
if [ ! -d "/opt/x8" ]; then
    wget -q https://github.com/Sh1Yo/x8/releases/latest/download/x8-linux-x86-64 -O x8
    sudo chmod +x x8
    sudo mv x8 /usr/local/bin/
fi

echo -e "${GREEN}[+] Installing ParamSpider...${NC}"
if [ ! -d "/opt/ParamSpider" ]; then
    sudo git clone https://github.com/devanshbatham/ParamSpider /opt/ParamSpider
    cd /opt/ParamSpider
    sudo pip3 install -r requirements.txt
    sudo chmod +x paramspider.py
    sudo ln -sf /opt/ParamSpider/paramspider.py /usr/local/bin/paramspider
fi

echo ""
echo "========================================"
echo "  Installing API Testing Tools"
echo "========================================"

echo -e "${GREEN}[+] Installing Kiterunner (API Discovery)...${NC}"
if [ ! -f "/usr/local/bin/kr" ]; then
    wget -q https://github.com/assetnote/kiterunner/releases/latest/download/kiterunner_1.0.2_linux_amd64.tar.gz
    tar -xzf kiterunner_1.0.2_linux_amd64.tar.gz
    sudo mv kr /usr/local/bin/
    rm kiterunner_1.0.2_linux_amd64.tar.gz
fi

echo -e "${GREEN}[+] Installing Postman/Newman...${NC}"
sudo npm install -g newman

echo ""
echo "========================================"
echo "  Installing SSRF & Out-of-Band Tools"
echo "========================================"

echo -e "${GREEN}[+] Installing interactsh-client...${NC}"
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

echo -e "${GREEN}[+] Installing SSRFmap...${NC}"
if [ ! -d "/opt/SSRFmap" ]; then
    sudo git clone https://github.com/swisskyrepo/SSRFmap /opt/SSRFmap
    cd /opt/SSRFmap
    sudo pip3 install -r requirements.txt
fi

echo ""
echo "========================================"
echo "  Installing Wordlists"
echo "========================================"

echo -e "${GREEN}[+] Installing/Updating SecLists...${NC}"
if [ ! -d "/opt/SecLists" ]; then
    sudo git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
else
    cd /opt/SecLists
    sudo git pull
fi

echo -e "${GREEN}[+] Installing custom subdomain wordlists...${NC}"
if [ ! -d "/opt/wordlists" ]; then
    sudo mkdir -p /opt/wordlists
fi

# Download best-dns-wordlist
if [ ! -f "/opt/wordlists/best-dns-wordlist.txt" ]; then
    sudo wget -q https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -O /opt/wordlists/best-dns-wordlist.txt
fi

echo ""
echo "========================================"
echo "  Installing Support Tools"
echo "========================================"

echo -e "${GREEN}[+] Installing anew (unique line filter)...${NC}"
go install -v github.com/tomnomnom/anew@latest

echo -e "${GREEN}[+] Installing unfurl (URL parser)...${NC}"
go install -v github.com/tomnomnom/unfurl@latest

echo -e "${GREEN}[+] Installing qsreplace (query string replacer)...${NC}"
go install -v github.com/tomnomnom/qsreplace@latest

echo -e "${GREEN}[+] Installing jq (JSON processor)...${NC}"
sudo apt install -y jq

echo -e "${GREEN}[+] Installing yq (YAML processor)...${NC}"
go install -v github.com/mikefarah/yq/v4@latest

echo ""
echo "========================================"
echo "  Installing Cloud Security Tools"
echo "========================================"

echo -e "${GREEN}[+] Installing cloud_enum (Cloud Asset Discovery)...${NC}"
if [ ! -d "/opt/cloud_enum" ]; then
    sudo git clone https://github.com/initstring/cloud_enum /opt/cloud_enum
    cd /opt/cloud_enum
    sudo pip3 install -r requirements.txt
fi

echo -e "${GREEN}[+] Installing S3Scanner...${NC}"
pip3 install s3scanner

echo ""
echo "========================================"
echo "  Python Dependencies"
echo "========================================"

echo -e "${GREEN}[+] Installing Python packages...${NC}"
pip3 install --upgrade \
    requests \
    urllib3 \
    pyyaml \
    shodan \
    censys \
    beautifulsoup4 \
    lxml \
    aiohttp \
    psutil \
    tqdm \
    colorama

echo ""
echo "========================================"
echo "  Configuration & Setup"
echo "========================================"

# Add Go bin to PATH if not already there
if ! grep -q 'export PATH=$PATH:~/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
fi

# Create directory structure for results
mkdir -p ~/bugbounty/results
mkdir -p ~/bugbounty/wordlists
mkdir -p ~/bugbounty/configs

# Create symlinks for easier access
sudo ln -sf /opt/SecLists ~/bugbounty/wordlists/SecLists 2>/dev/null || true

echo ""
echo "========================================="
echo -e "${GREEN}  Installation Complete!${NC}"
echo "========================================="
echo ""
echo "Installed tools:"
echo "  Reconnaissance:"
echo "    - subfinder, amass, assetfinder, github-subdomains"
echo "    - puredns, massdns, httpx, naabu"
echo ""
echo "  Vulnerability Scanning:"
echo "    - nuclei (with updated templates)"
echo "    - nikto, sqlmap, nosqlmap"
echo ""
echo "  Content Discovery:"
echo "    - ffuf, feroxbuster"
echo "    - waybackurls, gau, hakrawler"
echo "    - katana, gospider"
echo ""
echo "  XSS & Injection:"
echo "    - dalfox, xsstrike"
echo ""
echo "  Parameter Discovery:"
echo "    - arjun, x8, paramspider"
echo ""
echo "  API Testing:"
echo "    - kiterunner, newman"
echo ""
echo "  JavaScript Analysis:"
echo "    - linkfinder, retire.js, jsscanner"
echo ""
echo "  SSRF Testing:"
echo "    - interactsh-client, ssrfmap"
echo ""
echo "  Cloud Security:"
echo "    - cloud_enum, s3scanner"
echo ""
echo "  Support Tools:"
echo "    - anew, unfurl, qsreplace, jq, yq"
echo ""
echo "Next steps:"
echo "  1. Source your .bashrc: source ~/.bashrc"
echo "  2. Test nuclei: nuclei -version"
echo "  3. Configure API keys in your scanner config files"
echo ""
echo -e "${YELLOW}[*] Don't forget to configure API keys for:${NC}"
echo "    - Shodan (for recon)"
echo "    - Censys (for recon)"
echo "    - VirusTotal (optional)"
echo "    - GitHub Token (for github-subdomains)"
echo ""
echo -e "${GREEN}Happy Hunting! 🎯${NC}"

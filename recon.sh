#!/bin/bash

# =========================
# Ultimate Recon Pipeline
# =========================

set -e

# -------- Colors --------
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"

# -------- Go Path --------
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/bin"

# -------- Banner --------
clear
echo -e "${GREEN}"
cat << "EOF"
 _____     _                 _         _    _____                    _____ _         _ _         
|  _  |_ _| |_ ___ _____ ___| |_ ___ _| |  | __  |___ ___ ___ ___   |  _  |_|___ ___| |_|___ ___ 
|     | | |  _| . |     | .'|  _| -_| . |  |    -| -_|  _| . |   |  |   __| | . | -_| | |   | -_|
|__|__|___|_| |___|_|_|_|__,|_| |___|___|  |__|__|___|___|___|_|_|  |__|  |_|  _|___|_|_|_|_|___|
                                                                            |_|                  
EOF
echo -e "${RESET}"
echo

# -------- Privilege helper --------
if [[ $EUID -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

# -------- Helpers --------
check_tool() { command -v "$1" >/dev/null 2>&1; }
install_apt() {
  echo -e "${YELLOW}[+] Installing $1${RESET}"
  $SUDO apt install -y "$1" >/dev/null 2>&1
}
install_go() {
  echo -e "${YELLOW}[+] Installing $1${RESET}"
  go install "$2"@latest
}

# -------- Tool Check --------
echo -e "${GREEN}[*] Checking tools...${RESET}"
$SUDO apt update -qq >/dev/null 2>&1

APT_TOOLS=(git python3 dirsearch)
for tool in "${APT_TOOLS[@]}"; do
  if check_tool "$tool"; then
    echo -e "${GREEN}[✔] $tool found${RESET}"
  else
    install_apt "$tool"
  fi
done

check_tool go || install_apt golang

GO_TOOLS=(
  "subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  "httpx github.com/projectdiscovery/httpx/cmd/httpx"
  "katana github.com/projectdiscovery/katana/cmd/katana"
  "nuclei github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
  "gf github.com/tomnomnom/gf"
  "waybackurls github.com/tomnomnom/waybackurls"
)

for entry in "${GO_TOOLS[@]}"; do
  NAME=$(echo "$entry" | awk '{print $1}')
  PKG=$(echo "$entry" | awk '{print $2}')
  if check_tool "$NAME"; then
    echo -e "${GREEN}[✔] $NAME found${RESET}"
  else
    install_go "$NAME" "$PKG"
  fi
done

# -------- GF Patterns --------
if [[ ! -d "$HOME/.gf" ]]; then
  echo -e "${YELLOW}[+] Installing gf patterns${RESET}"
  git clone https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf" >/dev/null 2>&1
  echo 'export GF_PATTERNS_PATH=$HOME/.gf' >> "$HOME/.bashrc"
fi

# =========================
# Target Input
# =========================
echo
echo -e "${GREEN}-------------- TARGET INPUT --------------${RESET}"
echo

read -p " Enter target domain: " DOMAIN
[[ -z "$DOMAIN" ]] && echo -e "${RED}[!] No domain provided${RESET}" && exit 1

echo
echo " 1) Run full subdomain enumeration"
echo " 2) Use existing live subdomains file"
echo
read -p " Choose option (1 or 2): " MODE
echo

WORKDIR="$DOMAIN-recon"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# -------- Mode 1: Auto Enum --------
if [[ "$MODE" == "1" ]]; then
  echo "[+] Running subfinder..."
  subfinder -d "$DOMAIN" -silent -o subdomains.txt

  echo "[+] Checking live subdomains..."
  httpx -silent -l subdomains.txt > subdomains_alive.txt
fi

# -------- Mode 2: Manual File --------
if [[ "$MODE" == "2" ]]; then
  read -p " Enter path to live subdomains file: " LIVEFILE
  if [[ ! -f "$LIVEFILE" ]]; then
    echo -e "${RED}[!] File not found${RESET}"
    exit 1
  fi
  cp "$LIVEFILE" subdomains_alive.txt
fi

echo
echo "[+] Live subdomains loaded:"
wc -l subdomains_alive.txt
echo

# =========================
# JavaScript Discovery
# =========================
echo "[+] Discovering JavaScript files..."
katana -list subdomains_alive.txt -jc -silent | grep "\.js$" | sort -u > js.txt
wc -l js.txt
echo

# =========================
# URL Collection
# =========================
echo "[+] Crawling URLs..."
katana -list subdomains_alive.txt -d 5 \
  -ps -pss waybackarchive,commoncrawl,alienvault \
  -hf -jc -fx \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif \
  -o allurls.txt

wc -l allurls.txt
echo

# =========================
# Processing
# =========================
grep "=" allurls.txt | sort -u > params.txt

grep -E '\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config' \
  allurls.txt > sensitive_files.txt

gf xss params.txt > xss_candidates.txt
gf lfi allurls.txt > lfi_candidates.txt

# =========================
# Nuclei Scans
# =========================
echo "[+] Running Nuclei scans..."
nuclei -l js.txt -severity critical,high,medium -o nuclei_js.txt
cat lfi_candidates.txt | nuclei -tags lfi -o nuclei_lfi.txt

# =========================
# Wayback XSS
# =========================
waybackurls "https://$DOMAIN" | gf xss > wayback_xss.txt

echo
echo -e "${GREEN}==============================${RESET}"
echo -e "${GREEN}[✔] Recon completed successfully${RESET}"
echo -e "${GREEN}[+] Results saved in: $WORKDIR${RESET}"
echo -e "${GREEN}==============================${RESET}"

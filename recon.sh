#!/bin/bash

set -e

GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"

export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/bin"

clear
echo -e "${GREEN}Ultimate Recon Pipeline${RESET}"
echo

if [[ $EUID -ne 0 ]]; then SUDO="sudo"; else SUDO=""; fi

check_tool(){ command -v "$1" >/dev/null 2>&1; }
install_apt(){ echo "[+] Installing $1"; $SUDO apt install -y "$1" >/dev/null 2>&1; }
install_go(){ echo "[+] Installing $1"; go install "$2"@latest; }

echo "[*] Checking tools..."
$SUDO apt update -qq >/dev/null 2>&1

APT_TOOLS=(git python3 dirsearch)
for tool in "${APT_TOOLS[@]}"; do
  check_tool "$tool" && echo "[✔] $tool found" || install_apt "$tool"
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
  check_tool "$NAME" && echo "[✔] $NAME found" || install_go "$NAME" "$PKG"
done

# GF patterns
[[ ! -d "$HOME/.gf" ]] && git clone https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf" >/dev/null 2>&1

echo
echo "-------------- TARGET INPUT --------------"
read -p "Enter target domain: " DOMAIN

echo
echo "1) Full Recon (Everything)"
echo "2) Provide Live Subdomains File"
echo "3) Provide Live Subdomains + JS File"
echo
read -p "Choose option: " MODE

WORKDIR="$DOMAIN-recon"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# =========================
# MODE 1 — FULL RECON
# =========================
if [[ "$MODE" == "1" ]]; then
  echo "[+] Running subfinder..."
  subfinder -d "$DOMAIN" -silent -o subdomains.txt

  echo "[+] Checking live subdomains..."
  httpx -silent -l subdomains.txt > subdomains_alive.txt

  echo "[+] Finding JS files..."
  katana -list subdomains_alive.txt -jc -silent | grep "\.js$" | sort -u > js.txt
fi

# =========================
# MODE 2 — LIVE FILE INPUT
# =========================
if [[ "$MODE" == "2" ]]; then
  read -p "Path to LIVE subdomains file: " LIVEFILE
  cp "$LIVEFILE" subdomains_alive.txt

  echo "[+] Finding JS files..."
  katana -list subdomains_alive.txt -jc -silent | grep "\.js$" | sort -u > js.txt
fi

# =========================
# MODE 3 — LIVE + JS INPUT
# =========================
if [[ "$MODE" == "3" ]]; then
  read -p "Path to LIVE subdomains file: " LIVEFILE
  read -p "Path to JS file: " JSFILE
  cp "$LIVEFILE" subdomains_alive.txt
  cp "$JSFILE" js.txt
fi

echo
echo "[+] Live subdomains:"
wc -l subdomains_alive.txt
echo "[+] JS files:"
wc -l js.txt
echo

# =========================
# URL COLLECTION (FIXED)
# =========================
echo "[+] Crawling URLs (katana updated flags)..."
katana -list subdomains_alive.txt -d 5 -silent > allurls.txt
wc -l allurls.txt

# Parameters & Sensitive files
grep "=" allurls.txt | sort -u > params.txt
grep -E '\.txt|\.log|\.db|\.backup|\.json|\.zip|\.config' allurls.txt > sensitive_files.txt

# GF patterns
gf xss params.txt > xss_candidates.txt
gf lfi allurls.txt > lfi_candidates.txt

# =========================
# NUCLEI
# =========================
echo "[+] Running nuclei..."
nuclei -l js.txt -severity critical,high,medium -o nuclei_js.txt
cat lfi_candidates.txt | nuclei -tags lfi -o nuclei_lfi.txt

waybackurls "https://$DOMAIN" | gf xss > wayback_xss.txt

echo
echo "Recon completed!"
echo "Results saved in $WORKDIR"

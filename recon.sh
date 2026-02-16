#!/bin/bash

set -e

# ---------------- CONFIG ----------------
DOMAIN=$1
DATE=$(date +"%Y-%m-%d_%H%M%S")
OUTDIR="./recon_${DOMAIN}_${DATE}"
LOG="$OUTDIR/recon.log"

mkdir -p "$OUTDIR"
touch "$LOG"

echo "[*] Starting recon for $DOMAIN" | tee -a "$LOG"

# ---------------- CHECK TOOLS ----------------
TOOLS=(subfinder assetfinder amass httpx gau waybackurls gf nuclei)

for tool in "${TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo "[!] $tool not installed. Please install it first."
        exit 1
    fi
done

# ---------------- SUBDOMAIN ENUM ----------------
echo "[*] Running subdomain enumeration..." | tee -a "$LOG"

subfinder -d $DOMAIN -silent > "$OUTDIR/subs_subfinder.txt"
assetfinder --subs-only $DOMAIN > "$OUTDIR/subs_assetfinder.txt"
amass enum -passive -d $DOMAIN -o "$OUTDIR/subs_amass.txt"

cat "$OUTDIR"/subs_*.txt | sort -u > "$OUTDIR/all_subdomains.txt"
SUB_COUNT=$(wc -l < "$OUTDIR/all_subdomains.txt")
echo "[+] Found $SUB_COUNT subdomains" | tee -a "$LOG"

# ---------------- LIVE HOSTS ----------------
echo "[*] Probing for live hosts..." | tee -a "$LOG"

httpx -l "$OUTDIR/all_subdomains.txt" \
    -silent -threads 100 -timeout 10 \
    -status-code -title \
    -o "$OUTDIR/httpx-detection.txt"

cut -d ' ' -f1 "$OUTDIR/httpx-detection.txt" > "$OUTDIR/live_subdomains.txt"

LIVE_COUNT=$(wc -l < "$OUTDIR/live_subdomains.txt")
echo "[+] Live hosts: $LIVE_COUNT" | tee -a "$LOG"

# ---------------- URL COLLECTION ----------------
echo "[*] Collecting URLs..." | tee -a "$LOG"

gau $DOMAIN > "$OUTDIR/gau.txt"
waybackurls $DOMAIN > "$OUTDIR/wayback.txt"

cat "$OUTDIR"/gau.txt "$OUTDIR"/wayback.txt | sort -u > "$OUTDIR/all_urls.txt"

URL_COUNT=$(wc -l < "$OUTDIR/all_urls.txt")
echo "[+] Collected URLs: $URL_COUNT" | tee -a "$LOG"

# ---------------- PARAMETER URLS ----------------
echo "[*] Extracting parameter URLs..." | tee -a "$LOG"

grep "=" "$OUTDIR/all_urls.txt" | sort -u > "$OUTDIR/param_urls.txt"
PARAM_COUNT=$(wc -l < "$OUTDIR/param_urls.txt")
echo "[+] Parameter URLs: $PARAM_COUNT" | tee -a "$LOG"

# ---------------- JS FILES ----------------
echo "[*] Extracting JavaScript files..." | tee -a "$LOG"

grep "\.js" "$OUTDIR/all_urls.txt" | sort -u > "$OUTDIR/js_files.txt"
mkdir -p "$OUTDIR/js"

while read url; do
    wget -q "$url" -P "$OUTDIR/js/" || true
done < "$OUTDIR/js_files.txt"

# ---------------- SECRET SCAN ----------------
echo "[*] Searching for secrets in JS..." | tee -a "$LOG"

grep -R -E "apikey|token|secret|password|aws|auth" "$OUTDIR/js/" > "$OUTDIR/secrets.txt" || true

# ---------------- GF PATTERNS ----------------
echo "[*] Running gf patterns..." | tee -a "$LOG"

mkdir -p "$OUTDIR/gf"

gf xss "$OUTDIR/param_urls.txt" > "$OUTDIR/gf/xss.txt" || true
gf sqli "$OUTDIR/param_urls.txt" > "$OUTDIR/gf/sqli.txt" || true
gf ssrf "$OUTDIR/param_urls.txt" > "$OUTDIR/gf/ssrf.txt" || true
gf lfi "$OUTDIR/param_urls.txt" > "$OUTDIR/gf/lfi.txt" || true

# ---------------- NUCLEI SCAN ----------------
echo "[*] Updating nuclei templates..." | tee -a "$LOG"
nuclei -update-templates >/dev/null 2>&1

echo "[*] Preparing nuclei targets..." | tee -a "$LOG"
cat "$OUTDIR/live_subdomains.txt" "$OUTDIR/param_urls.txt" 2>/dev/null | sort -u > "$OUTDIR/nuclei_targets.txt"

TARGET_COUNT=$(wc -l < "$OUTDIR/nuclei_targets.txt")
echo "Targets for nuclei: $TARGET_COUNT" | tee -a "$LOG"

mkdir -p "$OUTDIR/nuclei"

if [ "$TARGET_COUNT" -gt 0 ]; then
    echo "[*] Running nuclei vulnerability scan..." | tee -a "$LOG"

    nuclei -l "$OUTDIR/nuclei_targets.txt" \
        -severity critical,high,medium \
        -stats \
        -rl 150 \
        -c 50 \
        -o "$OUTDIR/nuclei/results.txt"

    echo "[+] Nuclei scan finished!" | tee -a "$LOG"
else
    echo "[!] No targets for nuclei scan." | tee -a "$LOG"
fi

# ---------------- DONE ----------------
echo ""
echo "======================================"
echo " Recon Completed Successfully 🎯"
echo " Output Directory: $OUTDIR"
echo "======================================"

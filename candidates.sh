#!/bin/bash
# candidates.sh - fetch password lists LIVE over wlan0 internet (no preload).
# Usage: ./candidates.sh <SSID> <outdir>
# Always succeeds offline with built-in defaults; upgrades to big lists if net works.
set -u
SSID="${1:-Vijay}"
OUT="${2:-/tmp/pwn-words}"
mkdir -p "$OUT"

# 1. Built-in defaults (always available, course-lab focused)
cat > "$OUT/00-defaults.txt" <<EOF
password
password123
12345678
123456789
qwerty123
admin123
letmein
welcome123
vijay123
Vijay123
Vijay@123
vijay@123
$SSID
${SSID}123
${SSID}1234
${SSID}12345
${SSID}@123
${SSID}2024
${SSID}2025
Test1234
test1234
lab12345
college123
student123
wifi12345
internet123
JioFiber123
Airtel123
excitel123
EOF

# 2. SSID mangles (local generation, fast)
python3 - "$SSID" "$OUT/01-mangle.txt" <<'PYEOF'
import sys
ssid = sys.argv[1]; out = sys.argv[2]
suffixes = ["123","1234","12345","123456","@123","#123","@1234","2023","2024","2025",
            "007","111","000","321","987","999","01","02","0077","1212","1122"]
variants = {ssid, ssid.lower(), ssid.capitalize(), ssid.upper()}
with open(out, "w") as f:
    seen = set()
    for v in variants:
        for s in suffixes:
            for cand in (v+s, s+v):
                if cand not in seen and 8 <= len(cand) <= 63:
                    seen.add(cand); f.write(cand+"\n")
print(f"mangled: {len(seen)}", file=sys.stderr)
PYEOF

# 3. Live downloads over wlan0 (internet allowed). Best-effort, background-friendly.
dl() { # url outfile maxseconds
  curl -sL --max-time "$3" "$1" -o "$2" 2>/dev/null && echo "[*] got $2 ($(wc -l < "$2") lines)" || echo "[!] skip $1 (offline?)"
}
if ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
  echo "[*] internet OK via wlan0, fetching lists..."
  dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt" "$OUT/02-top500.txt" 30
  dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.txt" "$OUT/03-default-creds.txt" 30
  dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" "$OUT/04-top10k.txt" 60
  if [ ! -s "$OUT/04-top10k.txt" ]; then
    dl "https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/wordlists/top10000.txt" "$OUT/04-top10k.txt" 60
  fi
else
  echo "[!] no internet - using local lists only"
fi

# 4. Merge in priority order, dedupe, WPA-valid lengths only (8..63)
cat "$OUT"/0*.txt "$OUT"/0*.txt 2>/dev/null | awk 'length>=8 && length<=63' | awk '!seen[$0]++' > "$OUT/combined.txt" || true
echo "[OK] combined: $(wc -l < "$OUT/combined.txt") candidates -> $OUT/combined.txt"

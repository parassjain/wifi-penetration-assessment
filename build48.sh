#!/bin/bash
# build48.sh - build ~25k ordered candidates for a 48hr run. Run as root (uses net only).
# Usage: ./build48.sh <outdir-words>
# Order: hint(rifco/aruna/flats/blocks) -> B1-SSID mangles -> top500 -> default-creds -> top10k -> rockyou-head
set -u
W="${1:-/tmp/pwn-words-b1}"
REPO=/home/paras/wifi-penetration-assessment
mkdir -p "$W"
OLD=/tmp/pwn-words

echo "[*] hint list..."
python3 $REPO/gen_hint.py $W/00-hint.txt

echo "[*] B1 SSID mangles..."
python3 - "$W/01-mangle.txt" <<'PYEOF'
import sys, itertools
out = sys.argv[1]
ssids = ["2.4G_B1", "5G_B1", "B1", "b1", "2.4G", "5G"]
suffixes = ["123","1234","12345","123456","@123","#123","@1234","2023","2024","2025",
            "007","111","000","321","999","01","101","102","103","104","105","106",
            "401","402","403","404","405","406"]
seen, ordered = set(), []
def add(c):
    if 8 <= len(c) <= 63 and c not in seen:
        seen.add(c); ordered.append(c)
for s in ssids:
    for suf in suffixes:
        add(f"{s}{suf}"); add(f"{s}_{suf}"); add(f"{s}-{suf}")
for a, b in itertools.product(["rifco","aruna","Rifco","Aruna"], ["2.4G_B1","5G_B1","B1"]):
    add(f"{a}{b}"); add(f"{b}{a}"); add(f"{a}_{b}")
with open(out, "w") as f: f.write("\n".join(ordered) + "\n")
print(f"mangled: {len(ordered)}")
PYEOF

echo "[*] reusing live lists..."
cp $OLD/02-top500.txt $W/ 2>/dev/null || curl -sL --max-time 60 "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt" -o $W/02-top500.txt
cp $OLD/03-default-creds.txt $W/ 2>/dev/null || true
cp $OLD/04-top10k.txt $W/ 2>/dev/null || true

echo "[*] rockyou head (frequency-ordered)..."
if [ -f $W/rockyou.txt ]; then
  awk 'length>=8 && length<=63' $W/rockyou.txt | awk '!seen[$0]++' | head -11000 > $W/05-rockyou11k.txt
  wc -l $W/05-rockyou11k.txt
else
  echo "[!] no rockyou.txt - run rockyou download first"; touch $W/05-rockyou12k.txt
fi

echo "[*] merging ordered + dedupe..."
cat $W/00-hint.txt $W/01-mangle.txt 2>/dev/null | awk 'length>=8 && length<=63' | awk '!seen[$0]++' > $W/combined48.txt
cat $W/02-top500.txt $W/03-default-creds.txt $W/04-top10k.txt $W/05-rockyou11k.txt 2>/dev/null \
  | awk 'length>=8 && length<=63' | grep -vFxf $W/00-hint.txt | grep -vFxf $W/01-mangle.txt | awk '!seen[$0]++' >> $W/combined48.txt
wc -l $W/combined48.txt
echo "[*] at ~7.2s/try this covers ~$(( $(wc -l < $W/combined48.txt) * 72 / 10 / 3600 ))hr"

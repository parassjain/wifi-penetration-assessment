#!/bin/bash
# run.sh - headless launcher. Thin wrapper over `python -m piwps psk`.
# Usage: sudo ./scripts/run.sh --target 2.4G_B1 --time 2880 --words ./words/combined48.txt --out ./results-b1-48h
set -u
TARGET="2.4G_B1"; BUDGET=2880; OUT="./results-b1-48h"; WORDS="./words/combined48.txt"
while [ $# -gt 0 ]; do case "$1" in
  --target) TARGET="$2"; shift 2;;
  --time) BUDGET="$2"; shift 2;;
  --out) OUT="$2"; shift 2;;
  --words) WORDS="$2"; shift 2;;
  *) echo "unknown $1"; exit 1;;
esac; done
if [ "$(id -u)" -ne 0 ]; then echo "run as root: sudo ./scripts/run.sh"; exit 1; fi
cd "$(dirname "$0")/.." || exit 1
./scripts/setup_wlan1.sh || exit 1
[ -f "$WORDS" ] || { echo "[!] missing $WORDS - build it first (see README)"; exit 1; }
mkdir -p "$OUT"
nohup python3 -m piwps psk --target "$TARGET" --time "$BUDGET" --out "$OUT" --words "$WORDS" > "$OUT/console.log" 2>&1 &
echo "[*] piwps psk started pid=$! log=$OUT/console.log ; wlan0 untouched"

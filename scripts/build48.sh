#!/bin/bash
# build48.sh - compose the 48h queue from piwps wordlist builders.
# Usage: ./scripts/build48.sh <wordsdir>   (wordsdir persists, e.g. ./words48)
set -u
W="${1:?wordsdir}"
cd "$(dirname "$0")/.." || exit 1
mkdir -p "$W"
python3 -m piwps words hint --output "$W/00-hint.txt"
python3 -m piwps words mangle --output "$W/01-mangle.txt"
for f in 02-top500.txt 03-default-creds.txt 04-top10k.txt; do
  [ -f "$W/$f" ] || echo "[!] missing $W/$f - fetch via: python3 -m piwps words fetch --url <url> --output $W/$f"
done
python3 - <<EOF
from piwps import wordlists
def read(p):
    try:
        with open(p, errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except FileNotFoundError:
        return []
parts = ["$W/00-hint.txt", "$W/01-mangle.txt", "$W/02-top500.txt",
         "$W/03-default-creds.txt", "$W/04-top10k.txt", "$W/05-rockyou11k.txt"]
lists = [read(p) for p in parts]
merged = wordlists.merge(*lists)
with open("$W/combined48.txt", "w") as fh:
    fh.write("\n".join(merged) + ("\n" if merged else ""))
print(f"combined48: {len(merged)}")
EOF

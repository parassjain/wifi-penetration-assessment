#!/bin/bash
# build48c.sh - top-up queue to ~24k with streaming commands only (low RAM).
# Assumes combined48.txt already has hint+mangle+top500+creds+top10k (+rockyou11k).
# Appends next rockyou frequency tier, excluding everything already queued.
set -u
W=/tmp/pwn-words-b1
echo "[*] rockyou 30k head, deduped in-isolation (small)..."
awk 'length>=8 && length<=63' $W/rockyou.txt | head -30000 | awk '!seen[$0]++' > $W/05-rk30k.txt
wc -l < $W/05-rk30k.txt
echo "[*] excluding already-queued, taking 11k..."
awk 'NR==FNR{a[$0];next} !($0 in a)' $W/combined48.txt $W/05-rk30k.txt | head -11000 > $W/05-next.txt
wc -l < $W/05-next.txt
cat $W/05-next.txt >> $W/combined48.txt
echo -n "TOTAL: "; wc -l < $W/combined48.txt

#!/bin/bash
# build48b.sh - extend queue with next rockyou frequency tier (excludes all already queued).
# Fills ~48hr at ~7.2s/try (~24k total). Run on Pi, no sudo needed.
set -u
W=/tmp/pwn-words-b1
RK=$W/rockyou.txt
echo "[*] frequency-ordered deduped rockyou (takes a few min)..."
awk 'length>=8 && length<=63' $RK | awk '!seen[$0]++' > $W/rockyou-uniq.txt
wc -l $W/rockyou-uniq.txt
echo "[*] next 11k not already queued..."
awk 'NR==FNR{a[$0];next} !($0 in a)' $W/combined48.txt $W/rockyou-uniq.txt | head -11000 > $W/05-rockyou-next.txt
wc -l $W/05-rockyou-next.txt
cat $W/05-rockyou-next.txt >> $W/combined48.txt
wc -l < $W/combined48.txt

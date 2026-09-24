#!/bin/bash
# dash-start.sh - (re)start dashboard detached. Usage: dash-start.sh <results-dir> [port]
D="${1:-./results-actyoga2}"; P="${2:-8080}"
cd /home/paras/wifi-penetration-assessment || exit 1
if ss -tln 2>/dev/null | grep -q ":$P "; then echo ALREADY-LISTENING; exit 0; fi
nohup python3 ./dashboard.py --port "$P" --dir "$D" > ./dashboard.log 2>&1 < /dev/null &
echo "LAUNCHED pid=$!"

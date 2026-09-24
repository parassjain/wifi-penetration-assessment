#!/bin/bash
# dash-start.sh - (re)start dashboard detached. Usage: dash-start.sh <results-dir> [port]
D="${1:-./results-b1-48h}"; P="${2:-8080}"
cd "$(dirname "$0")/.." || exit 1
if ss -tln 2>/dev/null | grep -q ":$P "; then echo ALREADY-LISTENING; exit 0; fi
nohup python3 -m piwps dashboard --port "$P" --dir "$D" > ./dashboard.log 2>&1 < /dev/null &
echo "LAUNCHED pid=$!"

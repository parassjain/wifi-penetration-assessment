#!/bin/bash
# setup_wlan1.sh - thin wrapper. Real implementation: piwps.radio.ensure_wlan1.
# NEVER touches wlan0 / netplan. Safe to re-run. Must run as root.
set -u
if [ "$(id -u)" -ne 0 ]; then echo "run as root: sudo ./setup_wlan1.sh"; exit 1; fi
cd "$(dirname "$0")/.." || exit 1
exec python3 -m piwps setup-radio

#!/bin/bash
# setup_wlan1.sh - create second STA interface + isolated wpa_supplicant.
# NEVER touches wlan0 / netplan. Safe to re-run. Must run as root.
set -u
CTRLDIR=/run/wpa_supplicant_pwn
CONF=/tmp/pwn-wlan1.conf

if [ "$(id -u)" -ne 0 ]; then echo "run as root: sudo ./setup_wlan1.sh"; exit 1; fi

echo "[*] wlan0 must stay on B1-405. Verifying..."
wpa_cli -i wlan0 status 2>/dev/null | grep -E "^(ssid|wpa_state|ip_address)=" || echo "[!] WARN: cannot read wlan0 status (continuing)"

if ! iw dev | grep -q "Interface wlan1"; then
  echo "[*] creating wlan1..."
  iw dev wlan0 interface add wlan1 type managed || { echo "[!] FAILED to create wlan1"; exit 1; }
else
  echo "[*] wlan1 already exists"
fi
ip link set wlan1 up

mkdir -p "$CTRLDIR"
cat > "$CONF" <<EOF
ctrl_interface=DIR=$CTRLDIR GROUP=root
update_config=1
country=IN
EOF
chmod 600 "$CONF"

if pgrep -f "wpa_supplicant.*-iwlan1" >/dev/null; then
  echo "[*] wpa_supplicant for wlan1 already running"
else
  echo "[*] starting isolated wpa_supplicant on wlan1..."
  # -B daemonize; own ctrl dir so wlan0's netplan supplicant is untouched
  wpa_supplicant -B -i wlan1 -c "$CONF" -D nl80211
  sleep 2
fi

echo "[*] wlan1 ready. wlan0 check:"
wpa_cli -i wlan0 status 2>/dev/null | grep -E "^(ssid|wpa_state|ip_address)=" || true
wpa_cli -p "$CTRLDIR" -i wlan1 status 2>&1 | head -8 || true
echo "[OK] setup done. wlan0 untouched."

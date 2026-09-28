#!/bin/bash
# install.sh - enable reboot-safe services. Run as root, once (re-runnable).
# pi-pwn (dictionary) and pi-wps (persistent WPS) are independent; enable
# only the ones wanted. pi-dash (UI) is always safe to enable.
# After a power cut, enabled services resume automatically (done.log resume).
set -u
REPO=/home/paras/wifi-penetration-assessment
if [ "$(id -u)" -ne 0 ]; then echo "run as root: sudo ./install.sh [pwn|wps|dash|all]"; exit 1; fi
WANT="${1:-all}"
cp "$REPO"/systemd/pi-*.service /etc/systemd/system/
systemctl daemon-reload
enable() { systemctl enable "$1"; }
case "$WANT" in
  pwn) enable pi-pwn.service;;
  wps) enable pi-wps.service;;
  dash) enable pi-dash.service;;
  all) enable pi-pwn.service; enable pi-wps.service; enable pi-dash.service;;
  *) echo "unknown: $WANT (pwn|wps|dash|all)"; exit 1;;
esac
echo "[OK] enabled: $WANT. Status: systemctl status pi-pwn pi-wps pi-dash"
echo "Start now without reboot: systemctl start pi-wps pi-dash"

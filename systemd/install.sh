#!/bin/bash
# install.sh - enable reboot-safe autopwner + dashboard. Run as root, once.
# After a power cut the Pi resumes the attack from OUT/done.log automatically.
set -u
REPO=/home/paras/wifi-penetration-assessment
if [ "$(id -u)" -ne 0 ]; then echo "run as root: sudo ./install.sh"; exit 1; fi
cp "$REPO/systemd/pi-pwn.service" "$REPO/systemd/pi-dash.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable pi-pwn.service pi-dash.service
echo "[OK] enabled. Check: systemctl status pi-pwn pi-dash"
echo "Start now without reboot: systemctl start pi-pwn pi-dash"
echo "Logs: journalctl -u pi-pwn -f  |  tail -f $REPO/results-b1-48h/console.log"

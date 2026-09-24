# wifi-penetration-assessment (Pi 4, stock radio, Ubuntu Server 24.04)

Midterm tool: recover the test AP password (**target `Vijay`**) within 2h
**without ever disconnecting the Pi's own WiFi (`wlan0` on `B1-405`)**.

## Constraint -> design

Single Broadcom radio, `wlan0` carries SSH + internet. Classic
`airmon-ng / deauth / handshake` would kill `wlan0`, so this tool uses
**dual-STA**: `wlan0` (netplan, untouched) + `wlan1` (virtual managed
interface, own `wpa_supplicant` + ctrl dir). All recon/attacks run on
`wlan1`; a watchdog aborts if `wlan0` ever leaves `COMPLETED`.

`iw list` confirms `#{managed} <= 2` on this chip, verified live:
`iw dev wlan0 interface add wlan1 type managed` keeps `wlan0` COMPLETED.

## Scope / ethics

- Test ONLY the course-authorized AP (`Vijay`) and your own lab.
- Managed-mode try-to-connect only. No deauth, no injection, no monitor mode.
- Every run logs `wlan0` health to prove non-disruption.

## Files

- `setup_wlan1.sh` - create `wlan1` + isolated supplicant (idempotent, root)
- `candidates.sh` - build wordlist LIVE at runtime (no preload): built-in
  defaults + SSID mangles + SecLists/top10k over `wlan0` internet, fallback offline
- `pwn.py` - orchestrator: wait-for-target -> rank -> serial try-connect on
  `wlan1` -> DHCP prove -> `results/creds.txt + result.json`
- `run.sh` - headless entry: `sudo ./run.sh --target Vijay --time 100`

## Runbook (exam, 2h)

1. Pi already on `B1-405` via `wlan0`. SSH in (or console). Do NOT touch netplan.
2. `cd ~/wifi-penetration-assessment && sudo ./run.sh --target Vijay --time 100`
3. Watch: `tail -f results/console.log`; proof: `cat results/creds.txt results/result.json`
4. `wlan0` stays up the whole time - check: `wpa_cli -i wlan0 status`

Success = `results/creds.txt` contains `Vijay:<password>` and
`result.json:wlan0_intact=true`.

## Limitations

- ~3-7s per WPA try on stock radio => ~1-1.5k tries in 2h. Wins on weak/default
  passwords, loses to long random PSKs (documented in report, still earns recon marks).
- `wlan1` STA+STA needs same-phy support (present here); STA+AP same-channel also
  possible but unused.

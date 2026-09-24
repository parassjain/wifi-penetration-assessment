# wifi-penetration-assessment (Pi 4, stock radio, Ubuntu Server 24.04)

Midterm tool: recover the test AP password (**target `Vijay`**) within 2h
**without ever disconnecting the Pi's own WiFi (`wlan0` on `B1-405`)**.

> Code lives in the **`piwps/` package** — see **[ARCHITECTURE.md](ARCHITECTURE.md)**
> for the module map. One CLI: `python3 -m piwps recon|psk|wps|dashboard|migrate|setup-radio|words`.
> Pure-logic tests: `python3 -m pytest` (no Pi hardware required).

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

## Files (v0.2 modular layout)

- `piwps/` - the product: `radio` (wlan1 lifecycle) · `scan` (recon) ·
  `wordlists` (hint/mangle/fetch/merge) · `state` (reboot-safe resume) ·
  `attacks/psk` + `attacks/wps` (single PIN engine, profiles) ·
  `report` · `web/` (dashboard API + static UI)
- `scripts/` - thin wrappers: `setup_wlan1.sh`, `run.sh`, `dash-start.sh`,
  `build48.sh` (queue composer)
- `systemd/` - `pi-pwn.service` + `pi-dash.service` (autostart, resume on boot)
- `tests/` - pytest unit tests (15 tests, hardware-free)
- `words/`, `results*/` - runtime data, gitignored

Legacy flat scripts (`pwn.py`, `dashboard.py`, `wps_try*.sh`, `candidates.sh`,
`build48*.sh`, `migrate.py`) were consolidated into `piwps/` in v0.2;
see git history if you need them.

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

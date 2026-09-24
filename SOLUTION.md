# Potential Solution — Dual-STA Autopwner (wlan0 untouched, attacks via wlan1)

## Key insight
The Pi 4 radio supports **two managed (STA) interfaces**
(`iw list`: `#{ managed } <= 2, #channels <= 2`), verified live:
`iw dev wlan0 interface add wlan1 type managed` leaves `wlan0` `COMPLETED`
on `B1-405`. So the tool keeps `wlan0` (netplan, SSH/internet) completely
untouched and does **all recon + attacks on a virtual `wlan1`** with its own
isolated `wpa_supplicant` instance and ctrl dir (`/run/wpa_supplicant_pwn`).
A watchdog aborts if `wlan0` ever leaves `COMPLETED`.

This satisfies every constraint: stock-only, no monitor/injection needed,
`wlan0` never disconnects, internet stays up for live wordlist downloads.

## Architecture (implemented in the Pi repo `~/wifi-penetration-assessment`)
- `setup_wlan1.sh` — idempotent: create `wlan1`, bring up, start isolated
  `wpa_supplicant -B -i wlan1 -c /tmp/pwn-wlan1.conf -D nl80211`. Never touches
  netplan / `wlan0`'s supplicant (`/run/netplan/wpa-wlan0.conf`).
- `candidates.sh <SSID> <outdir>` — runtime wordlist builder (no preload):
  built-in defaults + SSID-mangled variants + live SecLists/top10k fetch over
  `wlan0` internet, merged/deduped to `combined.txt` (~2.6k candidates,
  verified). Fully offline-capable fallback.
- `pwn.py --target Vijay --time 100 --out ./results` — orchestrator (stdlib
  only): wait-for-target scan loop → fingerprint security → serial
  try-to-connect on `wlan1` via `wpa_cli add_network/set_network/enable` →
  `dhcpcd` + IP proof → `creds.txt` / `result.json` / `scan.json` / `pwn.log`.
  Polls `wlan0` health throughout; records `wlan0_intact=true`.
- `run.sh` — headless entry: `sudo ./run.sh --target Vijay --time 100`
  (setup → candidates → `nohup pwn.py`), SSH-safe.

## Exam runbook (2 h)
1. Pi boots on `B1-405` via `wlan0`; SSH in. Touch nothing in netplan.
2. `cd ~/wifi-penetration-assessment && sudo ./run.sh --target Vijay --time 100`
3. Monitor: `tail -f results/console.log`; grade proof:
   `cat results/creds.txt results/result.json`.
4. Priority order per AP: OPEN → vendor defaults → SSID mangles → top500 →
   top10k (strongest-signal AP first; WPA3/strong parked after 50 tries).

## Verified so far (live on the Pi)
- `wlan1` creation + isolated supplicant: `wlan0` stayed `COMPLETED/192.168.1.34`.
- Independent `wlan1` scan sees the full neighborhood while `wlan0` is up.
- `candidates.sh`: 2,631 live candidates; `pwn.py` wait-loop dry run exits
  cleanly with `wlan0` intact when `Vijay` is absent.
- Remaining: end-to-end password recovery once the `Vijay` AP is present
  (attack path is implemented; only the target is missing).

## Limitations / honest notes
- ~1–1.5k WPA tries per 2 h on stock hardware: weak/default PSKs fall,
  long random PSKs will not — the report documents recon findings for partial
  marks in that case.
- Single-phy STA+STA is same-radio time-sliced; brief latency on `wlan0`
  during `wlan1` association is possible but not a disconnect (watchdog proves it).
- Scope is strictly the authorized test AP + own lab; no deauth/injection used.

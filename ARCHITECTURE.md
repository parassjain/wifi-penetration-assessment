# ARCHITECTURE

## Constraint that shapes everything

One stock radio (`brcmfmac`, no monitor mode), one management uplink
(`wlan0` on home AP, carries SSH + internet) that must **never disconnect**.
`iw list` shows `#{ managed } <= 2`, so the design is **dual-STA**:

- `wlan0` — owned by netplan/systemd-networkd. The tool only *reads* it
  (watchdog). Never configured, never restarted by us.
- `wlan1` — virtual managed interface created by `piwps.radio.ensure_wlan1`,
  with its own `wpa_supplicant` + ctrl dir (`/run/wpa_supplicant_pwn`).
  All scans and associations happen here.

## Module map

```
piwps/config.py      constants + env overrides (single source of truth)
piwps/radio.py       ONLY module with radio side effects (wpa_cli, dhcpcd, iw)
piwps/scan.py        passive recon: parse, fingerprint (sec/WPS), rank
piwps/wordlists.py   pure candidate builders (hint/mangle/fetch/merge)
piwps/state.py       reboot safety: done.log + run.json + status.json
piwps/attacks/psk.py managed-mode passphrase attempts (bssid-pin, fail-fast)
piwps/attacks/wps.py ONE pin engine + profiles + checksum validation + lockout detect
piwps/wpsd (in __main__) persistent WPS supervisor: corpus batches, done.log
                     resume across reboots, lockout backoff, success-stop
piwps/report.py      result.json / creds.txt / sweep discovery / audit markdown
piwps/web/           dashboard backend (app.py) + frontend (static/index.html)
piwps/__main__.py    CLI: recon | psk | wps | wpsd | dashboard | migrate | setup-radio | words
scripts/             thin shell wrappers (setup, install, run)
systemd/             pi-pwn.service + pi-dash.service (autostart on boot)
tests/               pytest, pure logic, no hardware required
```

Rules: UI never touches the radio except via `radio`/`scan` helpers;
attack loops never parse logs (they write `state`); wordlists never touch
disk except `fetch`. `wlan0` appears in code only as a health check.

## Data flow (psk run)

```
words/combined48.txt
  -> psk loop: DoneLog skips tried -> radio.attempt on wlan1
  -> per try: done.log append + status.json write
  -> watchdog: radio.wlan0_healthy() every iteration, abort if disturbed
  -> finish: report.result.json + creds.txt
```

## Reboot safety

`run.json` records `first_start` once; every boot continues the *same*
48h budget. `done.log` makes retries idempotent. systemd
`ExecStartPre` recreates `wlan1`. Verified with a real power-cycle test:
run resumed at 900 -> 927 with zero loss.

## Throughput reality

~7s per failed try (AP-side scan+auth dominates) => ~800 tries per 2h,
~24k per 48h. Ordering (hint -> mangle -> top lists -> rockyou tiers)
is the performance strategy on a single PHY.

# Problem Statement — WiFi Penetration Tester on Raspberry Pi

## Context
Cybersecurity course midterm assignment: build a WiFi penetration-tester tool
running on a Raspberry Pi.

## Environment
- Board: Raspberry Pi 4, **stock onboard radio only** (CYW43455 / `brcmfmac`,
  no external adapter — strictly stock).
- OS: **Ubuntu Server 24.04 LTS** (`6.8.0-raspi`, aarch64).
- Management interface `wlan0` is connected to the lab/home AP (`B1-405`,
  `192.168.1.34`) and carries **SSH + internet**. No `nmcli`/`iw` by default;
  networking is owned by **netplan + systemd-networkd + wpa_supplicant**.

## Task
During the test, unknown sample networks appear in the vicinity (known test
SSID: **`Vijay`**). Within **2 hours**, the Pi must **penetrate them and show
the WiFi password** (`SSID:password` with connection proof).

## Constraints
1. **Target OS is Ubuntu Server** (no Kali GUI tooling, no NetworkManager).
2. **Test SSIDs are unknown until test time** — the tool must auto-discover,
   rank, and attack unattended within the 2h budget.
3. **No preloaded wordlists/passwords** on the Pi; **internet use during the
   test is allowed** (so lists must be fetched live at runtime).
4. **Strictly stock radio** — no USB adapter for monitor mode / injection.
5. **The currently connected WiFi (`wlan0` on `B1-405`) must not disconnect
   at any point** — SSH and internet must survive the whole run.

## Why it is hard
- One radio is normally bound to one association: every password attempt
  against `Vijay` would disconnect `wlan0` (killing SSH/internet).
- Stock `brcmfmac` has no reliable monitor mode / deauth / PMKID capture, so
  classic `aircrack-ng` handshake flows are unavailable.
- Managed-mode try-to-connect costs ~3–7 s per password ⇒ at most ~1–1.5k
  tries in 2 h: brute force cannot beat a strong random PSK; ranking and
  candidate quality decide the outcome.

## Success criteria
- `results/creds.txt` contains `Vijay:<password>` with DHCP/IP proof, produced
  inside 2 h, **and** `wlan0` is still `COMPLETED` on `B1-405` afterwards.
- Partial credit path: full passive recon + misconfiguration audit even when
  the PSK is too strong to crack on Pi hardware.

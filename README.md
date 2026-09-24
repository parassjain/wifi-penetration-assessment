# wifi-penetration-assessment (Pi 4, stock radio, Ubuntu Server 24.04)

Course midterm. This repository is a private, defensive lab for the two authorized test routers named below. Do not point it at any other network.

---

# Problem statement

## What the course is asking for

Build one WiFi assessment tool that runs on a Raspberry Pi and, during a timed lab, recovers the passphrase of a course-provided access point and proves the Pi actually joined that network. The grader does not hand you the password, a prebuilt wordlist, a second radio, or a Kali image. The tool has to discover the target, decide which recovery path applies, do the work unattended, write the passphrase down with connection proof, and leave the Pi’s own management WiFi up for the entire run.

There are two levels. They share the same board, the same operating system, and the same “do not drop the management link” rule. They differ in what the access point is willing to offer, and therefore in which recovery path is even available.

| Level | Router state | Authorized test SSID | What has to be shown |
| --- | --- | --- | --- |
| 1 | WPS enrollment is turned on | `5G_B1` | Passphrase (or the WPS enrollment secret that yields it), plus proof the Pi associated and received an address, without dropping `wlan0` |
| 2 | WPS is turned off | `Vijay` | WPA passphrase, plus the same association and address proof, inside a 2 hour budget, without dropping `wlan0` |

Level 1 is the WPS-on case. The access point still advertises Wi-Fi Protected Setup, so a recovery path exists that does not require guessing the full passphrase. Level 2 is the WPS-off case. That path is gone. The only remaining option on this hardware is a managed-mode association attempt against a ranked list of candidate passphrases, built at runtime, inside a hard time limit.

Both levels are graded on the same machine, in the same lab, against only those two SSIDs. A result that disconnects the Pi from its management network is a failed run even if the target passphrase was found, because the constraint that makes the assignment hard was violated.

## Why the assignment is shaped this way

A normal laptop assessment cheats the interesting constraint. You plug in a USB adapter that can sit in monitor mode, you leave the built-in radio associated to the lab network, and the two jobs never share a chip. This midterm removes that cheat. The Pi has one stock Broadcom radio. That radio is already associated. SSH and the internet ride on that association. Anything the tool does to a second network has to happen without tearing the first association down, and without a second physical radio to hide behind.

The two levels then split on a property of the target, not of the Pi:

- When WPS is enabled, the access point exposes an enrollment mechanism that was designed for push-button or PIN setup. On many home routers that mechanism is still on, still accepts a small set of enrollment values, and on success hands the station the network’s real passphrase. The assessment question is whether the tool can recognize that the target is in this state, exercise only that enrollment path against the authorized SSID, stop before the access point locks the feature, and record both the secret and proof of association.
- When WPS is disabled, enrollment is not offered. Classic offline recovery (capture a handshake or a PMKID, then test candidates on another machine) is also unavailable, because the stock driver does not give a reliable monitor interface or injection. The station can only try to associate, learn from the failure, and try again. Each try costs several seconds. Two hours is therefore a few thousand attempts at most, which is not enough to beat a long random passphrase and is enough to beat a weak, default, or human-pattern passphrase if the candidate order is good.

So level 1 tests whether the tool notices and uses an exposed enrollment feature. Level 2 tests whether the tool can still make progress when that feature is absent, under a time budget that punishes a naive search.

## Environment the tool must run in

The board is a Raspberry Pi 4. The radio is the onboard CYW43455, driven by `brcmfmac`. No USB WiFi adapter is allowed, including one brought in “only for scanning.” The operating system is Ubuntu Server 24.04 LTS (`6.8.0-raspi`, aarch64): no Kali metapackages, no desktop, no NetworkManager. Addressing and the existing association are owned by netplan, systemd-networkd, and wpa_supplicant.

At the start of a run the management interface `wlan0` is already associated to the lab access point `B1-405` and has an address (observed lab address `192.168.1.34`). That association is the path for SSH and for any internet use during the test. The tool may read its state. It may not rewrite netplan, restart the system supplicant, or otherwise bounce `wlan0`.

The chip can expose a second virtual managed interface beside `wlan0`. `iw list` reports a limit of two managed interfaces. Creating that second interface and running a separate supplicant on it is in bounds, because it does not replace the management association. Putting the only radio into monitor mode is not in bounds: on this driver it drops the station association the assignment forbids you to drop.

Test SSIDs are not guaranteed to be visible when you write the tool. During the sitting, sample networks appear in the vicinity. The two that count are `5G_B1` (level 1) and `Vijay` (level 2). The tool should identify a target by name, wait if it is not on the air yet, and proceed without an operator sitting on the keyboard for the whole window.

## Rules that apply to both levels

1. Ubuntu Server only. Do not depend on a graphical aircrack suite, NetworkManager profiles, or packages that are not available on this image.
2. Stock radio only. No external adapter, no monitor mode, no frame injection, no deauthentication. A design that needs those is a design for a different assignment.
3. The management association stays up. From the first command of the run until the proof files are written, `wlan0` remains associated to `B1-405` with an address. A watchdog that aborts the run if that stops being true is part of the requirement, not an optional extra. The grader can check `wlan0` at any moment.
4. Nothing secret is staged on the Pi beforehand. No password file, no copied wordlist, no note with the suspected passphrase sitting in the home directory before the clock starts. Internet use during the test is allowed, and it rides on `wlan0`, so public candidate material may be fetched when the run starts. If the fetch fails, the tool must still have a small offline fallback of ordinary defaults and SSID-derived guesses. It must not have been “preloaded” with the answer.
5. Scope is the named course router for that level, plus your own lab. Other SSIDs that show up in a scan are noise. They are not targets.
6. The run is headless and restartable. SSH can drop for reasons that are not a WiFi disconnect (laptop sleep, a brief stall). A restarted process should continue inside the remaining time budget instead of repeating work it already finished.
7. Every run logs enough `wlan0` health to show the management link was intact, not merely that a passphrase string appeared in a file.

## Level 1 — WPS enabled, test router `5G_B1`

The access point for this level broadcasts the SSID `5G_B1` and has WPS turned on. That is the condition you are told in advance. You are not told the WPA passphrase, and you are not told that a push-button press will happen during the sitting. The tool has to treat WPS as an enrollment interface the station can drive on its own.

What this level is testing:

- Detection. A scan of the neighborhood must show that this BSSID is advertising WPS, and the tool must select that BSSID rather than a same-named or similarly named network that is not the authorized target.
- Use of the enrollment path only. Recovery goes through the WPS exchange the access point is offering. It does not go through deauthentication, a handshake capture, or a full passphrase search. Those are the wrong tool for a network that is still offering enrollment, and the first two are ruled out by the radio constraint anyway.
- Lockout awareness. Consumer WPS implementations stop answering, or lock the feature, after a short run of failed attempts. A tool that keeps going past that point both fails the level and can leave the router unwilling to speak WPS for the rest of the sitting. The run must be a short, bounded set of attempts and must stop on success or on signs that the access point has stopped cooperating.
- Proof, not a guessed string. Success is an association on the virtual assessment interface, an IPv4 address obtained from the target network, and a written record that ties `5G_B1` to the enrollment result and to the passphrase the access point revealed. A log line that says a PIN was “accepted” with no association behind it is not proof.
- Isolation from level 2. Getting onto `5G_B1` must not disturb `wlan0`, and it must not require the level 2 passphrase search. The two levels can share the virtual interface and the health watchdog. They must not share a single “try everything” loop that hammers WPS and then falls through into thousands of passphrase attempts against the same router.

What you may assume: the router is a normal home or ISP gateway of the kind used in the lab, WPS is actually enabled for the sitting, and the enrollment secret is one a short, careful check can hit. What you may not assume: that WPS will stay enabled if you abuse it, that a second radio will appear, or that the management network can be used as a sacrificial link.

## Level 2 — WPS disabled, test router `Vijay`

The access point for this level broadcasts the SSID `Vijay` and has WPS turned off. Scanning it will not show an enrollment path you can drive. There is no button press coming. The passphrase is a WPA-PSK you do not know. You have two hours from the start of the run.

What this level is testing:

- Discovery under uncertainty. `Vijay` may be absent when the process starts. The tool waits, scans on the virtual interface, and begins only when that SSID is visible. It records signal, frequency, BSSID, and security flags so the report still has a recon result if the passphrase is never found.
- Security fingerprint. The tool must tell an open network, WEP, WPA-PSK, WPA2-PSK, and WPA3-SAE apart from the scan flags, and must not spend the two hours attempting PSK guesses against a network whose flags say that will not work. An open network is a configuration finding and is reported as such. A WPA3-only network is reported and then set aside; this stock station path is aimed at PSK.
- Candidate quality over raw speed. A managed-mode association attempt on this radio takes on the order of 3 to 7 seconds when it fails quickly, and longer when it is allowed to sit in a timeout. Across a 2 hour budget that is roughly 1,000 to 1,500 serious attempts, not millions. Order is the whole game: vendor and installation defaults first, then guesses derived from the SSID, then a small public list fetched over `wlan0` at runtime, then the longer tail. A strong random passphrase will not fall inside the budget. The write-up has to say that plainly. Partial credit is the recon record, the candidate strategy, and proof that `wlan0` never moved, not a fabricated password.
- One attempt at a time, on the virtual interface only. Each candidate is offered to `Vijay` through the second managed interface’s own supplicant. `wlan0`’s supplicant and netplan configuration are not the place those attempts are installed.
- Proof. Success is `SSID:password` together with an address leased on the assessment interface, written to the results directory, with a machine-readable flag that `wlan0` was still associated to `B1-405` at the end. Failure to find the passphrase is still a complete run if the recon, the attempt log, the time accounting, and the `wlan0` health log are all present.
- Restart. If the process is launched again, passwords already tried are skipped and the clock continues from the remaining budget. Repeating the first hour of the list after an SSH blip is a failed use of the time limit.

What you may assume: internet via `wlan0` works at the start, so a public list can be downloaded then; the target uses a passphrase a person or an installer might actually choose; the SSID string itself is fair material for guesses. What you may not assume: that the passphrase is short enough to brute force, that WPS can be switched on, or that you can kick a client and catch a handshake.

## What “done” looks like for the grader

A level is done only when all of the following are true at once.

- The results directory contains the recovered secret in the form the level requires: for `5G_B1`, the WPS enrollment result and the passphrase it produced; for `Vijay`, `Vijay:<password>`.
- The assessment interface has been associated to that SSID and holds an IPv4 address from it. The address is in the proof file, not only implied.
- `wlan0` is still `COMPLETED` on `B1-405` and still has its address. The results record says so, and a live check of `wlan0` agrees.
- The run stayed inside the level’s attempt bound (level 1) or the 2 hour budget (level 2).
- No deauthentication, injection, or monitor mode was used, and no other SSID was attacked.

If level 2’s passphrase is too strong for the attempt budget, the acceptable incomplete result is an honest one: scan record, security fingerprint, how candidates were ordered, how many were tried, and `wlan0` still up. Inventing a password, or borrowing one from a preloaded file, fails the level.

## What makes the shared design forced

One radio, one association, is the default shape of this chip. A password attempt issued on `wlan0` would replace the `B1-405` association and kill SSH and internet in the same moment the interesting work started. That is why both levels have to run on a second managed interface, with a separate supplicant and a separate control socket, while a watchdog treats any `wlan0` transition out of `COMPLETED` as a reason to stop.

That second interface is not a second radio. It is time-sliced on the same PHY. Brief latency on `wlan0` during an association on the second interface can happen. A disconnect cannot. The health log is how you tell those apart.

The same limit explains the split between the levels. Level 1 can finish quickly because enrollment is a handful of attempts against a feature the router is advertising. Level 2 cannot borrow that shortcut, and it cannot borrow an offline cracker, so it spends the two hours on ordered association attempts and must be able to stop with a clear negative result.

## Explicitly out of scope

- Any SSID other than `5G_B1` on level 1 and `Vijay` on level 2, including neighbors visible in the same scan.
- Attacks on WPA3-SAE, enterprise 802.1X, or clients associated to the target. The target is the access point, the method is the one each level allows, and client devices are not in play.
- Deauthentication, broadcast or directed, “to speed up a handshake.” It is disallowed by the radio rule and by the scope rule.
- Persistence on a network after the proof is recorded, scanning of hosts behind the access point, or anything past “we associated and here is the secret.”
- Running this tool outside the course lab. The two SSIDs are authorized fixtures for the sitting. The same commands against any other network are not this assignment.

## Deliverables the problem expects

- A headless entry point that accepts the target SSID and the time budget, brings up the virtual interface without touching netplan, and starts the level that matches that target.
- A runtime candidate builder for level 2, fed by a live fetch plus a small offline fallback, with no secret material stored in the repo or on the Pi before the run.
- A bounded WPS enrollment check for level 1 that stops on success or on lockout signs.
- Proof files: a credentials line, a machine-readable result that includes `wlan0` health, a scan record, and a log of what was tried.
- A short written account of the constraint, which path each level used, what was verified on the Pi, and the honest limit (about a thousand to fifteen hundred level 2 attempts, so a long random PSK survives).

---

## Constraint -> design

Single Broadcom radio, `wlan0` carries SSH + internet. Classic monitor-mode capture would kill `wlan0`, so this tool uses **dual-STA**: `wlan0` (netplan, untouched) + `wlan1` (virtual managed interface, own `wpa_supplicant` + ctrl dir). All recon and assessment runs on `wlan1`; a watchdog aborts if `wlan0` ever leaves `COMPLETED`.

`iw list` confirms `#{managed} <= 2` on this chip, verified live: `iw dev wlan0 interface add wlan1 type managed` keeps `wlan0` COMPLETED.

## Scope / ethics

- Level 1 target is only `5G_B1` (WPS on). Level 2 target is only `Vijay` (WPS off). Plus your own lab.
- Managed-mode only. No deauth, no injection, no monitor mode.
- Level 1 is a short bounded enrollment check and stops on lockout signs.
- Every run logs `wlan0` health to prove non-disruption.

## Files

- `setup_wlan1.sh` - create `wlan1` + isolated supplicant (idempotent, root)
- `candidates.sh` - build wordlist LIVE at runtime (no preload): built-in defaults + SSID mangles + SecLists/top10k over `wlan0` internet, fallback offline. Used by level 2.
- `wps_try.sh`, `wps_try_ext.sh` - level 1 bounded WPS enrollment attempts on `wlan1` against the authorized BSSID. Stops on success or lockout signs.
- `pwn.py` - level 2 orchestrator: wait-for-target -> rank -> serial try-connect on `wlan1` -> DHCP prove -> `results/creds.txt` + `result.json`
- `run.sh` - headless entry for level 2: `sudo ./run.sh --target Vijay --time 100`

## Runbook (level 2 exam window, 2h)

1. Pi already on `B1-405` via `wlan0`. SSH in (or console). Do NOT touch netplan.
2. `cd ~/wifi-penetration-assessment && sudo ./run.sh --target Vijay --time 100`
3. Watch: `tail -f results/console.log`; proof: `cat results/creds.txt results/result.json`
4. `wlan0` stays up the whole time - check: `wpa_cli -i wlan0 status`

Success = `results/creds.txt` contains `Vijay:<password>` and `result.json` records `wlan0_intact=true`.

Level 1 (`5G_B1`) uses the same `wlan1` setup and writes its proof under the WPS results directory. It is not the two-hour passphrase search.

## Limitations

- ~3-7s per WPA try on stock radio => ~1-1.5k tries in 2h. Wins on weak or default passphrases, loses to long random PSKs (documented in the report; recon still counts).
- `wlan1` STA+STA needs same-phy support (present here). STA+AP on the same channel is also possible and is unused.
- Level 1 must stay short. Extended PIN grinding locks WPS on the router and ends the level.

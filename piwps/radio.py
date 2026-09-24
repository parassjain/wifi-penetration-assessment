"""radio.py - all radio side effects live here and nowhere else.

wlan0 is READ-ONLY (status checks). wlan1 is created/managed here.
Nothing in this module may reconfigure wlan0 or netplan.
"""
import subprocess
from . import config


def run(cmd, timeout=15):
    """Run a command. Returns (returncode, combined_output). Never raises."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    except Exception as e:  # e.g. binary missing
        return 127, f"ERROR: {e}"


def wpa_cli(ctrl, iface, *args, timeout=15):
    return run(["wpa_cli", "-p", ctrl, "-i", iface] + list(args), timeout)


def iface_status(iface, ctrl=None):
    """Read-only status snapshot for an interface."""
    if ctrl:
        _, out = wpa_cli(ctrl, iface, "status")
    else:
        _, out = run(["wpa_cli", "-i", iface, "status"], 10)
    d = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return {"ssid": d.get("ssid", "-"), "state": d.get("wpa_state", "?"),
            "ip": d.get("ip_address", "-"), "bssid": d.get("bssid", "-")}


def wlan0_status():
    return iface_status(config.WLAN0_IFACE)


def wlan0_healthy():
    d = wlan0_status()
    return d.get("state") == "COMPLETED" and bool(d.get("ip") and d["ip"] != "-")


def wlan1_present():
    _, out = run(["iw", "dev"], 10)
    return "Interface wlan1" in out


def supplicant_running():
    _, out = run(["pgrep", "-f", "wpa_supplicant.*-iwlan1"], 10)
    return bool(out.strip())


def ensure_wlan1(ctrl=config.CTRL_DIR, log=print):
    """Idempotent: create wlan1 + isolated supplicant. Returns True on ready."""
    if not wlan1_present():
        log("[*] creating wlan1...")
        rc, out = run(["iw", "dev", config.WLAN0_IFACE, "interface", "add",
                       config.IFACE, "type", "managed"], 15)
        if rc != 0:
            log(f"[!] failed to create wlan1: {out.strip()}")
            return False
    run(["ip", "link", "set", config.IFACE, "up"], 10)
    if not supplicant_running():
        log("[*] starting isolated wpa_supplicant on wlan1...")
        conf = "/tmp/pwn-wlan1.conf"
        with open(conf, "w") as f:
            f.write(f"ctrl_interface=DIR={ctrl} GROUP=root\nupdate_config=1\ncountry={config.COUNTRY}\n")
        import os as _os
        _os.chmod(conf, 0o600)
        rc, out = run(["wpa_supplicant", "-B", "-i", config.IFACE,
                       "-c", conf, "-D", "nl80211"], 15)
        if rc != 0:
            log(f"[!] supplicant start failed: {out.strip()}")
            return False
    import time as _t
    _t.sleep(2)
    st = iface_status(config.IFACE, ctrl)
    log(f"[*] wlan1 state={st['state']}")
    return True

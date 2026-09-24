"""scan.py - passive reconnaissance parsing and ranking. No side effects
beyond triggering a scan on the ATTACKER interface (wlan1)."""
import time
from . import config
from .radio import wpa_cli


def parse_scan_results(text):
    """Parse `wpa_cli scan_results` output into a list of network dicts."""
    nets = []
    for line in text.splitlines():
        if line.startswith("bssid") or not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try:
            sig = int(parts[2])
        except (ValueError, TypeError):
            sig = parts[2]
        nets.append({"bssid": parts[0], "freq": parts[1], "signal": sig,
                     "flags": parts[3], "ssid": parts[4]})
    return nets


def scan(iface=config.IFACE, ctrl=config.CTRL_DIR, dwell=config.SCAN_DWELL_S):
    wpa_cli(ctrl, iface, "scan")
    time.sleep(dwell)
    _, out = wpa_cli(ctrl, iface, "scan_results")
    return parse_scan_results(out)


def sec_of(flags):
    f = flags or ""
    if "SAE" in f and "PSK" not in f:
        return "WPA3-SAE"
    if "SAE" in f:
        return "WPA2/WPA3-mixed"
    if "WPA2" in f and "PSK" in f:
        return "WPA2-PSK"
    if "WPA" in f:
        return "WPA-PSK"
    if "WEP" in f:
        return "WEP"
    if "ESS" in f or f in ("", "[ESS]"):
        return "OPEN"
    return f or "UNKNOWN"


def has_wps(flags):
    return "WPS" in (flags or "")


def strongest(nets, ssid):
    """Strongest BSS advertising an SSID, or None."""
    hit = [n for n in nets if n.get("ssid") == ssid]
    if not hit:
        return None
    return sorted(hit, key=lambda n: n["signal"] if isinstance(n.get("signal"), int) else -99,
                  reverse=True)[0]


def rank_key(net):
    """Priority for attack order: OPEN > WEP > WPA+WPS > WPA > WPA3."""
    sec = sec_of(net.get("flags"))
    order = {"OPEN": 0, "WEP": 1, "WPA-PSK": 2, "WPA2-PSK": 2, "WPA2/WPA3-mixed": 3,
             "WPA3-SAE": 4}
    sig = net.get("signal")
    sig = sig if isinstance(sig, int) else -99
    return (order.get(sec, 5), 0 if has_wps(net.get("flags")) else 1, -sig)

"""web/app.py - live dashboard backend (stdlib only). Serves static/index.html
plus JSON APIs. Read-only except /api/rescan and /api/wps-start, which use
the ATTACKER interface only (wlan0 is never touched).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from .. import config
from ..radio import run, iface_status
from ..scan import parse_scan_results, sec_of, has_wps
from ..report import list_sweeps

HERE = os.path.dirname(os.path.abspath(__file__))


def _out_dir():
    return ARGS.dir


def _repo_dir():
    d = os.path.abspath(_out_dir())
    if os.path.basename(d).startswith("results"):
        return os.path.dirname(d)
    return os.getcwd()


SCAN_CACHE = None
scan_lock = threading.Lock()


def _scan_cache():
    return os.path.join(_out_dir(), "live_scan.json")


def do_live_scan():
    with scan_lock:
        run(["wpa_cli", "-p", config.CTRL_DIR, "-i", config.IFACE, "scan"], 10)
        time.sleep(config.SCAN_DWELL_S)
        _, out = run(["wpa_cli", "-p", config.CTRL_DIR, "-i", config.IFACE, "scan_results"], 15)
        data = {"at": time.time(), "at_iso": time.strftime("%H:%M:%S"),
                "nets": parse_scan_results(out)}
        try:
            with open(_scan_cache(), "w") as f:
                json.dump(data, f)
        except Exception:
            pass
        return data


def get_live_scan():
    try:
        with open(_scan_cache()) as f:
            return json.load(f)
    except Exception:
        return {"at": 0, "at_iso": "-", "nets": []}


def tail(path, n=15):
    try:
        with open(path, errors="ignore") as f:
            return f.read().splitlines()[-n:]
    except Exception:
        return []


def build_status():
    out = _out_dir()
    lines = tail(os.path.join(out, "console.log"), 400)
    tried = total = 0
    current, started, first_try_t = "-", None, None
    for ln in lines:
        m = re.search(r"\[(\d+)/(\d+)\] try '(.*)': ok=(\S+)", ln)
        if m:
            tried, total, current = int(m.group(1)), int(m.group(2)), m.group(3)
            if first_try_t is None:
                tm = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", ln)
                if tm:
                    first_try_t = tm.group(1)
        m2 = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) \[\*] wlan0 healthy", ln)
        if m2 and started is None:
            started = m2.group(1)
    rate = eta = None
    if tried > 2:
        try:
            from datetime import datetime
            t0 = datetime.fromisoformat(first_try_t or started)
            el = (datetime.now() - t0).total_seconds()
            rate = tried / max(el, 1)
            if rate > 0 and total:
                eta = (total - tried) / rate
        except Exception:
            pass
    result, creds = {}, None
    for name in ("result.json", "creds.txt"):
        try:
            with open(os.path.join(out, name)) as f:
                if name.endswith(".json"):
                    result.update(json.load(f))
                else:
                    creds = f.read().strip()
        except Exception:
            pass
    live_run = {}
    try:
        with open(os.path.join(out, "status.json")) as f:
            live_run = json.load(f)
    except Exception:
        pass
    if live_run:
        tried = live_run.get("tried", tried)
        total = live_run.get("total", total)
        current = live_run.get("current", current)
    status_age = int(time.time() - live_run["updated_epoch"]) if live_run.get("updated_epoch") else None
    svc = {}
    for unit in ("pi-pwn", "pi-dash"):
        _, svc_out = run(["systemctl", "is-active", unit], 5)
        line = svc_out.strip().splitlines()[0] if svc_out.strip() else "unknown"
        if line.startswith("ERROR") or "No such file" in line:
            line = "unavailable"
        svc[unit] = line
    live = get_live_scan()
    nets = live.get("nets") or []
    if not nets:
        try:
            with open(os.path.join(out, "scan.json")) as f:
                nets = json.load(f).get("nets", [])
        except Exception:
            pass
    for n in nets:
        n["sec"] = sec_of(n.get("flags"))
        n["wps"] = has_wps(n.get("flags"))
    nets = sorted(nets, key=lambda n: n.get("signal", -99)
                  if isinstance(n.get("signal"), int) else -99, reverse=True)
    phase = "hint" if tried <= 730 else "generic"
    pct = round(100.0 * tried / total, 1) if total else 0
    done_flag = bool(result.get("password")) or any("[DONE]" in ln for ln in lines[-3:])
    run_state = ("FINISHED" if done_flag
                 else ("RUNNING" if (status_age is not None and status_age < 300) else "STALLED"))
    return {
        "target": result.get("target") or live_run.get("target"),
        "security": result.get("security"),
        "bssid": result.get("bssid"),
        "wlan0_intact": result.get("wlan0_intact"),
        "results_dir": out,
        "tried": tried, "total": total, "current": current, "phase": phase, "pct": pct,
        "run_state": run_state, "status_age_sec": status_age,
        "budget_left_min": live_run.get("budget_left_min"),
        "rate_per_min": round(rate * 60, 1) if rate else None,
        "eta_min": round(eta / 60, 1) if eta else None,
        "started": live_run.get("started_iso", started),
        "wlan0": iface_status(config.WLAN0_IFACE),
        "wlan1": iface_status(config.IFACE, config.CTRL_DIR),
        "found": result.get("password") or live_run.get("found"),
        "creds": creds, "svc": svc,
        "scan_live": bool(live.get("nets")),
        "scan_age_sec": int(time.time() - live["at"]) if live.get("at") else None,
        "scan_at": live.get("at_iso", "-"),
        "net_count": len(nets), "nets": nets[:30],
        "log_tail": tail(os.path.join(out, "console.log"), 16)
                    or tail(os.path.join(out, "pwn.log"), 16),
        "log_source": "console.log"
                    if tail(os.path.join(out, "console.log"), 1)
                    else ("pwn.log" if tail(os.path.join(out, "pwn.log"), 1) else None),
        "wps": list_sweeps(_repo_dir()),
    }


def _wps_busy():
    for sw in list_sweeps(_repo_dir()):
        if sw["state"] == "RUNNING":
            return sw
    return None


def start_wps_test(bssid, ssid):
    """Launch `python -m piwps wps` detached. One sweep at a time (single radio)."""
    if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid or ""):
        return {"error": "bad BSSID"}
    ssid = (ssid or "").strip()[:32]
    if not ssid:
        return {"error": "empty SSID"}
    busy = _wps_busy()
    if busy:
        return {"error": f"sweep already running: {busy['dir']} ({busy['tried']}/{busy['total']})"}
    st = iface_status(config.IFACE, config.CTRL_DIR)
    if st["state"] == "?":
        return {"error": "wlan1 supplicant down - run setup first"}
    d = "results-wps-" + time.strftime("%m%d-%H%M%S")
    outdir = os.path.join(_repo_dir(), d)
    os.makedirs(outdir, exist_ok=True)
    logf = open(os.path.join(outdir, "launcher.log"), "a")
    try:
        p = subprocess.Popen([sys.executable, "-m", "piwps", "wps",
                              "--bssid", bssid, "--ssid", ssid, "--out", outdir],
                             stdin=subprocess.DEVNULL, stdout=logf, stderr=subprocess.STDOUT,
                             start_new_session=True, cwd=_repo_dir())
    except Exception as e:
        return {"error": str(e)}
    return {"started": d, "pid": p.pid, "bssid": bssid, "ssid": ssid}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        pu = urlparse(self.path)
        if pu.path == "/api/status":
            self._send(json.dumps(build_status()).encode(), "application/json")
        elif pu.path == "/api/rescan":
            self._send(json.dumps(do_live_scan()).encode(), "application/json")
        elif pu.path == "/api/wps-start":
            q = parse_qs(pu.query)
            res = start_wps_test(q.get("bssid", [""])[0], q.get("ssid", [""])[0])
            body = json.dumps(res).encode()
            self.send_response(200 if "started" in res else 409)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            try:
                with open(os.path.join(HERE, "static", "index.html"), "rb") as f:
                    page = f.read()
            except Exception:
                page = b"dashboard static files missing"
            self._send(page, "text/html; charset=utf-8")


def main(argv=None):
    global ARGS
    ap = argparse.ArgumentParser(prog="piwps-dashboard")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--dir", default="./results-b1-48h")
    ARGS = ap.parse_args(argv)
    print(f"dashboard on :{ARGS.port} reading {ARGS.dir}", flush=True)
    HTTPServer(("0.0.0.0", ARGS.port), H).serve_forever()


if __name__ == "__main__":
    main()

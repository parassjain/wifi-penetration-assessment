"""report.py - results, credentials, sweep discovery, audit reports."""
import json
import os
import re
import time


def write_result(outdir, result):
    with open(os.path.join(outdir, "result.json"), "w") as f:
        json.dump(result, f, indent=2)


def write_creds(outdir, target, password):
    with open(os.path.join(outdir, "creds.txt"), "w") as f:
        f.write(f"{target}:{password}\n")


def list_sweeps(repo_dir):
    """Parse every results-*/wps.log into live sweep summaries. Pure file I/O."""
    sweeps = []
    try:
        names = sorted(os.listdir(repo_dir))
    except Exception:
        return sweeps
    for nm in names:
        if not nm.startswith("results-"):
            continue
        log = os.path.join(repo_dir, nm, "wps.log")
        if not os.path.isfile(log):
            continue
        try:
            tried = total = 0
            current = "-"
            with open(log, errors="ignore") as f:
                lines = f.read().splitlines()
            for ln in lines:
                m = re.search(r"(\d+) PINs", ln)
                if m and not total:
                    total = int(m.group(1))
                m2 = re.search(r"trying PIN (\S+)", ln)
                if m2:
                    tried += 1
                    current = m2.group(1).rstrip(" .")
            tail = lines[-4:]
            blob = "\n".join(lines[-5:])
            if "WPS SUCCESS" in blob or os.path.isfile(os.path.join(repo_dir, nm, "creds.txt")):
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
                           "state": state, "age_sec": age, "tail": tail})
        except Exception:
            pass
    return sorted(sweeps, key=lambda s: s["dir"], reverse=True)


def audit_markdown(target, nets, run_info):
    """One-page assessment summary for the midterm submission."""
    lines = [f"# WiFi audit: {target}", ""]
    for n in sorted(nets, key=lambda x: str(x.get("ssid"))):
        flags = n.get("flags", "")
        wps = "WPS-ON " if "WPS" in flags else ""
        lines.append(f"- {n.get('ssid') or '<hidden>'} ({n.get('bssid')}) "
                     f"sig={n.get('signal')} {wps}{flags}")
    lines += ["", "## Run", ""]
    for k in ("tried", "total", "password", "wlan0_intact"):
        lines.append(f"- {k}: {run_info.get(k)}")
    lines += ["",
              "## Remediation",
              "- Use WPA2-AES or WPA3, disable TKIP and WPS, 12+ char random PSK.",
              "- Change ISP default SSIDs/passwords; enable PMF where supported."]
    return "\n".join(lines) + "\n"

"""state.py - reboot-safe run state. All resume logic lives here.

- done.log   : one tried password per line (append-only)
- run.json   : first_start + total budget shared across restarts/reboots
- status.json: live per-try progress for the dashboard
"""
import json
import os
import time
import datetime


class DoneLog:
    def __init__(self, path):
        self.path = path

    def load(self):
        try:
            with open(self.path, errors="ignore") as f:
                return {ln.rstrip("\n") for ln in f if ln.rstrip("\n")}
        except FileNotFoundError:
            return set()

    def append(self, password):
        with open(self.path, "a", buffering=1) as f:
            f.write(password + "\n")


class RunBudget:
    def __init__(self, path, budget_min, target="", words=""):
        self.path = path
        try:
            with open(path) as f:
                self.run = json.load(f)
        except Exception:
            self.run = {}
        if "first_start" not in self.run:
            self.run = {"budget_min": budget_min, "first_start": time.time(),
                        "target": target, "words": words}
            with open(path, "w") as f:
                json.dump(self.run, f)

    def left_seconds(self):
        return self.run["budget_min"] * 60 - (time.time() - self.run["first_start"])

    def started_iso(self):
        return datetime.datetime.fromtimestamp(self.run["first_start"]).isoformat(timespec="seconds")


class StatusWriter:
    def __init__(self, path):
        self.path = path

    def write(self, **fields):
        fields["updated_epoch"] = time.time()
        try:
            with open(self.path, "w") as f:
                json.dump(fields, f)
        except Exception:
            pass


def filter_done(candidates, done):
    return [w for w in candidates if w not in done]


def migrate_old_run(outdir, words_path, budget_min):
    """Convert a pre-resume run (console.log with [N/total]) into done.log+run.json."""
    import re
    log = os.path.join(outdir, "console.log")
    last, first_ts = 0, None
    with open(log, errors="ignore") as f:
        for ln in f:
            m = re.search(r"\[(\d+)/(\d+)\]", ln)
            if m:
                last = int(m.group(1))
            if first_ts is None:
                m0 = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", ln)
                if m0:
                    first_ts = m0.group(1)
    cands = []
    with open(words_path, errors="ignore") as f:
        for line in f:
            w = line.rstrip("\n").strip()
            if w and not w.startswith("#"):
                cands.append(w)
    with open(os.path.join(outdir, "done.log"), "w") as f:
        if last:
            f.write("\n".join(cands[:last]) + "\n")
    first = (datetime.datetime.fromisoformat(first_ts).timestamp()
             if first_ts else time.time())
    run = {"budget_min": budget_min, "first_start": first,
           "migrated_from_old_run": True, "migrated_tried": last}
    with open(os.path.join(outdir, "run.json"), "w") as f:
        json.dump(run, f, indent=2)
    return {"tried": last, "queue": len(cands), "first_start": first_ts}

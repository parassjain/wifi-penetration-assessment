#!/usr/bin/env python3
"""migrate.py - convert an old (non-resumable) run into resume state.
Reads OUT/console.log last [N/total], writes OUT/done.log (first N queue
entries) + OUT/run.json (original first_start preserved for budget).
Usage: python3 migrate.py <outdir> <wordsfile> [budget_min]
"""
import sys, os, re, time, json, datetime

out, words = sys.argv[1], sys.argv[2]
budget = int(sys.argv[3]) if len(sys.argv) > 3 else 2880

last, first_ts = 0, None
with open(os.path.join(out, "console.log"), errors="ignore") as f:
    for ln in f:
        m = re.search(r"\[(\d+)/(\d+)\]", ln)
        if m:
            last = int(m.group(1))
        if first_ts is None:
            m0 = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", ln)
            if m0:
                first_ts = m0.group(1)

cands = []
with open(words, errors="ignore") as f:
    for line in f:
        w = line.rstrip("\n").strip()
        if w and not w.startswith("#"):
            cands.append(w)

with open(os.path.join(out, "done.log"), "w") as f:
    if last:
        f.write("\n".join(cands[:last]) + "\n")

run = {"budget_min": budget,
       "first_start": time.mktime(datetime.datetime.fromisoformat(first_ts).timetuple()) if first_ts else time.time(),
       "target": "2.4G_B1", "words": words,
       "migrated_from_old_run": True, "migrated_tried": last}
with open(os.path.join(out, "run.json"), "w") as f:
    json.dump(run, f, indent=2)
print(f"migrated tried={last} queue={len(cands)} first_start={first_ts}")

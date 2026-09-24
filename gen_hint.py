#!/usr/bin/env python3
"""gen_hint.py - build hint-prioritized candidates FIRST in queue.
Hint: password may contain rifco / aruna / flat nos 101-106, 401-406 / blocks b1, b2...
Usage: python3 gen_hint.py /tmp/pwn-words/00-hint.txt
"""
import sys, itertools

out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/pwn-words/00-hint.txt"

words = ["rifco", "aruna", "Rifco", "Aruna", "RIFCO", "ARUNA"]
flats = [str(n) for n in (101, 102, 103, 104, 105, 106, 401, 402, 403, 404, 405, 406)]
blocks = ["b1", "b2", "b3", "b4", "B1", "B2", "B3", "B4"]
seps = ["", "_", "-", "@", "#"]
tier2_seps = ["_", "-"]

ordered = []
def add(c):
    if 8 <= len(c) <= 63 and c not in seen:
        seen.add(c); ordered.append(c)
seen = set()

# Tier 1: word+flat, flat+word (most likely router-owner style)
for w, f in itertools.product(words, flats):
    add(f"{w}{f}"); add(f"{f}{w}")
# Tier 2: with separators (most common two only - keeps list fittable in 2h)
for w, f, s in itertools.product(words, flats, tier2_seps):
    add(f"{w}{s}{f}"); add(f"{f}{s}{w}")
# Tier 3: block involved (trimmed to most likely patterns)
for b, w, f in itertools.product(blocks, words[:2], flats):
    add(f"{b}{w}{f}")
for b, f in itertools.product(blocks, flats):
    add(f"{b}{f}")
# Tier 4: bare words + common suffixes
for w in words:
    for s in ["123", "1234", "@123", "#123", "2024", "2025", "007", "01"]:
        add(f"{w}{s}")
    add(w) if len(w) >= 8 else None
# Tier 5: cross with site name
for w in ["Actyoga", "actyoga", "Vijay", "vijay"]:
    for h in ["rifco", "aruna", "Rifco", "Aruna"]:
        add(f"{w}{h}"); add(f"{h}{w}"); add(f"{w}_{h}"); add(f"{w}123{h}")

with open(out, "w") as f:
    f.write("\n".join(ordered) + "\n")
print(f"hint candidates: {len(ordered)} -> {out}")

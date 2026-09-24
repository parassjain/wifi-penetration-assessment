"""Unit tests - pure logic only. No radio, no network, no root required.
Run: python -m pytest   (or: python3 -m pytest)
"""
import json
import os

from piwps.attacks import wps
from piwps.attacks.psk import quote, key_mgmt_for
from piwps.scan import parse_scan_results, sec_of, has_wps, strongest, rank_key
from piwps import wordlists
from piwps.state import filter_done, DoneLog, RunBudget, StatusWriter
from piwps.report import list_sweeps, audit_markdown


def test_wps_checksum_known_good():
    assert wps.valid_pin("12345670")
    assert wps.valid_pin("00000000")


def test_wps_checksum_known_bad():
    # these look plausible but fail the checksum - the round-3 silent-skip bug
    assert not wps.valid_pin("11111111")
    assert not wps.valid_pin("87654321")
    assert not wps.valid_pin("20080843")
    assert not wps.valid_pin("abcdef12")
    assert not wps.valid_pin("1234567")


def test_all_pin_profiles_valid():
    for name, pins in wps.PROFILES.items():
        bad = [p for p in pins if not wps.valid_pin(p)]
        assert not bad, f"profile {name} has invalid PINs: {bad}"


def test_sec_of():
    assert sec_of("[WPA2-PSK-CCMP][ESS]") == "WPA2-PSK"
    assert sec_of("[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][WPS][ESS]") == "WPA2-PSK"
    assert sec_of("[SAE][ESS]") == "WPA3-SAE"
    assert sec_of("[ESS]") == "OPEN"
    assert sec_of("[WEP][ESS]") == "WEP"
    assert has_wps("[WPA2-PSK-CCMP][WPS][ESS]")
    assert not has_wps("[WPA2-PSK-CCMP][ESS]")


def test_parse_scan_results():
    sample = ("bssid / frequency / signal level / flags / ssid\n"
              "b0:95:75:88:fa:9d\t2412\t-53\t[WPA2-PSK-CCMP][ESS]\tActyoga\n"
              "b4:86:18:86:cc:b3\t2452\t-52\t[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][WPS][ESS]\t2.4G_B1\n"
              "12:36:23:dc:33:19\t2462\t-38\t[ESS][UTF-8]\tFree Wifi\n")
    nets = parse_scan_results(sample)
    assert len(nets) == 3
    assert nets[0]["ssid"] == "Actyoga" and nets[0]["signal"] == -53
    assert has_wps(nets[1]["flags"])
    assert sec_of(nets[2]["flags"]) == "OPEN"


def test_strongest_and_rank():
    nets = [{"ssid": "X", "signal": -80, "flags": "[WPA2-PSK-CCMP][ESS]", "bssid": "a"},
            {"ssid": "X", "signal": -50, "flags": "[WPA2-PSK-CCMP][ESS]", "bssid": "b"}]
    assert strongest(nets, "X")["bssid"] == "b"
    assert strongest(nets, "Nope") is None
    open_net = {"ssid": "O", "signal": -90, "flags": "[ESS]"}
    wpa_net = {"ssid": "W", "signal": -40, "flags": "[WPA2-PSK-CCMP][ESS]"}
    assert rank_key(open_net) < rank_key(wpa_net)


def test_quote_escaping():
    assert quote('a"b\\c') == '"a\\"b\\\\c"'


def test_key_mgmt_for():
    assert key_mgmt_for("[SAE][ESS]") == "SAE"
    assert key_mgmt_for("[WPA2-PSK-CCMP][ESS]") == "WPA-PSK"


def test_hint_list_shape():
    h = wordlists.hint_candidates()
    assert len(h) == 730
    assert h[0] == "rifco101"
    assert all(8 <= len(w) <= 63 for w in h)
    assert len(set(h)) == len(h)


def test_mangle_b1_shape():
    m = wordlists.mangle()
    assert len(m) == 279
    assert "2.4G_B1123" in m


def test_merge_order_dedupe_lengths():
    merged = wordlists.merge(["short", "rifco101", "rifco101"], ["rifco101", "longenough123"])
    assert merged == ["rifco101", "longenough123"]


def test_filter_done():
    assert filter_done(["a", "b", "c"], {"a", "c"}) == ["b"]


def test_state_roundtrip(tmp_path):
    done = DoneLog(str(tmp_path / "done.log"))
    assert done.load() == set()
    done.append("pw1")
    done.append("pw2")
    assert done.load() == {"pw1", "pw2"}
    rb = RunBudget(str(tmp_path / "run.json"), 60, "T", "w")
    assert rb.left_seconds() > 50
    rb2 = RunBudget(str(tmp_path / "run.json"), 9999, "T", "w")
    assert rb2.run["budget_min"] == 60  # first start preserved, not overwritten
    sw = StatusWriter(str(tmp_path / "status.json"))
    sw.write(tried=3, total=10)
    assert json.load(open(tmp_path / "status.json"))["tried"] == 3


def test_list_sweeps(tmp_path):
    d = tmp_path / "results-x"
    d.mkdir()
    (d / "wps.log").write_text("[*] WPS sweep round 9 vs S (b), 2 PINs\n[*] trying PIN 12345670 ...\n")
    sw = list_sweeps(str(tmp_path))
    assert len(sw) == 1 and sw[0]["tried"] == 1 and sw[0]["total"] == 2
    assert sw[0]["state"] in ("RUNNING", "STALLED")


def test_audit_markdown():
    nets = [{"ssid": "Actyoga", "bssid": "b", "signal": -53, "flags": "[WPA2-PSK-CCMP][ESS]"}]
    md = audit_markdown("Actyoga", nets, {"tried": 5, "total": 10, "password": None, "wlan0_intact": True})
    assert "Actyoga" in md and "Remediation" in md

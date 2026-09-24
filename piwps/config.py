"""config.py - single source of truth. Env vars override defaults."""
import os

WLAN0_IFACE = os.environ.get("PIWPS_WLAN0", "wlan0")
IFACE = os.environ.get("PIWPS_IFACE", "wlan1")
CTRL_DIR = os.environ.get("PIWPS_CTRL", "/run/wpa_supplicant_pwn")
COUNTRY = os.environ.get("PIWPS_COUNTRY", "IN")

SCAN_DWELL_S = int(os.environ.get("PIWPS_SCAN_DWELL", "8"))
TRY_WAIT_S = float(os.environ.get("PIWPS_TRY_WAIT", "10"))
WPS_WAIT_S = int(os.environ.get("PIWPS_WPS_WAIT", "25"))
WPS_MAX_IGNORED = int(os.environ.get("PIWPS_WPS_MAX_IGNORED", "3"))
DHCP_TIMEOUT_S = int(os.environ.get("PIWPS_DHCP_TIMEOUT", "8"))

MIN_PSK_LEN = 8
MAX_PSK_LEN = 63

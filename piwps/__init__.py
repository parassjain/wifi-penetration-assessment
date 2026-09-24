"""piwps - dual-STA WiFi penetration assessment for Raspberry Pi.

wlan0 (management/SSH) is never touched; all attacks run on a virtual
wlan1 station with its own wpa_supplicant instance.
"""
__version__ = "0.2.0"

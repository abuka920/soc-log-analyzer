"""Offline IP geolocation for the impossible-travel detector.

The demo uses a small built-in table so the project runs with no API keys and
no internet. In production you would swap `lookup()` for a real database such
as MaxMind GeoLite2 (`geoip2` package) without changing the detector.
"""

import ipaddress
import math
from dataclasses import dataclass

# Fastest realistic travel: a commercial flight, plus some slack.
MAX_TRAVEL_SPEED_KMH = 900.0


@dataclass(frozen=True)
class GeoInfo:
    ip: str
    city: str
    country: str
    lat: float | None = None
    lon: float | None = None

    @property
    def known(self) -> bool:
        return self.lat is not None and self.lon is not None


# Demo geolocation table (prefix -> city, country, lat, lon).
# Locations are assigned for the synthetic scenario in sample_logs/.
_GEO_TABLE: dict[str, tuple[str, str, float, float]] = {
    "142.250.80.": ("Toronto", "Canada", 43.6532, -79.3832),
    "24.114.": ("Hamilton", "Canada", 43.2557, -79.8711),
    "99.230.": ("Ottawa", "Canada", 45.4215, -75.6972),
    "95.108.": ("Moscow", "Russia", 55.7558, 37.6173),
    "185.220.101.": ("Frankfurt", "Germany", 50.1109, 8.6821),
    "45.142.212.": ("Amsterdam", "Netherlands", 52.3676, 4.9041),
    "178.248.232.": ("Kyiv", "Ukraine", 50.4501, 30.5234),
    "103.21.244.": ("Singapore", "Singapore", 1.3521, 103.8198),
    "41.58.": ("Lagos", "Nigeria", 6.5244, 3.3792),
    "8.8.8.": ("Mountain View", "United States", 37.3861, -122.0839),
}


def lookup(ip: str) -> GeoInfo:
    """Return the location for an IP. Private ranges come back as country 'Private'."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return GeoInfo(ip=ip, city="Unknown", country="Unknown")

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return GeoInfo(ip=ip, city="Internal", country="Private")

    for prefix, (city, country, lat, lon) in _GEO_TABLE.items():
        if ip.startswith(prefix):
            return GeoInfo(ip=ip, city=city, country=country, lat=lat, lon=lon)

    return GeoInfo(ip=ip, city="Unknown", country="Unknown")


def distance_km(a: GeoInfo, b: GeoInfo) -> float:
    """Great-circle distance between two locations (haversine formula)."""
    r = 6371.0
    lat1, lon1, lat2, lon2 = map(math.radians, (a.lat, a.lon, b.lat, b.lon))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def travel_possible(a: GeoInfo, b: GeoInfo, gap_minutes: float) -> bool:
    """Could a person physically get from a to b in gap_minutes?

    Unknown locations return True: we can't prove travel was impossible,
    and flagging them would flood analysts with false positives.
    """
    if not (a.known and b.known):
        return True
    km = distance_km(a, b)
    if km < 50:  # same metro area
        return True
    hours = max(gap_minutes, 0.0) / 60.0
    return km <= MAX_TRAVEL_SPEED_KMH * hours

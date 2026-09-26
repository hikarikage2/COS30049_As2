"""
features.py
------------
Turns a raw URL string into a small table of numeric features, computed
from the URL text only (no page fetching -> works fully offline).
"""

import re
from urllib.parse import urlparse

import pandas as pd

IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


def _parse(url: str):
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        return urlparse(u)
    except ValueError:
        return urlparse("http://invalid")


def extract_features(url: str) -> dict:
    """One row of features for a single raw URL."""
    try:
        parsed = _parse(url)
        host = parsed.netloc.split(":")[0].split("@")[-1]
        return {
            "url_length": len(url),
            "hostname_length": len(host),
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_digits": sum(c.isdigit() for c in url),
            "has_ip_host": int(bool(IP_RE.match(host))),
            "has_at_symbol": int("@" in url),
        }
    except Exception:
        return {
            "url_length": 0, "hostname_length": 0, "num_dots": 0,
            "num_hyphens": 0, "num_digits": 0, "has_ip_host": 0,
            "has_at_symbol": 0,
        }


def extract_features_df(urls: pd.Series) -> pd.DataFrame:
    """Series of raw URLs -> feature table (one row per URL)."""
    return pd.DataFrame([extract_features(u) for u in urls.astype(str)], index=urls.index)


FEATURE_COLUMNS = list(extract_features("http://example.com").keys())

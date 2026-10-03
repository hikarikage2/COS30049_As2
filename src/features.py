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

BAD_TLDS = {"xyz", "shop", "tk", "ml", "ga", "cf", "gq", "today", "click", "link", "help", "top"} #likely abused tlds in phishing

SUSPICIOUS_WORDS = ( #suspicious words used in phishing urls
    "login", "password", "authenticate", "verify", "validate","confirm", "recover", #logins and account
    "wallet", "payment", "bank", "refund", "gift", "prize", "offer", "reward", #money related
    "apple", "google", "paypal", "microsoft", "amazon", "facebook", "outlook", "icloud", "netflix", "steam", "ebay", "linkedin", #brands
    "update", "upgrade", "security", "support", "helpdesk", #security
)

FEATURE_COLUMNS = [ #feature names in order
    "url_length", "hostname_length",
    "num_dots", "num_hyphens", "num_digits", 
    "num_slashes",
    "has_ip_host", "has_at_symbol",
    "subdomain_count", "bad_tld", "suspicious_words",
]

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
        host = parsed.hostname or "" #hostname is the domain name
        tld = host.split(".")[-1] if host else "" #splits the hostname and takes tld
        return {
            "url_length": len(url), #total characters in url
            "hostname_length": len(host), #characters in the domain name
            "num_dots": url.count("."), #dots in the url
            "num_hyphens": url.count("-"), #hyphens in the url
            "num_digits": sum(c.isdigit() for c in url), #how many digits in the url
            "num_slashes": url.count("/"), #slashes in the url
            "has_ip_host": int(bool(IP_RE.match(host))), #1 if the host is an ip address otherwise 0
            "has_at_symbol": int("@" in url), #1 if the url contains an @ symbol otherwise 0
            "subdomain_count": 0 if (not host or IP_RE.match(host)) else max(host.count(".") - 1, 0), #number of subdomains in the url (0 if no host or host is an ip address)
            "bad_tld": int(tld in BAD_TLDS), #1 if the tld is in the list otherwise 0
            "suspicious_words": int(any(word in url.lower() for word in SUSPICIOUS_WORDS)), #1 if any suspicious word is found otherwise 0
        }
    except Exception:
        return {c: 0 for c in FEATURE_COLUMNS} #return 0 for all features if theres an error


def extract_features_df(urls: pd.Series) -> pd.DataFrame: 
    """Series of raw URLs -> feature table (one row per URL)."""
    rows = [extract_features(u) for u in urls.astype(str)]
    return pd.DataFrame(rows, index=urls.index)[FEATURE_COLUMNS]

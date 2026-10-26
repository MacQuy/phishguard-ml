from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import pandas as pd

FEATURE_NAMES = [
    "url_length", "domain_length", "is_domain_ip", "tld_length",
    "no_of_subdomain", "has_obfuscation", "no_of_obfuscated_char",
    "obfuscation_ratio", "no_of_letters", "letter_ratio", "no_of_digits",
    "digit_ratio", "no_of_equals", "no_of_question_marks", "no_of_ampersands",
    "no_of_other_special_chars", "special_char_ratio", "is_https",
    "path_length", "query_length", "fragment_present", "has_at_symbol",
    "hyphen_count", "dot_count", "slash_count", "percent_count", "has_punycode",
]
_OBFUSCATED = re.compile(r"(?:%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;)")

def _normalise_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL must not be empty")
    if len(value) > 4096:
        raise ValueError("URL is too long (maximum 4096 characters)")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("URL contains control characters")
    candidate = value if "://" in value else f"http://{value}"
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported")
    if not parsed.hostname:
        raise ValueError("URL must contain a valid hostname")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    return candidate

def extract_url_features(value: str) -> dict[str, float]:
    raw = _normalise_url(value)
    parsed = urlsplit(raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = 1
    except ValueError:
        is_ip = 0
    labels = [part for part in host.split(".") if part]
    tld = labels[-1] if labels else ""
    letters = sum(ch.isalpha() for ch in raw)
    digits = sum(ch.isdigit() for ch in raw)
    specials = sum(not ch.isalnum() for ch in raw)
    obfuscated = len(_OBFUSCATED.findall(raw))
    return {
        "url_length": float(len(raw)),
        "domain_length": float(len(host)),
        "is_domain_ip": float(is_ip),
        "tld_length": float(len(tld)),
        "no_of_subdomain": float(max(0, len(labels) - 2)),
        "has_obfuscation": float(obfuscated > 0),
        "no_of_obfuscated_char": float(obfuscated),
        "obfuscation_ratio": float(obfuscated / max(1, len(raw))),
        "no_of_letters": float(letters),
        "letter_ratio": float(letters / max(1, len(raw))),
        "no_of_digits": float(digits),
        "digit_ratio": float(digits / max(1, len(raw))),
        "no_of_equals": float(raw.count("=")),
        "no_of_question_marks": float(raw.count("?")),
        "no_of_ampersands": float(raw.count("&")),
        "no_of_other_special_chars": float(sum(raw.count(ch) for ch in "@!$^*()[]{};,'\"<>\\")),
        "special_char_ratio": float(specials / max(1, len(raw))),
        "is_https": float(parsed.scheme.lower() == "https"),
        "path_length": float(len(parsed.path)),
        "query_length": float(len(parsed.query)),
        "fragment_present": float(bool(parsed.fragment)),
        "has_at_symbol": float("@" in raw),
        "hyphen_count": float(raw.count("-")),
        "dot_count": float(host.count(".")),
        "slash_count": float(raw.count("/")),
        "percent_count": float(raw.count("%")),
        "has_punycode": float("xn--" in host),
    }

def features_frame(urls: list[str]) -> pd.DataFrame:
    rows = [extract_url_features(url) for url in urls]
    return pd.DataFrame(rows, columns=FEATURE_NAMES)

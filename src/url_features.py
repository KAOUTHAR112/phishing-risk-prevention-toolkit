"""URL normalization and lexical feature extraction.

The same extractor is used during training and live inference. This avoids the
training-serving mismatch that occurs when a model is trained on HTML, WHOIS,
or search-engine features that are unavailable to a URL-only scanner.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import unquote, urlparse

from .config import (
    ACTION_WORDS,
    BRAND_OFFICIAL_DOMAINS,
    KNOWN_BRANDS,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_ALLOWED_SCHEMES = {"http", "https"}


def normalize_url(url: str | None) -> str:
    """Trim a URL and add ``http://`` when no scheme is supplied."""
    value = (url or "").strip()
    if not value:
        return ""
    if "://" not in value:
        return f"http://{value}"
    return value


def domain_matches(hostname: str, official_domain: str) -> bool:
    """Return True for an exact official domain or one of its subdomains."""
    host = (hostname or "").lower().rstrip(".")
    official = official_domain.lower().rstrip(".")
    return host == official or host.endswith(f".{official}")


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253 or " " in hostname:
        return False
    if _is_ip(hostname):
        return True
    labels = hostname.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    label_pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    return all(label_pattern.fullmatch(label) for label in labels)


def is_valid_url(url: str) -> bool:
    """Validate URL structure without making a network request."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        # Accessing ``port`` validates malformed port values.
        _ = parsed.port
    except ValueError:
        return False
    return parsed.scheme.lower() in _ALLOWED_SCHEMES and _is_valid_hostname(hostname)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _token_stats(text: str) -> tuple[int, int, float]:
    tokens = _TOKEN_RE.findall(text)
    if not tokens:
        return 0, 0, 0.0
    lengths = [len(token) for token in tokens]
    return min(lengths), max(lengths), sum(lengths) / len(lengths)


def _subdomain_count(hostname: str) -> int:
    if _is_ip(hostname):
        return 0
    labels = [label for label in hostname.split(".") if label]
    # Public-suffix parsing is deliberately not required, keeping the scanner
    # offline and reproducible. This is a lexical approximation.
    return max(0, len(labels) - 2)


def _brand_hits(text: str) -> list[str]:
    lowered = text.lower()
    return [brand for brand in KNOWN_BRANDS if brand in lowered]


def _non_official_brand_hits(hostname: str, full_url: str) -> list[str]:
    hits = _brand_hits(full_url)
    return [
        brand
        for brand in hits
        if not any(domain_matches(hostname, domain) for domain in BRAND_OFFICIAL_DOMAINS.get(brand, ()))
    ]


def official_brand_domains(hostname: str) -> list[str]:
    """Return brand names whose curated official domain matches the hostname."""
    return [
        brand
        for brand, domains in BRAND_OFFICIAL_DOMAINS.items()
        if any(domain_matches(hostname, domain) for domain in domains)
    ]


def extract_url_features(url: str | None) -> dict[str, Any]:
    """Extract live metadata and numeric lexical features from a URL."""
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    decoded = unquote(normalized)
    lowered = normalized.lower()

    try:
        explicit_port = int(parsed.port is not None)
    except ValueError:
        explicit_port = 1

    url_len = len(normalized)
    host_len = len(hostname)
    digit_count_url = sum(char.isdigit() for char in normalized)
    digit_count_host = sum(char.isdigit() for char in hostname)
    letter_count = sum(char.isalpha() for char in normalized)
    non_alnum_count = sum(not char.isalnum() for char in normalized)
    shortest, longest, avg_token = _token_stats(decoded)
    path_shortest, path_longest, path_avg = _token_stats(path)
    action_hits = [word for word in ACTION_WORDS if word in lowered]
    brand_hits = _brand_hits(normalized)
    non_official_brand_hits = _non_official_brand_hits(hostname, normalized)
    official_brands = official_brand_domains(hostname)

    path_lower = path.lower()
    suspicious_extension = int(any(path_lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS))
    suspicious_tld = int(any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS))
    is_shortened = int(any(domain_matches(hostname, shortener) for shortener in URL_SHORTENERS))

    numeric = {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "dot_count": normalized.count("."),
        "hostname_dot_count": hostname.count("."),
        "hyphen_count": normalized.count("-"),
        "hostname_hyphen_count": hostname.count("-"),
        "underscore_count": normalized.count("_"),
        "slash_count": normalized.count("/"),
        "question_count": normalized.count("?"),
        "ampersand_count": normalized.count("&"),
        "equals_count": normalized.count("="),
        "percent_count": normalized.count("%"),
        "at_count": normalized.count("@"),
        "colon_count": normalized.count(":"),
        "semicolon_count": normalized.count(";"),
        "comma_count": normalized.count(","),
        "digit_count_url": digit_count_url,
        "digit_count_host": digit_count_host,
        "letter_count_url": letter_count,
        "non_alnum_count": non_alnum_count,
        "digit_ratio_url": digit_count_url / max(url_len, 1),
        "digit_ratio_host": digit_count_host / max(host_len, 1),
        "non_alnum_ratio": non_alnum_count / max(url_len, 1),
        "url_entropy": _entropy(normalized),
        "hostname_entropy": _entropy(hostname),
        "subdomain_count": _subdomain_count(hostname),
        "path_depth": len([part for part in path.split("/") if part]),
        "query_parameter_count": len([part for part in query.split("&") if part]),
        "shortest_token_length": shortest,
        "longest_token_length": longest,
        "average_token_length": avg_token,
        "shortest_path_token_length": path_shortest,
        "longest_path_token_length": path_longest,
        "average_path_token_length": path_avg,
        "uses_ip": int(_is_ip(hostname)),
        "is_https": int(parsed.scheme.lower() == "https"),
        "has_explicit_port": explicit_port,
        "has_userinfo": int(parsed.username is not None or parsed.password is not None),
        "has_punycode": int("xn--" in hostname),
        "uses_shortener": is_shortened,
        "suspicious_tld": suspicious_tld,
        "suspicious_extension": suspicious_extension,
        "double_slash_in_path": int("//" in path),
        "http_token_in_path": int("http" in path_lower),
        "https_token_on_http": int(parsed.scheme.lower() == "http" and "https" in path_lower),
        "www_count": lowered.count("www"),
        "com_count": lowered.count(".com"),
        "action_keyword_count": len(action_hits),
        "brand_keyword_count": len(brand_hits),
        "non_official_brand_count": len(non_official_brand_hits),
        "encoded_character_count": len(re.findall(r"%[0-9A-Fa-f]{2}", normalized)),
    }

    return {
        "normalized_url": normalized,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "path": path,
        "query": query,
        "valid": is_valid_url(normalized),
        "action_hits": action_hits,
        "brand_hits": brand_hits,
        "non_official_brand_hits": non_official_brand_hits,
        "official_domain": bool(official_brands),
        "official_brands": official_brands,
        "numeric": numeric,
    }


def numeric_feature_names() -> list[str]:
    """Return the deterministic model feature order."""
    return list(extract_url_features("https://example.com/path?x=1")["numeric"].keys())

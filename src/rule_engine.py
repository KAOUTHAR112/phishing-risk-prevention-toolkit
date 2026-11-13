"""Explainable phishing rules operating only on URL-level evidence."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from typing import Any

from .config import BRAND_OFFICIAL_DOMAINS, KNOWN_BRANDS
from .url_features import domain_matches


@dataclass(frozen=True)
class Indicator:
    key: str
    severity: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _lookalike_brand(hostname: str) -> tuple[str, float] | None:
    compact = hostname.replace(".", "").replace("-", "").replace("_", "")
    for brand in KNOWN_BRANDS:
        if brand in hostname:
            continue
        similarity = SequenceMatcher(None, compact, brand).ratio()
        if 0.72 <= similarity < 1.0:
            return brand, similarity
    return None


def _is_official_for_brand(hostname: str, brand: str) -> bool:
    return any(domain_matches(hostname, domain) for domain in BRAND_OFFICIAL_DOMAINS.get(brand, ()))


def evaluate_rules(features: dict[str, Any]) -> dict[str, Any]:
    """Return a capped score and human-readable indicators."""
    if not features.get("valid"):
        return {
            "score": 0,
            "level": "Unknown",
            "indicators": [Indicator("invalid_url", 0, "The URL format is invalid.").to_dict()],
        }

    n = features["numeric"]
    hostname = features["hostname"]
    indicators: list[Indicator] = []

    def add(key: str, severity: int, message: str) -> None:
        indicators.append(Indicator(key, severity, message))

    if not n["is_https"]:
        add("missing_https", 10, "The URL uses HTTP instead of HTTPS.")
    if n["uses_ip"]:
        add("ip_address", 25, "The host is an IP address instead of a readable domain name.")
    if n["has_userinfo"] or n["at_count"]:
        add("userinfo", 25, "The URL contains user-information or an @ symbol that may hide the real destination.")
    if n["uses_shortener"]:
        add("shortened_url", 20, "A URL-shortening service hides the final destination.")
    if n["has_punycode"]:
        add("punycode", 25, "Punycode was detected; this can be used for visual domain impersonation.")
    if n["suspicious_tld"]:
        add("suspicious_tld", 15, "The domain uses a TLD frequently abused in phishing campaigns.")
    if n["suspicious_extension"]:
        add("suspicious_extension", 20, "The path ends with a potentially dangerous downloadable-file extension.")
    if n["url_length"] > 120:
        add("very_long_url", 15, f"The URL is unusually long ({n['url_length']} characters).")
    elif n["url_length"] > 75:
        add("long_url", 8, f"The URL is long ({n['url_length']} characters).")
    if n["hostname_length"] > 45:
        add("long_hostname", 10, f"The hostname is unusually long ({n['hostname_length']} characters).")
    if n["subdomain_count"] >= 3:
        add("many_subdomains", 15, f"The hostname contains approximately {n['subdomain_count']} subdomains.")
    if n["hostname_hyphen_count"] >= 2:
        add("many_hyphens", 12, "The hostname contains several hyphens, a common deceptive-domain pattern.")
    elif n["hostname_hyphen_count"] == 1:
        add("hyphen_hostname", 5, "The hostname contains a hyphen.")
    if n["encoded_character_count"] >= 3:
        add("heavy_encoding", 10, "The URL contains several percent-encoded characters.")
    if n["https_token_on_http"]:
        add("misleading_https_token", 20, "The URL uses HTTP while placing the word 'https' inside the path.")
    if features["action_hits"]:
        add("action_keywords", 12, f"Sensitive action terms were detected: {', '.join(features['action_hits'])}.")

    non_official = features["non_official_brand_hits"]
    if non_official:
        add(
            "brand_impersonation",
            25,
            f"Known brand terms appear outside official domains: {', '.join(non_official)}.",
        )
        if features["action_hits"]:
            add("brand_action_combination", 20, "Brand and account-action terms appear together.")

    # Lookalike analysis is skipped when the hostname is already an official domain
    # for any brand detected in the URL.
    official_brand = any(_is_official_for_brand(hostname, brand) for brand in features["brand_hits"])
    if not official_brand:
        lookalike = _lookalike_brand(hostname)
        if lookalike:
            brand, similarity = lookalike
            add("lookalike_domain", 18, f"The hostname resembles '{brand}' ({similarity:.0%} lexical similarity).")

    score = min(sum(item.severity for item in indicators), 100)
    level = "High" if score >= 70 else "Medium" if score >= 40 else "Low"
    return {"score": score, "level": level, "indicators": [item.to_dict() for item in indicators]}

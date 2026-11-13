"""Threat labels, CIA impact, recommendations, and response checklists."""

from __future__ import annotations

from typing import Any


def classify_attack_types(indicators: list[dict[str, Any]]) -> list[str]:
    keys = {item["key"] for item in indicators}
    attacks: list[str] = []
    if keys & {"brand_impersonation", "lookalike_domain", "brand_action_combination"}:
        attacks.append("Brand Impersonation")
    if keys & {"action_keywords", "brand_action_combination"}:
        attacks.append("Credential Phishing")
    if "shortened_url" in keys:
        attacks.append("Shortened URL Abuse")
    if keys & {"ip_address", "punycode", "userinfo", "heavy_encoding"}:
        attacks.append("URL Obfuscation")
    if keys & {"many_subdomains", "many_hyphens", "hyphen_hostname", "long_hostname"}:
        attacks.append("Deceptive Domain Structure")
    if "suspicious_extension" in keys:
        attacks.append("Malicious Download Risk")
    return attacks or ["No specific attack technique identified"]


def threat_classification(risk_level: str, attack_types: list[str]) -> dict[str, str]:
    if risk_level == "High":
        return {
            "Threat Type": "Probable phishing or malicious URL",
            "Detected Techniques": ", ".join(attack_types),
            "Main Objective": "Credential theft, fraud, malware delivery, or sensitive-data collection",
            "Targeted Assets": "Accounts, passwords, personal information, and financial information",
        }
    if risk_level == "Medium":
        return {
            "Threat Type": "Suspicious URL requiring verification",
            "Detected Techniques": ", ".join(attack_types),
            "Main Objective": "Possible redirection, impersonation, or data collection",
            "Targeted Assets": "User information and browsing session",
        }
    if risk_level == "Low":
        return {
            "Threat Type": "Low apparent URL-level risk",
            "Detected Techniques": ", ".join(attack_types),
            "Main Objective": "Not identified from URL-level evidence",
            "Targeted Assets": "Not identified",
        }
    return {
        "Threat Type": "Unknown",
        "Detected Techniques": "URL could not be analyzed",
        "Main Objective": "Unknown",
        "Targeted Assets": "Unknown",
    }


def cia_impact(risk_level: str) -> dict[str, str]:
    mapping = {
        "High": {
            "Confidentiality": "High — credentials or personal data may be exposed.",
            "Integrity": "Medium to high — compromised accounts or transactions may be altered.",
            "Availability": "Medium — accounts or devices may become unavailable after compromise.",
        },
        "Medium": {
            "Confidentiality": "Medium — data may be exposed if the user interacts with the page.",
            "Integrity": "Low to medium — redirections or deceptive actions may affect user data.",
            "Availability": "Low — no direct disruption is established from the URL alone.",
        },
        "Low": {
            "Confidentiality": "Low apparent impact from URL-level evidence.",
            "Integrity": "Low apparent impact from URL-level evidence.",
            "Availability": "Low apparent impact from URL-level evidence.",
        },
    }
    return mapping.get(risk_level, {key: "Unknown" for key in ("Confidentiality", "Integrity", "Availability")})


def recommendations(indicators: list[dict[str, Any]], risk_level: str) -> list[str]:
    keys = {item["key"] for item in indicators}
    recs: list[str] = []
    if keys & {"brand_impersonation", "lookalike_domain", "brand_action_combination"}:
        recs.append("Open the organization’s official website manually instead of following this link.")
    if keys & {"action_keywords", "brand_action_combination"}:
        recs.append("Do not enter usernames, passwords, payment details, or one-time codes.")
    if "shortened_url" in keys:
        recs.append("Expand the shortened URL using a trusted inspection service before opening it.")
    if "missing_https" in keys:
        recs.append("Do not submit sensitive information over an unencrypted HTTP connection.")
    if keys & {"ip_address", "punycode", "userinfo", "heavy_encoding"}:
        recs.append("Inspect the destination carefully because the address uses an obfuscation signal.")
    if "suspicious_extension" in keys:
        recs.append("Do not download or execute the linked file.")

    if risk_level == "High":
        recs.extend([
            "Close the page and report the URL to the relevant organization or security team.",
            "Change affected passwords immediately if any credentials were submitted.",
            "Enable multi-factor authentication and review recent account activity.",
        ])
    elif risk_level == "Medium":
        recs.extend([
            "Verify the domain through an independent official source before continuing.",
            "Avoid interacting with the page until its legitimacy is confirmed.",
        ])
    elif risk_level == "Low":
        recs.append("Low risk is not a guarantee of safety; continue checking the exact domain and page context.")

    return list(dict.fromkeys(recs))


def incident_response_checklist(risk_level: str) -> list[str]:
    items = [
        "Stop interacting with the suspicious page.",
        "Preserve the URL and relevant screenshots for reporting.",
        "Report the link to the organization or security team when applicable.",
    ]
    if risk_level == "High":
        items.extend([
            "Disconnect the device from sensitive sessions if malware may have been downloaded.",
            "Change affected passwords from a trusted device.",
            "Enable multi-factor authentication.",
            "Review account activity and active sessions.",
            "Contact the bank or service provider if financial information was exposed.",
            "Run an endpoint security scan if a file was opened or downloaded.",
        ])
    elif risk_level == "Medium":
        items.extend([
            "Confirm the domain using an official bookmark or search result.",
            "Avoid reusing the same password across services.",
        ])
    return items

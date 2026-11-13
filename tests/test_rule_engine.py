from src.rule_engine import evaluate_rules
from src.url_features import extract_url_features


def indicator_keys(url: str) -> set[str]:
    result = evaluate_rules(extract_url_features(url))
    return {item["key"] for item in result["indicators"]}


def test_detects_ip_http_and_action_words():
    result = evaluate_rules(extract_url_features("http://192.168.1.10/login/verify/account"))
    keys = {item["key"] for item in result["indicators"]}
    assert {"missing_https", "ip_address", "action_keywords"}.issubset(keys)
    assert result["score"] >= 40


def test_official_github_domain_is_not_brand_impersonation():
    assert "brand_impersonation" not in indicator_keys("https://github.com/login")


def test_fake_paypal_domain_is_brand_impersonation():
    keys = indicator_keys("http://secure-paypal-login-update.example.com/verify")
    assert "brand_impersonation" in keys
    assert "brand_action_combination" in keys

from src.url_features import extract_url_features, normalize_url


def test_normalize_adds_scheme():
    assert normalize_url("example.com/path") == "http://example.com/path"


def test_extracts_known_structure():
    result = extract_url_features("https://login.example.com/a/b?x=1&y=2")
    assert result["valid"] is True
    assert result["hostname"] == "login.example.com"
    assert result["numeric"]["subdomain_count"] == 1
    assert result["numeric"]["path_depth"] == 2
    assert result["numeric"]["query_parameter_count"] == 2
    assert result["numeric"]["is_https"] == 1


def test_rejects_invalid_hostname():
    assert extract_url_features("not a valid url")["valid"] is False

from src.scanner import scan_url


class StubPredictor:
    def __init__(self, probability):
        self.probability = probability

    def predict(self, normalized_url, numeric_features):
        from src.ml_predictor import Prediction
        return Prediction(
            probability=self.probability,
            label="phishing" if self.probability >= 0.5 else "legitimate",
            threshold=0.5,
            model_name="Stub",
        )


def test_invalid_url_returns_unknown():
    result = scan_url("not a valid url", predictor=StubPredictor(0.1))
    assert result["final_decision"]["final_risk_level"] == "Unknown"


def test_obvious_phishing_pattern_is_not_low():
    result = scan_url(
        "http://secure-paypal-login-update.example.com/verify/account",
        predictor=StubPredictor(0.90),
    )
    assert result["final_decision"]["final_risk_level"] == "High"


def test_result_schema():
    result = scan_url("https://www.python.org/", predictor=StubPredictor(0.05))
    assert result["features"]["valid"] is True
    assert set(result) == {
        "features", "rule_analysis", "ml", "final_decision", "attack_types",
        "threat_classification", "cia_impact", "recommendations",
    }

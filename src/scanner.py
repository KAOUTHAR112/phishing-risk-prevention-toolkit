"""End-to-end URL scanning orchestration."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from .config import DECISION_CONFIG_PATH
from .ml_predictor import URLModelPredictor
from .rule_engine import evaluate_rules
from .security_analysis import (
    cia_impact,
    classify_attack_types,
    recommendations,
    threat_classification,
)
from .url_features import extract_url_features

DEFAULT_DECISION_CONFIG = {
    "rule_weight": 0.60,
    "ml_weight": 0.40,
    "suspicious_threshold": 40.0,
    "high_threshold": 70.0,
    "ml_medium_probability": 0.55,
    "ml_high_probability": 0.85,
}


@lru_cache(maxsize=1)
def load_decision_config() -> dict[str, float]:
    config = DEFAULT_DECISION_CONFIG.copy()
    if DECISION_CONFIG_PATH.exists():
        try:
            loaded = json.loads(DECISION_CONFIG_PATH.read_text(encoding="utf-8"))
            for key in config:
                if key in loaded:
                    config[key] = float(loaded[key])
        except (OSError, ValueError, TypeError):
            pass
    return config


def combine_scores(rule_score: float, ml_probability: float | None) -> dict[str, Any]:
    config = load_decision_config()
    if ml_probability is None:
        final_score = float(rule_score)
        mode = "Rule-based fallback"
    else:
        final_score = (
            config["rule_weight"] * float(rule_score)
            + config["ml_weight"] * float(ml_probability) * 100.0
        )
        mode = f"Validated blend: {config['rule_weight']:.0%} rules + {config['ml_weight']:.0%} ML"

    if ml_probability is not None and ml_probability >= config["ml_high_probability"]:
        level = "High"
    elif final_score >= config["high_threshold"]:
        level = "High"
    elif (
        final_score >= config["suspicious_threshold"]
        or (ml_probability is not None and ml_probability >= config["ml_medium_probability"])
    ):
        level = "Medium"
    else:
        level = "Low"

    decision = {
        "High": "Blocked / Dangerous",
        "Medium": "Suspicious / Needs Verification",
        "Low": "Low Apparent Risk / Continue with Caution",
    }[level]
    return {
        "final_score": round(final_score),
        "final_risk_level": level,
        "decision": decision,
        "mode": mode,
    }


def scan_url(url: str, predictor: URLModelPredictor | None = None) -> dict[str, Any]:
    features = extract_url_features(url)
    rules = evaluate_rules(features)

    if not features["valid"]:
        return {
            "features": features,
            "rule_analysis": rules,
            "ml": {"probability": None, "label": None, "threshold": None, "model_name": None, "error": None},
            "final_decision": {"final_score": 0, "final_risk_level": "Unknown", "decision": "Invalid URL", "mode": "N/A"},
            "attack_types": ["Unknown"],
            "threat_classification": threat_classification("Unknown", ["Unknown"]),
            "cia_impact": cia_impact("Unknown"),
            "recommendations": ["Enter a valid HTTP or HTTPS URL containing a real hostname."],
        }

    predictor = predictor or URLModelPredictor()
    prediction = predictor.predict(features["normalized_url"], features["numeric"])
    final_decision = combine_scores(rules["score"], prediction.probability)
    attack_types = classify_attack_types(rules["indicators"])
    final_level = final_decision["final_risk_level"]

    return {
        "features": features,
        "rule_analysis": rules,
        "ml": {
            "probability": prediction.probability,
            "label": prediction.label,
            "threshold": prediction.threshold,
            "model_name": prediction.model_name,
            "error": prediction.error,
        },
        "final_decision": final_decision,
        "attack_types": attack_types,
        "threat_classification": threat_classification(final_level, attack_types),
        "cia_impact": cia_impact(final_level),
        "recommendations": recommendations(rules["indicators"], final_level),
    }

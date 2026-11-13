"""Model loading and URL-only phishing probability prediction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from .config import MODEL_BUNDLE_PATH


@dataclass
class Prediction:
    probability: float | None
    label: str | None
    threshold: float | None
    model_name: str | None
    error: str | None = None


class URLModelPredictor:
    """Load one model bundle and make deterministic predictions."""

    def __init__(self, bundle_path: str | Path = MODEL_BUNDLE_PATH):
        self.bundle_path = Path(bundle_path)
        self.bundle: dict[str, Any] | None = None
        self.load_error: str | None = None
        self._load()

    def _load(self) -> None:
        try:
            self.bundle = joblib.load(self.bundle_path)
            required = {"model", "feature_names", "threshold", "model_name", "input_mode"}
            missing = required.difference(self.bundle)
            if missing:
                raise ValueError(f"Model bundle is missing: {sorted(missing)}")
        except Exception as exc:  # app still works with rules only
            self.bundle = None
            self.load_error = str(exc)

    @property
    def available(self) -> bool:
        return self.bundle is not None

    def predict(self, normalized_url: str, numeric_features: dict[str, float | int]) -> Prediction:
        if not self.bundle:
            return Prediction(None, None, None, None, self.load_error or "Model unavailable")

        try:
            feature_names = list(self.bundle["feature_names"])
            if self.bundle["input_mode"] == "url_text":
                model_input = [normalized_url]
            else:
                model_input = pd.DataFrame(
                    [[numeric_features[name] for name in feature_names]],
                    columns=feature_names,
                )
            probability = float(self.bundle["model"].predict_proba(model_input)[0][1])
            threshold = float(self.bundle["threshold"])
            label = "phishing" if probability >= threshold else "legitimate"
            return Prediction(
                probability=probability,
                label=label,
                threshold=threshold,
                model_name=str(self.bundle["model_name"]),
            )
        except Exception as exc:
            return Prediction(None, None, None, None, str(exc))

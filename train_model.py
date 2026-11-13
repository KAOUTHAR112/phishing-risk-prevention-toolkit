"""Train and evaluate deployment-consistent URL-only phishing models.

The script compares handcrafted lexical models with a character n-gram model.
Every candidate uses only the URL string, so the saved model receives exactly
the same information during training and live scanning.
"""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.config import (
    BLEND_RESULTS_PATH,
    DATASET_PATH,
    DECISION_CONFIG_PATH,
    FEATURE_IMPORTANCE_PATH,
    FIGURES_DIR,
    MODEL_BUNDLE_PATH,
    MODEL_COMPARISON_PATH,
    MODEL_METRICS_PATH,
    MODELS_DIR,
)
from src.rule_engine import evaluate_rules
from src.url_features import extract_url_features, numeric_feature_names

RANDOM_STATE = 42


def build_feature_matrix(urls: pd.Series) -> pd.DataFrame:
    names = numeric_feature_names()
    rows = [extract_url_features(url)["numeric"] for url in urls.astype(str)]
    return pd.DataFrame(rows, columns=names).astype(float)


def choose_threshold(y_true: pd.Series, probabilities: np.ndarray) -> tuple[float, dict[str, float]]:
    rows = []
    for threshold in np.arange(0.20, 0.801, 0.01):
        predicted = (probabilities >= threshold).astype(int)
        rows.append((
            float(threshold),
            f1_score(y_true, predicted, zero_division=0),
            recall_score(y_true, predicted, zero_division=0),
            precision_score(y_true, predicted, zero_division=0),
        ))
    threshold, f1, recall, precision = max(rows, key=lambda row: (row[1], row[2], row[3]))
    return threshold, {"f1": f1, "recall": recall, "precision": precision}


def binary_metrics(y_true: pd.Series, predicted: np.ndarray, probabilities: np.ndarray) -> dict[str, float | int]:
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, predicted),
        "precision": precision_score(y_true, predicted, zero_division=0),
        "recall": recall_score(y_true, predicted, zero_division=0),
        "f1": f1_score(y_true, predicted, zero_division=0),
        "roc_auc": roc_auc_score(y_true, probabilities),
        "average_precision": average_precision_score(y_true, probabilities),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }


def calculate_rule_scores(urls: pd.Series) -> np.ndarray:
    return np.array([
        evaluate_rules(extract_url_features(url))["score"]
        for url in urls.astype(str)
    ], dtype=float)


def choose_blend(y_true: pd.Series, rule_scores: np.ndarray, probabilities: np.ndarray) -> tuple[dict[str, float], pd.DataFrame]:
    rows: list[dict[str, float]] = []
    # Includes the originally proposed 50/50, 60/40, and 70/30 settings,
    # plus ML-heavy alternatives to avoid assuming the best weight in advance.
    for rule_weight in (0.30, 0.40, 0.50, 0.60, 0.70):
        ml_weight = 1.0 - rule_weight
        scores = rule_weight * rule_scores + ml_weight * probabilities * 100.0
        for threshold in np.arange(25.0, 66.0, 1.0):
            predicted = (scores >= threshold).astype(int)
            rows.append({
                "rule_weight": rule_weight,
                "ml_weight": ml_weight,
                "suspicious_threshold": threshold,
                "accuracy": accuracy_score(y_true, predicted),
                "precision": precision_score(y_true, predicted, zero_division=0),
                "recall": recall_score(y_true, predicted, zero_division=0),
                "f1": f1_score(y_true, predicted, zero_division=0),
            })
    results = pd.DataFrame(rows).sort_values(
        ["f1", "recall", "precision", "accuracy"], ascending=False
    ).reset_index(drop=True)
    best = results.iloc[0]
    return {
        "rule_weight": float(best["rule_weight"]),
        "ml_weight": float(best["ml_weight"]),
        "suspicious_threshold": float(best["suspicious_threshold"]),
    }, results


def predict_probabilities(candidate: dict, model: object, indices: np.ndarray, urls: pd.Series, numeric: pd.DataFrame) -> np.ndarray:
    data = urls.iloc[indices] if candidate["input_mode"] == "url_text" else numeric.iloc[indices]
    return model.predict_proba(data)[:, 1]


def model_feature_importance(model: object, input_mode: str, numeric_names: list[str]) -> pd.DataFrame:
    if input_mode == "url_text":
        vectorizer = model.named_steps["tfidf"]
        classifier = model.named_steps["classifier"]
        features = vectorizer.get_feature_names_out()
        coefficients = classifier.coef_[0]
        frame = pd.DataFrame({
            "Feature": features,
            "Importance": np.abs(coefficients),
            "Direction": np.where(coefficients >= 0, "Phishing", "Legitimate"),
            "Coefficient": coefficients,
        })
        return frame.sort_values("Importance", ascending=False)

    estimator = model.named_steps["classifier"] if isinstance(model, Pipeline) else model
    if hasattr(estimator, "feature_importances_"):
        values = np.asarray(estimator.feature_importances_)
    else:
        values = np.abs(np.asarray(estimator.coef_)[0])
    return pd.DataFrame({
        "Feature": numeric_names,
        "Importance": values,
        "Direction": "Magnitude",
        "Coefficient": values,
    }).sort_values("Importance", ascending=False)


def save_figures(y_test, blend_predictions, probabilities, importance):
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay.from_predictions(
        y_test, blend_predictions, display_labels=["Legitimate", "Phishing"], values_format="d", ax=ax
    )
    ax.set_title("Test Confusion Matrix — Validated Hybrid Decision")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "confusion_matrix.png", dpi=180)
    plt.close(fig)

    fpr, tpr, _ = roc_curve(y_test, probabilities)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, label=f"ROC AUC = {roc_auc_score(y_test, probabilities):.3f}")
    ax.plot([0, 1], [0, 1], linestyle="--", label="Random baseline")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("URL-only Model ROC Curve")
    ax.legend()
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "roc_curve.png", dpi=180)
    plt.close(fig)

    precision, recall, _ = precision_recall_curve(y_test, probabilities)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(recall, precision, label=f"AP = {average_precision_score(y_test, probabilities):.3f}")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("URL-only Model Precision–Recall Curve")
    ax.legend()
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "precision_recall_curve.png", dpi=180)
    plt.close(fig)

    top = importance.head(15).sort_values("Importance")
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(top["Feature"].astype(str), top["Importance"])
    ax.set_xlabel("Absolute coefficient / importance")
    ax.set_title("Top Model Features")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "feature_importance.png", dpi=180)
    plt.close(fig)


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(DATASET_PATH, usecols=["url", "status"]).dropna()
    df = df[df["status"].isin(["legitimate", "phishing"])].reset_index(drop=True)
    urls = df["url"].astype(str)
    y = df["status"].map({"legitimate": 0, "phishing": 1}).astype(int)
    numeric = build_feature_matrix(urls)

    indices = np.arange(len(df))
    train_idx, temp_idx = train_test_split(indices, test_size=0.30, random_state=RANDOM_STATE, stratify=y)
    val_idx, test_idx = train_test_split(temp_idx, test_size=0.50, random_state=RANDOM_STATE, stratify=y.iloc[temp_idx])

    candidates = {
        "Character n-gram Logistic Regression": {
            "input_mode": "url_text",
            "model": Pipeline([
                ("tfidf", TfidfVectorizer(
                    analyzer="char", ngram_range=(3, 5), min_df=2,
                    max_features=60000, sublinear_tf=True, lowercase=True,
                )),
                ("classifier", LogisticRegression(
                    max_iter=2500, C=4.0, class_weight="balanced", random_state=RANDOM_STATE,
                )),
            ]),
        },
        "Lexical Logistic Regression": {
            "input_mode": "numeric",
            "model": Pipeline([
                ("scaler", StandardScaler()),
                ("classifier", LogisticRegression(
                    max_iter=3000, class_weight="balanced", random_state=RANDOM_STATE,
                )),
            ]),
        },
        "Lexical Random Forest": {
            "input_mode": "numeric",
            "model": RandomForestClassifier(
                n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
                random_state=RANDOM_STATE, n_jobs=-1,
            ),
        },
        "Lexical Extra Trees": {
            "input_mode": "numeric",
            "model": ExtraTreesClassifier(
                n_estimators=300, min_samples_leaf=2, class_weight="balanced",
                random_state=RANDOM_STATE, n_jobs=-1,
            ),
        },
    }

    comparison_rows = []
    fitted = {}
    thresholds = {}
    for name, candidate in candidates.items():
        model = candidate["model"]
        train_data = urls.iloc[train_idx] if candidate["input_mode"] == "url_text" else numeric.iloc[train_idx]
        model.fit(train_data, y.iloc[train_idx])
        fitted[name] = model
        probabilities = predict_probabilities(candidate, model, val_idx, urls, numeric)
        threshold, selected = choose_threshold(y.iloc[val_idx], probabilities)
        thresholds[name] = threshold
        comparison_rows.append({
            "Model": name,
            "Input Mode": candidate["input_mode"],
            "Validation Threshold": threshold,
            "Validation Accuracy": accuracy_score(y.iloc[val_idx], probabilities >= threshold),
            "Validation Precision": selected["precision"],
            "Validation Recall": selected["recall"],
            "Validation F1": selected["f1"],
            "Validation ROC AUC": roc_auc_score(y.iloc[val_idx], probabilities),
        })

    comparison = pd.DataFrame(comparison_rows).sort_values(
        ["Validation F1", "Validation Recall", "Validation Precision"], ascending=False
    ).reset_index(drop=True)
    comparison.to_csv(MODEL_COMPARISON_PATH, index=False)

    best_name = str(comparison.iloc[0]["Model"])
    best_candidate = candidates[best_name]
    best_model = fitted[best_name]
    probability_threshold = thresholds[best_name]
    val_probabilities = predict_probabilities(best_candidate, best_model, val_idx, urls, numeric)

    val_rule_scores = calculate_rule_scores(urls.iloc[val_idx])
    blend_config, blend_results = choose_blend(y.iloc[val_idx], val_rule_scores, val_probabilities)
    blend_results.to_csv(BLEND_RESULTS_PATH, index=False)

    decision_config = {
        **blend_config,
        "high_threshold": 70.0,
        "ml_medium_probability": float(probability_threshold),
        "ml_high_probability": float(max(0.85, probability_threshold + 0.20)),
        "selection_note": "Weights and suspicious threshold selected on validation F1; high-risk threshold is a conservative policy threshold.",
    }
    DECISION_CONFIG_PATH.write_text(json.dumps(decision_config, indent=2), encoding="utf-8")

    test_probabilities = predict_probabilities(best_candidate, best_model, test_idx, urls, numeric)
    model_predictions = (test_probabilities >= probability_threshold).astype(int)
    model_test_metrics = binary_metrics(y.iloc[test_idx], model_predictions, test_probabilities)

    test_rule_scores = calculate_rule_scores(urls.iloc[test_idx])
    test_blend_scores = (
        decision_config["rule_weight"] * test_rule_scores
        + decision_config["ml_weight"] * test_probabilities * 100.0
    )
    blend_predictions = (test_blend_scores >= decision_config["suspicious_threshold"]).astype(int)
    blend_test_metrics = binary_metrics(y.iloc[test_idx], blend_predictions, test_probabilities)

    importance = model_feature_importance(best_model, best_candidate["input_mode"], list(numeric.columns))
    importance.head(1000).to_csv(FEATURE_IMPORTANCE_PATH, index=False)
    save_figures(y.iloc[test_idx], blend_predictions, test_probabilities, importance)

    metadata = {
        "project_version": "2.0.0",
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_name": best_name,
        "input_mode": best_candidate["input_mode"],
        "feature_names": list(numeric.columns) if best_candidate["input_mode"] == "numeric" else ["character n-grams (3–5)"],
        "threshold": float(probability_threshold),
        "split": {
            "random_state": RANDOM_STATE,
            "train_rows": int(len(train_idx)),
            "validation_rows": int(len(val_idx)),
            "test_rows": int(len(test_idx)),
        },
        "dataset": {
            "rows": int(len(df)),
            "legitimate": int((y == 0).sum()),
            "phishing": int((y == 1).sum()),
        },
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
        },
        "model_test_metrics": model_test_metrics,
        "hybrid_test_metrics": blend_test_metrics,
        "decision_config": decision_config,
    }

    bundle = {
        "model": best_model,
        "feature_names": metadata["feature_names"],
        "threshold": float(probability_threshold),
        "model_name": best_name,
        "input_mode": best_candidate["input_mode"],
        "metadata": metadata,
    }
    joblib.dump(bundle, MODEL_BUNDLE_PATH, compress=3)
    MODEL_METRICS_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("Training completed successfully.")
    print(comparison.to_string(index=False))
    print(f"\nSelected model: {best_name}")
    print(f"Model threshold: {probability_threshold:.2f}")
    print(f"Decision configuration: {decision_config}")
    print(f"Hybrid test metrics: {blend_test_metrics}")


if __name__ == "__main__":
    main()

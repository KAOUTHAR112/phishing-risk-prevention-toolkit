# Technical Documentation

## 1. Objective

The application provides an explainable first-level assessment of phishing risk using only the URL entered by the user. It does not crawl the destination page and is therefore suitable for offline demonstrations, academic evaluation, and safe preliminary triage.

## 2. Design principles

### Deployment consistency

The statistical model receives the same type of information at training and inference time: the raw URL string. This resolves the former mismatch where unavailable page-level and external-service variables were assigned artificial values during deployment.

### Explainability

The ML output is accompanied by explicit lexical indicators such as IP-address hosting, brand terms outside official domains, excessive subdomains, punycode, URL shortening, dangerous extensions, sensitive action terms, and misleading HTTP/HTTPS patterns.

### Reproducible evaluation

The training script uses a fixed random seed and three independent partitions:

- 70% training;
- 15% validation;
- 15% final test.

Model selection, probability threshold selection, and hybrid weight selection occur on validation data. The test partition is evaluated only after configuration is fixed.

## 3. Core modules

### `src/url_features.py`

Responsibilities:

- URL normalization;
- structural validation;
- hostname extraction;
- lexical numeric features;
- brand and action-term detection;
- entropy and token statistics.

The module never makes a network request.

### `src/rule_engine.py`

Produces a rule score from 0 to 100 and an evidence list. Each indicator has:

```text
key + severity + human-readable message
```

The score is capped at 100. The rule engine is also available when the model artifact cannot be loaded.

### `src/ml_predictor.py`

Loads `models/url_model_bundle.joblib`, validates its required metadata, and returns:

- phishing probability;
- model label;
- selected probability threshold;
- model name;
- inference error, when applicable.

### `src/scanner.py`

Coordinates:

```text
feature extraction → rule analysis → ML prediction → score combination → security interpretation
```

The decision configuration is loaded from `models/decision_config.json`.

### `src/security_analysis.py`

Maps technical evidence to:

- probable attack types;
- CIA impact;
- recommendations;
- an incident-response checklist.

### `src/history.py`

Stores local scans in `reports/scan_history.csv`. The file is excluded by `.gitignore` because entered URLs may be sensitive.

## 4. Machine-learning pipeline

### Candidate models

The training script compares:

1. Character n-gram Logistic Regression;
2. Lexical Logistic Regression;
3. Lexical Random Forest;
4. Lexical Extra Trees.

The selected model is the one with the highest validation F1-score, with recall and precision as tie breakers.

### Selected model

The final model uses TF-IDF character n-grams of length 3 to 5 followed by balanced Logistic Regression.

Character n-grams can learn patterns such as:

- deceptive brand fragments;
- unusual path structures;
- suspicious delimiters;
- common phishing tokens;
- lexical combinations not covered by manual rules.

### Threshold selection

The probability threshold is selected from 0.20 to 0.80 on validation F1. The selected threshold is stored in the model bundle.

### Hybrid-weight selection

The following rule weights are evaluated:

```text
30%, 40%, 50%, 60%, 70%
```

The corresponding ML weight is `1 - rule_weight`. This explicitly includes the 50/50, 60/40, and 70/30 configurations. The best validation result was:

```text
Final score = 0.30 × Rule score + 0.70 × ML probability × 100
Suspicious threshold = 37
```

A probability of at least 85% independently forces a High risk level as a conservative security policy.

## 5. Verified test performance

Final hybrid performance on 1,715 untouched test examples:

| Metric | Value |
|---|---:|
| Accuracy | 94.17% |
| Precision | 94.27% |
| Recall | 94.05% |
| F1 | 94.16% |
| ROC AUC | 98.50% |
| Average Precision | 98.62% |

Confusion counts:

```text
TN = 809
FP = 49
FN = 51
TP = 806
```

## 6. Testing strategy

The test suite covers:

- URL normalization;
- structural feature extraction;
- invalid input handling;
- IP-address detection;
- brand-impersonation detection;
- avoidance of an obvious official-domain false positive;
- scanner output schema;
- high-risk phishing behavior;
- model artifact loading and probability output.

Run:

```bash
pytest
```

## 7. Security limitations

The tool cannot confirm that a page is safe because it does not inspect:

- HTML forms;
- JavaScript behavior;
- redirects after connection;
- certificate quality;
- domain registration history;
- malware payloads;
- reputation feeds;
- current threat intelligence.

It should be presented as URL-level decision support, not a replacement for browser protections, email gateways, endpoint security, sandboxing, or professional incident response.

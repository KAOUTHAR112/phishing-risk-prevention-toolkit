# Phishing Risk Prevention Toolkit

An explainable cybersecurity decision-support application that analyzes a URL without opening the website. It combines URL-level rules with a deployment-consistent machine-learning model, then converts the result into a risk level, attack interpretation, CIA impact, recommendations, and an incident-response checklist.

> **Author:** Kaouthar El Attaoui    
> **Institution:** Université Mohammed V de Rabat — Faculté des Sciences de Rabat  
> **Version:** 2.0.0

## Why version 2.0 is technically stronger

The previous implementation trained a model on many HTML, WHOIS, traffic, ranking, and search-engine variables that were not available during a live URL scan. Version 2.0 removes that training-serving mismatch.

The deployed model now uses only information available from the entered URL:

- character n-grams learned directly from the URL string;
- lexical and structural URL indicators used by the explainable rule engine;
- no web crawling;
- no Google-index lookup;
- no WHOIS request;
- no unavailable feature is silently replaced with zero.

## Verified test results

The data was divided into stratified training, validation, and untouched test partitions:

| Split | Rows |
|---|---:|
| Training | 8,001 |
| Validation | 1,714 |
| Test | 1,715 |

The selected statistical model is **Character n-gram Logistic Regression**. The final application uses a validation-selected hybrid decision with **30% rule score and 70% ML probability**.

| Metric | URL-only model | Final hybrid decision |
|---|---:|---:|
| Accuracy | 94.46% | **94.17%** |
| Precision | 95.47% | **94.27%** |
| Recall | 93.35% | **94.05%** |
| F1-score | 94.40% | **94.16%** |
| ROC AUC | 98.50% | 98.50% |

Hybrid test confusion counts:

| | Predicted legitimate | Predicted phishing |
|---|---:|---:|
| Actual legitimate | 809 | 49 |
| Actual phishing | 51 | 806 |

These metrics apply to the untouched test split of the supplied dataset. They do not guarantee the same performance on every future phishing campaign.

## Main features

- URL normalization and validation;
- offline URL-only analysis;
- explainable weighted indicators;
- character n-gram ML probability;
- validation-selected rule/ML weighting;
- Low, Medium, and High final risk levels;
- probable attack-technique classification;
- CIA impact assessment;
- dynamic security recommendations;
- incident-response checklist;
- local scan-history dashboard;
- downloadable JSON analysis and CSV history;
- command-line scanner;
- automated tests and GitHub Actions workflow;
- model card and technical documentation.

## Application architecture

```text
User URL
   │
   ├── URL validation and lexical metadata
   │
   ├── Explainable rule engine ───────────────┐
   │                                          │
   └── Character n-gram ML model ─────────────┤
                                              ▼
                                  Validated hybrid score
                                              │
                      ┌───────────────────────┼───────────────────────┐
                      ▼                       ▼                       ▼
                 Risk decision        Threat / CIA analysis    Response actions
                                              │
                                              ▼
                                       Local dashboard
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the detailed flow.

## Project structure

```text
phishing-risk-prevention-toolkit/
├── app.py
├── train_model.py
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── Dockerfile
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── src/
│   ├── config.py
│   ├── url_features.py
│   ├── rule_engine.py
│   ├── ml_predictor.py
│   ├── scanner.py
│   ├── security_analysis.py
│   ├── history.py
│   └── cli.py
├── tests/
├── data/
├── models/
├── figures/
├── reports/
├── examples/
├── docs/
├── scripts/
└── .github/workflows/tests.yml
```

## Quick start on Windows

### Option 1 — automatic scripts

Run:

```bat
scripts\setup_windows.bat
scripts\run_windows.bat
```

### Option 2 — manual commands

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

The application will normally open at:

```text
http://localhost:8501
```

## Command-line use

```powershell
python -m src.cli "https://www.python.org/"
python -m src.cli "http://secure-paypal-login-update.example.com/verify" --json
```

## Run the automated tests

```powershell
pip install -r requirements-dev.txt
pytest
```

## Retrain the model

The repository already includes a trained model. To reproduce training:

```powershell
python train_model.py
```

Training regenerates:

```text
models/url_model_bundle.joblib
models/model_metrics.json
models/model_comparison.csv
models/blend_validation_results.csv
models/decision_config.json
models/feature_importance.csv
figures/confusion_matrix.png
figures/roc_curve.png
figures/precision_recall_curve.png
figures/feature_importance.png
```

## Dataset

The supplied dataset contains 11,430 URLs, equally divided between legitimate and phishing labels. The original project identifies it as the **Web Page Phishing Detection Dataset** hosted on Kaggle.

Before redistributing the dataset publicly, review the source dataset terms. The repository's MIT license applies to the original project code and documentation, not automatically to third-party data. See [data/README.md](data/README.md).

## Security and privacy

- The scanner does not visit the submitted URL.
- The scanner does not send URLs to an external API.
- Scan history is stored locally in `reports/scan_history.csv`.
- That history file is excluded from Git to prevent accidental publication.
- A Low result means low apparent URL-level risk, not verified website safety.

Security reporting instructions are available in [SECURITY.md](SECURITY.md).

## Documentation

- [Technical documentation](docs/TECHNICAL_DOCUMENTATION.md)
- [Model card](docs/MODEL_CARD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [GitHub publication guide](docs/GITHUB_PUBLICATION.md)
- [Example URLs](examples/test_urls.md)

## License

The original code and documentation in this repository are released under the [MIT License](LICENSE). Third-party datasets and dependencies remain subject to their own terms.

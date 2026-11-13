# Model Card — URL-only Phishing Classifier

## Model details

- **Version:** 2.0.0
- **Selected model:** Character n-gram Logistic Regression
- **Input:** One raw HTTP or HTTPS URL string
- **Output:** Estimated phishing probability
- **Training rows:** 8,001
- **Validation rows:** 1,714
- **Test rows:** 1,715
- **Random seed:** 42

## Intended use

The model is intended for:

- educational demonstrations;
- academic cybersecurity projects;
- first-level URL triage;
- decision support alongside explicit rules.

It is not intended to make autonomous blocking decisions in critical production environments without additional security controls and ongoing validation.

## Data

The supplied dataset contains 11,430 labeled URLs:

```text
5,715 legitimate
5,715 phishing
```

The source project identifies the data as the Kaggle Web Page Phishing Detection Dataset. Dataset licensing must be checked separately before public redistribution.

## Training methodology

The dataset is stratified into 70% training, 15% validation, and 15% test data. The validation partition controls:

- model selection;
- probability threshold selection;
- hybrid rule/ML weighting;
- suspicious-score threshold selection.

The untouched test partition is used once for final reporting.

## Performance

### Statistical model only

| Metric | Value |
|---|---:|
| Accuracy | 94.46% |
| Precision | 95.47% |
| Recall | 93.35% |
| F1 | 94.40% |
| ROC AUC | 98.50% |

### Final hybrid decision

| Metric | Value |
|---|---:|
| Accuracy | 94.17% |
| Precision | 94.27% |
| Recall | 94.05% |
| F1 | 94.16% |

The hybrid slightly increases phishing recall compared with the model-only configuration, while preserving balanced precision and explainable evidence.

## Limitations and risks

- Results depend on patterns represented in the dataset.
- New phishing campaigns can use unseen lexical patterns.
- Legitimate URLs can be complex and trigger false positives.
- Compromised legitimate domains may appear lexically safe.
- Shortened links cannot be resolved because the tool does not connect to the network.
- A Low result is not proof of safety.
- Character n-gram importance is statistical and may not provide a semantic explanation by itself; manual indicators provide the human-readable explanation layer.

## Monitoring recommendations

For production adaptation:

- collect recent, independently verified examples;
- monitor false-negative and false-positive rates;
- retrain periodically;
- assess calibration drift;
- add safe reputation and sandbox integrations;
- perform organization-specific validation before enforcing blocking decisions.

# Architecture

## Runtime flow

```mermaid
flowchart TD
    A[User enters URL] --> B[Normalize and validate]
    B -->|Invalid| C[Unknown result]
    B -->|Valid| D[Extract lexical metadata]
    D --> E[Explainable rule engine]
    D --> F[Character n-gram ML model]
    E --> G[Rule score and indicators]
    F --> H[Phishing probability]
    G --> I[Validated hybrid decision]
    H --> I
    I --> J[Low / Medium / High]
    J --> K[Attack classification]
    J --> L[CIA impact]
    J --> M[Recommendations]
    J --> N[Incident response]
    J --> O[Local history dashboard]
```

## Training flow

```mermaid
flowchart TD
    A[Labeled URL dataset] --> B[Stratified 70/15/15 split]
    B --> C[Train candidate models]
    C --> D[Validation model selection]
    D --> E[Validation probability threshold]
    E --> F[Validation rule/ML weight search]
    F --> G[Freeze configuration]
    G --> H[One final untouched-test evaluation]
    H --> I[Save model, metrics, figures, and decision config]
```

## Trust boundaries

The application remains offline during scanning. Submitted URLs are processed locally. It does not contact the destination host, external reputation services, search engines, or WHOIS providers.

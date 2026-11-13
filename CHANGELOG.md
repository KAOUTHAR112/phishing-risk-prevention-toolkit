# Changelog

## 2.0.0 — Final GitHub-ready version

- replaced the deployment-inconsistent 87-feature model;
- added URL-only character n-gram model training;
- added stratified training, validation, and untouched test partitions;
- added validation-based probability-threshold selection;
- tested 30/70, 40/60, 50/50, 60/40, and 70/30 rule/ML weights;
- selected a 30% rules / 70% ML blend;
- modularized the code into `src/`;
- removed committed scan history;
- added automated tests and GitHub Actions;
- added model card, architecture, technical documentation, security policy, and contribution guide;
- added Windows scripts, CLI support, Docker configuration, and GitHub publication instructions.

## 1.0.0

- initial Streamlit interface;
- rule-based URL analysis;
- original full-dataset Random Forest experiment;
- incident-response and dashboard tabs.

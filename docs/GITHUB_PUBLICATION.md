# GitHub Publication Guide

## 1. Create the repository

Recommended repository name:

```text
phishing-risk-prevention-toolkit
```

Create it as an empty repository on GitHub. Do not add a GitHub-generated README because this project already includes one.

## 2. Open a terminal in the project folder

Example:

```powershell
cd "C:\Users\kaoutar\Music\mes projets\phishing-risk-prevention-toolkit"
```

## 3. Initialize and publish

```powershell
git init
git add .
git commit -m "Initial commit: final phishing risk prevention toolkit"
git branch -M main
git remote add origin https://github.com/KAOUTHAR112/phishing-risk-prevention-toolkit.git
git push -u origin main
```

## 4. When `origin` already exists

```powershell
git remote set-url origin https://github.com/KAOUTHAR112/phishing-risk-prevention-toolkit.git
git push -u origin main
```

## 5. Verify what will be published

Before pushing:

```powershell
git status
git ls-files
```

The local scan history should not appear because `reports/scan_history.csv` is ignored.

## 6. Recommended repository settings

After publication:

- add the topics `cybersecurity`, `phishing-detection`, `machine-learning`, `streamlit`, `python`, and `url-analysis`;
- enable the Issues tab;
- keep the GitHub Actions workflow enabled;
- add a short repository description;
- optionally deploy the application to Streamlit Community Cloud.

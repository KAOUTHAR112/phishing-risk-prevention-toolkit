# Contributing

1. Create a branch from `main`.
2. Keep URL analysis offline unless a clearly documented optional integration is introduced.
3. Add or update tests for every functional change.
4. Run:

```bash
pytest
ruff check .
```

5. Do not commit scan history, secrets, API keys, browser profiles, or sensitive URLs.
6. Update documentation when model behavior or thresholds change.
7. Open a pull request describing the purpose, tests, and security implications.

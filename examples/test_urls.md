# Safe Testing Examples

These examples are intended for local demonstrations. Domains under `example.com` and `example-security.com` are illustrative and should not host a real phishing page.

## Expected low apparent risk

```text
https://www.python.org/
https://github.com/
https://www.microsoft.com/
https://www.wikipedia.org/
```

## Expected suspicious or high risk

```text
http://secure-paypal-login-update.example.com/verify/account
http://192.168.1.10/login/verify/account
https://support-appleid-login-verification.example-security.com/
http://bit.ly/secure-bank-update
```

Results can vary after retraining because the statistical model and validation-selected configuration may change.

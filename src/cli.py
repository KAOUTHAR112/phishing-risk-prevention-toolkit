"""Command-line scanner for quick local use."""

from __future__ import annotations

import argparse
import json

from .scanner import scan_url


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a URL for phishing risk.")
    parser.add_argument("url", help="HTTP or HTTPS URL to analyze")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Print the full result as JSON")
    args = parser.parse_args()

    result = scan_url(args.url)
    if args.as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    probability = result["ml"]["probability"]
    print(f"URL: {result['features']['normalized_url']}")
    print(f"Rule score: {result['rule_analysis']['score']}/100")
    print(f"ML probability: {probability:.1%}" if probability is not None else "ML probability: unavailable")
    print(f"Final risk: {result['final_decision']['final_risk_level']}")
    print(f"Decision: {result['final_decision']['decision']}")
    for indicator in result["rule_analysis"]["indicators"]:
        print(f"- [{indicator['severity']}] {indicator['message']}")


if __name__ == "__main__":
    main()

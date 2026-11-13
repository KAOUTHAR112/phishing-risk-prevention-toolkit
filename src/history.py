"""Local scan-history persistence.

History is intentionally excluded from Git so user-entered URLs are not
published accidentally.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from .config import HISTORY_PATH

HISTORY_COLUMNS = [
    "Date",
    "URL",
    "Rule Score",
    "ML Probability",
    "Final Score",
    "Final Risk Level",
    "Decision",
    "Attack Types",
]


def load_history(path: str | Path = HISTORY_PATH) -> pd.DataFrame:
    target = Path(path)
    if not target.exists():
        return pd.DataFrame(columns=HISTORY_COLUMNS)
    try:
        frame = pd.read_csv(target)
        return frame.reindex(columns=HISTORY_COLUMNS)
    except (OSError, pd.errors.ParserError):
        return pd.DataFrame(columns=HISTORY_COLUMNS)


def append_history(url: str, result: dict[str, Any], path: str | Path = HISTORY_PATH) -> pd.DataFrame:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    history = load_history(target)
    probability = result["ml"]["probability"]
    row = {
        "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "URL": result["features"]["normalized_url"] or url,
        "Rule Score": result["rule_analysis"]["score"],
        "ML Probability": round(probability, 6) if probability is not None else None,
        "Final Score": result["final_decision"]["final_score"],
        "Final Risk Level": result["final_decision"]["final_risk_level"],
        "Decision": result["final_decision"]["decision"],
        "Attack Types": ", ".join(result["attack_types"]),
    }
    history = pd.concat([history, pd.DataFrame([row])], ignore_index=True)
    history.to_csv(target, index=False)
    return history

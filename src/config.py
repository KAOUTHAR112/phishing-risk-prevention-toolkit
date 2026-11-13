"""Project constants and filesystem paths."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
FIGURES_DIR = PROJECT_ROOT / "figures"
REPORTS_DIR = PROJECT_ROOT / "reports"

DATASET_PATH = DATA_DIR / "dataset_phishing.csv"
MODEL_BUNDLE_PATH = MODELS_DIR / "url_model_bundle.joblib"
MODEL_METRICS_PATH = MODELS_DIR / "model_metrics.json"
MODEL_COMPARISON_PATH = MODELS_DIR / "model_comparison.csv"
FEATURE_IMPORTANCE_PATH = MODELS_DIR / "feature_importance.csv"
BLEND_RESULTS_PATH = MODELS_DIR / "blend_validation_results.csv"
DECISION_CONFIG_PATH = MODELS_DIR / "decision_config.json"
HISTORY_PATH = REPORTS_DIR / "scan_history.csv"

KNOWN_BRANDS = (
    "paypal", "apple", "google", "microsoft", "facebook", "instagram",
    "amazon", "netflix", "linkedin", "outlook", "office", "whatsapp",
    "dropbox", "github", "dhl", "fedex", "bank",
)

ACTION_WORDS = (
    "login", "signin", "verify", "verification", "update", "secure",
    "account", "password", "confirm", "billing", "support", "unlock",
    "limited", "suspend", "urgent", "authentication", "validate",
    "wallet", "payment", "invoice", "recover", "reset",
)

URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
)

SUSPICIOUS_TLDS = (
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".fit", ".buzz", ".country", ".zip", ".mov",
)

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".scr", ".js", ".jar", ".zip", ".rar", ".apk", ".bat",
)

BRAND_OFFICIAL_DOMAINS = {
    "paypal": ("paypal.com",),
    "apple": ("apple.com", "icloud.com"),
    "google": ("google.com", "gmail.com", "youtube.com", "googleusercontent.com"),
    "microsoft": ("microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com", "azure.com"),
    "facebook": ("facebook.com",),
    "instagram": ("instagram.com",),
    "amazon": ("amazon.com", "amazon.fr"),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "outlook": ("outlook.com", "live.com", "microsoft.com"),
    "office": ("office.com", "office365.com", "microsoft.com", "microsoftonline.com"),
    "whatsapp": ("whatsapp.com",),
    "dropbox": ("dropbox.com",),
    "github": ("github.com",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "bank": (
        "attijariwafabank.com", "attijarinet.com", "cihbank.ma", "sgmaroc.com",
        "creditdumaroc.ma", "bankofafrica.ma", "bmci.ma",
    ),
}

"""Streamlit interface for the Phishing Risk Prevention Toolkit."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.config import (
    FEATURE_IMPORTANCE_PATH,
    FIGURES_DIR,
    MODEL_COMPARISON_PATH,
    MODEL_METRICS_PATH,
)
from src.history import append_history, load_history
from src.ml_predictor import URLModelPredictor
from src.scanner import scan_url
from src.security_analysis import incident_response_checklist

st.set_page_config(
    page_title="Phishing Risk Prevention Toolkit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
      .block-container {max-width: 1220px; padding-top: 2rem; padding-bottom: 3rem;}
      .hero {padding: 2rem 2.2rem; border-radius: 1.5rem; border: 1px solid #dbeafe;
             background: linear-gradient(135deg,#eff6ff,#ffffff); margin-bottom: 1.2rem;}
      .hero h1 {margin: 0 0 .5rem 0; font-size: 2.65rem; line-height: 1.1;}
      .hero p {margin: 0; color: #475569; font-size: 1.05rem; line-height: 1.65;}
      .risk {padding: 1rem 1.2rem; border-radius: 1rem; font-weight: 700; margin: .8rem 0 1.2rem;}
      .risk-high {background:#fee2e2; border:1px solid #fecaca; color:#991b1b;}
      .risk-medium {background:#fef3c7; border:1px solid #fde68a; color:#92400e;}
      .risk-low {background:#dcfce7; border:1px solid #bbf7d0; color:#166534;}
      .risk-unknown {background:#f1f5f9; border:1px solid #e2e8f0; color:#334155;}
      .indicator {padding:.8rem 1rem; border:1px solid #e2e8f0; border-left:4px solid #ef4444;
                  border-radius:.8rem; margin:.55rem 0; background:white;}
      .small-note {color:#64748b; font-size:.9rem;}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_predictor() -> URLModelPredictor:
    return URLModelPredictor()


def risk_css(level: str) -> str:
    return {
        "High": "risk-high",
        "Medium": "risk-medium",
        "Low": "risk-low",
    }.get(level, "risk-unknown")


def probability_text(value: float | None) -> str:
    return f"{value:.1%}" if value is not None else "Unavailable"


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


predictor = get_predictor()

if "last_scan" not in st.session_state:
    st.session_state.last_scan = None
if "history" not in st.session_state:
    st.session_state.history = load_history()

st.markdown(
    """
    <div class="hero">
      <h1>🛡️ Phishing Risk Prevention Toolkit</h1>
      <p>
        An explainable URL-security application combining lexical phishing rules with a deployment-consistent
        machine-learning model. It reports the risk, evidence, probable attack techniques, CIA impact, and response actions.
      </p>
    </div>
    """,
    unsafe_allow_html=True,
)

if predictor.available:
    st.success("URL-only ML model loaded. Hybrid analysis is active.")
else:
    st.warning("The ML model could not be loaded. The rule engine remains available.")
    if predictor.load_error:
        st.caption(predictor.load_error)

scanner_tab, response_tab, dashboard_tab, model_tab = st.tabs(
    ["URL Scanner", "Incident Response", "Dashboard", "Model & Methodology"]
)

with scanner_tab:
    st.subheader("Analyze a URL")
    st.caption("The scanner does not open the website or send the URL to an external service.")

    demos = [
        "https://www.python.org/",
        "https://github.com/",
        "https://www.wikipedia.org/",
        "http://secure-paypal-login-update.example.com/verify/account",
        "http://192.168.1.10/login/verify/account",
        "https://support-appleid-login-verification.example-security.com/",
    ]
    demo = st.selectbox("Example", demos)
    url = st.text_input("URL", value=demo, placeholder="https://example.com")

    if st.button("Analyze URL", type="primary", use_container_width=True):
        result = scan_url(url, predictor=predictor)
        st.session_state.last_scan = result
        if result["features"]["valid"]:
            st.session_state.history = append_history(url, result)

    result = st.session_state.last_scan
    if result:
        decision = result["final_decision"]
        level = decision["final_risk_level"]
        ml = result["ml"]
        rules = result["rule_analysis"]

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Rule score", f"{rules['score']}/100")
        c2.metric("ML probability", probability_text(ml["probability"]))
        c3.metric("Final score", f"{decision['final_score']}/100")
        c4.metric("Final risk", level)

        st.markdown(
            f'<div class="risk {risk_css(level)}">{decision["decision"]}<br>'
            f'<span class="small-note">{decision["mode"]}</span></div>',
            unsafe_allow_html=True,
        )
        st.progress(min(max(decision["final_score"], 0), 100) / 100)

        if ml["error"]:
            st.warning(f"ML inference was unavailable: {ml['error']}")

        left, right = st.columns([1, 1])
        with left:
            st.subheader("Extracted URL information")
            f = result["features"]
            n = f["numeric"]
            details = pd.DataFrame(
                [
                    ("Normalized URL", f["normalized_url"]),
                    ("Hostname", f["hostname"]),
                    ("Scheme", f["scheme"]),
                    ("URL length", n["url_length"]),
                    ("Hostname length", n["hostname_length"]),
                    ("Approx. subdomains", n["subdomain_count"]),
                    ("HTTPS", bool(n["is_https"])),
                    ("IP host", bool(n["uses_ip"])),
                    ("Punycode", bool(n["has_punycode"])),
                    ("Shortener", bool(n["uses_shortener"])),
                    ("Action terms", ", ".join(f["action_hits"]) or "None"),
                    ("Brand terms outside official domains", ", ".join(f["non_official_brand_hits"]) or "None"),
                ],
                columns=["Feature", "Value"],
            )
            st.dataframe(details, hide_index=True, use_container_width=True)

        with right:
            st.subheader("Explainable indicators")
            if rules["indicators"]:
                for item in rules["indicators"]:
                    st.markdown(
                        f'<div class="indicator"><strong>[{item["severity"]} points]</strong> {item["message"]}</div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.success("No suspicious rule indicator was detected.")

        st.subheader("Threat interpretation")
        a, b, c = st.columns(3)
        with a:
            st.markdown("**Probable attack techniques**")
            for attack in result["attack_types"]:
                st.write(f"• {attack}")
        with b:
            st.markdown("**CIA impact**")
            for key, value in result["cia_impact"].items():
                st.write(f"**{key}:** {value}")
        with c:
            st.markdown("**Recommended actions**")
            for item in result["recommendations"]:
                st.write(f"• {item}")

        with st.expander("Full technical result"):
            st.json(result)
            st.download_button(
                "Download analysis as JSON",
                data=json.dumps(result, indent=2, ensure_ascii=False),
                file_name="phishing_scan_result.json",
                mime="application/json",
            )

with response_tab:
    st.subheader("Incident response checklist")
    if not st.session_state.last_scan:
        st.info("Analyze a URL first.")
    else:
        last = st.session_state.last_scan
        level = last["final_decision"]["final_risk_level"]
        st.write(f"Last URL: `{last['features']['normalized_url']}`")
        st.write(f"Risk: **{level}**")
        for index, item in enumerate(incident_response_checklist(level)):
            st.checkbox(item, key=f"response-{index}-{level}")

with dashboard_tab:
    st.subheader("Local scan dashboard")
    history = st.session_state.history
    if history.empty:
        st.info("No local scan history is available yet.")
    else:
        counts = history["Final Risk Level"].value_counts()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total scans", len(history))
        c2.metric("High risk", int(counts.get("High", 0)))
        c3.metric("Medium risk", int(counts.get("Medium", 0)))
        c4.metric("Low risk", int(counts.get("Low", 0)))
        st.bar_chart(counts)
        st.dataframe(history.sort_values("Date", ascending=False), use_container_width=True, hide_index=True)
        st.download_button(
            "Download history as CSV",
            data=history.to_csv(index=False),
            file_name="scan_history.csv",
            mime="text/csv",
        )
    st.caption("Scan history is stored locally and excluded from Git by default.")

with model_tab:
    st.subheader("Evaluation methodology")
    st.markdown(
        """
        - All deployed model inputs come directly from the URL; no missing HTML, WHOIS, Google-index, or traffic features are replaced with zeros.
        - Data is split into stratified training, validation, and untouched test partitions.
        - Model choice and probability threshold are selected only on validation data.
        - Rule/ML weights are also selected on validation data, including 50/50, 60/40, and 70/30 candidates.
        - Final metrics below come from the untouched test partition.
        """
    )
    metrics = load_json(MODEL_METRICS_PATH)
    if metrics:
        hybrid = metrics.get("hybrid_test_metrics", {})
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Test accuracy", f"{hybrid.get('accuracy', 0):.2%}")
        c2.metric("Test precision", f"{hybrid.get('precision', 0):.2%}")
        c3.metric("Test recall", f"{hybrid.get('recall', 0):.2%}")
        c4.metric("Test F1", f"{hybrid.get('f1', 0):.2%}")
        st.json({
            "selected_model": metrics.get("model_name"),
            "input_mode": metrics.get("input_mode"),
            "split": metrics.get("split"),
            "decision_config": metrics.get("decision_config"),
            "confusion_counts": {
                key: hybrid.get(key)
                for key in ("true_negative", "false_positive", "false_negative", "true_positive")
            },
        })
    else:
        st.warning("Model metrics are unavailable. Run `python train_model.py`.")

    if MODEL_COMPARISON_PATH.exists():
        st.subheader("Candidate-model comparison")
        st.dataframe(pd.read_csv(MODEL_COMPARISON_PATH), hide_index=True, use_container_width=True)

    if FEATURE_IMPORTANCE_PATH.exists():
        st.subheader("Top statistical model patterns")
        st.dataframe(pd.read_csv(FEATURE_IMPORTANCE_PATH).head(20), hide_index=True, use_container_width=True)

    image_paths = [
        FIGURES_DIR / "confusion_matrix.png",
        FIGURES_DIR / "roc_curve.png",
        FIGURES_DIR / "precision_recall_curve.png",
        FIGURES_DIR / "feature_importance.png",
    ]
    for image in image_paths:
        if image.exists():
            st.image(str(image), use_container_width=True)

st.divider()
st.caption(
    "Educational decision-support tool. A Low result is not proof that a website is safe, and the application does not replace browser, endpoint, or organizational security controls."
)

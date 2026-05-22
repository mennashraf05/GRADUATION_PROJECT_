#ml.py
import os
import pickle
import pandas as pd
from urllib.parse import urlparse
from phishing_scanner.url_features import extract_features

# =========================
# Model & Scaler Loading
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), "data", "models")

MODEL_FILE = os.path.join(DATA_DIR, "rf_model.pkl")
SCALER_FILE = os.path.join(DATA_DIR, "scaler.pkl")

with open(MODEL_FILE, "rb") as f:
    model = pickle.load(f)

with open(SCALER_FILE, "rb") as f:
    scaler = pickle.load(f)

# =========================
# Configuration
# =========================
TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "wikipedia.org", "microsoft.com", "github.com", "linkedin.com",
    "apple.com", "amazon.com", "stackoverflow.com", "reddit.com"
]

FEATURE_ORDER = [
    "url_length", "n_dots", "n_hypens", "n_underline", "n_slash",
    "n_questionmark", "n_equal", "n_at", "n_and", "n_exclamation",
    "n_space", "n_tilde", "n_comma", "n_plus", "n_asterisk",
    "n_hastag", "n_dollar", "n_percent", "n_redirection"
]

# =========================
# ML Prediction
# =========================
def predict_url(url):
    domain = urlparse(url).netloc.lower().replace("www.", "")

    # 🔒 Trusted domain shortcut
    if any(td in domain for td in TRUSTED_DOMAINS):
        return {
            "prediction": 0,
            "probability": 0.0,
            "risk": "safe",
            "trusted_domain": True
        }

    # 🔹 Feature extraction
    features = extract_features(url)
    df = pd.DataFrame([features], columns=FEATURE_ORDER)
    df_scaled = scaler.transform(df)

    # 🔹 ML probability
    prob = model.predict_proba(df_scaled)[0, 1]

    # 🔹 Three-level risk classification
    if prob < 0.30:
        risk = "safe"
    elif prob < 0.60:
        risk = "suspicious"
    else:
        risk = "dangerous"

    return {
        "prediction": int(prob >= 0.60),
        "probability": float(prob),
        "risk": risk,
        "trusted_domain": False
    }

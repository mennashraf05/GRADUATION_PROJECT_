#train.py
import os
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "final_phishing_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "data", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

df = pd.read_csv(DATA_PATH)
print(f"📄 Dataset shape: {df.shape}")

FEATURE_COLS = [
    "url_length", "n_dots", "n_hypens", "n_underline", "n_slash",
    "n_questionmark", "n_equal", "n_at", "n_and", "n_exclamation",
    "n_space", "n_tilde", "n_comma", "n_plus", "n_asterisk",
    "n_hastag", "n_dollar", "n_percent", "n_redirection"
]
TARGET_COL = "phishing"

X = df[FEATURE_COLS]
y = df[TARGET_COL]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

rf_model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

print("\n🚀 Training Random Forest...")
rf_model.fit(X_train_scaled, y_train)

y_pred = rf_model.predict(X_test_scaled)
print(f"\n✅ RF Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(classification_report(y_test, y_pred))

importances = pd.Series(rf_model.feature_importances_, index=FEATURE_COLS).sort_values(ascending=False)
print("\n🔍 Top 15 important features:")
print(importances.head(15))

with open(os.path.join(MODEL_DIR, "rf_model.pkl"), "wb") as f:
    pickle.dump(rf_model, f)

with open(os.path.join(MODEL_DIR, "scaler.pkl"), "wb") as f:
    pickle.dump(scaler, f)

print("\n💾 Random Forest model & scaler saved in data/models")

import argparse, os, json, requests, pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

PRED_URL = "http://127.0.0.1:5000/predict"

def call_predict(features):
    r = requests.post(PRED_URL, json={"features": features}, timeout=30)
    r.raise_for_status()
    return r.json()

def main(csv_path, out_json):
    df = pd.read_csv(csv_path)
    if 'label' not in df.columns:
        raise SystemExit("CSV must contain a 'label' column")
    preds, trues = [], []
    results = []
    for _, row in df.iterrows():
        label = row['label']
        features = row.drop(labels=['label']).to_dict()
        try:
            resp = call_predict(features)
            pred = resp.get('prediction')
            confidence = resp.get('confidence')
        except Exception as e:
            pred = None
            confidence = None
        preds.append(pred)
        trues.append(label)
        results.append({"true": label, "pred": pred, "confidence": confidence, "features": features})
    acc = accuracy_score(trues, preds)
    report = classification_report(trues, preds, zero_division=0, output_dict=True)
    cm = confusion_matrix(trues, preds, labels=list(sorted(set(trues))))
    summary = {"accuracy": acc, "per_class": report, "confusion_matrix_labels": sorted(set(trues)), "confusion_matrix": cm.tolist()}
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "results": results}, f, indent=2, ensure_ascii=False)
    print("Accuracy:", acc)
    print("Classification report (per-class keys):", list(report.keys()))
    print("Summary saved to:", out_json)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--csv", default=os.path.join(os.path.dirname(__file__), "..", "data", "labeled_samples.csv"))
    p.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "validation_results.json"))
    args = p.parse_args()
    main(args.csv, args.out)
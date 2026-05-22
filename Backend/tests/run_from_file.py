import json, requests, os, time, sys

BASE = "http://127.0.0.1:5000"
PRED_URL = f"{BASE}/predict"

# Try possible locations for test_cases.json
here = os.path.dirname(__file__) or "."
candidates = [
    os.path.join(here, "..", "test_cases.json"),
    os.path.join(here, "test_cases.json"),
    os.path.join(here, "..", "..", "test_cases.json"),
    os.path.join(os.getcwd(), "test_cases.json"),
]

cases_path = None
for p in candidates:
    p = os.path.abspath(p)
    if os.path.exists(p):
        cases_path = p
        break

if not cases_path:
    print("ERROR: test_cases.json not found. Tried:\n" + "\n".join(candidates))
    sys.exit(1)

with open(cases_path, "r", encoding="utf-8") as f:
    cases = json.load(f)

def call_predict(features):
    try:
        r = requests.post(PRED_URL, json={"features": features}, timeout=30)
        return r.status_code, r.json()
    except Exception as e:
        return None, {"error": str(e)}

if __name__ == "__main__":
    print("Using test_cases:", cases_path)
    # cases may be list or dict; handle both
    if isinstance(cases, dict):
        items = cases.items()
    else:
        items = [(c.get("name", f"case{i}"), c.get("features", c)) for i,c in enumerate(cases,1)]
    for name, payload in items:
        print(f"\n=== {name} ===")
        status, resp = call_predict(payload)
        print("status:", status)
        try:
            print(json.dumps(resp, ensure_ascii=False, indent=2))
        except:
            print(resp)
        time.sleep(0.2)
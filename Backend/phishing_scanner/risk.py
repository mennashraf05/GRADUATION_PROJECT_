#risk.py
# =========================
# Risk Scoring
# =========================
def _clamp(value, minimum, maximum):
    return max(minimum, min(maximum, value))


def category_from_score(score):
    if score <= 39:
        return "safe"
    if score <= 69:
        return "suspicious"
    return "dangerous"


def calculate_risk(ml_result):
    if ml_result.get("trusted_domain"):
        return {
            "risk_score": 0,
            "category": "safe"
        }

    risk_score = int(_clamp(round(float(ml_result.get("probability", 0)) * 100), 0, 100))
    category = category_from_score(risk_score)

    return {
        "risk_score": risk_score,
        "category": category
    }


# =========================
# User Guidance
# =========================
def get_user_guidance(risk_level):
    if risk_level == "dangerous":
        return " This link is dangerous! Do NOT click. Report to admin."
    elif risk_level == "suspicious":
        return " This link looks suspicious. Proceed with caution."
    else:
        return " This link seems safe. You can proceed, but stay cautious."

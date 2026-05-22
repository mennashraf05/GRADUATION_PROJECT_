#risk.py
# =========================
# Risk Scoring
# =========================
def calculate_risk(ml_result):
    if ml_result.get("trusted_domain"):
        return {
            "risk_score": 0,
            "category": "safe"
        }

    if ml_result["risk"] == "dangerous":
        return {
            "risk_score": 80,
            "category": "dangerous"
        }
    elif ml_result["risk"] == "suspicious":
        return {
            "risk_score": 50,
            "category": "suspicious"
        }
    else:
        return {
            "risk_score": 20,
            "category": "safe"
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

#scan.py
from flask import Blueprint, request, jsonify, current_app
from phishing_scanner.ml import predict_url
from phishing_scanner.risk import calculate_risk, get_user_guidance
from phishing_scanner.database import save_scan, get_user_scans, delete_scan
from urllib.parse import urlparse

scan_bp = Blueprint("scan_bp", __name__, url_prefix="/api/v1")


@scan_bp.route("/scan-url", methods=["POST"])
def scan_url():
    get_current_user = current_app.extensions["get_current_user"]
    user = get_current_user()

    if not user:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "Missing URL"}), 400

    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Invalid URL"}), 400
    
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return jsonify({"error": "Invalid URL format"}), 400

    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "Only http/https URLs are allowed"}), 400


    # 🔹 ML Prediction
    ml_result = predict_url(url)

    # 🔹 Risk Score
    risk_data = calculate_risk(ml_result)

    # 🔹 Guidance
    guidance = get_user_guidance(risk_data["category"])

    save_scan(
        user_id=user.id,
        url=url,
        risk=risk_data["risk_score"],
        result=risk_data["category"]
    )

    return jsonify({
        "url": url,
        "ml_result": ml_result,
        "risk_score": risk_data["risk_score"],
        "category": risk_data["category"],
        "guidance": guidance
    }), 200


#@scan_bp.route("/scans", methods=["GET"])
#def get_scans():
#    return jsonify(get_user_scans(user_id=None)), 200

@scan_bp.route("/scans", methods=["GET"])
def get_scans():
    get_current_user = current_app.extensions["get_current_user"]
    user = get_current_user()

    if not user:
        return jsonify({"success": False, "message": "Not authenticated"}), 401


    scans = get_user_scans(user_id=user.id)
    # تحويل result → category لكل سجل
    for scan in scans:
        scan["category"] = scan.pop("result")
        scan["risk_score"] = scan.pop("risk")  # لو قاعدة البيانات تسميه risk
    return jsonify(scans), 200

@scan_bp.route("/scan/<int:scan_id>", methods=["DELETE"])
def delete_scan_route(scan_id):
    get_current_user = current_app.extensions["get_current_user"]
    user = get_current_user()

    if not user:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    delete_scan(scan_id, user.id)
    return jsonify({"message": f"Scan {scan_id} deleted"}), 200


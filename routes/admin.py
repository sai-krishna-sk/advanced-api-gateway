from flask import Blueprint, request, jsonify
from middlewares.waf_rules import update_waf_rules

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/threat-metrics', methods=['GET'])
def threat_metrics():
    # Here you would aggregate real metrics from your logging and analysis systems
    metrics = {
        "totalRequests": 1000,
        "blockedRequests": 50,
        "anomalyScoreAverage": 0.75,
        "ipReputationAverage": 90
    }
    return jsonify(metrics)

@admin_bp.route('/waf/update', methods=['POST'])
def update_waf():
    data = request.get_json()
    new_rules = data.get("newRules")
    if not isinstance(new_rules, list):
        return jsonify({"error": "newRules must be a list of regex strings"}), 400
    update_waf_rules(new_rules)
    return jsonify({"message": "WAF rules updated successfully"})


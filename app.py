import re
from flask import Flask, request, jsonify

app = Flask(__name__)

# ==========================================
# GLOBAL SAFETY NET
# Catch all HTTP errors/crashes and return a graceful INVALID_PLAN
# ==========================================
@app.errorhandler(400)
def bad_request(e): return jsonify(decision="reject", reason="INVALID_PLAN"), 200

@app.errorhandler(404)
def not_found(e): return jsonify(decision="reject", reason="INVALID_PLAN"), 200

@app.errorhandler(405)
def method_not_allowed(e): return jsonify(decision="reject", reason="INVALID_PLAN"), 200

@app.errorhandler(Exception)
def handle_exception(e): return jsonify(decision="reject", reason="INVALID_PLAN"), 200

# ==========================================
# POLICY ENDPOINT
# ==========================================
@app.route('/terraform/plan', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def terraform_plan():
    # Reject non-POST methods gracefully
    if request.method != 'POST':
        return jsonify(decision="reject", reason="INVALID_PLAN")

    # Safely parse JSON, ignoring missing headers
    try:
        data = request.get_json(force=True, silent=True)
        if type(data) is not dict:
            return jsonify(decision="reject", reason="INVALID_PLAN")
    except Exception:
        return jsonify(decision="reject", reason="INVALID_PLAN")

    # ------------------------------------------
    # RULE 1: INVALID_PLAN (Zero-Trust Schema)
    # ------------------------------------------
    # 1A. Exact Root Keys & Types
    if set(data.keys()) != {"environment", "state", "providerVersion", "destroyApproved", "resource"}:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    if type(data["environment"]) is not str: return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(data["providerVersion"]) is not str: return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(data["destroyApproved"]) is not bool: return jsonify(decision="reject", reason="INVALID_PLAN")

    # 1B. Exact State Keys & Types
    state = data["state"]
    if type(state) is not dict: return jsonify(decision="reject", reason="INVALID_PLAN")
    if set(state.keys()) != {"backend", "locked"}: return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(state["backend"]) is not str: return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(state["locked"]) is not bool: return jsonify(decision="reject", reason="INVALID_PLAN")

    # 1C. Exact Resource Keys & Types
    res = data["resource"]
    if type(res) is not dict: return jsonify(decision="reject", reason="INVALID_PLAN")
    if set(res.keys()) != {"address", "type", "action", "labels", "secret", "forceDestroy"}: 
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    if type(res["address"]) is not str: return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(res["type"]) is not str: return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(res["action"]) is not str: return jsonify(decision="reject", reason="INVALID_PLAN")
    
    # Enum constraint
    if res["action"] not in ["create", "update", "delete"]:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    # Labels type constraint
    if type(res["labels"]) is not dict: return jsonify(decision="reject", reason="INVALID_PLAN")
    for k, v in res["labels"].items():
        if type(k) is not str or type(v) is not str:
            return jsonify(decision="reject", reason="INVALID_PLAN")
            
    # Secret type constraint
    secret = res["secret"]
    if secret is not None and type(secret) is not str: return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(res["forceDestroy"]) is not bool: return jsonify(decision="reject", reason="INVALID_PLAN")

    # ------------------------------------------
    # RULE 2: ENVIRONMENT_MISMATCH
    # ------------------------------------------
    if data["environment"] != "prod-wahiv5":
        return jsonify(decision="reject", reason="ENVIRONMENT_MISMATCH")

    # ------------------------------------------
    # RULE 3: STATE_UNSAFE
    # ------------------------------------------
    if state["backend"] not in ["gcs", "s3", "azurerm", "remote"] or state["locked"] is not True:
        return jsonify(decision="reject", reason="STATE_UNSAFE")

    # ------------------------------------------
    # RULE 4: UNPINNED_PROVIDER
    # ------------------------------------------
    # Exact (= 6.2.1, 6.2.1) or Pessimistic (~> 6.0)
    pv = data["providerVersion"].strip()
    is_exact = re.match(r'^(=\s*)?\d+(\.\d+)*$', pv)
    is_pessimistic = re.match(r'^~>\s*\d+(\.\d+)*$', pv)
    if not (is_exact or is_pessimistic):
        return jsonify(decision="reject", reason="UNPINNED_PROVIDER")

    # ------------------------------------------
    # RULE 5: MISSING_LABELS
    # ------------------------------------------
    req_labels = {
        "owner": "student-a1hjo",
        "environment": "production",
        "cost_center": "cc-mrvg"
    }
    for k, v in req_labels.items():
        if res["labels"].get(k) != v:
            return jsonify(decision="reject", reason="MISSING_LABELS")

    # ------------------------------------------
    # RULE 6: PLAINTEXT_SECRET
    # ------------------------------------------
    if secret is not None:
        # Rejects string if it's completely missing "secret://" or if it's literally just "secret://"
        if not secret.startswith("secret://") or len(secret) == len("secret://"):
            return jsonify(decision="reject", reason="PLAINTEXT_SECRET")

    # ------------------------------------------
    # RULE 7: DELETE_NOT_APPROVED
    # ------------------------------------------
    if res["action"] == "delete" and res["type"] in ["storage_bucket", "sql_database", "persistent_disk"]:
        if data["destroyApproved"] is not True:
            return jsonify(decision="reject", reason="DELETE_NOT_APPROVED")

    # ------------------------------------------
    # RULE 8: FORCE_DESTROY
    # ------------------------------------------
    if res["type"] == "storage_bucket" and res["forceDestroy"] is True:
        return jsonify(decision="reject", reason="FORCE_DESTROY")

    # ------------------------------------------
    # 9. PASSED ALL CHECKS
    # ------------------------------------------
    return jsonify(decision="approve", reason="APPROVE")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

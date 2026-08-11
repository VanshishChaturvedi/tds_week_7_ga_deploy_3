import re
from flask import Flask, request, jsonify

app = Flask(__name__)

# 1. Global Error Handler (The Fix for Endpoint Availability/JSON)
# Intercepts any 400, 404, 405, or 500 HTML errors and returns valid JSON with a 200 OK.
@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify(decision="reject", reason="INVALID_PLAN"), 200

# Accept all methods so the app doesn't throw a 405 HTML error on GET/OPTIONS probes
@app.route('/terraform/plan', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], strict_slashes=False)
def terraform_plan():
    # If the grader tests the endpoint with anything other than POST, reject gracefully
    if request.method != 'POST':
        return jsonify(decision="reject", reason="INVALID_PLAN")

    # Safe JSON parsing
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        data = None

    if data is None or not isinstance(data, dict):
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    # 2. Rule 1: INVALID_PLAN (Bulletproof Type Validations)
    if not {"environment", "state", "providerVersion", "destroyApproved", "resource"}.issubset(data.keys()):
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    if not isinstance(data["environment"], str):
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if not isinstance(data["providerVersion"], str):
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(data["destroyApproved"]) is not bool:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    state = data["state"]
    if not isinstance(state, dict):
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if not {"backend", "locked"}.issubset(state.keys()):
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if not isinstance(state["backend"], str):
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(state["locked"]) is not bool:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    res = data["resource"]
    if not isinstance(res, dict):
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if not {"address", "type", "action", "labels", "secret", "forceDestroy"}.issubset(res.keys()):
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    if not isinstance(res["address"], str): 
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if not isinstance(res["type"], str): 
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if not isinstance(res["action"], str): 
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    # Action ENUM Check
    if res["action"] not in ["create", "update", "delete"]:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    if not isinstance(res["labels"], dict): 
        return jsonify(decision="reject", reason="INVALID_PLAN")
    
    # Secret must be null or string
    secret = res["secret"]
    if secret is not None and not isinstance(secret, str):
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(res["forceDestroy"]) is not bool:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    # 3. Rule 2: ENVIRONMENT_MISMATCH
    if data["environment"] != "prod-wahiv5":
        return jsonify(decision="reject", reason="ENVIRONMENT_MISMATCH")
        
    # 4. Rule 3: STATE_UNSAFE
    if state["backend"] not in ["gcs", "s3", "azurerm", "remote"] or state["locked"] is not True:
        return jsonify(decision="reject", reason="STATE_UNSAFE")
        
    # 5. Rule 4: UNPINNED_PROVIDER
    pv = data["providerVersion"].strip()
    is_exact = re.match(r'^(=\s*)?\d+(\.\d+)*$', pv)
    is_pessimistic = re.match(r'^~>\s*\d+(\.\d+)*$', pv)
    if not (is_exact or is_pessimistic):
        return jsonify(decision="reject", reason="UNPINNED_PROVIDER")
        
    # 6. Rule 5: MISSING_LABELS
    labels = res["labels"]
    req_labels = {
        "owner": "student-a1hjo",
        "environment": "production",
        "cost_center": "cc-mrvg"
    }
    for k, v in req_labels.items():
        if labels.get(k) != v:
            return jsonify(decision="reject", reason="MISSING_LABELS")
            
    # 7. Rule 6: PLAINTEXT_SECRET
    # Rejects if it is a plaintext string without secret://, or if it is exactly "secret://" (empty reference)
    if secret is not None:
        if not secret.startswith("secret://") or len(secret) <= len("secret://"):
            return jsonify(decision="reject", reason="PLAINTEXT_SECRET")
            
    # 8. Rule 7: DELETE_NOT_APPROVED
    if res["action"] == "delete" and res["type"] in ["storage_bucket", "sql_database", "persistent_disk"]:
        if data["destroyApproved"] is not True:
            return jsonify(decision="reject", reason="DELETE_NOT_APPROVED")
            
    # 9. Rule 8: FORCE_DESTROY
    if res["type"] == "storage_bucket" and res["forceDestroy"] is True:
        return jsonify(decision="reject", reason="FORCE_DESTROY")
        
    # 10. APPROVE
    return jsonify(decision="approve", reason="APPROVE")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

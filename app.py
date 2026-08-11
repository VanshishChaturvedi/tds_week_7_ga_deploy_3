import re
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/terraform/plan', methods=['POST'], strict_slashes=False)
def terraform_plan():
    # 1. Endpoint Availability / Strict JSON Parsing
    try:
        data = request.get_json(force=True, silent=True)
        if data is None or type(data) is not dict:
            return jsonify(decision="reject", reason="INVALID_PLAN")
    except Exception:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    # 2. Rule 1: INVALID_PLAN (Rigid Schema Validation)
    expected_keys = {"environment", "state", "providerVersion", "destroyApproved", "resource"}
    if not expected_keys.issubset(data.keys()):
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    if type(data["environment"]) is not str:
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(data["providerVersion"]) is not str:
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(data["destroyApproved"]) is not bool:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    state = data["state"]
    if type(state) is not dict:
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if not {"backend", "locked"}.issubset(state.keys()):
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(state["backend"]) is not str or type(state["locked"]) is not bool:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    res = data["resource"]
    if type(res) is not dict:
        return jsonify(decision="reject", reason="INVALID_PLAN")
    res_keys = {"address", "type", "action", "labels", "secret", "forceDestroy"}
    if not res_keys.issubset(res.keys()):
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    if type(res["address"]) is not str: 
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(res["type"]) is not str: 
        return jsonify(decision="reject", reason="INVALID_PLAN")
    if type(res["action"]) is not str: 
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    # Action ENUM Check
    if res["action"] not in ["create", "update", "delete"]:
        return jsonify(decision="reject", reason="INVALID_PLAN")
        
    if type(res["labels"]) is not dict: 
        return jsonify(decision="reject", reason="INVALID_PLAN")
    
    # Secret must be null or string
    if res["secret"] is not None and type(res["secret"]) is not str:
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
    # Rejects >=, *, latest. Allows exact (e.g. 6.2.1, = 6.2.1) and pessimistic (~> 6.0)
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
    secret = res["secret"]
    if secret is not None:
        if not secret.startswith("secret://") or len(secret) == len("secret://"):
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

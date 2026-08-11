import re
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/terraform/plan', methods=['POST'], strict_slashes=False)
def terraform_plan():
    # 1. Ensure valid JSON payload and endpoint availability
    try:
        data = request.get_json(force=True, silent=True)
        if type(data) is not dict:
            return jsonify(decision="reject", reason="INVALID_PLAN")
    except Exception:
        return jsonify(decision="reject", reason="INVALID_PLAN")

    # 2. Rule 1: INVALID_PLAN (Strict Type Checking)
    try:
        env = data.get("environment")
        state = data.get("state")
        prov_ver = data.get("providerVersion")
        dest_app = data.get("destroyApproved")
        res = data.get("resource")

        if type(env) is not str: raise ValueError
        if type(state) is not dict: raise ValueError
        if type(state.get("backend")) is not str: raise ValueError
        if type(state.get("locked")) is not bool: raise ValueError
        if type(prov_ver) is not str: raise ValueError
        if type(dest_app) is not bool: raise ValueError
        
        if type(res) is not dict: raise ValueError
        if type(res.get("address")) is not str: raise ValueError
        if type(res.get("type")) is not str: raise ValueError
        if type(res.get("action")) is not str: raise ValueError
        if type(res.get("labels")) is not dict: raise ValueError
        
        secret = res.get("secret")
        if secret is not None and type(secret) is not str: raise ValueError
        if type(res.get("forceDestroy")) is not bool: raise ValueError

    except ValueError:
        return jsonify(decision="reject", reason="INVALID_PLAN")

    # 3. Rule 2: ENVIRONMENT_MISMATCH
    if env != "prod-wahiv5":
        return jsonify(decision="reject", reason="ENVIRONMENT_MISMATCH")

    # 4. Rule 3: STATE_UNSAFE
    if state["backend"] not in ["gcs", "s3", "azurerm", "remote"] or state["locked"] is not True:
        return jsonify(decision="reject", reason="STATE_UNSAFE")

    # 5. Rule 4: UNPINNED_PROVIDER
    # Matches exact (6.2.1, = 6.2.1) or pessimistic (~> 6.0)
    # Rejects open ranges (>=), wildcards (*), and 'latest'
    exact_pattern = r'^(?:=\s*)?\d+\.\d+(?:\.\d+)?$'
    pessimistic_pattern = r'^~>\s*\d+\.\d+(?:\.\d+)?$'
    prov_ver_stripped = prov_ver.strip()
    if not (re.match(exact_pattern, prov_ver_stripped) or re.match(pessimistic_pattern, prov_ver_stripped)):
        return jsonify(decision="reject", reason="UNPINNED_PROVIDER")

    # 6. Rule 5: MISSING_LABELS
    req_labels = {
        "owner": "student-a1hjo",
        "environment": "production",
        "cost_center": "cc-mrvg"
    }
    labels = res["labels"]
    if not all(labels.get(k) == v for k, v in req_labels.items()):
        return jsonify(decision="reject", reason="MISSING_LABELS")

    # 7. Rule 6: PLAINTEXT_SECRET
    if secret is not None:
        if not secret.startswith("secret://") or len(secret) == len("secret://"):
            return jsonify(decision="reject", reason="PLAINTEXT_SECRET")

    # 8. Rule 7: DELETE_NOT_APPROVED
    res_type = res["type"]
    action = res["action"]
    if action == "delete" and res_type in ["storage_bucket", "sql_database", "persistent_disk"]:
        if dest_app is not True:
            return jsonify(decision="reject", reason="DELETE_NOT_APPROVED")

    # 9. Rule 8: FORCE_DESTROY
    if res_type == "storage_bucket" and res["forceDestroy"] is True:
        return jsonify(decision="reject", reason="FORCE_DESTROY")

    # 10. Passed all policies
    return jsonify(decision="approve", reason="APPROVE")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, jsonify, flash
from flask_cors import CORS
from utils.path import PATH, load_json, save_json
from utils.crypto import sign_sd_jwt
from utils.verify import verify_sd_jwt
from datetime import datetime
import os
import uuid
import qrcode
import jwt

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = "secret_for_twland"
os.makedirs(PATH["QR_DIR"], exist_ok=True)

def response(data=None, error=None, code=200):
    if error:
        return jsonify({"error": error}), code
    return jsonify(data), code

@app.route("/")
def index():
    session_id = str(uuid.uuid4())
    return redirect(url_for("vp_request", session_id=session_id))

# === Verifier: 建立 VP 請求（出示自然人 VC） ===
@app.route("/vp-request/<session_id>")
def vp_request(session_id):
    sessions = load_json(PATH["SESSIONS"])
    sessions[session_id] = {"verified": False}
    save_json(PATH["SESSIONS"], sessions)

    vp_url = url_for("verify_vc", session_id=session_id, _external=True)
    qr_path = os.path.join(PATH["QR_DIR"], f"vp_{session_id}.png")
    qrcode.make(vp_url).save(qr_path)

    return render_template("vp_request.html",
                           session_id=session_id,
                           vp_url=vp_url,
                           qr_path=f"/static/qrcodes/vp_{session_id}.png")

# === Verifier: 接收出示的 VC（VP） ===
@app.route("/verify/<session_id>", methods=["POST"])
def verify_vc(session_id):
    req = request.get_json()
    sd_jwt = req.get("vp")

    ok, result = verify_sd_jwt(sd_jwt)
    if not ok:
        return response(error=result, code=400)

    # 儲存驗章結果
    sessions = load_json(PATH["SESSIONS"])
    sessions[session_id] = {
        "verified": True,
        "vc_info": result  # name, national_id, holder_did
    }
    save_json(PATH["SESSIONS"], sessions)

    return response({"msg": "驗章成功"})

# === 顯示驗章結果 ===
@app.route("/verify/<session_id>", methods=["GET"])
def verify_result(session_id):
    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id)
    return render_template("verify_result.html", session=session, session_id=session_id)

# === 顯示符合本人身份的房產清單 ===
@app.route("/property/<session_id>")
def property(session_id):
    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id)
    if not session or not session.get("verified"):
        return "尚未通過驗證", 403

    name = session["vc_info"]["name"]
    national_id = session["vc_info"]["national_id"]

    from utils.property_db import get_properties_for_holder
    properties = get_properties_for_holder(name, national_id)

    return render_template("property.html",
                           session_id=session_id,
                           properties=properties,
                           name=name,
                           national_id=national_id)

# === 產生 Credential Offer ===
@app.route("/issue/<session_id>")
def issue(session_id):
    property_id = request.args.get("property_id")
    if not property_id:
        return "缺少 property_id", 400

    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id)
    if not session or not session.get("verified"):
        return "尚未通過驗證", 403

    from utils.property_db import get_all_properties
    all_props = get_all_properties()
    prop = next((p for p in all_props if p["property_id"] == property_id), None)
    if not prop:
        return "找不到房產資料", 404

    offer_code = str(uuid.uuid4())
    offers = load_json(PATH["OFFER"])
    offers[offer_code] = {
        "user_claims": {
            "owner_name": prop["owner_name"],
            "owner_national_id": prop["owner_national_id"],
            "property_id": prop["property_id"],
            "address": prop["address"]
        },
        "used": False
    }
    save_json(PATH["OFFER"], offers)

    offer_url = f"https://twland.ddns.net/credential-offer/{offer_code}"
    qr_path = os.path.join(PATH["QR_DIR"], f"{offer_code}.png")
    qrcode.make(offer_url).save(qr_path)

    return render_template("issued.html",
                           vc_id=offer_code,
                           offer_url=offer_url,
                           qr_path=f"/static/qrcodes/{offer_code}.png")

# === Credential Offer Endpoint ===
@app.route("/credential-offer/<code>")
def credential_offer(code):
    offers = load_json(PATH["OFFER"])
    offer = offers.get(code)
    if not offer or offer.get("used"):
        return response(error="無效或已使用的 code", code=400)

    return response({
        "credential_issuer": "https://twland.ddns.net",
        "credential_configuration_ids": ["twland-property-credential"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": code,
                "user_pin_required": False
            }
        }
    })

# === OID4VCI 領 VC ===
@app.route("/oid4vci/credential", methods=["POST"])
def credential_endpoint():
    req = request.get_json()
    code = req.get("pre-authorized_code")
    subject_did = req.get("subject_did")

    if not code or not subject_did:
        return response(error="缺少 pre-authorized_code 或 subject_did", code=400)

    offers = load_json(PATH["OFFER"])
    offer = offers.get(code)
    if not offer or offer.get("used"):
        return response(error="無效或已使用的 code", code=400)

    user_claims = offer.get("user_claims")
    if not user_claims:
        return response(error="找不到使用者資料", code=404)

    sd_jwt = sign_sd_jwt(user_claims, subject_did)
    jwt_payload = jwt.decode(sd_jwt.split("~")[0], options={"verify_signature": False})
    vc_id = jwt_payload.get("vc", {}).get("id", "")

    offer["used"] = True
    save_json(PATH["OFFER"], offers)

    issued = load_json(PATH["ISSUED"])
    issued.append({
        "vc": sd_jwt,
        "vc_id": vc_id,
        "property_id": user_claims.get("property_id", ""),
        "holder_did": subject_did,
        "issued_at": datetime.utcnow().isoformat()
    })
    save_json(PATH["ISSUED"], issued)

    return response({
        "format": "vc+sd-jwt",
        "credential": sd_jwt
    })

# === .well-known endpoint ===
@app.route("/.well-known/<path:filename>")
def well_known(filename):
    return send_from_directory(PATH["WELL_KNOWN"], filename)

if __name__ == "__main__":
    app.run(debug=True, port=5001)

from flask import Flask, request, render_template, redirect, url_for, send_from_directory, jsonify, flash
from flask_cors import CORS
import jwt
import json
import base64
import os
import uuid
import qrcode
from datetime import datetime, timedelta
from utils.crypto import sign_sd_jwt
from utils.verify import verify_sd_jwt
from utils.path import PATH, load_json, save_json

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = "some_random_secret_for_twland"
os.makedirs(PATH["QR_DIR"], exist_ok=True)

# 常數定義
VERIFIER_DID = "did:web:twland.ddns.net"
VERIFIER_DOMAIN = "twland.ddns.net"

def response(data=None, error=None, code=200):
    """統一的JSON回應格式"""
    if error:
        return jsonify({"error": error}), code
    return jsonify(data), code

# === 首頁：重導向到VP請求頁面 ===
@app.route("/")
def index():
    session_id = str(uuid.uuid4())
    return redirect(url_for("vp_request", session_id=session_id))

# === VP請求頁面：生成符合OID4VP規範的請求，讓用戶出示自然人憑證 ===
@app.route("/vp-request/<session_id>")
def vp_request(session_id):
    # 初始化session
    sessions = load_json(PATH["SESSIONS"])
    
    # 生成VP請求的nonce和state參數
    nonce = str(uuid.uuid4())
    state = str(uuid.uuid4())
    
    # 保存請求參數到session
    sessions[session_id] = {
        "verified": False,
        "nonce": nonce,
        "state": state,
        "created_at": datetime.utcnow().isoformat()
    }
    save_json(PATH["SESSIONS"], sessions)
    
    # 構建OID4VP請求URL
    vp_request_uri = f"https://{VERIFIER_DOMAIN}/oid4vp/request/{session_id}"
    
    # 生成QR code
    qr_filename = f"vp_{session_id}.png"
    qr_path = os.path.join(PATH["QR_DIR"], qr_filename)
    qrcode.make(vp_request_uri).save(qr_path)
    
    return render_template("vp_request.html",
                          session_id=session_id,
                          vp_url=vp_request_uri,
                          qr_path=f"/static/qrcodes/{qr_filename}")

# === 檢查驗證狀態 ===
@app.route("/check-verification/<session_id>")
def check_verification(session_id):
    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id, {})
    return jsonify({
        "verified": session.get("verified", False),
        "timestamp": datetime.utcnow().isoformat()
    })

# === OID4VP 請求端點：提供VP請求參數 ===
@app.route("/oid4vp/request/<session_id>")
def oid4vp_request(session_id):
    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id)
    
    if not session:
        return response(error="無效的session", code=404)
    
    # 構建符合OID4VP規範的請求
    vp_request = {
        "presentation_definition": {
            "id": f"citizen-vp-request-{session_id}",
            "input_descriptors": [
                {
                    "id": "citizen-credential",
                    "name": "自然人憑證",
                    "purpose": "需要您的自然人憑證以驗證身分",
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vc.type"],
                                "filter": {
                                    "type": "string",
                                    "pattern": "CitizenCredential"
                                }
                            }
                        ]
                    }
                }
            ]
        },
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "client_id": VERIFIER_DID,
        "nonce": session["nonce"],
        "state": session["state"],
        "redirect_uri": f"https://{VERIFIER_DOMAIN}/oid4vp/callback",
        "response_uri": f"https://{VERIFIER_DOMAIN}/oid4vp/presentation/{session_id}"
    }
    
    return response(vp_request)

# === OID4VP 呈現端點：接收VP令牌 ===
@app.route("/oid4vp/presentation/<session_id>", methods=["POST"])
def oid4vp_presentation(session_id):
    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id)
    
    if not session:
        return response(error="無效的session", code=404)
    
    # 獲取VP令牌和狀態
    req = request.get_json()
    vp_token = req.get("vp_token")  # 使用 OID4VP 標準字段名
    state = req.get("state")
    
    # 驗證狀態
    if state != session.get("state"):
        return response(error="狀態不匹配", code=400)
    
    # 驗證VP令牌
    if not vp_token:
        return response(error="缺少VP令牌", code=400)
    
    # 假設VP令牌是一個SD-JWT格式的憑證
    valid, result = verify_sd_jwt(vp_token)  # 這裡傳入 vp_token
    if not valid:
        return response(error=f"憑證驗證失敗: {result}", code=400)
    
    # 獲取憑證中的必要信息
    name = result.get("name")
    national_id = result.get("national_id")
    holder_did = result.get("holder_did")
    
    if not name or not national_id:
        return response(error="缺少必要的身分信息", code=400)
    
    # 更新session狀態
    sessions[session_id].update({
        "verified": True,
        "vc_info": {
            "name": name,
            "national_id": national_id,
            "holder_did": holder_did
        },
        "verification_time": datetime.utcnow().isoformat()
    })
    save_json(PATH["SESSIONS"], sessions)
    
    return response({"status": "success", "message": "憑證驗證成功"})

# === OID4VP 回調端點 ===
@app.route("/oid4vp/callback")
def oid4vp_callback():
    # 這是一個可選的重定向端點，在某些情況下可能需要
    state = request.args.get("state")
    
    # 查找對應的session
    sessions = load_json(PATH["SESSIONS"])
    for session_id, session in sessions.items():
        if session.get("state") == state:
            return redirect(url_for("verify_result", session_id=session_id))
    
    return "驗證過程中發生錯誤", 400

# === 舊的驗證端點：保持向後兼容 ===
@app.route("/verify/<session_id>", methods=["POST"])
def verify_vc(session_id):
    req = request.get_json()
    sd_jwt = req.get("vp")
    
    if not sd_jwt:
        return response(error="缺少VP憑證資料", code=400)
    
    # 重定向到新的OID4VP端點
    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id, {})
    
    # 驗證SD-JWT憑證
    valid, result = verify_sd_jwt(sd_jwt)
    if not valid:
        return response(error=f"憑證驗證失敗: {result}", code=400)
    
    # 更新session
    sessions[session_id] = {
        "verified": True,
        "vc_info": {
            "name": result.get("name", ""),
            "national_id": result.get("national_id", ""),
            "holder_did": result.get("holder_did", "")
        }
    }
    save_json(PATH["SESSIONS"], sessions)
    
    return response({"status": "success", "message": "憑證驗證成功"})

# === 顯示驗證結果 ===
@app.route("/verify/<session_id>", methods=["GET"])
def verify_result(session_id):
    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id, {})
    
    return render_template("verify_result.html", 
                          session=session,
                          session_id=session_id)

# === 房產列表：顯示用戶名下房產 ===
@app.route("/property/<session_id>")
def property_list(session_id):
    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id)
    
    if not session or not session.get("verified"):
        flash("請先完成身分驗證", "warning")
        return redirect(url_for("index"))
    
    name = session["vc_info"].get("name")
    national_id = session["vc_info"].get("national_id")
    
    # 從模擬資料庫獲取房產清單
    from utils.property_db import get_properties_for_holder
    properties = get_properties_for_holder(name, national_id)
    
    return render_template("property.html",
                          session_id=session_id,
                          properties=properties,
                          name=name,
                          national_id=national_id)

# === 產生房產憑證預授權碼 ===
@app.route("/issue/<session_id>")
def issue(session_id):
    property_id = request.args.get("property_id")
    if not property_id:
        return response(error="缺少 property_id", code=400)
    
    sessions = load_json(PATH["SESSIONS"])
    session = sessions.get(session_id)
    if not session or not session.get("verified"):
        return response(error="尚未通過身分驗證", code=403)
    
    # 從資料庫獲取房產資訊
    from utils.property_db import get_all_properties
    all_properties = get_all_properties()
    property_info = next((p for p in all_properties if p["property_id"] == property_id), None)
    
    if not property_info:
        return response(error="找不到房產資料", code=404)
    
    # 檢查是否為屬於該使用者的房產
    if (property_info["owner_name"] != session["vc_info"]["name"] or 
        property_info["owner_national_id"] != session["vc_info"]["national_id"]):
        return response(error="無權申請此房產憑證", code=403)
    
    # 產生預授權碼
    offer_code = str(uuid.uuid4())
    offers = load_json(PATH["OFFER"])
    
    offers[offer_code] = {
        "user_claims": {
            "owner_name": property_info["owner_name"],
            "owner_national_id": property_info["owner_national_id"],
            "property_id": property_info["property_id"],
            "address": property_info["address"]
        },
        "used": False
    }
    save_json(PATH["OFFER"], offers)
    
    # 產生 QR code 供錢包掃描
    offer_url = f"https://{VERIFIER_DOMAIN}/credential-offer/{offer_code}"
    qr_filename = f"{offer_code}.png"
    qr_path = os.path.join(PATH["QR_DIR"], qr_filename)
    qrcode.make(offer_url).save(qr_path)
    
    return render_template("issued.html",
                          vc_id=offer_code,
                          offer_url=offer_url,
                          qr_path=f"/static/qrcodes/{qr_filename}")

# === Credential Offer Endpoint (OID4VCI) ===
@app.route("/credential-offer/<code>")
def credential_offer(code):
    offers = load_json(PATH["OFFER"])
    offer = offers.get(code)
    if not offer or offer.get("used"):
        return response(error="Invalid or used code", code=400)
    
    # 回傳 OID4VCI Metadata
    return response({
        "credential_issuer": f"https://{VERIFIER_DOMAIN}",
        "credential_configuration_ids": ["twland-property-credential"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": code,
                "user_pin_required": False
            }
        }
    })

# === OID4VCI：Holder 帶 subject_did 來兌換 VC ===
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
        return response(error="找不到使用者資料，無法發憑證", code=404)
    
    # === 簽發 SD-JWT（預設全部欄位都使用 Selective Disclosure）===
    sd_jwt = sign_sd_jwt(user_claims, subject_did)
    
    # === 從 payload 抓出 VC ID ===
    jwt_payload = jwt.decode(sd_jwt.split("~")[0], options={"verify_signature": False})
    vc_id = jwt_payload.get("vc", {}).get("id", "")
    
    # === 標記此預授權碼已使用 ===
    offer["used"] = True
    save_json(PATH["OFFER"], offers)
    
    # === 記錄憑證（方便後台管理）===
    issued_list = load_json(PATH["ISSUED"])
    issued_list.append({
        "vc": sd_jwt,
        "vc_id": vc_id,
        "property_id": user_claims.get("property_id", ""),
        "holder_did": subject_did,
        "issued_at": datetime.utcnow().isoformat()
    })
    save_json(PATH["ISSUED"], issued_list)
    
    # === 回傳 SD-JWT VC 給 Holder ===
    return response({
        "format": "vc+sd-jwt",
        "credential": sd_jwt
    })

# === 已核發清單：顯示 VC 狀態、支援撤銷 ===
@app.route("/issued")
def issued_list():
    issued_list = load_json(PATH["ISSUED"])
    rev_list = load_json(os.path.join(PATH["WELL_KNOWN"], "revocation-list.json"))
    revoked_ids = rev_list.get("vc_status", [])
    
    return render_template("issued_list.html",
                          issued=issued_list,
                          revoked_ids=revoked_ids)

# === 撤銷 VC ===
@app.route("/revoke/<vc_id>", methods=["POST"])
def revoke(vc_id):
    rev_list_path = os.path.join(PATH["WELL_KNOWN"], "revocation-list.json")
    rev_data = load_json(rev_list_path)
    if "vc_status" not in rev_data:
        rev_data["vc_status"] = []
    
    if vc_id in rev_data["vc_status"]:
        flash("該VC已被撤銷或重複撤銷", "warning")
    else:
        rev_data["vc_status"].append(vc_id)
        save_json(rev_list_path, rev_data)
        flash(f"VC {vc_id} 已成功吊銷", "success")
    
    return redirect(url_for("issued_list"))

# === 提供 .well-known 檔案 ===
@app.route("/.well-known/<path:filename>")
def well_known(filename):
    return send_from_directory(PATH["WELL_KNOWN"], filename)

if __name__ == "__main__":
    app.run(debug=True, port=5001)
import jwt
import json
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse
import os
import traceback
import requests
from datetime import datetime, timedelta
from utils.path import PATH, load_json, save_json

# DID 文件緩存
DID_CACHE_PATH = os.path.join(PATH.get("DATA_DIR", "."), "did_cache.json")
DID_CACHE_EXPIRY = timedelta(hours=24)

def load_did_cache():
    if os.path.exists(DID_CACHE_PATH):
        try:
            with open(DID_CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_did_cache(cache):
    try:
        os.makedirs(os.path.dirname(DID_CACHE_PATH), exist_ok=True)
        with open(DID_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass

def decode_disclosure(disclosure_b64):
    try:
        padded = disclosure_b64 + '=' * (-len(disclosure_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode())
        disclosure_array = json.loads(decoded)
        
        if not isinstance(disclosure_array, list) or len(disclosure_array) != 3:
            return None
            
        salt, key, value = disclosure_array
        return {"salt": salt, "key": key, "value": value}
    except Exception:
        return None

def compute_hash(disclosure_obj):
    disclosure_array = [
        disclosure_obj["salt"], 
        disclosure_obj["key"], 
        disclosure_obj["value"]
    ]
    disclosure_json = json.dumps(disclosure_array, separators=(",", ":")).encode()
    digest = hashlib.sha256(disclosure_json).digest()
    return "sha-256:" + base64.urlsafe_b64encode(digest).decode().rstrip("=")

def fetch_did_document(did):
    if not did.startswith("did:web:"):
        raise ValueError(f"目前僅支持 did:web 方法: {did}")
    
    domain = did.replace("did:web:", "")
    url = f"https://{domain}/.well-known/did.json"
    
    response = requests.get(url, timeout=10)
    
    if response.status_code != 200:
        raise Exception(f"獲取 DID 文件失敗 ({response.status_code}): {response.text}")
    
    return response.json()

def get_did_document(did):
    # 檢查緩存
    cache = load_did_cache()
    now = datetime.utcnow().isoformat()
    
    if did in cache and "expires" in cache[did] and "document" in cache[did]:
        if cache[did]["expires"] > now:
            return cache[did]["document"]
    
    # 獲取新文件並更新緩存
    try:
        document = fetch_did_document(did)
        cache[did] = {
            "document": document,
            "expires": (datetime.utcnow() + DID_CACHE_EXPIRY).isoformat(),
            "updated": now
        }
        save_did_cache(cache)
        return document
    except Exception as e:
        # 嘗試使用過期緩存
        if did in cache and "document" in cache[did]:
            return cache[did]["document"]
        raise

def load_issuer_public_key(issuer_did: str):
    try:
        did_doc = get_did_document(issuer_did)
        
        if "verificationMethod" not in did_doc:
            raise Exception(f"DID 文件缺少 verificationMethod: {issuer_did}")
        
        # 優先選擇 assertionMethod 中的驗證方法
        if "assertionMethod" in did_doc:
            vm_id = did_doc["assertionMethod"][0]
            if isinstance(vm_id, str):
                vm = next((v for v in did_doc["verificationMethod"] if v["id"] == vm_id), None)
            else:
                vm = vm_id
        else:
            vm = did_doc["verificationMethod"][0]
        
        if not vm:
            raise Exception(f"找不到有效的驗證方法: {issuer_did}")
        
        if "publicKeyJwk" not in vm:
            raise Exception(f"驗證方法缺少 publicKeyJwk: {vm}")
        
        jwk = vm["publicKeyJwk"]
        public_key = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
        return public_key
    
    except Exception as e:
        raise

def is_revoked(vc_id: str, issuer_did: str):
    try:
        # 檢查遠程撤銷列表
        if issuer_did:
            domain = issuer_did.replace("did:web:", "")
            try:
                url = f"https://{domain}/.well-known/revocation-list.json"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    rev_list = response.json()
                    return vc_id in rev_list.get("vc_status", [])
            except Exception:
                pass
        
        # 檢查本地撤銷列表
        rev_list_path = os.path.join(PATH["WELL_KNOWN"], "revocation-list.json")
        if os.path.exists(rev_list_path):
            rev = load_json(rev_list_path)
            return vc_id in rev.get("vc_status", [])
        
        return False
    except Exception:
        return False

def verify_sd_jwt(sd_jwt: str):
    try:
        # 分離 JWT 和 disclosures
        parts = sd_jwt.split("~")
        jwt_part = parts[0]
        disclosures = parts[1:] if len(parts) > 1 else []
        
        # 先解析 JWT 內容以獲取發行者信息
        header = jwt.get_unverified_header(jwt_part)
        payload = jwt.decode(jwt_part, options={"verify_signature": False}, algorithms=["ES256"])
        
        # 確認必要字段
        if 'iss' not in payload:
            return False, "JWT 缺少發行者 (iss) 字段"
        if 'vc' not in payload:
            return False, "JWT 缺少 VC 字段"
        
        issuer_did = payload["iss"]
        vc_id = payload.get("vc", {}).get("id", "")
        
        # 驗證 JWT 簽名
        try:
            pubkey = load_issuer_public_key(issuer_did)
            jwt.decode(jwt_part, key=pubkey, algorithms=["ES256"])
            print("✓ JWT 簽名驗證成功")
        except Exception as e:
            print(f"✗ JWT 簽名驗證失敗: {str(e)}")
            return False, f"簽名驗證失敗: {str(e)}"
        
        # 驗證 disclosures 完整性
        credential_subject = payload["vc"]["credentialSubject"]
        sd_list = credential_subject.get("_sd", [])
        hash_set = set(sd_list) if sd_list else set()
        
        revealed = {}
        
        # 驗證每個 disclosure 的哈希
        for disclosure_b64 in disclosures:
            disclosure_obj = decode_disclosure(disclosure_b64)
            if not disclosure_obj:
                continue
                
            computed_hash = compute_hash(disclosure_obj)
            
            if hash_set and computed_hash not in hash_set:
                print(f"✗ Disclosure Hash 不符合: {disclosure_obj.get('key')}")
                return False, f"Disclosure Hash 不符合: {disclosure_obj.get('key')}"
            
            key = disclosure_obj.get("key", "unknown")
            value = disclosure_obj.get("value")
            if key and key != "unknown":
                revealed[key] = value
        
        print(f"✓ Disclosures 驗證成功")
        
        # 檢查撤銷狀態
        if vc_id and is_revoked(vc_id, issuer_did):
            print(f"✗ VC {vc_id} 已被撤銷")
            return False, "此 VC 已被吊銷"
        
        # 組裝結果
        revealed["holder_did"] = payload["sub"]
        
        for key, value in credential_subject.items():
            if key != "_sd" and key != "id" and key not in revealed:
                revealed[key] = value
        
        return True, revealed

    except Exception as e:
        print(f"✗ 驗證失敗: {str(e)}")
        return False, f"驗證失敗: {str(e)}"
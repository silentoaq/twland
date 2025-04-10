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
DID_CACHE_EXPIRY = timedelta(hours=24)  # 緩存 24 小時

def load_did_cache():
    """加載 DID 文件緩存"""
    if os.path.exists(DID_CACHE_PATH):
        try:
            with open(DID_CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"加載 DID 緩存失敗: {str(e)}")
    return {}

def save_did_cache(cache):
    """保存 DID 文件緩存"""
    try:
        os.makedirs(os.path.dirname(DID_CACHE_PATH), exist_ok=True)
        with open(DID_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print(f"保存 DID 緩存失敗: {str(e)}")

def decode_disclosure(disclosure_b64):
    """解碼單個 disclosure 值"""
    try:
        # 補全 Base64URL 的 padding
        padded = disclosure_b64 + '=' * (-len(disclosure_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode())
        return json.loads(decoded)
    except Exception as e:
        print(f"解碼 disclosure 失敗: {disclosure_b64[:20]}...")
        print(f"錯誤: {str(e)}")
        return None

def compute_hash(disclosure_obj):
    """計算披露對象的哈希值"""
    disclosure_json = json.dumps(disclosure_obj, separators=(",", ":")).encode()
    digest = hashlib.sha256(disclosure_json).digest()
    return "sha-256:" + base64.urlsafe_b64encode(digest).decode().rstrip("=")

def fetch_did_document(did):
    """從網絡獲取 DID 文件"""
    if not did.startswith("did:web:"):
        raise ValueError(f"目前僅支持 did:web 方法: {did}")
    
    domain = did.replace("did:web:", "")
    url = f"https://{domain}/.well-known/did.json"
    
    print(f"從 {url} 獲取 DID 文件...")
    response = requests.get(url, timeout=10)
    
    if response.status_code != 200:
        raise Exception(f"獲取 DID 文件失敗 ({response.status_code}): {response.text}")
    
    return response.json()

def get_did_document(did):
    """獲取 DID 文件，優先使用緩存"""
    # 加載緩存
    cache = load_did_cache()
    now = datetime.utcnow().isoformat()
    
    # 檢查緩存是否有效
    if did in cache and "expires" in cache[did] and "document" in cache[did]:
        if cache[did]["expires"] > now:
            print(f"使用緩存的 DID 文件: {did}")
            return cache[did]["document"]
    
    # 獲取新的 DID 文件
    try:
        document = fetch_did_document(did)
        # 更新緩存
        cache[did] = {
            "document": document,
            "expires": (datetime.utcnow() + DID_CACHE_EXPIRY).isoformat(),
            "updated": now
        }
        save_did_cache(cache)
        return document
    except Exception as e:
        print(f"獲取 DID 文件失敗: {str(e)}")
        # 如果有過期的緩存，也返回
        if did in cache and "document" in cache[did]:
            print(f"使用過期的緩存 DID 文件: {did}")
            return cache[did]["document"]
        raise

def load_issuer_public_key(issuer_did: str):
    """加載發行者的公鑰"""
    try:
        # 獲取 DID 文件
        did_doc = get_did_document(issuer_did)
        
        # 獲取驗證方法
        if "verificationMethod" not in did_doc:
            raise Exception(f"DID 文件缺少 verificationMethod: {issuer_did}")
        
        # 優先選擇 assertionMethod 中的驗證方法
        if "assertionMethod" in did_doc:
            vm_id = did_doc["assertionMethod"][0]
            if isinstance(vm_id, str):
                vm = next((v for v in did_doc["verificationMethod"] if v["id"] == vm_id), None)
            else:
                vm = vm_id  # 某些 DID 文件直接內嵌驗證方法
        else:
            # 否則使用第一個驗證方法
            vm = did_doc["verificationMethod"][0]
        
        if not vm:
            raise Exception(f"找不到有效的驗證方法: {issuer_did}")
        
        # 確保有 publicKeyJwk
        if "publicKeyJwk" not in vm:
            raise Exception(f"驗證方法缺少 publicKeyJwk: {vm}")
        
        jwk = vm["publicKeyJwk"]
        
        # 轉換為 PyJWT 可用的公鑰格式
        public_key = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
        return public_key
    
    except Exception as e:
        print(f"加載發行者公鑰時出錯: {str(e)}")
        traceback.print_exc()
        raise

def is_revoked(vc_id: str, issuer_did: str):
    """檢查憑證是否被撤銷"""
    try:
        # 優先檢查遠程撤銷列表
        if issuer_did:
            domain = issuer_did.replace("did:web:", "")
            try:
                url = f"https://{domain}/.well-known/revocation-list.json"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    rev_list = response.json()
                    return vc_id in rev_list.get("vc_status", [])
            except Exception as e:
                print(f"檢查遠程撤銷列表失敗: {str(e)}")
        
        # 如果遠程檢查失敗，檢查本地撤銷列表
        rev_list_path = os.path.join(PATH["WELL_KNOWN"], "revocation-list.json")
        if os.path.exists(rev_list_path):
            rev = load_json(rev_list_path)
            return vc_id in rev.get("vc_status", [])
        
        return False
    except Exception as e:
        print(f"檢查撤銷狀態時出錯: {str(e)}")
        return False

def verify_sd_jwt(sd_jwt: str):
    """驗證 SD-JWT 格式的憑證"""
    try:
        print(f"開始驗證 SD-JWT: {sd_jwt[:50]}...")
        
        # 1. 分離 JWT 和 disclosures
        parts = sd_jwt.split("~")
        jwt_part = parts[0]
        disclosures = parts[1:] if len(parts) > 1 else []
        
        print(f"JWT部分: {jwt_part[:50]}...")
        print(f"找到 {len(disclosures)} 個揭露部分")
        
        # 2. 解析 JWT header 和 payload (不驗證簽名)
        header = jwt.get_unverified_header(jwt_part)
        payload = jwt.decode(jwt_part, options={"verify_signature": False})
        
        print(f"JWT Header: {header}")
        print(f"發行者: {payload.get('iss')}")
        
        # 3. 確認必要字段
        if 'iss' not in payload:
            return False, "JWT 缺少發行者 (iss) 字段"
        if 'vc' not in payload:
            return False, "JWT 缺少 VC 字段"
        
        issuer_did = payload["iss"]
        vc_id = payload.get("vc", {}).get("id", "")
        
        # 4. 加載發行者公鑰並驗證簽名
        try:
            pubkey = load_issuer_public_key(issuer_did)
            # 僅驗證 JWT 部分，不包括 disclosures
            jwt.decode(jwt_part, key=pubkey, algorithms=["ES256"])
            print("JWT 簽名驗證成功")
        except Exception as e:
            print(f"JWT 簽名驗證失敗: {str(e)}")
            traceback.print_exc()
            return False, f"簽名驗證失敗: {str(e)}"
        
        # 5. 驗證 disclosures
        credential_subject = payload["vc"]["credentialSubject"]
        sd_list = credential_subject.get("_sd", [])
        hash_set = set(sd_list) if sd_list else set()
        
        revealed = {}
        
        # 如果有 disclosures，驗證它們的哈希是否在 _sd 列表中
        for disclosure_b64 in disclosures:
            disclosure_obj = decode_disclosure(disclosure_b64)
            if not disclosure_obj:
                continue
                
            # 計算哈希並檢查是否在 _sd 列表中
            computed_hash = compute_hash(disclosure_obj)
            print(f"Disclosure: {disclosure_obj.get('key')} - Hash: {computed_hash}")
            
            if hash_set and computed_hash not in hash_set:
                print(f"Disclosure Hash 不匹配: {computed_hash}")
                print(f"Expected in: {list(hash_set)[:3]}...")
                # 不匹配時返回錯誤
                return False, f"Disclosure Hash 不符合: {disclosure_obj.get('key')}"
            
            # 收集揭露的聲明
            key = disclosure_obj.get("key", "unknown")
            value = disclosure_obj.get("value")
            if key and key != "unknown":
                revealed[key] = value
        
        # 6. 檢查是否被撤銷
        if vc_id and is_revoked(vc_id, issuer_did):
            print(f"VC {vc_id} 已被撤銷")
            return False, "此 VC 已被吊銷"
        
        # 7. 添加持有者 DID
        revealed["holder_did"] = payload["sub"]
        
        # 8. 添加非選擇性揭露的聲明
        for key, value in credential_subject.items():
            if key != "_sd" and key != "id" and key not in revealed:
                revealed[key] = value
        
        print(f"成功驗證並揭露欄位: {list(revealed.keys())}")
        return True, revealed

    except Exception as e:
        print(f"驗證 SD-JWT 時發生未捕獲的錯誤: {str(e)}")
        traceback.print_exc()
        return False, f"驗證失敗: {str(e)}"
import jwt
import json
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse
import os
from utils.path import PATH, load_json

def decode_disclosure(disclosure_b64):
    padded = disclosure_b64 + '=' * (-len(disclosure_b64) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode())
    return json.loads(decoded)

def compute_hash(disclosure_obj):
    disclosure_json = json.dumps(disclosure_obj, separators=(",", ":")).encode()
    digest = hashlib.sha256(disclosure_json).digest()
    return "sha-256:" + base64.urlsafe_b64encode(digest).decode().rstrip("=")

def load_issuer_public_key(issuer_did: str):
    parsed = urlparse(issuer_did.replace("did:web:", "https://"))
    base_path = parsed.netloc
    did_path = parsed.path.lstrip("/")

    full_path = os.path.join(PATH["WELL_KNOWN"], "did.json")
    if not os.path.exists(full_path):
        raise Exception("找不到 did.json")

    with open(full_path, "r", encoding="utf-8") as f:
        did_doc = json.load(f)

    vm = did_doc["verificationMethod"][0]
    jwk = vm["publicKeyJwk"]

    public_key = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
    return public_key

def is_revoked(vc_id: str):
    rev = load_json(os.path.join(PATH["WELL_KNOWN"], "revocation-list.json"))
    return vc_id in rev.get("vc_status", [])

def verify_sd_jwt(sd_jwt: str):
    try:
        parts = sd_jwt.split("~")
        jwt_part = parts[0]
        disclosures = parts[1:]

        header = jwt.get_unverified_header(jwt_part)
        payload = jwt.decode(jwt_part, options={"verify_signature": False})
        issuer_did = payload["iss"]
        vc_id = payload.get("vc", {}).get("id", "")

        pubkey = load_issuer_public_key(issuer_did)
        jwt.decode(jwt_part, key=pubkey, algorithms=["ES256"])  

        credential_subject = payload["vc"]["credentialSubject"]
        sd_list = credential_subject.get("_sd", [])
        hash_set = set(sd_list)

        for disclosure_b64 in disclosures:
            disclosure_obj = decode_disclosure(disclosure_b64)
            computed_hash = compute_hash(disclosure_obj)
            if computed_hash not in hash_set:
                return False, "Disclosure hash 不符合"
        
        if vc_id and is_revoked(vc_id):
            return False, "此 VC 已被吊銷"

        revealed = {d["key"]: d["value"] for d in map(decode_disclosure, disclosures)}
        revealed["holder_did"] = payload["sub"]

        return True, revealed

    except Exception as e:
        return False, f"驗證失敗：{str(e)}"

import jwt
import base64
import hashlib
import secrets
import json
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from utils.path import PATH

ISSUER_DID = "did:web:twland.ddns.net"

def load_private_key():
    with open(PATH["PRIVATE_KEY"], "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def encode_disclosure(salt, key, value):
    disclosure_obj = {"salt": salt, "key": key, "value": value}
    disclosure_json = json.dumps(disclosure_obj, separators=(",", ":"))
    disclosure_b64 = base64.urlsafe_b64encode(disclosure_json.encode()).decode().rstrip("=")
    disclosure_hash = hashlib.sha256(disclosure_json.encode()).digest()
    disclosure_hash_b64 = base64.urlsafe_b64encode(disclosure_hash).decode().rstrip("=")
    return disclosure_b64, f"sha-256:{disclosure_hash_b64}"

def sign_sd_jwt(claims: dict, holder_did: str, disclose_keys: list = None) -> str:
    disclose_keys = disclose_keys or []
    now = datetime.utcnow()

    vc_uuid = str(uuid.uuid4())
    vc_uri = f"urn:uuid:{vc_uuid}"

    disclosures = []
    sd_hashes = []
    credential_subject = {"id": holder_did}

    for key, value in claims.items():
        if key in disclose_keys:
            credential_subject[key] = value
        else:
            salt = secrets.token_urlsafe(8)
            disclosure_b64, hash_b64 = encode_disclosure(salt, key, value)
            disclosures.append(disclosure_b64)
            sd_hashes.append(hash_b64)

    if sd_hashes:
        credential_subject["_sd"] = sd_hashes

    payload = {
        "iss": ISSUER_DID,
        "sub": holder_did,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=365)).timestamp()),
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": vc_uri,
            "type": ["VerifiableCredential", "PropertyCredential"],
            "issuer": ISSUER_DID,
            "issuanceDate": now.isoformat() + "Z",
            "credentialSubject": credential_subject
        },
        "_sd_alg": "sha-256"
    }

    header = {
        "alg": "ES256",
        "typ": "JWT",
        "kid": f"{ISSUER_DID}#key-1"
    }

    signed_jwt = jwt.encode(payload, load_private_key(), algorithm="ES256", headers=header)

    if disclosures:
        return signed_jwt + "~" + "~".join(disclosures)
    else:
        return signed_jwt

import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# === 設定 ===
DOMAIN = "twland.ddns.net"
DID = f"did:web:{DOMAIN}"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WELL_KNOWN_DIR = os.path.join(BASE_DIR, ".well-known")
KEY_DIR = os.path.join(BASE_DIR, "keys")

# === 建立資料夾 ===
os.makedirs(WELL_KNOWN_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)

# === 產生金鑰對 (ECC P-256) ===
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# === 存私鑰 PEM ===
with open(os.path.join(KEY_DIR, "issuer_private_key.pem"), "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# === 存公鑰 PEM ===
with open(os.path.join(KEY_DIR, "issuer_public_key.pem"), "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# === JWK 格式 ===
numbers = public_key.public_numbers()
x = base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big")).decode("utf-8").rstrip("=")
y = base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big")).decode("utf-8").rstrip("=")

jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": x,
    "y": y
}

# === DID Document ===
did_document = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": DID,
    "verificationMethod": [{
        "id": f"{DID}#key-1",
        "type": "JsonWebKey2020",
        "controller": DID,
        "publicKeyJwk": jwk
    }],
    "assertionMethod": [f"{DID}#key-1"],
    "service": [
        {
            "id": f"{DID}#vci",
            "type": "OpenID4VCIService",
            "serviceEndpoint": f"https://{DOMAIN}/oid4vci/credential"
        },
        {
            "id": f"{DID}#revocation",
            "type": "CredentialStatusList2021",
            "serviceEndpoint": f"https://{DOMAIN}/.well-known/revocation-list.json"
        }
    ]
}

with open(os.path.join(WELL_KNOWN_DIR, "did.json"), "w", encoding="utf-8") as f:
    json.dump(did_document, f, indent=2)

# === OID4VCI Metadata ===
metadata = {
    "credential_issuer": f"https://{DOMAIN}",
    "credential_endpoint": f"https://{DOMAIN}/oid4vci/credential",
    "credentials_supported": [{
        "format": "vc+sd-jwt",
        "id": "twland-property-credential",
        "cryptographic_binding_methods_supported": ["did"],
        "cryptographic_suites_supported": ["ES256"],
        "display": [{
            "name": "Property Credential",
            "locale": "en"
        }]
    }],
    "credential_issuer_metadata": {
        "pre-authorized_grant_supported": True,
        "user_pin_required": False,
        "authorization_servers": [],
        "credential_configuration_ids_supported": ["twland-property-credential"],
        "credential_issuer_signing_alg_values_supported": ["ES256"]
    }
}

with open(os.path.join(WELL_KNOWN_DIR, "openid-credential-issuer.json"), "w", encoding="utf-8") as f:
    json.dump(metadata, f, indent=2)

# === 初始 revocation-list.json ===
revocation_list = {
    "issuer": DID,
    "vc_status": []
}

with open(os.path.join(WELL_KNOWN_DIR, "revocation-list.json"), "w", encoding="utf-8") as f:
    json.dump(revocation_list, f, indent=2)

print("生成.well-known相關文件")

import os
import json

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

PATH = {
    "SESSIONS": os.path.join(BASE_DIR,  "data", "sessions.json"),
    "ISSUED": os.path.join(BASE_DIR, "data", "issued.json"),
    "OFFER": os.path.join(BASE_DIR, "data", "offers.json"),
    "REVOKED": os.path.join(BASE_DIR, "data", "revoked.json"),
    "QR_DIR": os.path.join(BASE_DIR, "static", "qrcodes"),
    "WELL_KNOWN": os.path.join(BASE_DIR, ".well-known"),
    "PRIVATE_KEY": os.path.join(BASE_DIR, "keys", "issuer_private_key.pem"),
    "PROPERTY_DB": os.path.join(BASE_DIR, "data", "properties.json")
}

def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

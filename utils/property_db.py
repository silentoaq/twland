import json
from utils.path import PATH

def get_all_properties():
    with open(PATH["PROPERTY_DB"], "r", encoding="utf-8") as f:
        return json.load(f)

def get_properties_for_holder(name, national_id):
    all_props = get_all_properties()
    return [p for p in all_props if p["owner_name"] == name and p["owner_national_id"] == national_id]

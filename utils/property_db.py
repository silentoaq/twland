import json
import os
from utils.path import PATH

def get_all_properties():
    """獲取所有房產資料"""
    try:
        with open(PATH["PROPERTY_DB"], "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # 如果檔案不存在或內容為空，則初始化範例資料
        sample_properties = [
            {
                "property_id": "A-10001",
                "owner_name": "張大明",
                "owner_id_number": "A123456789",
                "address": "台北市中正區忠孝東路一段100號",
                "land_number": "中正區忠孝段一小段100地號",
                "building_number": "中正區忠孝段一小段100建號",
                "rights_scope": "全部",
                "rights_portion": "1/1",
                "certificate_number": "中市字第123456號",
                "certificate_date": "2023-01-15",
                "area": {
                    "land": "50.5坪",
                    "building": "42.3坪"
                },
                "use": "住宅",
                "notes": "依都市計畫為第三種住宅區"
            }
        ]
        # 確保資料目錄存在
        os.makedirs(os.path.dirname(PATH["PROPERTY_DB"]), exist_ok=True)
        # 保存範例資料
        with open(PATH["PROPERTY_DB"], "w", encoding="utf-8") as f:
            json.dump(sample_properties, f, ensure_ascii=False, indent=2)
        return sample_properties

def get_properties_for_holder(name, id_number):
    """依據持有人資訊查詢房產資料"""
    all_props = get_all_properties()
    return [p for p in all_props if p["owner_name"] == name and p["owner_id_number"] == id_number]

def get_property_by_id(property_id):
    """根據房產ID獲取房產資訊"""
    all_props = get_all_properties()
    return next((p for p in all_props if p["property_id"] == property_id), None)

def add_property(property_data):
    """新增房產資料"""
    all_props = get_all_properties()
    # 檢查 property_id 是否已存在
    if any(p["property_id"] == property_data["property_id"] for p in all_props):
        return False, "房產ID已存在"
    all_props.append(property_data)
    with open(PATH["PROPERTY_DB"], "w", encoding="utf-8") as f:
        json.dump(all_props, f, ensure_ascii=False, indent=2)
    return True, "新增房產成功"

def update_property(property_id, updated_data):
    """更新房產資料"""
    all_props = get_all_properties()
    for i, prop in enumerate(all_props):
        if prop["property_id"] == property_id:
            # 更新資料，但保留 property_id
            updated_data["property_id"] = property_id
            all_props[i] = updated_data
            with open(PATH["PROPERTY_DB"], "w", encoding="utf-8") as f:
                json.dump(all_props, f, ensure_ascii=False, indent=2)
            return True, "房產資料更新成功"
    return False, "找不到該房產ID"
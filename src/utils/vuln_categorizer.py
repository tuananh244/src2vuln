import json
import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("VulnCategorizer")

class VulnerabilityCategorizer:
    def __init__(self, mapping_file_path: str = "/home/tuananh/Desktop/test/src2vuln/data/cwe_labels_only.json"):
        self.mapping = {}
        self.load_mapping(mapping_file_path)

# 1. Cập nhật load_mapping để dùng normalize_cwe_id
    def load_mapping(self, file_path: str):
        if not os.path.exists(file_path):
            # Dùng đường dẫn tuyệt đối để tránh lỗi path tương đối
            abs_path = os.path.abspath(file_path)
            print(f"⚠️ Warning: File not found at {abs_path}")
            return

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for item in data:
                # FIX: Chuẩn hóa ID ngay khi load
                raw_id = item.get("id")
                cwe_id = self.normalize_cwe_id(raw_id)
                label = item.get("label", "Uncategorized").strip()
                
                if cwe_id != "UNKNOWN":
                    self.mapping[cwe_id] = label
            
            print(f"✅ Loaded {len(self.mapping)} CWEs. Has CWE-20? {'20' in self.mapping}")
            
        except Exception as e:
            print(f"❌ Error loading JSON: {e}")

    # 2. Cập nhật normalize_cwe_id để xử lý nhiều loại rác hơn
    def normalize_cwe_id(self, cwe_raw: any) -> str:
        if not cwe_raw:
            return "UNKNOWN"
        
        # Chuyển về string
        s = str(cwe_raw).upper().strip()
        
        # Xử lý nếu input bị bọc trong list string "['CWE-20']" (lỗi thường gặp khi parse log)
        s = s.replace("['", "").replace("']", "").replace('["', '').replace('"]', '')

        # Bỏ prefix
        s = s.replace("CWE-", "").replace("CWE_", "").replace("CWE", "")
        
        # Xử lý số thực 20.0 -> 20
        if "." in s:
            try:
                s = str(int(float(s)))
            except:
                pass

        # Bỏ số 0 ở đầu
        if s.isdigit():
            s = str(int(s))
            
        return s

    def get_category(self, cwe_raw: any, vuln_name_hint: str = "") -> str:
        cwe_id = self.normalize_cwe_id(cwe_raw)
        
        # Debug nhẹ để xem nó đang tìm key gì (nếu cần)
        # logger.debug(f"Categorizing: Raw='{cwe_raw}' -> Normalized='{cwe_id}'")

        # 1. Tra cứu trong file mapping
        if cwe_id in self.mapping:
            return self.mapping[cwe_id]

        # 2. Fallback logic
        hint = vuln_name_hint.lower()
        
        # Lưu ý: Các số trong list này cũng phải viết không có số 0 ở đầu
        if "xss" in hint or cwe_id in ["79", "80", "81", "116"]:
            return "Cross-Site Scripting (XSS)"
        if "sql" in hint or cwe_id in ["89", "564"]:
            return "SQL Injection"
        if "remote code" in hint or "command" in hint or cwe_id in ["78", "77", "94"]:
            return "Remote Code Execution (RCE)"
        if "upload" in hint or cwe_id in ["434"]:
            return "Unrestricted File Upload"
        if "csrf" in hint or cwe_id in ["352"]:
            return "CSRF"
        if "ssrf" in hint or cwe_id in ["918"]:
            return "SSRF"
            
        return "Other Vulnerabilities"

# Singleton instance
categorizer = VulnerabilityCategorizer()
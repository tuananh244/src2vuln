import json
import logging
import re
import os
from pathlib import Path
from typing import Any, Dict, List, Union

# Khởi tạo logger
logger = logging.getLogger("DataProcessor")

class DataProcessor:
    """
    Utility Class xử lý dữ liệu: JSON Parsing, File Reading, SARIF Parsing, Normalization.
    (Static Methods Version)
    """

    # ==========================================================
    # 1. JSON UTILS
    # ==========================================================
    
    @staticmethod
    def clean_code_snippet(text: str) -> str:
        """
        [NEW] Loại bỏ các tag markdown (```python, ```bash, ```) khỏi chuỗi code.
        Dùng để làm sạch payload trước khi thực thi.
        """
        if not isinstance(text, str):
            return text
            
        # Regex tìm:
        # ^```[a-zA-Z]*\s* : Tìm ```python, ```bash... ở đầu chuỗi (kèm xuống dòng)
        # \s*```$          : Tìm ``` ở cuối chuỗi
        pattern = r"^```[a-zA-Z]*\s*|\s*```$"
        
        # re.MULTILINE để ^ và $ khớp với đầu/cuối của nội dung text
        cleaned = re.sub(pattern, "", text.strip(), flags=re.MULTILINE)
        
        return cleaned.strip()

    @staticmethod
    def safe_extract_json(text: str) -> Union[Dict, List, None]:
        """
        Trích xuất JSON từ chuỗi văn bản hỗn độn (Markdown, Text...).
        Sử dụng thuật toán Stack-based mạnh mẽ.
        """
        if not text:
            return None

        text = str(text) # Ép kiểu string

        # Cách 1: Parse trực tiếp
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Cách 2: Regex Markdown Block
        match = re.search(r'```(?:json)?\s*([\[\{].*?[\]\}])\s*```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Cách 3: Stack Scanning (Tìm cặp ngoặc {} hoặc [] ngoài cùng)
        stack = []
        start_index = -1
        
        for i, char in enumerate(text):
            if char in ('{', '['):
                if not stack:
                    start_index = i
                stack.append(char)
            elif char in ('}', ']'):
                if stack:
                    last = stack[-1]
                    if (last == '{' and char == '}') or (last == '[' and char == ']'):
                        stack.pop()
                        if not stack:
                            try:
                                return json.loads(text[start_index : i+1])
                            except json.JSONDecodeError:
                                pass
                    else:
                        stack = [] 
        
        return None

    # ==========================================================
    # 2. FILE SYSTEM UTILS
    # ==========================================================

    @staticmethod
    def read_source_line(base_path: Union[Path, str], relative_path: str, line_num: int) -> str:
        """
        Đọc dòng code cụ thể từ file an toàn.
        Hỗ trợ tìm file trong folder tạm hoặc đường dẫn gốc.
        """
        if not line_num or line_num < 1:
            return "[Invalid line number]"

        target_file = None
        
        # Chuyển đổi input
        p_base = Path(base_path) if base_path else Path(".")
        p_rel = Path(relative_path)

        # --- CHIẾN THUẬT TÌM FILE (Logic thông minh) ---
        
        # Case A: Base là thư mục -> Ghép trực tiếp
        if p_base.is_dir():
            try_1 = (p_base / p_rel).resolve()
            if try_1.exists() and try_1.is_file():
                target_file = try_1

        # Case B: Base là file (Single File Mode)
        if not target_file and p_base.is_file():
            # Kiểm tra nếu p_rel chính là tên file của p_base (VD: code.py == code.py)
            if p_rel.name == p_base.name:
                target_file = p_base
            else:
                # Thử tìm trong cùng thư mục cha
                try_2 = p_base.parent / p_rel.name
                if try_2.exists():
                    target_file = try_2

        # Case C: Relative path thực chất là Absolute path
        if not target_file and p_rel.is_absolute() and p_rel.exists():
            target_file = p_rel

        # Đọc file nếu tìm thấy
        if target_file:
            try:
                # Thử utf-8 trước
                content = target_file.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                if line_num <= len(lines):
                    return lines[line_num - 1].strip()
            except Exception:
                pass
        
        return "[Source unavailable]"

    @staticmethod
    def add_line_numbers(code: str, start_line: int = 1) -> str:
        """Thêm số dòng vào trước mỗi dòng code."""
        if not code: 
            return ""
        
        code_str = str(code)
        lines = code_str.split('\n')
        return "\n".join([f"{start_line + i:<4} | {line}" for i, line in enumerate(lines)])

    @staticmethod
    def normalize_code_flow(flow_list: List[Dict], target_repo: str) -> List[Dict]:
        """Làm sạch Code Flow."""
        if not flow_list: return []
        cleaned = []
        last_line = -1
        
        for step in flow_list:
            cur_line = step.get("line")
            if cur_line == last_line: continue
            
            if not step.get("code"): step["code"] = "[Code snippet not captured]"
            
            fpath = step.get("file")
            if fpath and target_repo and target_repo in str(fpath):
                try: 
                    if os.path.isabs(fpath):
                        step["file"] = os.path.relpath(fpath, target_repo)
                except: pass
            
            cleaned.append(step)
            last_line = cur_line
        return cleaned

    # ==========================================================
    # 3. SARIF PARSER (STATIC VERSION)
    # ==========================================================

    @staticmethod
    def _extract_sarif_location(loc_obj, artifacts, base_path):
        """Private helper extract location details."""
        phys = loc_obj.get("physicalLocation", {}) if "physicalLocation" not in loc_obj else loc_obj["physicalLocation"]
        art_loc = phys.get("artifactLocation", {})
        
        uri = art_loc.get("uri")
        idx = art_loc.get("index")
        
        if not uri and idx is not None and 0 <= idx < len(artifacts):
            uri = artifacts[idx].get("location", {}).get("uri")
            
        region = phys.get("region", {})
        line = region.get("startLine")
        snippet = region.get("snippet", {}).get("text")
        
        if not snippet and line and uri:
            snippet = DataProcessor.read_source_line(base_path, uri, line)
            
        return {"file": uri, "line": line, "snippet": snippet}

    @staticmethod
    def parse_sarif_file(sarif_path: Path, job_context: Dict) -> List[Dict]:
        """Parse file SARIF và trả về danh sách Hypothesis."""
        logger.info(f"Parsing SARIF file: {sarif_path}")  # Dùng logger global thay vì self.logger
        
        if not sarif_path.exists():
            logger.warning(f"SARIF missing: {sarif_path}")
            return []

        try:
            content = sarif_path.read_text(encoding="utf-8", errors="replace")
            sarif_data = json.loads(content)
        except Exception as e:
            logger.error(f"SARIF decode error: {e}")
            return []

        hypos = []
        base_path = Path(job_context["path"])

        for run in sarif_data.get("runs", []):
            artifacts = run.get("artifacts", [])
            rules = run.get("tool", {}).get("driver", {}).get("rules", [])
            
            rule_map = {r.get("id"): r for r in rules}

            for idx, res in enumerate(run.get("results", [])):
                rule_id = res.get("ruleId")
                rule_info = rule_map.get(rule_id, {})
                
                # Logic lấy type/CWE giữ nguyên...
                vuln_type = rule_info.get("shortDescription", {}).get("text") or rule_info.get("name") or rule_id or "Unknown"
                
                cwe = "CWE-UNKNOWN"
                for t in rule_info.get("properties", {}).get("tags", []):
                    if "external/cwe" in t.lower():
                        cwe = t.split("/")[-1].upper() if "/" in t else t
                        break
                
                # [FIX 2] Gọi hàm con phải dùng TênClass.TênHàm
                sink = {}
                if res.get("locations"):
                    sink = DataProcessor._extract_sarif_location(res["locations"][0], artifacts, base_path)

                code_flow = []
                if res.get("codeFlows"):
                    tflows = res["codeFlows"][0].get("threadFlows", [])
                    if tflows:
                        for step in tflows[0].get("locations", []):
                            loc = step.get("location", {})
                            msg = loc.get("message", {}).get("text", "Step")
                            
                            # [FIX 2] Gọi hàm con phải dùng TênClass.TênHàm
                            step_data = DataProcessor._extract_sarif_location(loc, artifacts, base_path)
                            
                            if step_data["file"]:
                                code_flow.append({
                                    "file": step_data["file"],
                                    "line": step_data["line"],
                                    "code": step_data["snippet"],
                                    "step_description": msg
                                })

                source = {}
                if code_flow:
                    source = {"file": code_flow[0]["file"], "line": code_flow[0]["line"]}

                hypos.append({
                    "vuln_id": f"{job_context['name']}-{idx}",
                    "rule_id": rule_id,
                    "type": vuln_type,
                    "cwe": cwe,
                    "severity": res.get("level", "warning"),
                    "description": res.get("message", {}).get("text", ""),
                    "sink": sink,
                    "source": source,
                    "code_flow": code_flow,
                    "job": job_context
                })
        return hypos
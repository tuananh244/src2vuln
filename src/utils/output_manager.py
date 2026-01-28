import os
import json
import logging
import datetime
from pathlib import Path
from typing import Union, List, Dict, Any

import os
import json
import logging
import datetime
from pathlib import Path
from typing import Union, List, Dict, Any

class OutputManager:
    """
    Quản lý Output System: Log, JSON, Markdown, Folder paths.
    """

    # [FIX] Thêm tham số artifact_path (đường dẫn cụ thể)
    def __init__(self, repo_name: str, base_output_path: str = "output", artifact_path: str = None):
        self.repo_name = repo_name
        
        # LOGIC MỚI: Nếu có đường dẫn cụ thể (từ job['output_dir']), dùng luôn
        if artifact_path:
            self.repo_dir = Path(artifact_path)
            # Nếu đường dẫn chưa tuyệt đối, biến nó thành tuyệt đối
            if not self.repo_dir.is_absolute():
                self.repo_dir = Path.cwd() / self.repo_dir
        else:
            # LOGIC CŨ: Tự ghép output/repo_name
            base = Path(base_output_path)
            if not base.is_absolute():
                base = Path.cwd() / base_output_path
            self.repo_dir = base / repo_name

        # 1. Tạo folder gốc
        self.repo_dir.mkdir(parents=True, exist_ok=True)

        # 2. Tạo folder logs
        self.log_dir = self.repo_dir / "logs"
        self.log_dir.mkdir(exist_ok=True)
        self.log_file = self.log_dir / "pipeline.log"

        # 3. Tạo folder PoC
        self.poc_dir = self.repo_dir / "PoC"
        self.poc_dir.mkdir(exist_ok=True)

        # Logger
        self.logger = logging.getLogger(f"OutputManager-{repo_name}")

    # ================================================================
    # PATH HELPERS
    # ================================================================

    def get_repo_dir(self) -> Path:
        return self.repo_dir

    def get_agent_dir(self, agent_name: str) -> Path:
        """Tạo folder riêng cho Agent (VD: output/repo/CodeQL-Agent)."""
        agent_dir = self.repo_dir / agent_name
        agent_dir.mkdir(parents=True, exist_ok=True)
        return agent_dir
        
    def get_poc_dir(self) -> Path:
        return self.poc_dir
    
    def get_temp_dir(self, agent_name: str) -> Path:
        """Tạo folder tạm ẩn."""
        tmp_path = self.repo_dir / f".{agent_name}_data"
        tmp_path.mkdir(exist_ok=True)
        return tmp_path

    # ================================================================
    # WRITERS
    # ================================================================

    def append_log(self, agent_name: str, message: str):
        """Ghi log vào file pipeline.log."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{agent_name}] {message}\n"
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception:
            pass

    def write_json(self, agent_name: str, filename: str, data: Any):
        """Ghi dữ liệu ra file JSON."""
        try:
            target_dir = self.get_agent_dir(agent_name)
            file_path = target_dir / filename
            
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Failed to write JSON {filename}: {e}")

    def write_markdown(self, filename: str, content: str):
        """Ghi file Markdown."""
        try:
            if filename.lower().startswith("poc"):
                target_dir = self.poc_dir
            else:
                target_dir = self.repo_dir
                
            if not filename.endswith(".md"): 
                filename += ".md"
                
            file_path = target_dir / filename
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            self.logger.error(f"Failed to write MD {filename}: {e}")

    # ================================================================
    # ALIASES (Tương thích ngược & Fix lỗi filename_suffix)
    # ================================================================
    
    def save_agent_output(self, agent_name: str, data: Any, filename: str = None, filename_suffix: str = ""):
        """
        Alias trỏ về write_json.
        [FIX] Hỗ trợ cả tham số 'filename' lẫn 'filename_suffix'.
        """
        final_name = filename

        # Nếu filename chưa có, hoặc user dùng suffix -> tự tạo tên file
        if not final_name:
            if filename_suffix:
                final_name = f"{agent_name}_{filename_suffix}.json"
            else:
                final_name = f"{agent_name}.json"
        
        # Đảm bảo đuôi .json
        if not final_name.endswith(".json"):
             final_name += ".json"
             
        self.write_json(agent_name, final_name, data)

    def write_poc(self, filename: str, content: str):
        self.write_markdown(filename, content)
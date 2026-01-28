import logging
import shutil
import os
from pathlib import Path
from src.utils.codeql_runner import run_command
from src.utils.output_manager import OutputManager
from src.utils.data_processors import DataProcessor

logger = logging.getLogger("Scanner-CodeQL")

# [FIX] Bảng Map ngôn ngữ chuẩn CodeQL
LANG_MAP = {
    "py": "python",
    "python": "python",
    "js": "javascript",
    "javascript": "javascript",
    "ts": "javascript",
    "typescript": "javascript",
    "java": "java",
    "cpp": "cpp",
    "c": "cpp",
    "cs": "csharp",
    "go": "go",
    "rb": "ruby"
}

async def logic_codeql_scan(job: dict) -> list:
    """
    Logic cốt lõi: Chạy CodeQL và trả về danh sách lỗ hổng.
    Dùng cho cả chế độ Queue Worker và Sequential.
    """
    name = job["name"]
    raw_lang = job["language"]
    
    # [FIX] Chuẩn hóa ngôn ngữ (vd: py -> python)
    lang = LANG_MAP.get(raw_lang.lower(), raw_lang)
    
    # Chuyển path thành Path object để xử lý
    original_path = Path(job["path"])
    
    # 1. Setup Output Manager
    AGENT_NAME = "codeQL-Agent"
    
    # [FIX] Lấy output_dir chính xác từ job context (do QueueManager tạo)
    # Đây là đường dẫn dạng: output/SecurityEval/CWE-xxx
    job_output_dir = job.get("output_dir")
    
    # Khởi tạo OutputManager với artifact_path
    out_man = OutputManager(repo_name=name, artifact_path=job_output_dir)
    
    # Tạo folder riêng cho Agent (Dùng hàm của class, không truy cập biến nội bộ)
    agent_dir = out_man.get_agent_dir(AGENT_NAME)

    db_path = agent_dir / f"{name}-{lang}-db"
    sarif_path = agent_dir / f"{name}.sarif"

    logger.info(f"[{name}] 🔍 Starting CodeQL Scan (Lang: {lang})...")
    out_man.append_log(AGENT_NAME, f"Starting CodeQL scan for {original_path}")

    # ======================================================
    # [FIX] XỬ LÝ LỖI SINGLE FILE & SOURCE ROOT
    # ======================================================
    actual_source_root = original_path

    if original_path.is_file():
        # Tạo thư mục tạm để chứa file code
        temp_src_dir = agent_dir / "src_temp"
        if temp_src_dir.exists():
            shutil.rmtree(temp_src_dir)
        temp_src_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy file code vào đó
        dest_file = temp_src_dir / original_path.name
        try:
            shutil.copy(original_path, dest_file)
            actual_source_root = temp_src_dir
            logger.info(f"[{name}] Single File Mode. Copied to temp root: {actual_source_root}")
        except Exception as e:
            logger.error(f"Failed to copy single file: {e}")
            return []
    else:
        # Nếu là folder thì giữ nguyên
        logger.info(f"[{name}] Project Mode. Source: {actual_source_root}")

    # ======================================================

    # 2. Clean old DB
    if db_path.exists():
        shutil.rmtree(db_path)

    # 3. Create Database
    logger.info(f"[{name}] Building CodeQL DB...")
    
    ok_create = await run_command([
        "codeql", "database", "create", str(db_path),
        f"--language={lang}",                 # Dùng lang đã chuẩn hóa
        f"--source-root={actual_source_root}", # Dùng source root thực tế (temp hoặc gốc)
        "--overwrite"
    ], progress=True, phase="DB Init")

    if not ok_create:
        msg = "❌ CodeQL DB Creation failed."
        logger.error(f"[{name}] {msg}")
        out_man.append_log(AGENT_NAME, msg)
        return [] 

    # 4. Analyze
    # Đường dẫn Suite (Hardcode hoặc fallback default)
    suite_path = {
        "python": "/home/tuananh/Desktop/codeql/python/ql/src/codeql-suites/python-security-and-quality.qls",
        "java":   "codeql/java-queries" 
    }.get(lang)

    # Nếu không tìm thấy suite config cứng, thử dùng pack mặc định của CodeQL
    if not suite_path or not os.path.exists(suite_path):
        suite_path = f"codeql/{lang}-queries" # Fallback sang codeql pack chuẩn
        logger.warning(f"[{name}] Custom suite not found. Trying default pack: {suite_path}")

    logger.info(f"[{name}] Analyzing Queries...")
    ok_analyze = await run_command([
        "codeql", "database", "analyze", str(db_path),
        suite_path,
        "--format=sarifv2.1.0",
        f"--output={sarif_path}",
        "--download" # Tự động tải query pack nếu thiếu
    ], progress=True, phase="Analyzing")

    if not ok_analyze:
        msg = "❌ CodeQL Analysis failed."
        logger.error(f"[{name}] {msg}")
        out_man.append_log(AGENT_NAME, msg)
        return []

    # 5. Parse & Save Results
    logger.info(f"[{name}] Parsing SARIF...")
    
    try:
        # Sử dụng static method của DataProcessor
        findings = DataProcessor.parse_sarif_file(sarif_path, job)
        
        count = len(findings)
        logger.info(f"[{name}] ✅ CodeQL Finished. Found {count} issues.")
        out_man.append_log(AGENT_NAME, f"Finished. Found {count} issues.")
        
        # Lưu kết quả
        out_man.save_agent_output(AGENT_NAME, findings)
        return findings

    except Exception as e:
        logger.error(f"[{name}] Error parsing SARIF: {e}")
        out_man.append_log(AGENT_NAME, f"Error parsing SARIF: {e}")
        return []
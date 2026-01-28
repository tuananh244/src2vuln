import logging
import asyncio
import json
import os
from pathlib import Path
from typing import List, Dict, Union, Any
from src.utils.output_manager import OutputManager

logger = logging.getLogger("Collector")

def _deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Helper: Loại bỏ trùng lặp dựa trên bộ ba (CWE, File, Line).
    Giữ lại finding có nhiều thông tin nhất.
    """
    unique_map = {}
    
    for f in findings:
        # 1. Tạo Key định danh
        v_type = str(f.get("type", "unknown")).lower().strip()
        v_cwe = str(f.get("cwe", "unknown")).lower().strip()
        
        # Lấy file path (ưu tiên file_path, fallback sang sink)
        raw_file = f.get("file_path") or f.get("sink", {}).get("file", "")
        v_file = str(raw_file).strip()
        
        # Chuẩn hóa tên file (chỉ lấy tên file, bỏ folder path)
        try:
            v_filename = Path(v_file).name
        except:
            v_filename = v_file
        
        # Lấy line number
        raw_line = f.get("location_hint") or f.get("sink", {}).get("line", "?")
        v_line = str(raw_line).strip()
        
        # Key: CWE + Filename + Line (VD: cwe-89|app.py|36)
        key = f"{v_cwe}|{v_filename}|{v_line}"
        
        # 2. Logic Gộp/Thay thế
        if key not in unique_map:
            unique_map[key] = f
        else:
            # Nếu đã tồn tại, kiểm tra xem cái mới có tốt hơn không?
            existing = unique_map[key]
            
            # Ưu tiên tool CodeQL vì độ tin cậy cao hơn LLM ở vị trí
            if f.get("source_tool") == "CodeQL" and existing.get("source_tool") != "CodeQL":
                unique_map[key] = f
            # Hoặc ưu tiên cái nào mô tả dài hơn (nếu cùng tool hoặc đều là LLM)
            elif len(str(f.get("details", ""))) > len(str(existing.get("details", ""))):
                unique_map[key] = f
                
    return list(unique_map.values())

async def logic_collector_merge(
    job: Dict, 
    codeql_results: Union[List, None], 
    llm_results: Union[List, None],
    target_queue: asyncio.Queue = None
) -> List[Dict]:
    """
    Collector Logic:
    1. Merge kết quả CodeQL & LLM.
    2. Lọc trùng (Deduplicate).
    3. Lưu Snapshot.
    4. Đẩy vào Queue tiếp theo (nếu có).
    """
    repo_name = job.get("name", "Unknown-Repo") 
    
    # [FIX] Lấy đường dẫn output chính xác từ Job
    # Đây là đường dẫn mà QueueManager đã tính toán (VD: output/SecurityEval/CWE-xxx)
    job_output_dir = job.get("output_dir")
    
    # Khởi tạo OutputManager với đường dẫn cụ thể
    out_man = OutputManager(repo_name=repo_name, artifact_path=job_output_dir)

    logger.info(f"🔹 [Collector] Processing results for {repo_name}...")

    # 1. Fail-safe normalization
    safe_codeql = codeql_results if isinstance(codeql_results, list) else []
    safe_llm = llm_results if isinstance(llm_results, list) else []
    
    # 2. Raw Merge
    raw_findings = safe_codeql + safe_llm
    count_raw = len(raw_findings)
    
    # 3. Deduplication
    final_findings = _deduplicate_findings(raw_findings)
    count_final = len(final_findings)
    count_dup = count_raw - count_final
    
    # 4. Logging & Snapshot
    log_msg = (
        f"Merged: CodeQL({len(safe_codeql)}) + LLM({len(safe_llm)}) = {count_raw}. "
        f"Unique: {count_final} (Removed {count_dup} duplicates)."
    )
    logger.info(f"   -> {log_msg}")
    
    out_man.append_log("Collector", log_msg)
    
    # Lưu file kết quả gộp
    try:
        out_man.write_json("Collector", "combined_raw_findings.json", final_findings)
    except Exception as e:
        logger.error(f"❌ Error saving combined findings: {e}")

    # 5. Prepare Payload for Next Step
    updated_context = job.copy()
    updated_context["total_findings"] = count_final
    
    next_payload = {
        "name": repo_name,
        "path": job["path"],
        "output_dir": job["output_dir"],
        "findings": final_findings,
        "job_context": updated_context 
    }

    # 6. Push to Queue (Nếu được truyền vào)
    if target_queue:
        await target_queue.put(next_payload)
        logger.info(f"   -> 📨 Pushed {count_final} items to next Queue.")

    return final_findings
#!/usr/bin/env python3
"""
queue_manager.py
Unified Orchestrator / Facade:
- Điều phối luồng chạy (Pipeline).
- [UPDATED] Tự động xử lý Single File (Tạo temp folder để CodeQL/LLM chạy ổn định).
"""

import asyncio
import logging
import time
import shutil  # [NEW] Cần để copy file
from pathlib import Path
from typing import Dict, List

# --- IMPORTS TỪ CÁC MODULE LOGIC (IMPL) ---
try:
    from src.agents.impl.scanner_codeql import logic_codeql_scan
    from src.agents.impl.scanner_llm import logic_llm_batch_scan
    from src.agents.impl.collector import logic_collector_merge
    from src.agents.impl.debate import logic_debate_pipeline
    from src.agents.impl.planner import step_planning
    from src.agents.impl.executor_old import step_execution
    from src.agents.impl.verifier import step_verification
    from src.agents.impl.reporter import step_reporting
except ImportError as e:
    print(f"❌ [QueueManager] Missing Implementation Modules: {e}")
    # Dummy fallback để không crash khi import lỗi
    async def logic_codeql_scan(*a): return []
    async def logic_llm_batch_scan(*a): return []
    async def logic_collector_merge(*a, **k): return []
    async def logic_debate_pipeline(*a): return []
    async def step_planning(*a, **k): return []
    async def step_execution(*a): return []
    async def step_verification(*a): return []
    async def step_reporting(*a): return {}

from src.utils.output_manager import OutputManager
from src.utils.input_manager import get_dataset_files

logger = logging.getLogger("QueueManager")

# ====================================================================
# PART 1: SEQUENTIAL RUNNER (CHẠY 1 JOB CỤ THỂ)
# ====================================================================

async def run_single_repo_pipeline(job: Dict):
    """
    Chạy pipeline cho 1 đối tượng duy nhất (1 file code HOẶC 1 folder project).
    [UPDATED] Thêm logic xử lý Single File -> Temp Folder.
    """
    start_time = time.time()
    repo_name = job["name"]
    out_dir = Path(job["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Init Output Manager
    out_man = OutputManager(repo_name=repo_name)
    out_man.append_log("System", f"Pipeline Started for: {job['path']}")
    
    logger.info(f"🚀 STARTING PIPELINE: {repo_name} ({job.get('repo_type', 'unknown')})")

    # =================================================================
    # [NEW LOGIC] PRE-PROCESS: XỬ LÝ PATH & LANGUAGE CHO SINGLE FILE
    # =================================================================
    original_path = Path(job["path"])
    
    # Map ngôn ngữ chuẩn cho CodeQL (tránh lỗi 'py' not found)
    LANG_MAP = {
        "py": "python", "js": "javascript", "ts": "javascript", 
        "java": "java", "cpp": "cpp", "c": "cpp", "cs": "csharp"
    }
    raw_lang = job.get("language", "python")
    job["language"] = LANG_MAP.get(raw_lang, raw_lang)

    # Nếu input là FILE, ta cần tạo môi trường giả lập Folder để CodeQL/LLM không bị lỗi
    if original_path.is_file():
        logger.info(f"🔄 [Pre-Process] Detected Single File: {original_path.name}")
        
        # 1. Tạo folder tạm trong output directory
        temp_src_dir = out_dir / "src_temp_for_scan"
        if temp_src_dir.exists():
            shutil.rmtree(temp_src_dir)
        temp_src_dir.mkdir(parents=True, exist_ok=True)
        
        # 2. Copy file vào folder tạm
        try:
            shutil.copy(original_path, temp_src_dir / original_path.name)
            
            # 3. [QUAN TRỌNG] Cập nhật job['path'] trỏ vào folder tạm
            # Việc này đánh lừa CodeQL và LLM rằng đây là một Project Folder
            job["path"] = str(temp_src_dir)
            job["original_path"] = str(original_path) # Lưu lại path gốc để report
            
            logger.info(f"   -> Created temp env at: {temp_src_dir}")
            logger.info(f"   -> CodeQL/LLM will scan this temp folder.")
        except Exception as e:
            logger.error(f"❌ Failed to prepare temp environment: {e}")
            return {"results": [], "metrics": {}}

    # =================================================================

    # 2. Scanning (Giờ đây Agent sẽ nhận path là Folder -> Chạy ổn định)
    try:
        findings_ql = await logic_codeql_scan(job)
    except Exception as e:
        logger.error(f"CodeQL Error: {e}")
        findings_ql = []
        
    try:
        findings_llm = await logic_llm_batch_scan(job)
    except Exception as e:
        logger.error(f"LLM Scan Error: {e}")
        findings_llm = []

    # 3. Collector
    all_findings = await logic_collector_merge(
        job=job,
        codeql_results=findings_ql,
        llm_results=findings_llm,
        target_queue=None
    )
    total_raw = len(all_findings)
    
    if not all_findings:
        logger.warning(f"⛔ [{repo_name}] Pipeline stop: No findings.")
        return {"results": [], "metrics": {}}

    # 4. Debate
    confirmed_vulns = await logic_debate_pipeline(job, all_findings)
    if not confirmed_vulns:
        logger.warning(f"⛔ [{repo_name}] All findings rejected by Debate.")
        await step_reporting({"repo_name": repo_name, "total_raw_findings": total_raw, "verified_jobs": []})
        return {"results": [], "metrics": {}}

    # 5. Planner
    # Lưu ý: job['path'] hiện tại là folder tạm. Nếu Executor cần Dockerfile gốc, 
    # ta nên trả lại path gốc hoặc copy Dockerfile vào temp nếu cần.
    # Ở đây ta giả định Executor xử lý được hoặc dùng fallback image.
    plans = await step_planning(confirmed_vulns, job_context=job)

    # 6. Executor
    executed_plans = await step_execution(plans)

    # 7. Verifier
    final_results = await step_verification(executed_plans)

    # 8. Reporter
    report_payload = {
        "repo_name": repo_name,
        "total_raw_findings": total_raw,
        "verified_jobs": final_results,
        "test2": job.get("test2", False),
        "test2_data": job.get("test2_data")
    }
    metrics = await step_reporting(report_payload)

    elapsed = time.time() - start_time
    logger.info(f"✅ FINISHED {repo_name} in {elapsed:.2f}s")
    
    return {"results": final_results, "metrics": metrics}

# ====================================================================
# PART 2: ORCHESTRATOR (ĐIỀU PHỐI CHÍNH)
# ====================================================================

async def run_pipeline_orchestrator(job: Dict, mode: str = "auto"):
    """
    Facade thông minh:
    1. Kiểm tra input path.
    2. Nếu input là folder chứa nhiều file lẻ (Dataset) -> Chạy vòng lặp từng file.
    3. Nếu input là folder project hoặc file đơn -> Chạy 1 lần.
    """
    input_path = Path(job["path"])
    root_output_dir = Path(job["output_dir"])

    logger.info(f"🔍 Analyzing input: {input_path}")

    # 1. Thử lấy danh sách file lẻ bằng input_manager
    dataset_files = get_dataset_files(str(input_path))

    # LOGIC: Nếu tìm thấy nhiều file VÀ input là thư mục -> Chế độ Dataset (Batch Files)
    if dataset_files and input_path.is_dir():
        count = len(dataset_files)
        logger.info(f"📂 DETECTED DATASET MODE: Found {count} individual files.")
        
        results_summary = []

        # --- VÒNG LẶP TUẦN TỰ TỪNG FILE ---
        for i, file_info in enumerate(dataset_files, 1):
            file_name = file_info["name"]
            logger.info(f"\n{'='*40}")
            logger.info(f"📄 Processing File [{i}/{count}]: {file_name}")
            logger.info(f"{'='*40}")

            # Tạo Job con cho từng file
            sub_job = {
                "name": file_info["name"],         
                "path": file_info["path"],         
                "language": file_info["type"],     
                "repo_type": "single-file",
                "output_dir": str(root_output_dir / file_info["stem"]), # output/author_1/
                "security_eval": job.get("security_eval", False),
                "security_eval_data": job.get("security_eval_data", {})
            }

            try:
                # Gọi pipeline (Đã có logic xử lý temp folder bên trong)
                res = await run_single_repo_pipeline(sub_job)
                results_summary.append(res)
                
                # Dọn dẹp RAM
                import gc; gc.collect()
                
            except Exception as e:
                logger.error(f"❌ Error processing file {file_name}: {e}")
                continue

        logger.info(f"\n🎉 DATASET SCAN COMPLETED. Processed {len(results_summary)}/{count} files.")
        return results_summary

    # 2. Ngược lại: Chạy Project Mode (Single Repo hoặc Single File input trực tiếp)
    else:
        logger.info("📂 DETECTED SINGLE TARGET MODE.")
        return await run_single_repo_pipeline(job)

# Export alias để giữ tương thích
run_sequential_pipeline = run_pipeline_orchestrator
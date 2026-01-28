#!/usr/bin/env python3
"""
queue_manager.py
Unified Orchestrator / Facade:
- Điều phối luồng chạy (Pipeline).
- Tự động xử lý Single File (Tạo temp folder).
- [UPDATED] Skip logic: Nếu Debate không tìm thấy lỗi -> Jump to Reporter.
"""

import asyncio
import logging
import time
import shutil
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
    [UPDATED] Logic nhảy cóc: Scan/Debate Empty -> Report ngay.
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
    # PRE-PROCESS: XỬ LÝ PATH & LANGUAGE CHO SINGLE FILE
    # =================================================================
    original_path = Path(job["path"])
    
    # Map ngôn ngữ chuẩn cho CodeQL
    LANG_MAP = {
        "py": "python", "js": "javascript", "ts": "javascript", 
        "java": "java", "cpp": "cpp", "c": "cpp", "cs": "csharp"
    }
    raw_lang = job.get("language", "python")
    job["language"] = LANG_MAP.get(raw_lang, raw_lang)

    # Nếu input là FILE, tạo môi trường giả lập Folder
    if original_path.is_file():
        logger.info(f"🔄 [Pre-Process] Detected Single File: {original_path.name}")
        
        temp_src_dir = out_dir / "src_temp_for_scan"
        if temp_src_dir.exists():
            shutil.rmtree(temp_src_dir)
        temp_src_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            shutil.copy(original_path, temp_src_dir / original_path.name)
            
            # Cập nhật job path trỏ vào folder tạm
            job["path"] = str(temp_src_dir)
            job["original_path"] = str(original_path) # Lưu lại path gốc
            
            logger.info(f"   -> Created temp env at: {temp_src_dir}")
        except Exception as e:
            logger.error(f"❌ Failed to prepare temp environment: {e}")
            return {"results": [], "metrics": {}}

    # =================================================================
    # 1. SCANNING (CodeQL + LLM)
    # =================================================================
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

    # =================================================================
    # 2. COLLECTOR
    # =================================================================
    all_findings = await logic_collector_merge(
        job=job,
        codeql_results=findings_ql,
        llm_results=findings_llm,
        target_queue=None
    )
    total_raw = len(all_findings)
    
    # [CHECK POINT 1] Nếu không có raw findings -> Report 0 lỗi & Thoát
    if not all_findings:
        logger.warning(f"⛔ [{repo_name}] Pipeline stop: No raw findings found.")
        out_man.append_log("System", "No raw findings found. Skipping to Report.")
        
        metrics = await step_reporting({
            "repo_name": repo_name,
            "total_raw_findings": 0,
            "verified_jobs": [],
            "test2": job.get("test2", False),
            "test2_data": job.get("test2_data")
        })
        return {"results": [], "metrics": metrics}

    # =================================================================
    # 3. DEBATE
    # =================================================================
    confirmed_vulns = await logic_debate_pipeline(job, all_findings)

    # [CHECK POINT 2] Nếu Debate loại hết -> Report 0 lỗi & Thoát
    if not confirmed_vulns:
        logger.warning(f"⛔ [{repo_name}] All findings rejected by Debate. Skipping Planner/Executor.")
        out_man.append_log("System", "Debate rejected all findings. Skipping exploitation phase.")
        
        metrics = await step_reporting({
            "repo_name": repo_name,
            "total_raw_findings": total_raw,
            "verified_jobs": [],
            "test2": job.get("test2", False),
            "test2_data": job.get("test2_data")
        })
        return {"results": [], "metrics": metrics}

    # =================================================================
    # 4. PLANNER
    # =================================================================
    plans = await step_planning(confirmed_vulns, job_context=job)

    # =================================================================
    # 5. EXECUTOR
    # =================================================================
    executed_plans = await step_execution(plans)

    # =================================================================
    # 6. VERIFIER
    # =================================================================
    final_results = await step_verification(executed_plans)

    # =================================================================
    # 7. REPORTER
    # =================================================================
    report_payload = {
        "repo_name": repo_name,
        "total_raw_findings": total_raw,
        "verified_jobs": final_results,
        "test2": job.get("test2", False),
        "test2_data": job.get("test2_data")
    }
    logger.info(f"report_payload: {report_payload}")
    metrics = await step_reporting(report_payload)

    elapsed = time.time() - start_time
    #logger.info(f"report_payload: {report_payload}")
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
                "output_dir": str(root_output_dir / file_info["stem"]), 
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
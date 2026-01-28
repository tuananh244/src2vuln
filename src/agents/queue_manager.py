#!/usr/bin/env python3
"""
queue_manager.py
Unified Orchestrator / Facade (Branching Logic Enhanced)
"""

import asyncio
import logging
import time
import gc
import traceback
import json
from pathlib import Path
from typing import Dict, List

# --- IMPORTS TỪ CÁC MODULE LOGIC (IMPL) ---
try:
    from src.agents.impl.scanner_codeql import logic_codeql_scan
    from src.agents.impl.scanner_llm import logic_llm_batch_scan
    from src.agents.impl.collector import logic_collector_merge
    from src.agents.impl.debate import logic_debate_pipeline
    from src.agents.impl.planner import step_planning
    from src.agents.impl.executor import step_execution
    from src.agents.impl.verifier import step_verification
    from src.agents.impl.reporter import step_reporting
except ImportError as e:
    print(f"❌ [QueueManager] Missing Implementation Modules: {e}")
    # Dummy functions
    async def logic_codeql_scan(*a): return []
    async def logic_llm_batch_scan(*a): return []
    async def logic_collector_merge(*a, **k): return []
    async def logic_debate_pipeline(*a): return []
    async def step_planning(*a, **k): return []
    async def step_execution(*a): return []
    async def step_verification(*a, **k): return []
    async def step_reporting(*a): return {}

from src.utils.output_manager import OutputManager
from src.utils.input_manager import get_recursive_files

logger = logging.getLogger("QueueManager")

# ====================================================================
# PART 1: SEQUENTIAL RUNNER (CHẠY 1 REPO / 1 FILE)
# ====================================================================

async def run_single_repo_pipeline(job: Dict):
    start_time = time.time()
    
    repo_name = job.get("name", "unknown")
    logger.info(f"--- [DEBUG] START Single Pipeline. Name: '{repo_name}' ---")
    
    if "name" not in job:
        return {"error": "Missing name"}

    out_dir = Path(job.get("output_dir", "outputs"))
    out_dir.mkdir(parents=True, exist_ok=True)

    # Khởi tạo biến kết quả mặc định
    executed_plans = []
    final_results = []
    total_raw = 0

    # 1. Scanning
    logger.info(f"🔍 [1/7] Scanning CodeQL & LLM...")
    try: findings_ql = await logic_codeql_scan(job)
    except: findings_ql = []
        
    try: findings_llm = await logic_llm_batch_scan(job)
    except: findings_llm = []

    # 2. Collector
    logger.info(f"📥 [2/7] Collecting & Merging...")
    all_findings = await logic_collector_merge(job, findings_ql, findings_llm, target_queue=None)
    total_raw = len(all_findings)
    
    # 3. Debate
    confirmed_vulns = []
    if all_findings:
        logger.info(f"🗣️ [3/7] Debating...")
        confirmed_vulns = await logic_debate_pipeline(job, all_findings)
    else:
        logger.info("    -> Skipping Debate (No raw findings).")
    
    # 4 & 5. Planner & Executor (Conditional)
    if confirmed_vulns:
        # [NHÁNH A] Có lỗi -> Tấn công
        logger.info(f"📝 [4/7] Planning for {len(confirmed_vulns)} vulns...")
        plans = await step_planning(confirmed_vulns, job_context=job)
        
        if plans:
            logger.info(f"💥 [5/7] Executing {len(plans)} plans...")
            executed_plans = await step_execution(plans)
        else:
            logger.warning("    -> No plans generated.")
    else:
        # [NHÁNH B] Không lỗi -> Bỏ qua tấn công
        logger.info("🛡️ [Info] No vulns confirmed. Skipping Plan/Exec.")
        logger.info("    -> Preparing for Safety Verification.")
        executed_plans = []

    # 6. Verifier (ALWAYS RUN)
    # Logic: Nếu executed_plans có item -> Verify Exploit.
    #        Nếu executed_plans rỗng -> Verify Cleanliness (Safety Check).
    logger.info(f"⚖️ [6/7] Verifying...")
    final_results = await step_verification(
        executed_plans, 
        job_context=job, 
        is_clean_check=(len(executed_plans) == 0)
    )
    
    # 7. Reporter
    logger.info(f"📊 [7/7] Reporting...")
    report_payload = {
        "repo_name": repo_name,
        "total_raw_findings": total_raw,
        "verified_jobs": final_results,
        "security_eval": job.get("security_eval", False),
        "security_eval_data": job.get("security_eval_data")
    }
    metrics = await step_reporting(report_payload)

    elapsed = time.time() - start_time
    logger.info(f"✅ FINISHED {repo_name} in {elapsed:.2f}s")
    
    return {"results": final_results, "metrics": metrics}


# ====================================================================
# PART 2: BATCH RUNNER (FIXED & UNIFIED)
# ====================================================================

class PipelineController:
    def __init__(self):
        self.codeql_lock = asyncio.Lock()      
        self.llm_scan_lock = asyncio.Lock()    
        self.debate_sem = asyncio.Semaphore(2) 
        self.plan_lock = asyncio.Lock()        
        self.exec_lock = asyncio.Lock()        

    async def process_sub_item(self, name: str, path: Path, root_output: Path, extra_config: Dict = None):
        repo_name = name
        logger.info(f"\n🔹 [DEBUG] START SUB-ITEM: '{repo_name}'")

        # Setup paths & job
        job_output_dir = root_output / repo_name
        job_output_dir.mkdir(parents=True, exist_ok=True)
        
        input_path = Path(path)
        codeql_root = str(input_path.parent) if input_path.is_file() else str(input_path)

        job = {
            "name": repo_name,
            "path": str(input_path),
            "codeql_root": codeql_root,
            "language": "python", 
            "output_dir": str(job_output_dir)
        }
        if extra_config: job.update(extra_config)

        # Khởi tạo biến trạng thái
        findings_ql, findings_llm = [], []
        all_findings, confirmed = [], []
        executed, results = [], []

        # --- A. SCANNING ---
        try:
            async with self.codeql_lock:
                findings_ql = await logic_codeql_scan(job)
        except Exception: logger.error(f"❌ [{repo_name}] CodeQL Error.")

        try:
            async with self.llm_scan_lock:
                findings_llm = await logic_llm_batch_scan(job)
        except Exception: logger.error(f"❌ [{repo_name}] LLM Scan Error.")

        # --- B. COLLECT & DEBATE ---
        try:
            async with self.debate_sem:
                all_findings = await logic_collector_merge(job, findings_ql, findings_llm, target_queue=None)
                if all_findings:
                    confirmed = await logic_debate_pipeline(job, all_findings)
        except Exception as e:
            logger.error(f"❌ [{repo_name}] Debate Error: {e}")

        # --- C. PLAN & EXECUTE (BRANCHING) ---
        # Chỉ chạy nếu có lỗi đã confirm
        if confirmed:
            try:
                plans = []
                async with self.plan_lock:
                    plans = await step_planning(confirmed, job_context=job)
                
                if plans:
                    async with self.exec_lock:
                        executed = await step_execution(plans)
            except Exception as e:
                logger.error(f"❌ [{repo_name}] Plan/Exec Error: {e}")
        else:
            logger.info(f"   [{repo_name}] -- Skipping Plan/Exec (No confirmed vulns).")

        # --- D. VERIFICATION (ALWAYS RUN) ---
        # Logic: executed rỗng -> Verify Safety. executed có item -> Verify Exploit.
        try:
            logger.info(f"   [{repo_name}] >> Verifying...")
            results = await step_verification(
                executed, 
                job_context=job,
                is_clean_check=(len(executed) == 0) # Cờ quan trọng
            )
        except Exception as e:
            logger.error(f"❌ [{repo_name}] Verify Error: {e}")

        # --- E. REPORTING (ALWAYS RUN) ---
        try:
            logger.info(f"   [{repo_name}] >> Reporting...")
            await step_reporting({
                "repo_name": repo_name,
                "total_raw_findings": len(all_findings),
                "verified_jobs": results,
                "security_eval": job.get("security_eval", False),
                "security_eval_data": job.get("security_eval_data")
            })
        except Exception as e:
            logger.error(f"❌ [{repo_name}] Report Error: {e}")
            
        logger.info(f"🏁 [{repo_name}] DONE.")


async def run_batch_repos(input_items: List[Dict], output_base: str, parent_job_config: Dict = None, batch_name: str = "Batch_Run"):
    """
    Chạy batch với controller đã fix.
    Tham số batch_name dùng để tạo folder con gom nhóm kết quả.
    """
    controller = PipelineController()
    # [FIX PATH] Gom output vào folder con (VD: output/SecurityEval)
    final_out = Path(output_base) / batch_name
    final_out.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"📂 BATCH OUTPUT ROOT: {final_out.resolve()}")

    is_dataset_mode = parent_job_config and parent_job_config.get("security_eval")
    final_tasks_list = []

    logger.info(f"🚀 BATCH PREPARATION: Analyzing {len(input_items)} input items...")

    for item in input_items:
        item_path = Path(item['path'])
        item_name = item['name']

        if is_dataset_mode and item_path.is_dir():
            logger.info(f"   📂 Exploding folder: {item_name}")
            sub_files = get_recursive_files(str(item_path), extensions=['.py', '.java', '.c', '.cpp'])
            
            if sub_files:
                for f in sub_files:
                    unique_job_name = f"{item_name}_{f['stem']}"
                    final_tasks_list.append({
                        "name": unique_job_name,
                        "path": Path(f['path']),
                        "category": item_name
                    })
            else:
                logger.warning(f"      -> ⚠️ Folder {item_name} is empty!")
        else:
            final_tasks_list.append({
                "name": item_name,
                "path": item_path,
                "category": "project"
            })

    logger.info(f"🚀 BATCH START: Processing {len(final_tasks_list)} jobs into '{final_out}'.")

    logger.info(f"🚀 BATCH START: {len(final_tasks_list)} jobs into '{final_out}'.")

    for idx, task_info in enumerate(final_tasks_list, 1):
        job_name = task_info["name"]

        logger.info("\n" + "="*60)
        logger.info(f"🚦 [{idx}/{len(final_tasks_list)}] STARTING JOB: {job_name}")
        logger.info("="*60)

        current_config = parent_job_config.copy() if parent_job_config else {}
        current_config["cwe_target"] = task_info.get("category")

        try:
            await controller.process_sub_item(
                name=job_name, 
                path=task_info["path"], 
                root_output=final_out, 
                extra_config=current_config
            )
            gc.collect()
            await asyncio.sleep(0.5)
        except Exception as e:
            logger.error(f"❌ Batch Loop Error: {e}")
            logger.error(traceback.format_exc())
            continue

    logger.info(f"✅ ALL BATCHES COMPLETED. Check results at: {final_out}")

# ====================================================================
# PART 3: FACADE
# ====================================================================

def _detect_input_type(path_str: str) -> str:
    p = Path(path_str)
    if not p.exists(): return "invalid"
    if p.is_file(): return "file"
    if p.is_dir():
        children = [x for x in p.iterdir() if not x.name.startswith('.')]
        has_code = any(f.suffix in ['.py', '.java', '.js', '.cpp', '.c'] for f in children if f.is_file())
        return "single_repo" if has_code else "batch_folder"
    return "invalid"

async def run_pipeline_orchestrator(job: Dict, mode: str = "auto"):
    input_path = Path(job["path"])
    
    if mode == "auto":
        detected_type = _detect_input_type(job["path"])
        mode = "batch" if detected_type == "batch_folder" else "single"
        if detected_type == "file": mode = "file"

    if mode == "batch":
        sub_items = []
        is_dataset = job.get("security_eval", False) or "securityeval" in job["name"].lower()
        
        if is_dataset:
            raw_files = get_recursive_files(str(input_path), extensions=['.py', '.java', '.c', '.cpp'])
            for f in raw_files:
                sub_items.append({'name': f['stem'], 'path': Path(f['path']), 'category': f['category']})
            extra_config = {"security_eval": True, "security_eval_data": job.get("security_eval_data", {})}
        else:
            for item in input_path.iterdir():
                if item.name.startswith('.'): continue
                if item.is_dir() or (item.is_file() and item.suffix in ['.py', '.java', '.c', '.cpp']):
                    sub_items.append({'name': item.stem, 'path': item, 'category': 'root'})
            extra_config = {}

        if not sub_items:
            logger.warning("⚠️ Batch mode: No items found.")
            return {}
            
        # [FIX] Lấy tên Job làm tên folder Batch (VD: SecurityEval)
        batch_folder_name = job.get("name", "Batch_Run")
        
        await run_batch_repos(
            sub_items, 
            job["output_dir"], 
            parent_job_config=extra_config,
            batch_name=batch_folder_name # <--- TRUYỀN TÊN VÀO ĐÂY
        )
        return {"status": "Batch Completed"}

    if mode == "file":
        job["name"] = f"File_{input_path.stem}"
        
    return await run_single_repo_pipeline(job)

run_sequential_pipeline = run_pipeline_orchestrator
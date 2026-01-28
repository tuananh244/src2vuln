#!/usr/bin/env python3
"""
queue_manager.py
Unified Orchestrator / Facade:
- Điều phối luồng chạy (Pipeline) bằng cách gọi các module trong src/agents/impl/
- Hỗ trợ chạy tuần tự (Single) và chạy song song có kiểm soát (Batch).
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Dict, List

# --- IMPORTS TỪ CÁC MODULE LOGIC (IMPL) ---
# Đảm bảo bạn đã tạo các file này trong src/agents/impl/
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
    # Placeholder functions để không crash IDE khi chưa tạo file con
    async def logic_codeql_scan(*a): return []
    async def logic_llm_batch_scan(*a): return []
    async def logic_collector_merge(*a, **k): return []
    async def logic_debate_pipeline(*a): return []
    async def step_planning(*a, **k): return []
    async def step_execution(*a): return []
    async def step_verification(*a): return []
    async def step_reporting(*a): return {}

from src.utils.output_manager import OutputManager

logger = logging.getLogger("QueueManager")

# ====================================================================
# PART 1: SEQUENTIAL RUNNER (CHẠY 1 REPO / 1 FILE)
# ====================================================================

async def run_single_repo_pipeline(job: Dict):
    """
    Chạy pipeline cho 1 repo duy nhất theo thứ tự tuần tự.
    Flow: CodeQL -> LLM -> Collector -> Debate -> Planner -> Executor -> Verifier -> Reporter
    """
    start_time = time.time()
    repo_name = job["name"]
    out_dir = Path(job["output_dir"])
    
    # 0. Setup Output
    out_dir.mkdir(parents=True, exist_ok=True)
    out_man = OutputManager(repo_name=repo_name)
    out_man.append_log("System", f"Sequential Pipeline Started for: {job['path']}")
    
    logger.info(f"🚀 STARTING PIPELINE: {repo_name}")

    # 1. Scanning (CodeQL & LLM)
    # Chạy CodeQL
    try:
        findings_ql = await logic_codeql_scan(job)
    except Exception as e:
        logger.error(f"CodeQL Error: {e}")
        findings_ql = []
        
    # Chạy LLM
    try:
        findings_llm = await logic_llm_batch_scan(job)
    except Exception as e:
        logger.error(f"LLM Scan Error: {e}")
        findings_llm = []

    # 2. Collector (Gộp kết quả)
    # Gọi hàm logic (không dùng queue)
    all_findings = await logic_collector_merge(
        job=job,
        codeql_results=findings_ql,
        llm_results=findings_llm,
        target_queue=None # Chạy tuần tự không cần đẩy queue
    )
    total_raw = len(all_findings)
    
    if not all_findings:
        logger.warning(f"⛔ [{repo_name}] Pipeline stop: No findings.")
        return {"results": [], "metrics": {}}

    # 3. Debate (Lọc nhiễu)
    confirmed_vulns = await logic_debate_pipeline(job, all_findings)
    
    if not confirmed_vulns:
        logger.warning(f"⛔ [{repo_name}] All findings rejected by Debate.")
        # Vẫn chạy report để ghi nhận kết quả 0
        await step_reporting({"repo_name": repo_name, "total_raw_findings": total_raw, "verified_jobs": []})
        return {"results": [], "metrics": {}}

    # 4. Planner (Lập kế hoạch)
    plans = await step_planning(confirmed_vulns, job_context=job)

    # 5. Executor (Thực thi PoC)
    executed_plans = await step_execution(plans)

    # 6. Verifier (Kiểm tra kết quả)
    final_results = await step_verification(executed_plans)

    # 7. Reporter (Báo cáo)
    # Đóng gói payload cho reporter
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
# PART 2: BATCH RUNNER (CHẠY NHIỀU REPO GỐI ĐẦU)
# ====================================================================

class PipelineController:
    """
    Điều phối tài nguyên cho Batch Processing.
    Dùng Async Lock để đảm bảo không bị xung đột tài nguyên.
    """
    def __init__(self):
        # Cấu hình khóa
        self.codeql_lock = asyncio.Lock()      # Chỉ 1 CodeQL chạy cùng lúc
        self.llm_scan_lock = asyncio.Lock()    # Chỉ 1 LLM Scan chạy cùng lúc
        self.debate_sem = asyncio.Semaphore(2) # Cho phép 2 Debate song song (nhẹ)
        self.plan_lock = asyncio.Lock()        # Chỉ 1 Planner
        self.exec_lock = asyncio.Lock()        # QUAN TRỌNG: Chỉ 1 Docker chạy cùng lúc

    async def process_sub_item(self, name: str, path: Path, root_output: Path):
        """Xử lý 1 item trong batch (folder con)."""
        repo_name = name
        job = {
            "name": repo_name,
            "path": str(path),
            "language": "python", # TODO: Auto-detect language
            "output_dir": str(root_output / repo_name)
        }
        Path(job["output_dir"]).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"⏳ [{repo_name}] Registered. Waiting for slots...")

        # A. SCANNING PHASE (Gối đầu)
        # Repo A chạy CodeQL, Repo B đợi. A xong CodeQL sang LLM -> B vào CodeQL.
        async with self.codeql_lock:
            logger.info(f"🔹 [{repo_name}] Running CodeQL...")
            try: findings_ql = await logic_codeql_scan(job)
            except: findings_ql = []
            
        async with self.llm_scan_lock:
            logger.info(f"🔹 [{repo_name}] Running LLM Scan...")
            try: findings_llm = await logic_llm_batch_scan(job)
            except: findings_llm = []

        # B. COLLECT & DEBATE
        async with self.debate_sem:
            all_findings = await logic_collector_merge(job, findings_ql, findings_llm, target_queue=None)
            if not all_findings: return
            
            logger.info(f"🔹 [{repo_name}] Debating...")
            confirmed = await logic_debate_pipeline(job, all_findings)
            if not confirmed: return

        # C. PLANNING
        async with self.plan_lock:
            logger.info(f"🔹 [{repo_name}] Planning...")
            plans = await step_planning(confirmed, job_context=job)

        # D. EXECUTION & REPORT (Độc quyền Docker)
        async with self.exec_lock:
            logger.info(f"🔹 [{repo_name}] Executing & Verifying...")
            executed = await step_execution(plans)
            results = await step_verification(executed)
            
            report_payload = {
                "repo_name": repo_name,
                "total_raw_findings": len(all_findings),
                "verified_jobs": results
            }
            await step_reporting(report_payload)
            
        logger.info(f"🏁 [{repo_name}] DONE.")

async def run_batch_processing(input_items: List[Dict], output_base: str):
    """
    input_items = [{'name': 'A', 'path': PathObj}, ...]
    """
    controller = PipelineController()
    out = Path(output_base)
    
    logger.info(f"🚀 BATCH START: Processing {len(input_items)} items.")
    
    # Tạo task cho tất cả, Controller sẽ tự điều phối việc chờ đợi (await lock)
    tasks = [
        controller.process_sub_item(item['name'], item['path'], out) 
        for item in input_items
    ]
    await asyncio.gather(*tasks)
    
    logger.info("✅ ALL BATCHES COMPLETED.")


# ====================================================================
# PART 3: SMART ORCHESTRATOR (FACADE)
# ====================================================================

def _detect_input_type(path_str: str) -> str:
    p = Path(path_str)
    if not p.exists(): return "invalid"
    
    if p.is_file():
        return "file"
        
    if p.is_dir():
        # Lấy danh sách bên trong (bỏ file ẩn)
        children = [x for x in p.iterdir() if not x.name.startswith('.')]
        
        # Kiểm tra xem có chứa file code trực tiếp không
        has_code = any(f.suffix in ['.py', '.java', '.js', '.cpp', '.c', '.go'] for f in children if f.is_file())
        # Kiểm tra xem có chứa folder con không
        sub_dirs = [f for f in children if f.is_dir()]
        
        if has_code:
            return "single_repo"
        elif sub_dirs:
            return "batch_folder" # Dấu hiệu của Dataset chứa nhiều project
        else:
            return "single_repo" # Folder rỗng hoặc chỉ có text
            
    return "invalid"

async def run_pipeline_orchestrator(job: Dict, mode: str = "auto"):
    """
    Hàm Main Facade thông minh.
    """
    input_path = Path(job["path"])
    
    # 1. Auto-Detect Mode
    if mode == "auto":
        detected_type = _detect_input_type(job["path"])
        logger.info(f"🔍 Auto-detected input type: {detected_type}")
        
        if detected_type == "batch_folder":
            mode = "batch"
        elif detected_type == "file":
            mode = "file"
        else:
            mode = "single"

    # 2. Xử lý Batch
    if mode == "batch":
        sub_items = []
        for item in input_path.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                sub_items.append({'name': item.name, 'path': item})
        
        if not sub_items:
            logger.warning("⚠️ Batch mode selected but no sub-folders found.")
            return {}
            
        await run_batch_processing(sub_items, job["output_dir"])
        return {"status": "Batch Completed"}

    # 3. Xử lý Single / File
    if mode == "file":
        job["name"] = f"File_{input_path.stem}"
        
    return await run_single_repo_pipeline(job)

# Export alias để giữ tương thích với main.py cũ
run_sequential_pipeline = run_pipeline_orchestrator
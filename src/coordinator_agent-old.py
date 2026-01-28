#!/usr/bin/env python3
"""
main.py
Coordinator (Sequential Mode): 
Cấu hình hệ thống, chọn Repo và gọi hàm chạy tuần tự (run_sequential_pipeline).
"""

import asyncio
import logging
import os
import sys
import json
from pathlib import Path

# --- IMPORTS TỪ PROJECT ---
from src.utils.input_manager import (
    get_input_data, 
    choose_repository, 
    load_security_eval_cases
)
from src.llm.llm_manager import scan_models

# [QUAN TRỌNG] Import hàm chạy tuần tự từ queue_manager
try:
    from agents.queue_manager_v14 import run_sequential_pipeline
except ImportError as e:
    print(f"❌ Error importing queue_manager: {e}")
    sys.exit(1)

# --- CẤU HÌNH ĐƯỜNG DẪN GỐC ---
BASE_OUTPUT_PATH = Path("/home/tuananh/Desktop/src2vuln/output/")

# ======================================================
# UI & CONFIG HELPERS
# ======================================================
def setup_logger(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    return logging.getLogger("Coordinator")

def choose_llm_model():
    """Menu chọn model đơn giản"""
    models = scan_models()
    if not models:
        print("⚠ No LLM configs found.")
        return None
    
    print("\n=== AVAILABLE LLM MODELS ===")
    for idx, m in enumerate(models, 1):
        print(f"{idx}. {m['model_name']:<25} | {m['provider']}")
    
    choice = input("Select model (Enter=Skip): ").strip()
    if not choice.isdigit(): return None
    idx = int(choice)
    if 1 <= idx <= len(models):
        return models[idx-1]["model_name"]
    return None

# ======================================================
# MAIN FLOW
# ======================================================
async def main():
    logger = setup_logger()
    input_data_path = os.environ.get("DATA_PATH", "data/input")

    # 1. Cấu hình (LLM)
    # ----------------------------
    selected_model = choose_llm_model()
    if selected_model:
        # Set biến môi trường để các Agent bên trong tự đọc
        os.environ["ACTIVE_LLM_MODEL"] = selected_model
        logger.info(f"🧠 Model selected: {selected_model}")
    else:
        logger.warning("⚠ No model selected. Pipeline might fail at LLM steps.")

    # 2. Chọn Repository
    # ------------------
    repos = get_input_data(input_data_path)
    if not repos:
        logger.error(f"❌ No repositories found in {input_data_path}")
        return

    selected_repo = choose_repository(repos)
    if not selected_repo:
        logger.info("User cancelled.")
        return
    
    repo_name = selected_repo["name"]
    logger.info(f"📌 Target Repo: {repo_name} ({selected_repo['type']})")

    # =====================================================
    # SPECIAL CASE: SecurityEval Repo
    # =====================================================
    security_eval_data = {}
    if repo_name.lower() == "securityeval":
        security_eval_data = load_security_eval_cases(selected_repo)

        logger.info("🧪 SECURITY EVAL MODE DETECTED")
        logger.info(f"🗂 Testcases Root: {security_eval_data['testcases_root']}")
        logger.info(f"📌 Total CWE Folders: {len(security_eval_data['cwe_cases'])}")
        # (Có thể in chi tiết nếu cần)

    # 3. Chuẩn bị Output Directory
    # ----------------------------
    target_output_dir = (BASE_OUTPUT_PATH / repo_name).resolve()
    target_output_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"📂 Output directory: {target_output_dir}")

    # 4. Chuẩn bị Job Payload
    # ----------------------------------------
    job = {
        "name": repo_name,
        "path": selected_repo["path"],      # Source code input path
        "language": selected_repo["type"],  # python, java, etc.
        "repo_type": "manual-selected",
        "output_dir": str(target_output_dir), # Nơi lưu kết quả
        
        # Thông tin đặc biệt cho SecurityEval
        "security_eval": bool(security_eval_data),
        "security_eval_data": security_eval_data
    }

    # 5. KHỞI CHẠY PIPELINE TUẦN TỰ
    # ----------------------------------------
    logger.info("--------------------------------------------------")
    logger.info(f"🔥 Running Sequential Pipeline for: {repo_name}")
    logger.info("   Steps: CodeQL -> LLM -> Collector -> Debate -> Planner -> Executor -> Verifier -> Report")
    logger.info("--------------------------------------------------")

    try:
        # Gọi hàm chạy và đợi kết quả (Blocking Async Call)
        # Hàm này trả về Dict: {'results': [...], 'metrics': {...}}
        pipeline_output = await run_sequential_pipeline(job)
        
        # Tách dữ liệu từ output
        final_results = []
        metrics = {}
        
        if isinstance(pipeline_output, dict):
            final_results = pipeline_output.get("results", [])
            metrics = pipeline_output.get("metrics", {})
        elif isinstance(pipeline_output, list):
            final_results = pipeline_output # Fallback
        
        # 6. Hiển thị Báo cáo ra Console
        # ------------------------------
        print("\n" + "="*60)
        print(f"=== 🏁 FINAL PIPELINE REPORT: {repo_name} ===")
        print("="*60)
        
        # Hiển thị Metrics (Chỉ số)
        if metrics:
            mode = metrics.get("mode", "normal")
            
            if mode == "security_eval":
                print("🧪 SECURITY EVAL METRICS (Official Dataset)")
                print(f"   - TP={metrics.get('TP')}, FP={metrics.get('FP')}")
                print(f"   - FN={metrics.get('FN')}, TN={metrics.get('TN')}")
                print(f"   - Precision: {metrics.get('precision')}")
                print(f"   - Recall:    {metrics.get('recall')}")
                print(f"   - F1-Score:  {metrics.get('f1_score')}")
                print(f"   - Accuracy:  {metrics.get('accuracy')}")
            else:
                print(f"📊 SYSTEM PERFORMANCE:")
                print(f"   - Total Scan Candidates:  {metrics.get('total_candidates', 0)}")
                print(f"   - Confirmed (True Pos):   {metrics.get('true_positives', 0)}")
                print(f"   - Precision:              {metrics.get('precision', 0)*100:.1f}%")
                print(f"   - Recall (Relative):      {metrics.get('recall_relative', 0)*100:.1f}%")
                print(f"   - F1-Score:               {metrics.get('f1_score', 0):.4f}")
            print("-" * 60)

        # Hiển thị danh sách lỗi (Chỉ hiển thị nếu không phải SecurityEval, vì SE quá nhiều case)
        if not job.get("security_eval"):
            if not final_results:
                print("🟢 No confirmed vulnerabilities found.")
            else:
                print(f"🔍 DETAILED FINDINGS ({len(final_results)}):")
                for idx, item in enumerate(final_results, 1):
                    h = item.get('hypothesis', {}) 
                    plan = item.get('test_plan', {})
                    verify = item.get('verify', {})
                    
                    vuln_type = h.get('type', 'Unknown Vulnerability')
                    cwe = h.get('cwe', 'N/A')
                    file_path = h.get('file_path') or h.get('sink', {}).get('file', '?')
                    line_num = h.get('location_hint') or h.get('sink', {}).get('line', '?')
                    
                    status = verify.get('status', 'UNKNOWN').upper()
                    reason = verify.get('reason', 'No verification details')
                    
                    icon = "✅" if status == "CONFIRMED" else "❌"
                    
                    print(f"{idx}. {icon} [{status}] {vuln_type} ({cwe})")
                    print(f"   📍 Location: {file_path}:{line_num}")
                    print(f"   🛠️  PoC Script: {'Generated' if plan.get('script_content') else 'No'}")
                    print(f"   📝 Verification: {reason}")
                    print("-" * 60)
                
        print(f"\n📂 Data saved at: {target_output_dir}")
        print(f"📄 PoC Reports at: {target_output_dir}/PoC/")

    except KeyboardInterrupt:
        logger.warning("\n🛑 Pipeline interrupted by user.")
    except Exception as e:
        logger.error(f"❌ Critical Error in Pipeline: {e}", exc_info=True)
    finally:
        logger.info("System shutdown.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
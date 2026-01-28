#!/usr/bin/env python3
"""
coordinator_agent.py
Coordinator (Sequential Mode): 
Cấu hình hệ thống, chọn Repo và điều phối chạy:
1. Project Mode: Chạy 1 lần cho toàn bộ folder.
2. Dataset Mode: Chạy vòng lặp cho từng file lẻ (Đệ quy).
3. Custom SE Mode: Chọn CWE folder cụ thể (Batch).
"""

import asyncio
import logging
import os
import sys
import json
import time
import gc  # Garbage Collection để dọn RAM khi chạy loop
from pathlib import Path

# --- IMPORTS TỪ PROJECT ---
from src.utils.input_manager import (
    get_input_data, 
    choose_repository, 
    get_recursive_files,          # [NEW] Hàm quét đệ quy
    select_security_eval_folders  # [NEW] Hàm chọn folder SE
)
from src.llm.llm_manager import scan_models

# Import hàm chạy tuần tự & Batch từ queue_manager
try:
    from src.agents.queue_manager import (
        run_sequential_pipeline,
        run_batch_repos
    )
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

def print_report_summary(repo_name, results, metrics):
    """Helper in báo cáo kết quả (cho 1 job chạy đơn lẻ)."""
    print("\n" + "="*60)
    print(f"=== 🏁 FINAL REPORT: {repo_name} ===")
    print("="*60)
    
    # [UPDATE] Đọc từ structure mới
    # Metrics đầu vào ở đây là dict trả về từ step_reporting
    # Structure: { "summary": { "TP": 1, ... }, "breakdown...": ... }
    
    summary = metrics.get("summary", {})
    
    print(f"📊 METRICS:")
    # Hiển thị TP/FP/FN thay vì các chỉ số cũ
    print(f"   - True Positives (TP):    {summary.get('TP', 0)}")
    print(f"   - False Positives (FP):   {summary.get('FP', 0)}")
    print(f"   - False Negatives (FN):   {summary.get('FN', 0)}")
    print(f"   -------------------------")
    print(f"   - Precision:              {summary.get('precision', 0)*100:.1f}%")
    print(f"   - Recall:                 {summary.get('recall', 0)*100:.1f}%")
    print(f"   - F1-Score:               {summary.get('f1_score', 0):.4f}")
    
    if not results:
        print("\n🟢 No confirmed vulnerabilities found.")
    else:
        print(f"\n🔍 Found {len(results)} confirmed issues.")
    print("-" * 60)

def scan_output_and_print_summary(output_dir: Path):
    """
    Quét folder output và tổng hợp metrics từ cấu trúc JSON mới.
    Hỗ trợ đọc TP, FP, FN, TN và tính toán Accuracy.
    """
    if isinstance(output_dir, str):
        output_dir = Path(output_dir)

    print("\n" + "="*80)
    print(f"🔎 SCANNING OUTPUT RESULTS AT: {output_dir}")
    print("="*80)

    # 1. Khởi tạo bộ đếm Global (Thêm TN)
    global_cat = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}    # Category Metrics
    global_strict = {"TP": 0, "FP": 0, "FN": 0, "TN": 0} # Strict CWE Metrics
    
    total_files_scanned = 0
    details_list = []

    # 2. Quét file
    metrics_files = list(output_dir.rglob("final_metrics.json"))
    
    if not metrics_files:
        print("⚠️ No 'final_metrics.json' files found.")
        return

    for mfile in metrics_files:
        try:
            content = mfile.read_text(encoding='utf-8')
            if not content.strip(): continue
            
            data = json.loads(content)
            
            # --- EXTRACT DATA (Theo cấu trúc JSON mới) ---
            # 1. Lấy dữ liệu Category (Ưu tiên key mới 'metric_category', fallback key cũ)
            cat_block = data.get("metric_category") or data.get("metric_error_category", {})
            cat_stats = cat_block.get("stats", {})
            
            # 2. Lấy dữ liệu Strict
            strict_block = data.get("metric_strict_cwe", {})
            strict_stats = strict_block.get("stats", {})
            
            # --- CỘNG DỒN GLOBAL ---
            # Hàm helper cộng dồn
            def add_stats(target_dict, source_dict):
                target_dict["TP"] += source_dict.get("TP", 0)
                target_dict["FP"] += source_dict.get("FP", 0)
                target_dict["FN"] += source_dict.get("FN", 0)
                target_dict["TN"] += source_dict.get("TN", 0)

            add_stats(global_cat, cat_stats)
            add_stats(global_strict, strict_stats)
            
            # Lấy summary để biết số lượng file trong job này (thường là 1)
            summary = data.get("summary", {})
            total_files_scanned += summary.get("total_files_scanned", 1)

            # --- TRẠNG THÁI HIỂN THỊ (Log từng file) ---
            c_tp = cat_stats.get("TP", 0)
            c_tn = cat_stats.get("TN", 0)
            c_fp = cat_stats.get("FP", 0)
            c_fn = cat_stats.get("FN", 0)

            # Logic xác định trạng thái file
            if c_tp > 0:
                status_str = "🟢 EXPLOITED (TP)"
            elif c_tn > 0:
                status_str = "🛡️ SAFE VERIFIED (TN)"
            elif c_fp > 0:
                status_str = "❌ FALSE POSITIVE (FP)"
            elif c_fn > 0:
                status_str = "⚠️ MISSED (FN)"
            else:
                status_str = "⚪ UNKNOWN"

            # Lấy tên task/file
            try:
                job_name = f"{mfile.parent.parent.name}" # VD: task_11
            except:
                job_name = mfile.name

            details_list.append(f"{job_name:<30} | {status_str:<25} (TP={c_tp}, FP={c_fp}, FN={c_fn}, TN={c_tn})")

        except Exception as e:
            print(f"⚠️ Error reading {mfile}: {e}")
            continue

    # 3. In bảng chi tiết các file
    print(f"{'TASK NAME':<30} | {'VERDICT':<25} METRICS")
    print("-" * 90)
    details_list.sort()
    for line in details_list:
        print(line)
    print("-" * 90)

    # 4. Helper tính toán Metrics (Bao gồm Accuracy)
    def calc_final_metrics(g_stats):
        tp, fp, fn, tn = g_stats["TP"], g_stats["FP"], g_stats["FN"], g_stats["TN"]
        total = tp + fp + fn + tn
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        
        f1 = 0.0
        if (precision + recall) > 0:
            f1 = 2 * precision * recall / (precision + recall)
            
        accuracy = (tp + tn) / total if total > 0 else 0.0
        
        return {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "Precision": precision, "Recall": recall, 
            "F1": f1, "Accuracy": accuracy
        }

    # Tính toán
    m_cat = calc_final_metrics(global_cat)
    m_strict = calc_final_metrics(global_strict)

    # 5. IN BÁO CÁO TỔNG HỢP
    print("\n" + "="*60)
    print("📊 FINAL AGGREGATED REPORT (STRICT vs CATEGORY)")
    print("="*60)
    print(f"📂 Total Scans Processed:    {total_files_scanned}")
    
    # TABLE 1: CATEGORY METRICS
    print(f"\n[1] 🛠️  CATEGORY / EXPLOIT METRICS")
    print(f"    (Focus: Did we find the right type of vulnerability?)")
    print(f"    --------------------------------------------------")
    print(f"    ✅ True Positives (TP):   {m_cat['TP']}")
    print(f"    🛡️ True Negatives (TN):   {m_cat['TN']}")
    print(f"    ❌ False Positives (FP):  {m_cat['FP']}")
    print(f"    ⚠️ False Negatives (FN):  {m_cat['FN']}")
    print(f"    --------------------------------------------------")
    print(f"    🎯 Accuracy:             {m_cat['Accuracy']*100:.2f}%")
    print(f"    🔹 Precision:            {m_cat['Precision']*100:.2f}%")
    print(f"    🔹 Recall:               {m_cat['Recall']*100:.2f}%")
    print(f"    🏆 F1-Score:             {m_cat['F1']:.4f}")

    # TABLE 2: STRICT METRICS
    print(f"\n[2] 🏷️  STRICT CWE ID METRICS")
    print(f"    (Focus: Exact CWE ID Match. Mismatch counts as FP+1 & FN+1)")
    print(f"    --------------------------------------------------")
    print(f"    ✅ True Positives (TP):   {m_strict['TP']}")
    print(f"    🛡️ True Negatives (TN):   {m_strict['TN']}")
    print(f"    ❌ False Positives (FP):  {m_strict['FP']}")
    print(f"    ⚠️ False Negatives (FN):  {m_strict['FN']}")
    print(f"    --------------------------------------------------")
    print(f"    🎯 Accuracy:             {m_strict['Accuracy']*100:.2f}%")
    print(f"    🔹 Precision:            {m_strict['Precision']*100:.2f}%")
    print(f"    🔹 Recall:               {m_strict['Recall']*100:.2f}%")
    print(f"    🏆 F1-Score:             {m_strict['F1']:.4f}")
    print("="*60 + "\n")

# ======================================================
# MAIN FLOW
# ======================================================
async def main():
    logger = setup_logger()
    input_data_path = os.environ.get("DATA_PATH", "data/input")

    # 1. Cấu hình (LLM)
    selected_model = choose_llm_model()
    if selected_model:
        os.environ["ACTIVE_LLM_MODEL"] = selected_model
        logger.info(f"🧠 Model selected: {selected_model}")
    else:
        logger.warning("⚠ No model selected. Pipeline might fail at LLM steps.")

    # 2. Chọn Repository / Input Folder
    repos = get_input_data(input_data_path)
    if not repos:
        logger.error(f"❌ No repositories found in {input_data_path}")
        return

    selected_repo = choose_repository(repos)
    if not selected_repo:
        logger.info("User cancelled.")
        return
    
    repo_name = selected_repo["name"]
    repo_path = selected_repo["path"]
    
    # Chuẩn bị thư mục output gốc cho Repo này
    repo_output_root = (BASE_OUTPUT_PATH / repo_name).resolve()
    repo_output_root.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"📂 Output Root: {repo_output_root}")
    # =====================================================
    # 3. CHỌN CHẾ ĐỘ CHẠY
    # =====================================================
    print("\n=== SELECT SCAN MODE ===")
    print("1. Project Mode (Scan WHOLE folder as one project)")
    print("2. Dataset Mode (Scan each .py file recursively)")
    
    # Nếu là SecurityEval, hiện thêm option chọn folder
    is_sec_eval = "securityeval" in repo_name.lower()
    if is_sec_eval:
        print("3. SecurityEval Custom (Select specific CWE folders)")
    
    mode_choice = input("Select mode (1/2" + ("/3" if is_sec_eval else "") + "): ").strip()
    start = time.time()
    # -----------------------------------------------------
    # MODE 2: DATASET MODE (Recursive File Scan)
    # -----------------------------------------------------
    if mode_choice == "2":
        # Quét đệ quy (lấy cả file trong folder con CWE-xxx)
        files = get_recursive_files(repo_path, extensions=['.py'])
        
        if not files:
            logger.error(f"❌ No source files found in {repo_path}")
            return

        total_files = len(files)
        logger.info(f"📂 DATASET MODE: Found {total_files} files. Starting sequential scan...")
        
        summary_stats = {"total": 0, "vulns": 0, "errors": 0}

        for idx, file_info in enumerate(files, 1):
            file_name = file_info["name"]
            file_stem = file_info["stem"]
            category = file_info.get("category", "root") # CWE-20 or root
            
            logger.info("\n" + "="*60)
            logger.info(f"🚀 [{idx}/{total_files}] PROCESSING: {category}/{file_name}")
            logger.info("="*60)

            # Tạo output dir theo cấu trúc: output/SecurityEval/CWE-20/codeql_1/
            file_out_dir = repo_output_root / category / file_stem
            file_out_dir.mkdir(parents=True, exist_ok=True)

            # Tạo Job Payload
            job = {
                "name": f"{category}_{file_stem}", # Unique name
                "path": file_info["path"],
                "language": "python", # Hoặc file_info["type"]
                "repo_type": "single-file",
                "output_dir": str(file_out_dir),
                "security_eval": is_sec_eval,
                "cwe_target": category
            }

            try:
                # GỌI PIPELINE TUẦN TỰ
                output = await run_sequential_pipeline(job)
                
                vuln_count = len(output.get("results", []))
                summary_stats["total"] += 1
                summary_stats["vulns"] += vuln_count
                
                gc.collect()

            except Exception as e:
                logger.error(f"❌ Error processing {file_name}: {e}")
                summary_stats["errors"] += 1
                continue
        
        print("\n" + "="*60)
        print(f"🎉 DATASET SCAN COMPLETED")
        print(f"   - Files Processed: {summary_stats['total']}/{total_files}")
        print(f"   - Total Vulns: {summary_stats['vulns']}")
        print(f"   - Errors: {summary_stats['errors']}")
        print("="*60)

    # -----------------------------------------------------
    # MODE 3: SECURITY EVAL CUSTOM (Batch w/ Reporting)
    # -----------------------------------------------------
    elif mode_choice == "3" and is_sec_eval:
        logger.info("🧪 SECURITY EVAL CUSTOM MODE")
        batch_items = select_security_eval_folders(repo_path)
        
        if batch_items:
            logger.info(f"🚀 Starting Batch Pipeline for {len(batch_items)} folders...")
            try:
                # 1. Chạy Batch (Gối đầu - Nhanh)
                dataset_config = {
                    "security_eval": True,
                    "dataset_mode": True,
                    "security_eval_data": {"path": repo_path}
                }

                await run_batch_repos(
                    input_items=batch_items, 
                    output_base=str(repo_output_root),
                    parent_job_config=dataset_config
                )
                
                print(f"\n✅ Batch Execution Completed.")
                
                # 2. Tổng hợp báo cáo từ các file output
                # (Thay thế đoạn gọi run_sequential_pipeline sai logic cũ)
                scan_output_and_print_summary(repo_output_root)

            except Exception as e:
                logger.error(f"Batch Execution Failed: {e}", exc_info=True)
        else:
            logger.warning("No folders selected.")

    # -----------------------------------------------------
    # MODE 1: PROJECT MODE (Default)
    # -----------------------------------------------------
    else:
        logger.info(f"📂 PROJECT MODE: Scanning whole folder {repo_name}...")
        
        job = {
            "name": repo_name,
            "path": selected_repo["path"],
            "language": selected_repo["type"],
            "repo_type": "project",
            "output_dir": str(repo_output_root),
            "security_eval": is_sec_eval,
        }

        try:
            pipeline_output = await run_sequential_pipeline(job)
            results = pipeline_output.get("results", [])
            metrics = pipeline_output.get("metrics", {})
            print_report_summary(repo_name, results, metrics)

        except KeyboardInterrupt:
            logger.warning("\n🛑 Pipeline interrupted by user.")
        except Exception as e:
            logger.error(f"❌ Critical Error: {e}", exc_info=True)
    end = time.time()
    logger.info(f"Total execution time: {end - start:.2f} seconds")
    logger.info("System shutdown.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
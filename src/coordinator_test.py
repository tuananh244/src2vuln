#!/usr/bin/env python3
"""
coordinator_agent.py
Coordinator (Sequential Mode): 
Cấu hình hệ thống, chọn Repo và điều phối chạy.
[UPDATED] Tự động tổng hợp Metrics (F1, Precision, Recall) sau khi chạy xong Dataset.
"""

import asyncio
import logging
import os
import sys
import json
import gc  # Garbage Collection
from pathlib import Path
from typing import List, Dict

# --- IMPORTS ---
from src.utils.input_manager import (
    get_input_data, 
    choose_repository, 
    load_security_eval_cases,
    get_recursive_files,          
    select_security_eval_folders  
)
from src.llm.llm_manager import scan_models

try:
    from src.agents.queue_manager import (
        run_sequential_pipeline,
        run_batch_repos
    )
except ImportError as e:
    print(f"❌ Error importing queue_manager: {e}")
    sys.exit(1)

BASE_OUTPUT_PATH = Path("/home/tuananh/Desktop/src2vuln/output/")

# ======================================================
# HELPER: METRICS AGGREGATOR
# ======================================================
import json
import logging
from pathlib import Path
from typing import Dict

# ======================================================
# HELPER: METRICS AGGREGATOR (UPDATED FOR TN)
# ======================================================

def scan_output_for_metrics(output_dir: Path) -> Dict:
    """
    Quét folder output để tổng hợp metrics từ các file JSON.
    Hỗ trợ đọc sâu vào cấu trúc Strict Metrics để lấy TP, FP, FN, TN.
    """
    agg_stats = {
        "tp": 0, 
        "fp": 0, 
        "fn": 0, 
        "tn": 0,
        "total_files": 0
    }
    
    # Tìm tất cả file final_metrics.json (hoặc tên tương tự)
    json_files = list(output_dir.rglob("*metrics.json"))
    
    if not json_files:
        return agg_stats

    for metric_file in json_files:
        try:
            data = json.loads(metric_file.read_text(encoding='utf-8'))
            
            # --- CASE 1: Cấu trúc STRICT (SecurityEval) ---
            if "metric_strict_cwe" in data:
                stats = data["metric_strict_cwe"].get("stats", {})
                agg_stats["tp"] += stats.get("TP", 0)
                agg_stats["fp"] += stats.get("FP", 0)
                agg_stats["fn"] += stats.get("FN", 0)
                agg_stats["tn"] += stats.get("TN", 0)
                
                # Tổng file trong lần chạy này
                summary = data.get("summary", {})
                agg_stats["total_files"] += summary.get("total_files_scanned", 0) or \
                                            summary.get("total_samples", 0)

            # --- CASE 2: Cấu trúc NORMAL (Cũ) ---
            elif "summary" in data and "TP" in data["summary"]:
                # Logic cũ thường không có TN, chỉ có TP/FP
                s = data["summary"]
                agg_stats["tp"] += s.get("TP", 0)
                agg_stats["fp"] += s.get("FP", 0)
                agg_stats["fn"] += s.get("FN", 0)
                # TN mặc định 0 nếu không có
                agg_stats["total_files"] += 1 # Ước lượng mỗi file json là 1 lần chạy
                
            # --- CASE 3: Fallback (Cấu trúc phẳng) ---
            else:
                agg_stats["tp"] += data.get("true_positives", 0)
                agg_stats["fp"] += data.get("false_positives", 0)
                
        except Exception as e:
            print(f"⚠️ Error reading {metric_file.name}: {e}")
            
    return agg_stats

def calculate_and_print_final_metrics(stats: Dict, mode: str = "normal"):
    """
    Tính toán và in báo cáo, bao gồm cả True Negative (TN) và Accuracy.
    """
    tp = stats.get("tp", 0)
    fp = stats.get("fp", 0)
    fn = stats.get("fn", 0)
    tn = stats.get("tn", 0)
    
    total_files = stats.get("total_files", tp + fp + fn + tn)
    
    # --- TÍNH TOÁN CHỈ SỐ ---
    
    # 1. Precision = TP / (TP + FP)
    # (Tỷ lệ báo đúng trong số những lần báo lỗi)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    
    # 2. Recall = TP / (TP + FN)
    # (Tỷ lệ tìm ra lỗi trong tổng số lỗi thực tế)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    # 3. F1-Score
    f1 = 0.0
    if (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
        
    # 4. Accuracy = (TP + TN) / (TP + TN + FP + FN)
    # (Độ chính xác tổng thể: Bắt đúng lỗi VÀ Im lặng đúng lúc)
    total_decisions = tp + tn + fp + fn
    accuracy = (tp + tn) / total_decisions if total_decisions > 0 else 0.0
    
    # --- IN BÁO CÁO ---
    print("\n" + "="*60)
    print(f"📊 FINAL AGGREGATED REPORT [{mode.upper()}]")
    print("="*60)
    
    print(f"   📂 Total Files Scanned: {total_files}")
    print(f"   ---------------------------")
    print(f"   ✅ True Positives (TP):  {tp}  (Found Correctly)")
    print(f"   🛡️ True Negatives (TN):  {tn}  (Ignored Safe Files)")
    print(f"   ❌ False Positives (FP): {fp}  (False Alarm / Mismatch)")
    print(f"   ⚠️ False Negatives (FN): {fn}  (Missed Vuln / Mismatch)")
    print(f"   ---------------------------")
    
    # Hiển thị màu sắc (nếu terminal hỗ trợ) hoặc format rõ ràng
    print(f"   🎯 Accuracy:         {accuracy*100:.2f}%  (Overall Correctness)")
    print(f"   ---------------")
    print(f"   🔹 Precision:        {precision*100:.2f}%")
    print(f"   🔹 Recall:           {recall*100:.2f}%")
    print(f"   🔹 F1-Score:         {f1:.4f}")
    
    if mode == "security_eval" and fp > 0:
        print("\n   *Note: In Strict Mode, 'Mismatch CWE' counts as both FP and FN.")
        
    print("="*60 + "\n")

# ======================================================
# CONFIG SETUP
# ======================================================
def setup_logger(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    return logging.getLogger("Coordinator")

def choose_llm_model():
    models = scan_models()
    if not models:
        print("⚠ No LLM configs.")
        return None
    print("\n=== AVAILABLE LLM MODELS ===")
    for idx, m in enumerate(models, 1): print(f"{idx}. {m['model_name']}")
    choice = input("Select model: ").strip()
    return models[int(choice)-1]["model_name"] if choice.isdigit() else None

# ======================================================
# MAIN FLOW
# ======================================================
async def main():
    logger = setup_logger()
    input_data_path = os.environ.get("DATA_PATH", "data/input")

    selected_model = choose_llm_model()
    if selected_model:
        os.environ["ACTIVE_LLM_MODEL"] = selected_model

    repos = get_input_data(input_data_path)
    selected_repo = choose_repository(repos)
    if not selected_repo: return
    
    repo_name = selected_repo["name"]
    repo_path = selected_repo["path"]
    
    repo_output_root = (BASE_OUTPUT_PATH / repo_name).resolve()
    repo_output_root.mkdir(parents=True, exist_ok=True)

    # MENU CHỌN MODE
    print("\n=== SELECT SCAN MODE ===")
    print("1. Project Mode (Scan whole folder)")
    print("2. Dataset Mode (Scan each .py file sequentially)")
    
    is_sec_eval = "securityeval" in repo_name.lower()
    if is_sec_eval:
        print("3. SecurityEval Custom (Select specific CWE folders)")
    
    mode_choice = input("Select mode: ").strip()

    # -----------------------------------------------------
    # MODE 2: DATASET MODE (Sequential File Loop)
    # -----------------------------------------------------
    if mode_choice == "2":
        files = get_recursive_files(repo_path, extensions=['.py'])
        if not files: return

        total_files = len(files)
        logger.info(f"📂 DATASET MODE: Found {total_files} files.")
        
        # Biến tích lũy cho báo cáo tổng
        agg_stats = {
            "tp": 0, 
            "fp": 0, 
            "total_candidates": 0 # Hoặc total_files nếu là SecurityEval
        }

        for idx, file_info in enumerate(files, 1):
            file_name = file_info["name"]
            category = file_info.get("category", "root")
            
            logger.info(f"\n🚀 [{idx}/{total_files}] Processing: {category}/{file_name}")

            file_out_dir = repo_output_root / category / file_info["stem"]
            
            job = {
                "name": f"{category}_{file_info['stem']}",
                "path": file_info["path"],
                "language": "python",
                "repo_type": "single-file",
                "output_dir": str(file_out_dir),
                "security_eval": is_sec_eval,
                "cwe_target": category
            }

            try:
                # Chạy pipeline
                output = await run_sequential_pipeline(job)
                
                # --- TỔNG HỢP METRICS TẠI ĐÂY ---
                metrics = output.get("metrics", {})
                
                if is_sec_eval:
                    # Logic SecurityEval: Mỗi file là 1 sample
                    # Nếu tìm thấy TP > 0 thì file đó ĐẠT
                    if metrics.get("true_positives", 0) > 0:
                        agg_stats["tp"] += 1
                    # Total candidates = Số file đã chạy
                    agg_stats["total_candidates"] += 1
                else:
                    # Logic thường: Cộng dồn số findings
                    agg_stats["tp"] += metrics.get("true_positives", 0)
                    agg_stats["fp"] += metrics.get("false_positives_at_verify", 0)
                    agg_stats["total_candidates"] += metrics.get("total_candidates", 0)
                
                gc.collect()

            except Exception as e:
                logger.error(f"❌ Error on {file_name}: {e}")
                continue
        
        # IN BÁO CÁO TỔNG HỢP SAU KHI CHẠY HẾT VÒNG LẶP
        report_mode = "security_eval" if is_sec_eval else "normal"
        calculate_and_print_final_metrics(agg_stats, mode=report_mode)

    # -----------------------------------------------------
    # MODE 3: SECURITY EVAL CUSTOM (Batch)
    # -----------------------------------------------------
    elif mode_choice == "3" and is_sec_eval:
        batch_items = select_security_eval_folders(repo_path)
        if batch_items:
            logger.info(f"🚀 Starting Batch Pipeline...")
            
            dataset_config = {
                "security_eval": True,
                "dataset_mode": True,
                "security_eval_data": {"path": repo_path}
            }

            await run_batch_repos(batch_items, str(repo_output_root), dataset_config)
            
            # Sau khi chạy Batch xong, quét folder output để tổng hợp kết quả
            logger.info("⏳ Aggregating results from output files...")
            agg_stats = scan_output_for_metrics(repo_output_root)
            
            # SecurityEval tính trên số file, nên cần trick nhẹ:
            # Hàm scan_output_for_metrics ở trên cộng dồn số finding.
            # Với SecurityEval, ta cần đếm số file output có kết quả.
            # (Bạn có thể tinh chỉnh hàm scan_output tùy nhu cầu chính xác cao hơn)
            
            # In tạm kết quả cộng dồn tìm thấy
            print("\n" + "="*60)
            print("=== BATCH RUN SUMMARY ===")
            print(f"Confirmed Vulnerabilities Found: {agg_stats['tp']}")
            print(f"Total Raw Candidates processed: {agg_stats['total_candidates']}")
            print("="*60)

    # -----------------------------------------------------
    # MODE 1: PROJECT MODE
    # -----------------------------------------------------
    else:
        # ... (Giữ nguyên logic cũ) ...
        job = {
            "name": repo_name,
            "path": selected_repo["path"],
            "language": selected_repo["type"],
            "repo_type": "project",
            "output_dir": str(repo_output_root),
            "security_eval": is_sec_eval,
        }
        output = await run_sequential_pipeline(job)
        print_report_summary(repo_name, output.get("results"), output.get("metrics"))

    logger.info("System shutdown.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
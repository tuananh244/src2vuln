import logging
import os
import asyncio
import json
import re
import markdown
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set

# --- IMPORTS (Giữ nguyên) ---
from src.utils.output_manager import OutputManager
from src.llm.llm_manager import call_model
from src.prompts.prompt_reported import get_poc_report_prompt
from src.utils.vuln_categorizer import categorizer

logger = logging.getLogger("Reporter")

# ====================================================================
# 1. METRICS CORE (Updated with Accuracy & TN)
# ====================================================================

def calculate_metrics_primitive(tp: int, fp: int, fn: int = 0, tn: int = 0) -> Dict[str, Any]:
    """Tính toán Precision, Recall, F1, Accuracy."""
    # Precision = TP / (TP + FP)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    
    # Recall = TP / (TP + FN)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    # F1 Score
    f1 = 0.0
    if (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    
    # Accuracy = (TP + TN) / (TP + TN + FP + FN)
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
        
    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4)
    }

# ====================================================================
# 0. GROUND TRUTH HELPER (NEW)
# ====================================================================

def get_ground_truth_info(file_path: str) -> Dict[str, Any]:
    """
    Phân tích đường dẫn file để xác định Ground Truth.
    Giả định cấu trúc dataset: .../CWE-79/file.py hoặc .../Safe/file.py
    """
    if not file_path:
        return {"is_vuln": False, "cwe": "Safe", "cat": "Safe"}

    normalized_path = file_path.replace('\\', '/')
    
    # Regex tìm CWE-XXX trong đường dẫn
    match = re.search(r"(CWE-\d+)", normalized_path, re.IGNORECASE)
    
    if match:
        raw_cwe = match.group(1).upper() # VD: CWE-79
        cwe_num = str(categorizer.normalize_cwe_id(raw_cwe)).strip()
        category = categorizer.get_category(cwe_num, "")
        return {
            "is_vuln": True,
            "cwe": cwe_num,      # "79"
            "cat": category      # "XSS"
        }
    
    # Nếu không có CWE trong path -> Coi là File Sạch (Safe)
    return {"is_vuln": False, "cwe": "Safe", "cat": "Safe"}

# ====================================================================
# 2. SECURITY EVAL METRICS (STRICT LOGIC)
# ====================================================================

def evaluate_security_eval(repo_path: str, verified_jobs: List[Dict], repo_name: str = "") -> Dict:
    """
    Tính metrics dựa trên logic nghiêm ngặt:
    - TN: File sạch và không báo Confirmed.
    - Mismatch: File lỗi A báo B -> FP+1 & FN+1.
    """
    
    # --- A. PREPARE DATA: Gom nhóm Jobs theo File ---
    # Mục đích: Biết được tổng số file đã quét để tính TN
    
    file_map = {} # path -> { "gt": dict, "jobs": list }
    
    for job in verified_jobs:
        # Lấy path chuẩn
        path = job.get("job_context", {}).get("path") or \
               job.get("job_context", {}).get("original_path") or \
               job.get("hypothesis", {}).get("file_path", "")
               
        if not path: continue
        
        if path not in file_map:
            file_map[path] = {
                "gt": get_ground_truth_info(path),
                "jobs": []
            }
        file_map[path]["jobs"].append(job)

    # --- B. INIT COUNTERS ---
    # Tách riêng 2 bộ chỉ số: Strict (đúng số CWE) và Category (đúng loại)
    stats_strict = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    stats_cat    = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    
    logger.info(f"🧪 [METRICS] Evaluating {len(file_map)} unique files...")

    # --- C. CORE EVALUATION LOOP ---
    for f_path, info in file_map.items():
        gt = info["gt"]
        jobs = info["jobs"]
        
        # Tìm xem có job nào CONFIRMED không?
        # (Nếu có nhiều job confirm, ta lấy job đầu tiên để check đúng/sai)
        confirmed_job = next((j for j in jobs if j.get("verify", {}).get("status", "").upper() == "CONFIRMED"), None)
        
        # Lấy thông tin dự đoán (Prediction)
        pred_cwe = "None"
        pred_cat = "None"
        
        if confirmed_job:
            h = confirmed_job.get("hypothesis", {})
            raw_cwe = (h.get("cwe_id") or h.get("cwe") or "UNKNOWN")
            if isinstance(raw_cwe, list): raw_cwe = str(raw_cwe[0])
            
            pred_cwe = str(categorizer.normalize_cwe_id(raw_cwe)).strip()
            pred_cat = categorizer.get_category(pred_cwe, h.get("vuln_type", ""))
            
            logger.info(f"   📄 File: {Path(f_path).name} | GT: {gt['cwe']} | Pred: {pred_cwe}")

        # === LOGIC ĐÁNH GIÁ ===

        # 1. TRƯỜNG HỢP: GROUND TRUTH = SAFE (File Sạch)
        if not gt["is_vuln"]:
            if confirmed_job:
                # File sạch mà báo lỗi -> FP (Hallucination)
                stats_strict["fp"] += 1
                stats_cat["fp"]    += 1
                logger.warning(f"     -> ❌ FP (Safe File detected as Vuln)")
            else:
                # File sạch và im lặng -> TN
                stats_strict["tn"] += 1
                stats_cat["tn"]    += 1
        
        # 2. TRƯỜNG HỢP: GROUND TRUTH = VULN (File Lỗi)
        else:
            if not confirmed_job:
                # Có lỗi mà không confirm -> FN (Missed)
                stats_strict["fn"] += 1
                stats_cat["fn"]    += 1
            else:
                # Có confirm, giờ so sánh khớp hay lệch
                
                # --- CHECK STRICT CWE ---
                if pred_cwe == gt["cwe"]:
                    stats_strict["tp"] += 1 # Chuẩn
                else:
                    # Mismatch -> Theo luật của bạn: FP+1 (báo sai) VÀ FN+1 (không báo đúng)
                    stats_strict["fp"] += 1
                    stats_strict["fn"] += 1
                    logger.warning(f"     -> ⚠️ Strict Mismatch (GT:{gt['cwe']} != Pred:{pred_cwe}) -> FP++ & FN++")

                # --- CHECK CATEGORY ---
                # Category lỏng hơn: Nếu CWE khớp HOẶC Category khớp
                if pred_cwe == gt["cwe"] or pred_cat == gt["cat"]:
                    stats_cat["tp"] += 1
                else:
                    # Mismatch Category
                    stats_cat["fp"] += 1
                    stats_cat["fn"] += 1

    # --- D. RETURN RESULTS ---
    metric_strict = calculate_metrics_primitive(**stats_strict)
    metric_cat = calculate_metrics_primitive(**stats_cat)
    
    total_vuln_files = sum(1 for v in file_map.values() if v["gt"]["is_vuln"])
    total_safe_files = len(file_map) - total_vuln_files

    return {
        "summary": {
            "total_files_scanned": len(file_map),
            "total_vuln_files_gt": total_vuln_files,
            "total_safe_files_gt": total_safe_files,
            "verified_exploits_raw": sum(1 for j in verified_jobs if j.get("verify", {}).get("status") == "CONFIRMED")
        },
        "metric_strict_cwe": {
            "description": "Strict Match (CWE ID). Mismatch = FP+1 & FN+1.",
            "stats": metric_strict
        },
        "metric_category": {
            "description": "Category Match. Mismatch = FP+1 & FN+1.",
            "stats": metric_cat
        }
    }

# ====================================================================
# 3. NORMAL METRICS (Giữ nguyên logic cũ cho các repo không chuẩn)
# ====================================================================

def build_normal_metrics(verified_jobs: List[Dict]) -> Dict:
    """
    Tính metrics cho chế độ thường (Không Ground Truth).
    Cập nhật: Hỗ trợ tính TN cho Safety_Audit.
    """
    stats = {
        "tp": 0,
        "fp": 0,
        "fn": 0, # Normal mode thường không biết FN
        "tn": 0  # New: Tính TN nếu Safety Audit bảo SAFE
    }
    
    # Breakdown theo loại lỗi
    cat_stats = {}

    for job in verified_jobs:
        # Lấy thông tin cơ bản
        verify_data = job.get("verify", {})
        status = verify_data.get("status", "UNKNOWN").upper()
        h = job.get("hypothesis", {})
        vuln_type = h.get("type", "Unknown")
        
        # --- LOGIC MỚI ---
        
        # 1. Trường hợp SAFETY AUDIT (Quét lại code sạch)
        if vuln_type == "Safety_Audit":
            if status == "SAFE":
                # Agent xác nhận file sạch -> TN (Im lặng đúng lúc)
                stats["tn"] += 1
            elif status == "SUSPICIOUS":
                # Agent nghi ngờ nhưng không confirm -> FP (Báo động giả/chưa chứng minh được)
                stats["fp"] += 1
            elif status == "CONFIRMED":
                # Hiếm gặp: Audit tìm ra lỗi và confirm -> TP
                stats["tp"] += 1
            continue # Xử lý xong Audit thì qua job khác

        # 2. Trường hợp EXPLOIT JOB (Các job tấn công bình thường)
        exploit_success = (status == "CONFIRMED")
        
        # Lấy category để thống kê chi tiết
        raw_cwe = (h.get("cwe_id") or "UNKNOWN")
        if isinstance(raw_cwe, list): raw_cwe = str(raw_cwe[0])
        clean_cwe = str(categorizer.normalize_cwe_id(raw_cwe)).strip()
        vuln_label = categorizer.get_category(clean_cwe, h.get("vuln_type", ""))
        
        if vuln_label not in cat_stats: cat_stats[vuln_label] = {"tp": 0, "fp": 0}

        if exploit_success:
            stats["tp"] += 1
            cat_stats[vuln_label]["tp"] += 1
        else:
            # Nếu đã tạo ra hypothesis tấn công mà verify thất bại -> FP
            stats["fp"] += 1
            cat_stats[vuln_label]["fp"] += 1

    # Tính toán chỉ số tổng hợp
    summary = calculate_metrics_primitive(**stats)
    
    # Breakdown chi tiết (chỉ cho các job exploit)
    cat_output = {k: calculate_metrics_primitive(v["tp"], v["fp"]) for k, v in cat_stats.items()}
    
    return {
        "summary": summary, 
        "breakdown_by_category": cat_output,
        "note": "Metrics updated to count Safety_Audit(SAFE) as TN."
    }

# ====================================================================
# 4. MAIN REPORTING FLOW
# ====================================================================

async def step_reporting(job_payload: Dict) -> Dict:
    repo_name = job_payload.get("repo_name") or "unknown"
    verified_jobs = job_payload.get("verified_jobs", [])
    
    # Setup Output
    target_output_dir = None
    if verified_jobs:
        ctx = verified_jobs[0].get("job_context") or verified_jobs[0].get("hypothesis", {}).get("job", {})
        target_output_dir = ctx.get("output_dir")
    
    out_man = OutputManager(repo_name=repo_name, artifact_path=target_output_dir)
    logger.info(f"🔹 [Reporter] Reporting for {repo_name}...")

    is_seceval = job_payload.get("security_eval", False)
    repo_path = job_payload.get("path", "")
    
    # Fallback path finding
    if not repo_path and verified_jobs:
        repo_path = verified_jobs[0].get("hypothesis", {}).get("job", {}).get("path", "")

    # --- CALC METRICS ---
    # Trigger logic Strict nếu phát hiện dấu hiệu Dataset (CWE, SecurityEval...)
    use_strict = is_seceval or "CWE" in repo_name or "SecurityEval" in str(repo_path)
    
    if use_strict:
        logger.info("🧪 Running STRICT Metrics (TP/FP/FN/TN + Mismatch Logic)...")
        metrics_data = evaluate_security_eval(repo_path, verified_jobs, repo_name=repo_name)
    else:
        logger.info("📊 Running Normal Metrics (Exploit Success Rate only)...")
        metrics_data = build_normal_metrics(verified_jobs)
    
    out_man.write_json("Reporter-Agent", "final_metrics.json", metrics_data)
    
    # --- Generate PoC ---
    confirmed_items = [j for j in verified_jobs if j.get("verify", {}).get("status") == "CONFIRMED"]
    
    if confirmed_items:
        logger.info(f"✅ Generating PoCs for {len(confirmed_items)} confirmed vulnerabilities...")
        model_name = os.environ.get("ACTIVE_LLM_MODEL") or "gemini-2.0-flash"

        for idx, item in enumerate(confirmed_items, 1):
            h = item.get("hypothesis", {})
            plan = item.get("test_plan", {})
            exec_res = item.get("exec_result", {})
            vuln_id = h.get("vuln_id", f"VULN-{idx}")
            
            prompt = get_poc_report_prompt(h, plan, exec_res)
            try:
                poc_content = await asyncio.to_thread(call_model, model_name, prompt)
                # file_name = f"PoC_{vuln_id}.md".replace(" ", "_").replace(":", "")
                # --- [MỚI] BẮT ĐẦU PHẦN CHUYỂN ĐỔI HTML ---
            
                # 1. Chuyển Markdown sang HTML body (sử dụng extension để hỗ trợ code block đẹp hơn)
                html_body = markdown.markdown(
                    poc_content, 
                    extensions=['fenced_code', 'tables', 'nl2br']
                )

                # 2. Tạo khung HTML hoàn chỉnh với CSS cơ bản để báo cáo đẹp hơn
                full_html_content = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>PoC Report - {vuln_id}</title>
                    <style>
                        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
                        h1, h2, h3 {{ color: #2c3e50; border-bottom: 1px solid #eaeaea; padding-bottom: 0.3em; }}
                        pre {{ background-color: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; border: 1px solid #e1e4e8; }}
                        code {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; font-size: 85%; }}
                        blockquote {{ border-left: 4px solid #dfe2e5; color: #6a737d; padding-left: 16px; margin-left: 0; }}
                        table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; }}
                        th, td {{ border: 1px solid #dfe2e5; padding: 6px 13px; }}
                        th {{ background-color: #f6f8fa; font-weight: 600; }}
                    </style>
                </head>
                <body>
                    {html_body}
                </body>
                </html>
                """
                
                # 3. Lưu file với đuôi .html
                file_name = f"PoC_{vuln_id}.html".replace(" ", "_").replace(":", "")
                out_man.write_poc(file_name, full_html_content)
                # out_man.write_poc(file_name, poc_content)
            except Exception as e:
                logger.error(f"❌ PoC Error {vuln_id}: {e}")
    else:
        logger.warning("⚠️ No CONFIRMED exploits. Skipping PoC generation.")

    return metrics_data
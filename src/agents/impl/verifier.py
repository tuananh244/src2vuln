import logging
import os
import asyncio
from pathlib import Path
from typing import List, Dict, Optional, Any

# --- Imports Logic ---
from src.llm.llm_manager import call_model
from src.utils.data_processors import DataProcessor
from src.utils.output_manager import OutputManager

# --- Imports Prompt ---
try:
    from src.prompts.prompt_verifier import build_verifier_prompt, build_safety_audit_prompt
except ImportError:
    logging.error("❌ Missing prompt definitions. Using dummy fallbacks.")
    def build_verifier_prompt(plan, res): return f"Verify this: {plan} -> {res}"
    def build_safety_audit_prompt(code, path): return f"Audit this code: {code}"

logger = logging.getLogger("Verifier")

def _normalize_status(status_raw: str) -> str:
    """Helper: Chuẩn hóa trạng thái verify về các key chuẩn."""
    s = str(status_raw).upper().strip()
    if "CONFIRM" in s: return "CONFIRMED"
    if "FALSE" in s or "POSITIVE" in s: return "FALSE_POSITIVE"
    if "FAIL" in s or "ERROR" in s: return "EXECUTION_FAILED"
    return "UNKNOWN"

async def step_verification(executed_jobs: List[Dict], job_context: Dict = None, is_clean_check: bool = False) -> List[Dict]:
    """
    Verifier Logic (Robust Version):
    - Đảm bảo không crash nếu 1 job trong list bị lỗi format.
    - Xử lý các trường hợp null/missing keys an toàn.
    """
    
    # --- 1. Validate Input & Context ---
    if not isinstance(executed_jobs, list):
        logger.error(f"❌ [Verifier] Invalid input type: {type(executed_jobs)}. Expected List.")
        return []

    # Nhánh Safety Audit (Không đổi logic, chỉ thêm logging check)
    if is_clean_check and not executed_jobs:
        if not job_context:
            logger.warning("🔹 [Verifier] Clean check requested but missing Job Context.")
            return []
        return await _run_safety_audit(job_context)

    if not executed_jobs:
        logger.warning("🔹 [Verifier] Empty job list received.")
        return []

    logger.info(f"🔹 [Verifier] Analyzing {len(executed_jobs)} execution results...")

    # --- 2. Setup OutputManager (Thử tìm context hợp lệ nhất) ---
    out_man: Optional[OutputManager] = None
    try:
        # Ưu tiên lấy từ tham số truyền vào, nếu không thì tìm trong list jobs
        valid_ctx = job_context
        if not valid_ctx:
            for j in executed_jobs:
                if j.get("job_context"):
                    valid_ctx = j.get("job_context")
                    break
                # Fallback: support cấu trúc cũ
                if j.get("hypothesis", {}).get("job"):
                    valid_ctx = j.get("hypothesis", {}).get("job")
                    break
        
        if valid_ctx:
            out_man = OutputManager(repo_name=valid_ctx.get("name"), artifact_path=valid_ctx.get("output_dir"))
    except Exception as e:
        logger.warning(f"⚠️ [Verifier] Failed to initialize OutputManager: {e}")

    # --- 3. Main Loop (Isolated Error Handling) ---
    verified_results = []
    model_name = os.environ.get("ACTIVE_LLM_MODEL") or "gemini-2.0-flash"

    for i, job in enumerate(executed_jobs):
        # Biến tạm để lưu thông tin cơ bản phòng khi crash sâu bên trong
        vuln_type = "Unknown"
        
        try:
            if not isinstance(job, dict):
                logger.warning(f"⚠️ [Verifier] Job #{i} is malformed (not a dict). Skipping.")
                continue

            # Safely get nested data
            h = job.get("hypothesis", {})
            plan = job.get("test_plan", {})
            exec_res = job.get("exec_result", {})
            vuln_type = h.get("type", "Unknown_Vuln")
            
            verify_data = {}

            # --- A. Check Execution Status ---
            # Phòng trường hợp exec_result là None hoặc rỗng
            if not exec_res or exec_res.get("status") != "executed" or "error" in exec_res:
                reason = exec_res.get("reason") or exec_res.get("error") or "Executor failed or skipped"
                verify_data = {
                    "status": "EXECUTION_FAILED",
                    "reason": f"Skipped verification: {reason}"
                }
            
            # --- B. Call LLM for Verification ---
            else:
                prompt = build_verifier_prompt(plan, exec_res)
                try:
                    response = call_model(model_name, prompt)
                    
                    # Safe Extraction
                    parsed_json = DataProcessor.safe_extract_json(response)
                    
                    if parsed_json:
                        verify_data = parsed_json
                    else:
                        # Fallback thông minh hơn: Chỉ confirm nếu LLM thực sự nói code chạy được
                        logger.warning(f"   ⚠️ [Verifier] LLM returned raw text for {vuln_type}")
                        lower_resp = response.lower()
                        if "successfully executed" in lower_resp or "vulnerability confirmed" in lower_resp:
                            verify_data = {"status": "CONFIRMED", "reason": "LLM text analysis (JSON failed)"}
                        else:
                            verify_data = {"status": "FALSE_POSITIVE", "reason": "LLM text analysis (JSON failed)"}

                except Exception as llm_err:
                    logger.error(f"   ❌ [Verifier] LLM Call Error for {vuln_type}: {llm_err}")
                    verify_data = {"status": "ERROR", "reason": f"LLM Error: {str(llm_err)}"}

            # --- C. Normalize & Save ---
            status_norm = _normalize_status(verify_data.get("status", "UNKNOWN"))
            verify_data["status"] = status_norm
            
            # Update Job (Clone để tránh sửa trực tiếp vào tham chiếu nếu cần, ở đây sửa trực tiếp ok)
            job["verify"] = verify_data
            verified_results.append(job)

            # Logging
            log_icon = "✅" if status_norm == "CONFIRMED" else ("⚠️" if status_norm == "EXECUTION_FAILED" else "❌")
            logger.info(f"   {log_icon} [{status_norm}] {vuln_type}")
            
            if out_man:
                out_man.append_log("Verifier", f"Verdict: {status_norm} | Type: {vuln_type}")

        except Exception as job_err:
            # Catch-all cho bất kỳ lỗi logic nào trong vòng lặp để không ảnh hưởng job khác
            logger.error(f"   ❌ [Verifier] CRITICAL ERROR processing job {vuln_type}: {job_err}", exc_info=True)
            # Vẫn cố gắng append job lỗi vào list kết quả để user biết nó failed
            job["verify"] = {"status": "INTERNAL_ERROR", "reason": str(job_err)}
            verified_results.append(job)

    # --- 4. Final Save ---
    if verified_results and out_man:
        try:
            out_man.save_agent_output("Verify-Agent", verified_results)
        except Exception as save_err:
            logger.error(f"❌ [Verifier] Failed to save output file: {save_err}")
        
    return verified_results


async def _run_safety_audit(job_context: Dict) -> List[Dict]:
    """
    Helper function: Safety Audit (Refined Error Handling)
    """
    repo_name = job_context.get("name", "unknown")
    target_path = job_context.get("path", "")
    job_output_dir = job_context.get("output_dir")
    
    logger.info(f"🛡️ [Verifier] Running Safety Audit for '{repo_name}'...")
    
    code_snippet = ""
    try:
        if not target_path:
            raise ValueError("Target path is empty")
            
        real_path = Path(target_path)
        if real_path.is_file():
            # Đọc file an toàn với giới hạn size
            code_snippet = real_path.read_text(encoding='utf-8', errors='replace')[:8000]
        elif real_path.is_dir():
            files = [p.name for p in real_path.glob('*') if p.suffix in ['.py', '.js', '.java', '.c', '.go', '.php']]
            code_snippet = f"Directory Scan. Top files: {', '.join(files[:30])}"
        else:
            code_snippet = "Path not found or invalid."
    except Exception as e:
        logger.warning(f"   ⚠️ Error reading source for audit: {e}")
        code_snippet = f"Error reading source code: {str(e)}"

    # LLM Call
    model_name = os.environ.get("ACTIVE_LLM_MODEL") or "gemini-2.0-flash"
    prompt = build_safety_audit_prompt(code_snippet, str(target_path))
    
    # Default result
    audit_data = {"status": "UNKNOWN", "reason": "Audit failed or LLM error"}
    
    try:
        response = call_model(model_name, prompt)
        parsed = DataProcessor.safe_extract_json(response)
        
        if parsed:
            audit_data = parsed
            st = str(audit_data.get("status", "")).upper()
            audit_data["status"] = "SAFE" if "SAFE" in st else "SUSPICIOUS"
        else:
            logger.warning("   ⚠️ Safety Audit returned invalid JSON.")
            # Fallback simple
            audit_data["reason"] = "LLM returned raw text, check logs."
            
    except Exception as e:
        logger.error(f"   ⚠️ Safety Audit LLM Error: {e}")
        audit_data["reason"] = str(e)

    # Đóng gói kết quả
    audit_result = {
        "hypothesis": {
            "type": "Safety_Audit",
            "severity": "INFO",
            "description": "Double-check by LLM (No Scanner findings)."
        },
        "verify": {
            "status": audit_data.get("status", "SAFE"),
            "reason": audit_data.get("reason", "No reason"),
            "confidence": audit_data.get("confidence", "UNKNOWN")
        },
        "job_context": job_context
    }
    
    # Logging an toàn
    try:
        if job_output_dir:
            out_man = OutputManager(repo_name=repo_name, artifact_path=job_output_dir)
            out_man.append_log("Verifier", f"Safety Audit Verdict: {audit_result['verify']['status']}")
            out_man.save_agent_output("Verify-Safety-Audit", [audit_result])
    except Exception as log_err:
        logger.error(f"❌ Failed to log audit result: {log_err}")
    
    return [audit_result]
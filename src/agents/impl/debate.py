import logging
import json
import asyncio
import os
from typing import List, Dict
from pathlib import Path

# Imports
from src.llm.llm_manager import call_model
from src.utils.data_processors import DataProcessor
from src.utils.output_manager import OutputManager

from src.prompts.prompt_debate import get_ranker_prompt, get_critic_prompt, get_ranker_refinement_prompt

logger = logging.getLogger("Debate")

# --- HELPER: RANKER ---
async def _ranker_scan(model_name: str, findings: List[Dict], output_manager: OutputManager) -> List[Dict]:
    """Lọc thô danh sách Findings."""
    if not findings: return []
    
    # Rút gọn dữ liệu gửi cho LLM để tiết kiệm token
    simplified = [{
        "id": i, 
        "tool": f.get("source_tool"), 
        "type": f.get("type"), 
        "file": f.get("file_path"),
        "details": str(f.get("details", ""))[:200] # Ép kiểu str để tránh lỗi nếu details là None/Dict
    } for i, f in enumerate(findings)]

    try:
        # Gọi Prompt Ranker
        prompt = get_ranker_prompt("", simplified) 
        # Gọi call_model (đã xử lý thread/sync bên trong)
        resp = call_model(model_name, prompt)
        data = DataProcessor.safe_extract_json(resp)
        
        # Log chi tiết Ranker Decision
        output_manager.append_log("Debate-Agent", f"\n=== RANKER DECISION ===\n{json.dumps(data, indent=2)}")
        
        # [FIX] Xử lý ID an toàn (Tránh lỗi so sánh int vs str)
        ranked_ids = []
        if data and isinstance(data.get('ranked_vulnerabilities'), list):
            for x in data.get('ranked_vulnerabilities', []):
                try:
                    # Ép kiểu sang int. Nếu LLM trả về "1" hoặc 1 đều nhận được.
                    uid = int(x.get('id'))
                    ranked_ids.append(uid)
                except (ValueError, TypeError):
                    continue
        
        # Map ngược lại danh sách gốc
        selected = []
        for idx in ranked_ids:
            # Bây giờ idx đã là int, phép so sánh này sẽ an toàn
            if 0 <= idx < len(findings):
                item = findings[idx].copy()
                # Lấy lý do (chuyển id sang int để so sánh)
                reason = next((r.get('reason') for r in data.get('ranked_vulnerabilities', []) if int(r.get('id', -1)) == idx), "")
                item['ranker_reason'] = reason
                selected.append(item)
        return selected

    except Exception as e:
        logger.error(f"[Debate] Ranker failed: {e}. Fallback to all findings.")
        return findings

# --- HELPER: DEBATE LOOP ---
async def _debate_loop(model_name: str, vuln: Dict, source_root: str, output_manager: OutputManager) -> Dict:
    """Tranh biện chi tiết cho 1 lỗi."""
    current = vuln.copy()
    vuln_id = current.get("type", "Unknown")
    
    # Lấy Context (Source Code)
    context = ""
    file_path = current.get("file_path")
    
    # [FIX] Logic đọc file context hỗ trợ cả Folder và Single File
    if source_root:
        root_path = Path(source_root)
        
        # Case A: source_root là file (Chế độ Dataset Mode/Single File)
        if root_path.is_file():
            try:
                context = root_path.read_text(encoding="utf-8", errors="ignore")[:3000]
            except: pass
            
        # Case B: source_root là folder (Chế độ Project Mode)
        elif file_path:
            full_path = root_path / file_path
            # Xử lý nếu file_path là tuyệt đối hoặc tương đối
            if not full_path.exists() and os.path.isabs(file_path):
                 # Thử tìm tương đối
                 try:
                     full_path = root_path / Path(file_path).name
                 except: pass

            if full_path.exists() and full_path.is_file():
                try: context = full_path.read_text(encoding="utf-8", errors="ignore")[:3000] 
                except: pass
    
    # Fallback: Nếu không đọc được file, dùng Code Flow
    if not context:
        context = json.dumps(current.get("code_flow", []), indent=2)

    output_manager.append_log("Debate-Agent", f"\n--- DEBATING: {vuln_id} ---")

    # Chạy tối đa 3 vòng
    for round_num in range(1, 4):
        # 1. CRITIC REVIEW
        p_crit = get_critic_prompt(context, current)
        # Gọi call_model (đã xử lý thread/sync)
        r_crit = call_model(model_name, p_crit)
        d_crit = DataProcessor.safe_extract_json(r_crit)
        logger.info(f"[Debate] Critic Response (Round {round_num}): {d_crit}")
        if not d_crit: break # Tránh lỗi nếu parse thất bại

        verdict = str(d_crit.get('verdict')).upper()
        reason_crit = str(d_crit.get('reason', ''))[:100] 
        
        # Log Critic
        log_c = f"[Round {round_num}] Critic: {verdict} | Reason: {reason_crit}..."
        output_manager.append_log("Debate-Agent", log_c)
        
        if verdict == "AGREE":
            current['final_status'] = "CONFIRMED"
            current['critic_reason'] = d_crit.get('reason')
            return current
        
        # 2. RANKER REFINE
        feedback = d_crit.get('feedback', '')
        p_ref = get_ranker_refinement_prompt(context, current, feedback)
        # Gọi call_model
        r_ref = call_model(model_name, p_ref)
        d_ref = DataProcessor.safe_extract_json(r_ref)
        logger.info(f"[Debate] Ranker Refinement Response (Round {round_num}): {d_ref}")
        if not d_ref: break

        status = str(d_ref.get('status')).upper()
        reason_ref = str(d_ref.get('refined_reasoning', ''))[:100]

        # Log Ranker
        log_r = f"[Round {round_num}] Ranker: {status} | Refined: {reason_ref}..."
        output_manager.append_log("Debate-Agent", log_r)
        
        if status == 'FALSE_POSITIVE':
            output_manager.append_log("Debate-Agent", f"-> Drop {vuln_id} (False Positive)")
            return None
            
        current['reasoning'] = d_ref.get('refined_reasoning', current.get('details'))

    output_manager.append_log("Debate-Agent", f"-> Drop {vuln_id} (No consensus)")
    return None 

# --- EXPORTED FUNCTION ---
async def logic_debate_pipeline(job: Dict, raw_findings: List[Dict]) -> List[Dict]:
    """
    Logic chính của Debate (có thể gọi bởi Queue Worker hoặc Sequential Runner).
    """
    repo_name = job.get("name", "unknown")
    source_path = job.get("path")
    
    # [FIX] Lấy đường dẫn output chính xác từ job
    # Điều này đảm bảo file log của Debate nằm chung folder với Executor/Reporter
    job_output_dir = job.get("output_dir")
    
    out_man = OutputManager(repo_name=repo_name, artifact_path=job_output_dir)
    model_name = os.environ.get("ACTIVE_LLM_MODEL") or os.environ.get("PLANNER_LLM_MODEL") or "gemini-2.0-flash"

    logger.info(f"🔹 [Debate] Processing {len(raw_findings)} items...")
    
    # 1. RANKER
    logger.info(f"   -> Running Ranker...")
    ranked_candidates = await _ranker_scan(model_name, raw_findings, out_man)
    
    msg_rank = f"Ranker filtered: {len(raw_findings)} -> {len(ranked_candidates)} potential issues."
    logger.info(f"   -> {msg_rank}")
    out_man.append_log("Debate-Agent", msg_rank)

    # 2. LOOP
    logger.info(f"   -> Running Debate Loop...")
    confirmed_vulns = []
    
    for idx, vuln in enumerate(ranked_candidates):
        v_type = vuln.get("type", "Unknown")
        logger.info(f"      [{idx+1}/{len(ranked_candidates)}] Debating: {v_type}")
        
        # Truyền output_manager vào để ghi log chi tiết
        res = await _debate_loop(model_name, vuln, source_path, out_man)
        
        if res:
            logger.info("        ✅ CONFIRMED")
            confirmed_vulns.append(res)
        else:
            logger.info("        ❌ REJECTED")

    # 3. FINISH
    try:
        out_man.write_json("Debate-Agent", "confirmed_vulnerabilities.json", confirmed_vulns)
    except Exception as e:
        logger.error(f"Failed to write Debate JSON: {e}")
    
    return confirmed_vulns
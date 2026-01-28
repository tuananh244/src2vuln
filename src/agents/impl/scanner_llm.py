import asyncio
import logging
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import List, Dict

# --- IMPORTS ---
from src.llm.llm_manager import call_model
from src.utils.code_analyzer import SmartFileDiscovery, FunctionExtractor
from src.utils.context_filter import SemanticContextFilter
from src.prompts.prompt_analysis import generate_sast_prompt
from src.utils.data_processors import DataProcessor 
from src.utils.output_manager import OutputManager

logger = logging.getLogger("Scanner-LLM")

_local_thread_pool = ThreadPoolExecutor(max_workers=4)

def _run_llm_logic_sync(job: Dict, output_manager: OutputManager) -> List[Dict]:
    """
    Core logic: Quét mã nguồn bằng LLM (Chạy Sync để đưa vào ThreadPool).
    """
    # 1. Lấy Path và Resolve thành đường dẫn tuyệt đối
    raw_path = job["path"]
    target_path = Path(raw_path).resolve()
    
    # [FIX] Định nghĩa biến target_repo (dạng string) để dùng cho normalize path bên dưới
    target_repo = str(target_path)

    language = job["language"]
    
    # Lấy model
    model_name = os.environ.get("ACTIVE_LLM_MODEL") or "gemini-2.0-flash"
    
    logger.info(f"[{job['name']}] Starting LLM Analysis...")
    output_manager.append_log("LLM-Scanner", f"Starting LLM Scan on {target_path}")
    
    # =================================================================
    # 2. DISCOVERY & INPUT HANDLING
    # =================================================================
    files = []

    if not target_path.exists():
        msg = f"❌ Path does not exist: {target_path}"
        logger.error(msg)
        output_manager.append_log("LLM-Scanner", msg)
        return []

    # CASE A: Input là File cụ thể
    if target_path.is_file():
        logger.info(f"[{job['name']}] Detected Single File mode.")
        files = [str(target_path)]

    # CASE B: Input là Folder
    elif target_path.is_dir():
        logger.info(f"[{job['name']}] Running Smart Discovery on folder...")
        
        try:
            discovery = SmartFileDiscovery(str(target_path), language)
            files = discovery.scan()
        except Exception as e:
            logger.warning(f"SmartFileDiscovery failed: {e}. Switching to manual fallback.")
            files = []

        # Fallback nếu Smart Discovery rỗng
        if not files:
            logger.warning(f"[{job['name']}] Smart Discovery found 0 files. Trying manual glob...")
            
            extensions = {
                "python": [".py"],
                "java": [".java"],
                "javascript": [".js", ".ts", ".jsx", ".tsx"],
                "cpp": [".c", ".cpp", ".h", ".hpp"]
            }.get(language, [])
            
            for ext in extensions:
                found = list(target_path.rglob(f"*{ext}"))
                files.extend([str(f) for f in found])
            
            # Fallback cuối cùng cho python
            if not files and language == "python":
                files = [str(f) for f in target_path.rglob("*.py")]

    if not files:
        msg = f"⛔ No source files found for LLM Scan in: {target_path}"
        logger.warning(f"[{job['name']}] {msg}")
        output_manager.append_log("LLM-Scanner", msg)
        return []

    # =================================================================
    # 3. EXTRACTION
    # =================================================================
    extractor = FunctionExtractor()
    all_funcs = []
    
    for f in files:
        try: 
            all_funcs.extend(extractor.extract_from_file(f))
        except Exception as e: 
            logger.debug(f"Extract error {f}: {e}")

    # Fallback nếu không tách được hàm (File script đơn giản)
    if not all_funcs:
        for f in files:
            try:
                content = Path(f).read_text(encoding='utf-8', errors='ignore')
                if content.strip():
                    all_funcs.append({
                        "name": f"Script_Content_{Path(f).stem}",
                        "code": content,
                        "file_path": f,
                        "decorators": [],
                        "start_line": 1
                    })
            except: pass

    # =================================================================
    # 4. FILTERING
    # =================================================================
    try:
        ctx_filter = SemanticContextFilter(threshold=0.35)
        relevant_funcs = ctx_filter.filter(all_funcs)
    except Exception as e:
        logger.warning(f"Context Filter error: {e}. Analyzing all functions.")
        relevant_funcs = all_funcs
    
    msg_scan = f"Scanning {len(relevant_funcs)}/{len(all_funcs)} relevant functions."
    logger.info(f"[{job['name']}] {msg_scan}")
    output_manager.append_log("LLM-Scanner", msg_scan)
    
    # =================================================================
    # 5. ANALYSIS LOOP
    # =================================================================
    findings = []
    
    for func in relevant_funcs:
        func_name = func['name']
        fpath = func['file_path']
        start_line = func.get('start_line', 1)
        
        code_str = str(func['code']) if func['code'] else ""
        
        # Gọi Static Method
        numbered_code = DataProcessor.add_line_numbers(code_str, start_line)

        prompt = generate_sast_prompt(
            language=language,
            func_name=func_name,
            file_path=fpath,
            source_code=numbered_code, 
            decorators=func['decorators']
        )

        try:
            # Gọi LLM (đã tích hợp sync/async, retry, rate limit)
            response = call_model(model_name=model_name, prompt=prompt, temperature=0.1)
            
            data = DataProcessor.safe_extract_json(response)
            
            if data and data.get("vulnerabilities"):
                for vuln in data["vulnerabilities"]:
                    
                    # [FIX] Dùng biến target_repo đã định nghĩa
                    clean_flow = DataProcessor.normalize_code_flow(vuln.get("code_flow", []), target_repo)
                    
                    finding = {
                        "source_tool": "LLM-Scanner",
                        "type": vuln.get("type", "Unknown"),
                        "cwe": vuln.get("cwe_id", "Unknown"),
                        "severity": vuln.get("severity", "Medium"),
                        "location_hint": str(clean_flow[-1].get("line", start_line)) if clean_flow else str(start_line),
                        "file_path": fpath,
                        "details": vuln.get("reasoning", ""),
                        "code_flow": clean_flow,
                        "output_dir": str(output_manager.get_repo_dir()),
                        "prompt_log": prompt 
                    }
                    findings.append(finding)
                    logger.info(f"   ⚠️ [LLM] Found {finding['type']} in {func_name}")
                    
        except Exception as e:
            logger.error(f"[LLM-Scanner] Error analyzing {func_name}: {e}")

    output_manager.append_log("LLM-Scanner", f"Finished. Found {len(findings)} issues.")
    return findings


async def logic_llm_batch_scan(job: Dict) -> List[Dict]:
    """
    Wrapper Async: Được gọi bởi Queue Manager hoặc Batch Runner.
    """
    repo_name = job.get("name", "unknown_repo")
    
    # [FIX] Lấy đường dẫn output chính xác từ job context
    # Đây là đường dẫn dạng: output/SecurityEval/CWE-xxx
    job_output_dir = job.get("output_dir")
    
    # Khởi tạo OutputManager với artifact_path
    out_man = OutputManager(repo_name=repo_name, artifact_path=job_output_dir)
    
    logger.info(f"[{repo_name}] 🧠 Executing LLM Logic...")
    
    try:
        loop = asyncio.get_running_loop()
        findings = await loop.run_in_executor(
            _local_thread_pool,
            partial(_run_llm_logic_sync, job=job, output_manager=out_man)
        )
    except Exception as e:
        logger.error(f"[{repo_name}] LLM Logic Crash: {e}")
        out_man.append_log("LLM-Scanner", f"CRASH: {e}")
        findings = [] 
        
    out_man.save_agent_output("LLM-Scanner", findings)
    
    return findings
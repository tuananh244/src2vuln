##!/usr/bin/env python3
"""
queue_manager.py
Clean version:
- No prompt templates
- No prompt strings
- No business rules
- Only pipeline orchestration
"""

import asyncio
import asyncio
import logging
import json
import os
import sys
import re
import shutil
import tempfile
import time
import docker
import aiohttp
from docker.errors import DockerException, BuildError, APIError
from functools import partial
from typing import List, Dict, Union
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Import function from utils and llm modules
from src.llm.llm_manager import call_model
from src.utils.codeql_runner import run_command
from src.utils.output_manager import OutputManager
from src.utils.data_processors import DataProcessor
from src.utils.code_analyzer import SmartFileDiscovery, FunctionExtractor
from src.utils.context_filter import SemanticContextFilter

# Import prompt builders (user-defined modules)
from src.prompts.prompt_planner_3strep import get_strategy_prompt, get_payload_prompt, get_refiner_prompt
from src.prompts.prompt_debate import get_ranker_prompt, get_critic_prompt, get_ranker_refinement_prompt
from src.prompts.prompt_verifier import build_verifier_prompt
from src.prompts.prompt_analysis import generate_sast_prompt
from src.prompts.prompt_reported import get_poc_report_prompt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
thread_pool = ThreadPoolExecutor(max_workers=4)

# Pipeline Queue Manager
queue_input     = asyncio.Queue()  # <-- Hàng đợi đầu vào của toàn bộ hệ thống
queue_codeql    = asyncio.Queue() # CodeQL Task
queue_llm       = asyncio.Queue() # LLM Task
queue_collect   = asyncio.Queue() # Merge Task
queue_debate    = asyncio.Queue() # Verification Task
queue_plan      = asyncio.Queue() # Strategy Task
queue_exec      = asyncio.Queue() # PoC Task
queue_verify    = asyncio.Queue() # Final Verify
queue_final     = asyncio.Queue() # Report

logger = logging.getLogger("Agents")

# docker client
try:
    docker_client = docker.from_env()
    docker_client.ping()
except Exception as e:
    logger.error("❌ Docker daemon not available.", e)
    docker_client = None

# ---------------------------------------------------------
# AGENT 0: DISPATCHER AGENT (Cổng phân phối Job)
# ---------------------------------------------------------

async def dispatcher_agent():
    """
    Dispatcher Agent:
    1. Nhận Job từ queue_input (do Main gửi tới).
    2. Tạo thư mục Output.
    3. Nhân bản Job và đẩy vào queue_codeql và queue_llm.
    """
    logger.info("=== Dispatcher Agent Started ===")
    
    while True:
        # Lấy job từ Main
        job = await queue_input.get()
        
        repo_name = job["name"]
        logger.info(f"[{repo_name}] Dispatching job to Scanners...")

        # Đảm bảo output directory tồn tại
        out_dir = Path(job["output_dir"])
        out_dir.mkdir(parents=True, exist_ok=True)
        
        # Tạo OutputManager để log khởi động
        out_man = OutputManager(repo_name=repo_name)
        out_man.append_log("Dispatcher", "Job received and dispatched.")

        # Nhân bản job để gửi đi 2 hướng song song
        # .copy() là cần thiết để tránh xung đột pointer
        await queue_codeql.put(job.copy())
        await queue_llm.put(job.copy())
        
        logger.info(f"[{repo_name}] Sent to CodeQL & LLM Queues.")
        
        queue_input.task_done()

# ---------------------------------------------------------
# Stage 1: SAST With CodeQL
# Agent Usage: codeql_agent
# ---------------------------------------------------------

def safe_extract_json( text: str) -> Union[Dict, List, None]:
    """
    Trích xuất JSON từ chuỗi văn bản hỗn độn (Markdown, Text...).
    Sử dụng thuật toán Stack-based mạnh mẽ.
    """
    if not text:
        return None

    # Cách 1: Parse trực tiếp
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Cách 2: Regex Markdown Block
    match = re.search(r'```(?:json)?\s*([\[\{].*?[\]\}])\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Cách 3: Stack Scanning (Tìm cặp ngoặc {} hoặc [] ngoài cùng)
    stack = []
    start_index = -1
    
    for i, char in enumerate(text):
        if char in ('{', '['):
            if not stack:
                start_index = i
            stack.append(char)
        elif char in ('}', ']'):
            if stack:
                last = stack[-1]
                if (last == '{' and char == '}') or (last == '[' and char == ']'):
                    stack.pop()
                    if not stack: # Tìm thấy trọn vẹn 1 object/array
                        try:
                            return json.loads(text[start_index : i+1])
                        except json.JSONDecodeError:
                            pass # Thử tiếp
                else:
                    stack = [] # Ngoặc lỗi
    
    logger.warning("No valid JSON found in text.")
    return None

# ==========================================================
# 2. FILE SYSTEM UTILS
# ==========================================================

def read_source_line( base_path: Path, relative_path: str, line_num: int) -> str:
    """Đọc dòng code cụ thể từ file an toàn."""
    if not relative_path or not line_num or line_num < 1:
        return "[Invalid location]"

    try:
        target_file = (base_path / relative_path).resolve()
        if target_file.exists():
            try:
                content = target_file.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = target_file.read_text(encoding="latin-1")
            
            lines = content.splitlines()
            if line_num <= len(lines):
                return lines[line_num - 1].strip()
    except Exception:
        pass
    
    return "[Source unavailable]"

def add_line_numbers( code: str, start_line: int = 1) -> str:
    """Thêm số dòng vào trước mỗi dòng code (cho LLM Context)."""
    if not code: return ""
    lines = code.split('\n')
    return "\n".join([f"{start_line + i:<4} | {line}" for i, line in enumerate(lines)])

def normalize_code_flow( flow_list: List[Dict], target_repo: str) -> List[Dict]:
    """Làm sạch Code Flow (Xóa trùng lặp, chuyển path tuyệt đối -> tương đối)."""
    if not flow_list: return []
    cleaned = []
    last_line = -1
    
    for step in flow_list:
        cur_line = step.get("line")
        # Bỏ qua dòng trùng liên tiếp
        if cur_line == last_line: continue
        
        # Xử lý code thiếu
        if not step.get("code"): step["code"] = "[Code snippet not captured]"
        
        # Xử lý path
        fpath = step.get("file")
        if fpath and target_repo in fpath and os.path.isabs(fpath):
            try: step["file"] = os.path.relpath(fpath, target_repo)
            except: pass
        
        cleaned.append(step)
        last_line = cur_line
    return cleaned

# ==========================================================
# 3. SARIF PARSER (Async)
# ==========================================================
def _extract_sarif_location(loc_obj, artifacts, base_path):
    """Private helper extract location details."""
    phys = loc_obj.get("physicalLocation", {}) if "physicalLocation" not in loc_obj else loc_obj["physicalLocation"]
    art_loc = phys.get("artifactLocation", {})
    
    uri = art_loc.get("uri")
    idx = art_loc.get("index")
    
    # Resolve index to uri
    if not uri and idx is not None and 0 <= idx < len(artifacts):
        uri = artifacts[idx].get("location", {}).get("uri")
        
    region = phys.get("region", {})
    line = region.get("startLine")
    snippet = region.get("snippet", {}).get("text")
    
    if not snippet and line and uri:
        snippet = read_source_line(base_path, uri, line)
        
    return {"file": uri, "line": line, "snippet": snippet}

def safe_parse_json(text: str) -> Union[Dict, List, None]:
    """
    Trích xuất JSON từ chuỗi văn bản hỗn độn (Markdown, Text...).
    Sử dụng thuật toán Stack-based mạnh mẽ.
    """
    if not text:
        return None

    # Cách 1: Parse trực tiếp
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Cách 2: Regex Markdown Block
    match = re.search(r'```(?:json)?\s*([\[\{].*?[\]\}])\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Cách 3: Stack Scanning (Tìm cặp ngoặc {} hoặc [] ngoài cùng)
    stack = []
    start_index = -1
    
    for i, char in enumerate(text):
        if char in ('{', '['):
            if not stack:
                start_index = i
            stack.append(char)
        elif char in ('}', ']'):
            if stack:
                last = stack[-1]
                if (last == '{' and char == '}') or (last == '[' and char == ']'):
                    stack.pop()
                    if not stack: # Tìm thấy trọn vẹn 1 object/array
                        try:
                            return json.loads(text[start_index : i+1])
                        except json.JSONDecodeError:
                            pass # Thử tiếp
                else:
                    stack = [] # Ngoặc lỗi
    
    logger.warning("No valid JSON found in text.")
    return None

def parse_sarif_file(sarif_path: Path, job_context: Dict) -> List[Dict]:
    """Parse file SARIF và trả về danh sách Hypothesis."""
    logger.info(f"Parsing SARIF file: {sarif_path}")
    print(f"Test thanh cong")  # Debug line
    if not sarif_path.exists():
        logger.warning(f"SARIF missing: {sarif_path}")
        return []

    try:
        content = sarif_path.read_text(encoding="utf-8", errors="replace")
        sarif_data = json.loads(content)
    except Exception as e:
        logger.error(f"SARIF decode error: {e}")
        return []

    hypos = []
    base_path = Path(job_context["path"])

    for run in sarif_data.get("runs", []):
        artifacts = run.get("artifacts", [])
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        rule_map = {r.get("id"): r for r in rules}

        for idx, res in enumerate(run.get("results", [])):
            rule_id = res.get("ruleId")
            rule_info = rule_map.get(rule_id, {})
            
            # Extract CWE
            cwe = "CWE-UNKNOWN"
            for t in rule_info.get("properties", {}).get("tags", []):
                if "external/cwe" in t.lower():
                    cwe = t.split("/")[-1].upper() if "/" in t else t
                    break
            
            # Extract Location
            sink = {}
            locs = res.get("locations", [])
            if locs:
                sink = _extract_sarif_location(locs[0], artifacts, base_path)

            # Extract Code Flow
            code_flow = []
            cflows = res.get("codeFlows", [])
            if cflows:
                # Lấy flow đầu tiên
                tflows = cflows[0].get("threadFlows", [])
                if tflows:
                    for step in tflows[0].get("locations", []):
                        loc_obj = step.get("location", {})
                        msg = loc_obj.get("message", {}).get("text", "Step")
                        
                        step_data = _extract_sarif_location(loc_obj, artifacts, base_path)
                        if step_data["file"]:
                            code_flow.append({
                                "file": step_data["file"],
                                "line": step_data["line"],
                                "code": step_data["snippet"] or "[No code]",
                                "step_description": msg
                            })

            # Entry Point (Source)
            source = {}
            if code_flow:
                source = {"file": code_flow[0]["file"], "line": code_flow[0]["line"]}

            hypos.append({
                "vuln_id": f"{job_context['name']}-{idx}",
                "rule_id": rule_id,
                "cwe": cwe,
                "severity": res.get("level", "warning"),
                "description": res.get("message", {}).get("text", ""),
                "sink": sink,
                "source": source,
                "code_flow": code_flow,
                "job": job_context
            })
    
    return hypos

async def codeql_agent():
    """Static Analysis Agent (CodeQL)."""
    logger.info("=== CodeQL Agent Started ===")
    while True:
        # 1. Nhận Job từ hàng đợi riêng của CodeQL
        job = await queue_codeql.get()
        name = job["name"]
        lang = job["language"]
        path = job["path"]

        # Đảm bảo trong OutputManager.AGENTS đã có tên "CodeQL-Agent" (hoặc dùng "A-Agent" nếu muốn)
        AGENT_NAME = "codeQL-Agent" 
        out_man = OutputManager(repo_name=name)
        
        # Tạo folder
        try:
            agent_dir = out_man.get_agent_dir(AGENT_NAME)
        except ValueError:
            # Fallback nếu chưa config tên này trong OutputManager
            agent_dir = out_man.repo_dir / AGENT_NAME
            agent_dir.mkdir(exist_ok=True)

        db_path = agent_dir / f"{name}-{lang}-db"
        sarif_path = agent_dir / f"{name}.sarif"
        
        logger.info(f"[{name}] Starting CodeQL Analysis...")
        out_man.append_log(AGENT_NAME, f"Starting CodeQL for {name}...")

        # 2. Clean up
        if db_path.exists():
            shutil.rmtree(db_path)

        # 3. Create DB
        logger.info(f"[{name}] Building CodeQL DB...")
        ok_create = await run_command([
            "codeql", "database", "create", str(db_path),
            f"--language={lang}",
            f"--source-root={path}"
        ], progress=True, phase="DB Init")

        if not ok_create:
            msg = "DB Creation failed."
            logger.error(f"[{name}] {msg}")
            out_man.append_log(AGENT_NAME, msg)
            queue_codeql.task_done()
            continue

        # 4. Analyze
        suite = {
            "python": "/home/tuananh/Desktop/codeql/python/ql/src/codeql-suites/python-security-and-quality.qls",
            "java":   "/home/tuananh/Desktop/codeql/java/ql/src/codeql-suites/java-security-and-quality.qls"
        }.get(lang)

        if not suite:
            logger.error(f"[{name}] No suite for {lang}")
            queue_codeql.task_done()
            continue

        logger.info(f"[{name}] Analyzing...")
        ok_analyze = await run_command([
            "codeql", "database", "analyze", str(db_path),
            suite,
            "--format=sarifv2.1.0",
            f"--output={sarif_path}"
        ], progress=True, phase="Analyzing")
        logger.info(f"[{name}] Analysis completed.")
        if not ok_analyze:
            msg = "Analysis failed."
            logger.info(f"[{name}] {msg}")
            out_man.append_log(AGENT_NAME, msg)
            queue_codeql.task_done()
            continue
        logger.info(f"DEBUG: SARIF generated at {sarif_path}")
        # 5. Process Data
        # Gọi hàm parse
        #logger.info(f"[DEBUG]: {parse_sarif_file(sarif_path, job)}")
        hypos = parse_sarif_file(sarif_path, job)
        logger.info(f"[{name}] CodeQL found {len(hypos)} issues.")
        out_man.write_json(AGENT_NAME, "findings.json", hypos)
        out_man.append_log(AGENT_NAME, "Finished.")

        # CodeQL là 1 nhánh song song, cần Collector đợi nhánh LLM xong mới gộp
        await queue_collect.put({
            "repo": name,
            "tool": "CodeQL",
            "findings": hypos,
            "job": job # Truyền job gốc để Collector dùng tiếp
        })

        queue_codeql.task_done()
    

# ---------------------------------------------------------
# Stage 2: SAST With LLM
# Agent Usage: LLM_SAST_Agent
# ---------------------------------------------------------

# Hàm xử lý sync để chạy trong ThreadPool
def _run_llm_logic_sync(job, output_manager):
    """Core logic của LLM Scan (Chạy Sync để không block Event Loop)."""
    target_repo = job["path"]
    language = job["language"]
    model_name = os.environ.get("ACTIVE_LLM_MODEL", "gemini-2.0-flash")
    
    # Logging qua OutputManager
    logger.info(f"[{job['name']}] Starting LLM Analysis...")
    output_manager.append_log("LLM-Scanner", f"Starting LLM Scan on {target_repo} using {model_name}")
    
    # 1. DISCOVERY
    discovery = SmartFileDiscovery(str(target_repo), language)
    files = discovery.scan()
    if not files:
        logger.info(f"[{job['name']}] No source files found for LLM Scan.")
        output_manager.append_log("LLM-Scanner", "No files found.")
        return []

    # 2. EXTRACTION
    extractor = FunctionExtractor()
    all_funcs = []
    for f in files:
        try: all_funcs.extend(extractor.extract_from_file(f))
        except: pass

    # 3. FILTERING
    ctx_filter = SemanticContextFilter(threshold=0.35)
    relevant_funcs = ctx_filter.filter(all_funcs)
    logger.info(f"[{job['name']}] {len(relevant_funcs)}/{len(all_funcs)} functions relevant after filtering.")
    output_manager.append_log("LLM-Scanner", f"Scanning {len(relevant_funcs)} relevant functions.")
    
    # 4. ANALYSIS LOOP
    findings = []
    for func in relevant_funcs:
        func_name = func['name']
        fpath = func['file_path']
        start_line = func.get('start_line', 1)
        
        # Dùng DataProcessor để đánh số dòng
        numbered_code = add_line_numbers(func['code'], start_line)

        prompt = generate_sast_prompt(
            language=language,
            func_name=func_name,
            file_path=fpath,
            source_code=numbered_code, 
            decorators=func['decorators']
        )

        try:
            # Gọi Model
            response = call_model(model_name=model_name, prompt=prompt, temperature=0.1)
            
            # Dùng DataProcessor để parse an toàn
            data = safe_extract_json(response)
            
            if data and data.get("vulnerabilities"):
                for vuln in data["vulnerabilities"]:
                    # Dùng DataProcessor để normalize path
                    clean_flow = normalize_code_flow(vuln.get("code_flow", []), target_repo)
                    
                    # Chuẩn hóa format finding
                    finding = {
                        "source_tool": "LLM-Scanner",
                        "type": vuln.get("type", "Unknown"),
                        "cwe": vuln.get("cwe_id", "Unknown"),
                        "severity": vuln.get("severity", "Medium"),
                        "location_hint": str(clean_flow[-1].get("line", start_line)) if clean_flow else str(start_line),
                        "file_path": fpath,
                        "details": vuln.get("reasoning", ""),
                        "code_flow": clean_flow,
                        # Output dir để các bước sau biết chỗ lưu file
                        "output_dir": str(output_manager.get_repo_dir()) 
                    }
                    findings.append(finding)
                    logger.info(f"   ⚠️ [LLM] Found {finding['type']} in {func_name}")
                    
        except Exception as e:
            logger.error(f"[LLM-Scanner] Error analyzing {func_name}: {e}")

    output_manager.append_log("LLM-Scanner", f"Finished. Found {len(findings)} issues.")
    return findings


async def LLM_SAST_Agent():
    """Agent Wrapper: Nhận Job từ Queue -> Chạy Logic -> Đẩy sang Collector."""
    logger.info("=== LLM SAST Agent Started ===")
    
    while True:
        job = await queue_llm.get()
        name = job["name"]
        
        # Setup Output Manager
        out_man = OutputManager(repo_name=name)
        # Tạo folder nếu chưa có (mặc định OutputManager init đã tạo rồi)
        # agent_dir = out_man.get_agent_dir("LLM-Scanner") 

        logger.info(f"[{name}] 🧠 Starting LLM Analysis...")
        
        try:
            # Chạy logic trong ThreadPool
            findings = await asyncio.get_running_loop().run_in_executor(
                thread_pool, # Nên dùng biến global thread_pool nếu có
                partial(_run_llm_logic_sync, job=job, output_manager=out_man)
            )
        except Exception as e:
            logger.error(f"[{name}] LLM Agent CRASHED: {e}")
            findings = [] # Trả về rỗng để Collector không bị treo
        
        # Lưu kết quả thô
        out_man.write_json("LLM-Scanner", "findings.json", findings)
        
        # Gửi sang Collector
        await queue_collect.put({
            "repo": name,
            "tool": "LLM-Scanner",
            "findings": findings,
            "job": job
        })
        
        queue_llm.task_done()

# ---------------------------------------------------------
# Stage 3: Collector report from 2 agents
# Agent Usage: Collector_Agent
# ---------------------------------------------------------
async def collector_agent():
    """
    Collector Agent (Worker):
    - Lắng nghe queue_collect.
    - Chờ đủ kết quả (CodeQL + LLM).
    - Gộp kết quả.
    - Quan trọng: Đóng gói 'total_findings' để Reporter tính Recall sau này.
    """
    logger.info("=== Collector Agent Started (Worker) ===")
    
    # Buffer: key=repo_name
    buffer = {} 
    
    while True:
        msg = await queue_collect.get()
        
        repo_name = msg["repo"]
        tool_name = msg["tool"]
        new_findings = msg["findings"]
        job_context = msg["job"]
        
        # 1. Init Buffer
        if repo_name not in buffer:
            buffer[repo_name] = {
                "tools_done": set(),
                "all_findings": [],
                "job_context": job_context
            }
            
        # 2. Update Buffer
        buffer[repo_name]["tools_done"].add(tool_name)
        buffer[repo_name]["all_findings"].extend(new_findings)
        
        # Log tiến độ
        out_man = OutputManager(repo_name=repo_name)
        status = f"Received {len(new_findings)} issues from {tool_name}. Progress: {len(buffer[repo_name]['tools_done'])}/2"
        logger.info(f"[{repo_name}] {status}")
        out_man.append_log("Collector", status)
        
        # 3. KIỂM TRA ĐIỀU KIỆN ĐỦ (Sync Point)
        if len(buffer[repo_name]["tools_done"]) >= 2:
            final_findings = buffer[repo_name]["all_findings"]
            total = len(final_findings)
            
            log_done = f"✅ Collection Complete. Merged Total: {total}. Forwarding to Debate."
            logger.info(f"[{repo_name}] {log_done}")
            out_man.append_log("Collector", log_done)
            
            # Lưu file Snapshot
            out_man.write_json("Collector", "combined_raw_findings.json", final_findings)
            
            # --- QUAN TRỌNG: Cập nhật job_context cho Reporter ---
            # Reporter cần biết tổng số lỗi ban đầu để tính Recall (TP / Total)
            # Vì các bước sau (Debate) sẽ lọc bớt lỗi đi, nên con số này phải được lưu ngay tại đây.
            
            updated_context = job_context.copy()
            updated_context["total_findings"] = total  # <--- DÒNG MỚI THÊM
            
            # Đóng gói payload
            debate_payload = {
                "name": repo_name,
                "path": job_context["path"],
                "output_dir": job_context["output_dir"],
                "findings": final_findings,
                "job_context": updated_context # Truyền context đã update
            }
            
            # Đẩy sang Queue Debate
            await queue_debate.put(debate_payload)
            
            # Xóa buffer
            del buffer[repo_name]
            
        queue_collect.task_done()

# ---------------------------------------------------------
# Stage 4: Debate Agent
# Agent Usage: Debate_Agent
# ---------------------------------------------------------

# --- HELPER 1: RANKER SCAN ---
async def _ranker_scan(model_name: str, findings: List[Dict]) -> List[Dict]:
    """Lọc thô: Chọn ra các lỗi tiềm năng nhất."""
    if not findings: return []
    
    # Rút gọn dữ liệu gửi cho LLM để tiết kiệm token
    simplified = [{
        "id": i, 
        "tool": f.get("source_tool"), 
        "type": f.get("type"), 
        "file": f.get("file_path"),
        "details": f.get("details", "")[:200]
    } for i, f in enumerate(findings)]

    try:
        prompt = get_ranker_prompt("", simplified) 
        resp = await asyncio.to_thread(call_model, model_name, prompt)
        data = safe_parse_json(resp)
        
        ranked_ids = [x.get('id') for x in data.get('ranked_vulnerabilities', []) if x.get('id') is not None]
        
        # Map ngược lại danh sách gốc
        selected = []
        for idx in ranked_ids:
            if 0 <= idx < len(findings):
                item = findings[idx].copy()
                # Lấy lý do từ Ranker
                reason = next((r.get('reason') for r in data.get('ranked_vulnerabilities', []) if r.get('id') == idx), "")
                item['ranker_reason'] = reason
                selected.append(item)
        return selected
    except Exception as e:
        logger.error(f"[Debate] Ranker error: {e}")
        return findings # Fallback: Trả về tất cả nếu lỗi

# --- HELPER 2: DEBATE LOOP ---
async def _debate_loop(model_name: str, vuln: Dict, source_root: str) -> Dict:
    """Tranh biện chi tiết (Critic vs Ranker) cho 1 lỗi."""
    current = vuln.copy()
    
    # 1. Lấy Context (File content hoặc Code Flow)
    context = ""
    if current.get("file_path"):
        full_path = Path(source_root) / current["file_path"]
        if full_path.exists():
            try: context = full_path.read_text(encoding="utf-8", errors="ignore")
            except: pass
    
    if not context:
        context = json.dumps(current.get("code_flow", []), indent=2)

    # 2. Vòng lặp tối đa 3 lần
    for _ in range(3):
        # Critic Review
        p_crit = get_critic_prompt(context, current)
        r_crit = await asyncio.to_thread(call_model, model_name, p_crit)
        d_crit = safe_parse_json(r_crit)
        
        # Chốt nếu Critic đồng ý
        if str(d_crit.get('verdict')).upper() == "AGREE":
            current['final_status'] = "CONFIRMED"
            current['critic_reason'] = d_crit.get('reason')
            return current
        
        # Ranker Refine (Sửa lại argumen dựa trên feedback)
        p_ref = get_ranker_refinement_prompt(context, current, d_crit.get('feedback', ''))
        r_ref = await asyncio.to_thread(call_model, model_name, p_ref)
        d_ref = safe_parse_json(r_ref)
        
        # Loại nếu Ranker nhận sai
        if str(d_ref.get('status')).upper() == 'FALSE_POSITIVE':
            return None
            
        current['reasoning'] = d_ref.get('refined_reasoning', current.get('details'))

    return None # Loại nếu hết vòng mà không chốt

# --- MAIN AGENT (WORKER) ---
async def agent_debate():
    """
    Debate Agent (Worker Mode):
    - Lắng nghe queue_debate.
    - Chạy Ranker -> Loop.
    - Đẩy kết quả vào queue_plan.
    """
    logger.info("=== Debate Agent Started (Worker) ===")
    
    while True:
        # 1. Nhận Job từ Queue
        msg = await queue_debate.get()
        
        repo_name = msg["name"]
        raw_findings = msg["findings"]
        source_path = msg["path"]
        
        # Setup Output
        out_man = OutputManager(repo_name=repo_name)
        out_man.append_log("Debate-Agent", f"Received {len(raw_findings)} items from Collector.")
        logger.info(f"🔹 [Debate-Agent] Processing {repo_name} ({len(raw_findings)} items)...")

        if not raw_findings:
            logger.warning(f"[{repo_name}] No findings to debate.")
            queue_debate.task_done()
            continue

        model_name = os.environ.get("ACTIVE_LLM_MODEL", "gemini-2.0-flash")

        # 2. RUN RANKER
        logger.info(f"   -> Running Ranker...")
        ranked_candidates = await _ranker_scan(model_name, raw_findings)
        
        log_rank = f"Ranker filtered: {len(raw_findings)} -> {len(ranked_candidates)} potential issues."
        logger.info(f"   -> {log_rank}")
        out_man.append_log("Debate-Agent", log_rank)

        # 3. RUN DEBATE LOOP
        logger.info(f"   -> Running Debate Loop...")
        confirmed_vulns = []
        
        for idx, vuln in enumerate(ranked_candidates):
            v_type = vuln.get("type", "Unknown")
            logger.info(f"      [{idx+1}/{len(ranked_candidates)}] Debating: {v_type}")
            
            res = await _debate_loop(model_name, vuln, source_path)
            
            if res:
                logger.info("        ✅ CONFIRMED")
                confirmed_vulns.append(res)
            else:
                logger.info("        ❌ REJECTED")

        # 4. KẾT THÚC & ĐẨY TIẾP
        logger.info(f"[{repo_name}] Debate Finished. Valid: {len(confirmed_vulns)}")
        out_man.write_json("Debate-Agent", "confirmed_vulnerabilities.json", confirmed_vulns)
        
        if confirmed_vulns:
            # Để Planner biết context (Repo nào, Output vào đâu)
            planner_job = {
                "name": repo_name,
                "path": source_path,
                "output_dir": msg.get("output_dir"), # Lấy lại từ msg đầu vào
                "findings": confirmed_vulns,         # Dữ liệu chính
                "job_context": msg.get("job_context")
            }

            await queue_plan.put(planner_job)  # <-- Gửi gói tin đầy đủ
            logger.info(f"   -> 📨 Pushed job to Queue Plan ({len(confirmed_vulns)} findings).")
        else:
            logger.warning(f"   -> No vulnerabilities confirmed. Flow stops here.")

        queue_debate.task_done()

# ---------------------------------------------------------
# Stage 5: Planner the hypotheses into strategies
# Agent Usage: Planner_Agent
# ---------------------------------------------------------
# ====================================================================
# PHASE 3: PLANNER AGENT (RAG + Strategy + Payload + Refine)
# ====================================================================

# --- CONFIG & HELPERS ---
logger = logging.getLogger("P-Agent")
RAG_INDEX_PATH = "/home/tuananh/Desktop/src2vuln/data/RAG"
EMBEDDING_MODEL_NAME = "BAAI/bge-base-en-v1.5"

# Biến global để cache vector store, tránh load lại nhiều lần
_CACHED_VECTOR_STORE = None

def get_vector_store():
    """Load FAISS index an toàn (Singleton Pattern)."""
    global _CACHED_VECTOR_STORE
    if _CACHED_VECTOR_STORE: 
        return _CACHED_VECTOR_STORE

    if not os.path.exists(RAG_INDEX_PATH):
        logger.warning(f"[RAG] Path not found: {RAG_INDEX_PATH}")
        return None
    
    # Kiểm tra thư viện
    if not FAISS or not OpenAIEmbeddings:
        logger.warning("[RAG] Libraries (langchain/faiss) not installed.")
        return None

    try:
        if not os.environ.get("OPENAI_API_KEY"): 
            return None 
            
        embeddings = OpenAIEmbeddings(model=EMBEDDING_MODEL_NAME)
        # allow_dangerous_deserialization là cần thiết khi load local pickle
        _CACHED_VECTOR_STORE = FAISS.load_local(
            RAG_INDEX_PATH, embeddings, allow_dangerous_deserialization=True
        )
        logger.info("[RAG] Vector store loaded successfully.")
        return _CACHED_VECTOR_STORE
    except Exception as e:
        logger.warning(f"[RAG] Failed to load (non-fatal): {e}")
        return None

def retrieve_rag_context(vector_store, query: str, k=3) -> str:
    """Truy vấn vector DB."""
    if not vector_store: return ""
    try:
        docs = vector_store.similarity_search(query, k=k)
        # Format context gọn gàng
        return "\n\n".join([f"Info: {d.page_content}" for d in docs])
    except Exception:
        return ""

# --- CORE LOGIC (Dùng cho cả Sequential & Worker) ---
async def step_planning(confirmed_vulns: List[Dict], job_context: Dict = None) -> List[Dict]:
    """
    Logic chính: Nhận danh sách lỗi -> Tạo kế hoạch khai thác (PoC).
    """
    if not confirmed_vulns:
        return []

    logger.info(f"🔹 [Planner-Agent] Planning for {len(confirmed_vulns)} verified items...")
    model = os.environ.get("ACTIVE_LLM_MODEL", "gemini-2.0-flash")
    
    # Load RAG
    vector_store = await asyncio.to_thread(get_vector_store)
    
    results = []
    
    for h in confirmed_vulns:
        vuln_type = h.get('type', 'Unknown')
        details = h.get('details', '')
        
        # 1. RAG Retrieval
        rag_context = ""
        if vector_store:
            query = f"{vuln_type} {h.get('cwe', '')} exploitation"
            rag_context = await asyncio.to_thread(retrieve_rag_context, vector_store, query)

        try:
            # 2. Strategy Generation
            p1 = get_strategy_prompt(h, rag_context)
            r1 = await asyncio.to_thread(call_model, model, p1)
            strat = safe_parse_json(r1)
            
            # 3. Payload Generation
            p2 = get_payload_prompt(json.dumps(strat, indent=2))
            r2 = await asyncio.to_thread(call_model, model, p2)
            pay = safe_parse_json(r2)
            
            # 4. Refinement (Final Script)
            p3 = get_refiner_prompt(h, json.dumps(strat), json.dumps(pay))
            r3 = await asyncio.to_thread(call_model, model, p3)
            final_plan = safe_parse_json(r3)
            
            # Đóng gói kết quả cho Executor
            results.append({
                "hypothesis": h,          # Thông tin lỗi
                "test_plan": final_plan,  # Kịch bản tấn công
                "job_context": job_context # QUAN TRỌNG: Truyền path/output_dir cho Executor
            })
            
            logger.info(f"   -> Plan generated for {vuln_type}")

        except Exception as e:
            logger.error(f"   -> [P-Agent] Plan failed for {vuln_type}: {e}")

    return results

# --- WORKER AGENT (Async Queue Mode) ---
async def agent_planner():
    """
    Planner Agent (Worker):
    - Lắng nghe queue_plan.
    - Gọi logic step_planning.
    - Đẩy sang queue_exec.
    """
    logger.info("=== Planner Agent Started (Worker) ===")
    
    while True:
        # Nhận message (Dạng Dict chứ không phải List như code cũ)
        msg = await queue_plan.get()
        
        # Unpack dữ liệu (Xử lý Data Mismatch)
        if isinstance(msg, dict):
            findings = msg.get("findings", [])
            job_ctx = {
                "name": msg.get("name"),
                "path": msg.get("path"),
                "output_dir": msg.get("output_dir")
            }
        else:
            # Fallback cho code cũ (nếu msg là list)
            findings = msg
            job_ctx = {} # Mất context

        if not findings:
            queue_plan.task_done()
            continue

        # Gọi Core Logic
        plans = await step_planning(findings, job_ctx)
        
        if plans:
            await queue_exec.put(plans)
            logger.info(f"   -> 📨 Pushed {len(plans)} plans to Executor.")
        
        queue_plan.task_done()

# ---------------------------------------------------------
# Stage 6: Execute Planner Strategies
# Agent Usage: Execute_Agent
# ---------------------------------------------------------

async def step_execution(plans: List[Dict]) -> List[Dict]:
    """
    Thực thi các kế hoạch tấn công (PoC).
    1. Dựng Docker Target.
    2. Chạy script tấn công.
    3. Lưu kết quả.
    """
    logger.info(f"🔹 [Executor] Running {len(plans)} plans...")
    
    results = []
    
    for job in plans:
        # Unpack dữ liệu
        h = job.get("hypothesis", {})
        plan = job.get("test_plan", {})
        script_content = plan.get("script_content")
        
        # Context từ các bước trước
        repo_name = h.get("job", {}).get("name", "unknown_repo")
        repo_path = h.get("job", {}).get("path")
        output_dir = h.get("job", {}).get("output_dir") or h.get("output_dir")

        # Setup Output Manager
        out_man = OutputManager(repo_name=repo_name)
        
        exec_res = {"status": "skipped", "reason": "Unknown"}
        container = None
        
        # --- KIỂM TRA ĐIỀU KIỆN ---
        dockerfile_path = os.path.join(repo_path, "Dockerfile") if repo_path else ""
        has_dockerfile = os.path.exists(dockerfile_path)

        if not docker_client:
            exec_res = {"status": "error", "reason": "Docker daemon not available"}
        elif not script_content:
            exec_res = {"status": "error", "reason": "No script content in plan"}
        elif not has_dockerfile:
            exec_res = {"status": "error", "reason": "No Dockerfile in repo"}
            out_man.append_log("Executor", f"Skipping {h.get('vuln_id')}: No Dockerfile found.")
        else:
            # --- START EXECUTION ---
            try:
                # 1. SETUP TARGET (DOCKER)
                vid = h.get("vuln_id", "test").lower().replace(":", "").replace(" ", "")
                img_tag = f"vuln-target-{vid}"
                container_name = f"run-{vid}"

                out_man.append_log("Executor", f"Building image {img_tag}...")
                
                # Build Image
                await asyncio.to_thread(
                    docker_client.images.build,
                    path=repo_path,
                    tag=img_tag,
                    rm=True
                )

                # Run Container (Target)
                # Map port 5000 container ra port ngẫu nhiên hoặc cố định (ở đây dùng 5000)
                try:
                    old = docker_client.containers.get(container_name)
                    old.remove(force=True)
                except: pass

                out_man.append_log("Executor", "Starting container...")
                container = await asyncio.to_thread(
                    docker_client.containers.run,
                    img_tag,
                    detach=True,
                    name=container_name,
                    ports={'5000/tcp': 5000}, # Cảnh báo: Port conflict nếu chạy song song
                    remove=True
                )
                
                # Wait for startup
                await asyncio.sleep(5) 

                # 2. RUN ATTACK SCRIPT
                out_man.append_log("Executor", "Running PoC Script...")
                
                # Lưu script ra file trong folder PoC của OutputManager
                poc_filename = f"poc_{vid}.py"
                poc_path = out_man.get_poc_dir() / poc_filename
                poc_path.write_text(script_content, encoding="utf-8")
                
                # Thực thi script (Trên Host, gọi vào Container qua localhost:5000)
                proc = await asyncio.create_subprocess_exec(
                    sys.executable, str(poc_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await proc.communicate()
                raw_out = stdout.decode().strip()
                raw_err = stderr.decode().strip()
                
                out_man.append_log("Executor", f"Script Output: {raw_out}")
                if raw_err:
                    out_man.append_log("Executor", f"Script Error: {raw_err}")

                # 3. PARSE OUTPUT (Quan trọng: Dùng Safe Parse)
                # Dùng safe_extract_json để lọc JSON từ đống log hỗn độn
                from src.utils.data_processors import data_processor
                parsed_json = data_processor.safe_extract_json(raw_out)
                
                exec_res = {
                    "status": "executed",
                    "return_code": proc.returncode,
                    "parsed_output": parsed_json if parsed_json else {"raw": raw_out},
                    "stderr": raw_err
                }

            except Exception as e:
                logger.error(f"[Executor] Error: {e}")
                exec_res = {"status": "exception", "error": str(e)}
            finally:
                # Cleanup Container
                if container:
                    try:
                        container.stop()
                        out_man.append_log("Executor", "Container stopped.")
                    except: pass

        # Đóng gói kết quả
        results.append({
            "hypothesis": h,
            "test_plan": plan,
            "exec_result": exec_res
        })

    return results

async def execute_agent():
    """Executor Agent (Worker Mode)."""
    logger.info("=== Executor Agent Started ===")
    
    while True:
        # Lấy jobs từ Queue Plan (List các plan)
        plans = await queue_exec.get()
        
        if not plans:
            queue_exec.task_done()
            continue
            
        # Gọi hàm Core Logic
        executed_results = await step_execution(plans)
        
        # Đẩy sang Verifier
        await queue_verify.put(executed_results)
        
        queue_exec.task_done()

# ---------------------------------------------------------
# Stage 7: Verifier Agent
# Agent Usage: Verifier_Agent
# ---------------------------------------------------------
async def step_verification(executed_jobs: List[Dict]) -> List[Dict]:
    """
    Verifier Logic:
    1. Nhận input: Kế hoạch test (Plan) + Kết quả chạy thực tế (Exec Result).
    2. Gọi LLM: So sánh xem kết quả có khớp với kỳ vọng không.
    3. Output: Trạng thái cuối cùng (CONFIRMED / FALSE POSITIVE / ERROR).
    """
    if not executed_jobs:
        return []

    logger.info(f"🔹 [Verifier] Checking {len(executed_jobs)} executed plans...")
    model = os.environ.get("ACTIVE_LLM_MODEL", "gemini-2.5-flash")
    
    final_output = []

    for job in executed_jobs:
        # Unpack dữ liệu
        plan = job.get("test_plan", {})
        exec_res = job.get("exec_result", {})
        h = job.get("hypothesis", {})
        
        # Lấy tên repo để init OutputManager
        # Cấu trúc job có thể sâu, dùng .get chuỗi để an toàn
        repo_name = h.get("job", {}).get("name") or "unknown_repo"
        out_man = OutputManager(repo_name=repo_name)

        # 1. Build Prompt
        # (Giả sử hàm build_verifier_prompt đã import từ src.prompts...)
        prompt = build_verifier_prompt(plan, exec_res)

        try:
            # 2. Call LLM
            # Lưu ý: exec_res có thể rất dài (log stdout), prompt builder nên cắt ngắn bớt
            response = await asyncio.to_thread(call_model, model, prompt)
            
            # 3. Parse JSON an toàn
            verify_data = safe_parse_json(response)
            
            # Fallback nếu LLM trả về format sai
            if not verify_data:
                verify_data = {"status": "review_required", "reason": "LLM returned invalid JSON"}

        except Exception as e:
            logger.error(f"[Verifier] Error: {e}")
            verify_data = {"status": "error", "reason": str(e)}

        # 4. Update Job
        job["verify"] = verify_data
        final_output.append(job)
        
        # 5. Logging & Saving
        vuln_type = h.get("type", "Unknown")
        status = verify_data.get("status", "UNKNOWN").upper()
        
        log_msg = f"Vuln: {vuln_type} | Execution: {exec_res.get('status')} | Verdict: {status}"
        logger.info(f"   -> {log_msg}")
        out_man.append_log("V-Agent", log_msg)

    # Lưu báo cáo cuối cùng của repo này
    if final_output:
        # Lấy repo name từ item đầu tiên
        r_name = final_output[0].get("hypothesis", {}).get("job", {}).get("name", "repo")
        tmp_man = OutputManager(repo_name=r_name)
        tmp_man.write_json("V-Agent", "final_verification_report.json", final_output)

    return final_output

# ====================================================================
# AGENT 7: VERIFIER AGENT (Worker Mode - Updated for Reporter)
# ====================================================================

async def verifier_agent():
    """
    Verifier Agent (Worker Mode).
    Nhiệm vụ:
    1. Nhận kết quả chạy thực tế từ Executor.
    2. Gọi LLM để thẩm định (Verify).
    3. Đóng gói dữ liệu + Metadata gửi sang QUEUE_FINAL cho Reporter.
    """
    logger.info("=== Verifier Agent Started ===")
    
    while True:
        # 1. Nhận input từ Executor
        jobs = await queue_verify.get()
        
        if not jobs:
            queue_verify.task_done()
            continue
            
        # 2. Gọi Core Logic (Hàm này đã có ở trên)
        verified_results = await step_verification(jobs)
        
        # 3. Đóng gói dữ liệu cho Reporter Agent
        # Reporter cần biết 'total_raw_findings' để tính Recall (TP / Total)
        if verified_results:
            # Lấy metadata từ item đầu tiên trong list
            first_item = verified_results[0]
            
            # Trích xuất context đã được truyền từ Collector -> Debate -> Planner -> Executor
            # Lưu ý: Cần đảm bảo Collector đã nhét 'total_findings' vào 'job_context'
            job_context = first_item.get("hypothesis", {}).get("job", {})
            repo_name = job_context.get("name", "Unknown Repo")
            
            # Lấy tổng số lỗi thô ban đầu (Nếu không có thì fallback bằng số lượng hiện tại -> Recall sẽ sai lệch)
            total_raw = job_context.get("total_findings") 
            if total_raw is None:
                # Thử tìm trong job_context lồng nhau (do cấu trúc data qua nhiều bước có thể bị lồng)
                total_raw = job_context.get("job_context", {}).get("total_findings", len(verified_results))

            # Payload chuẩn cho Reporter
            reporter_payload = {
                "repo_name": repo_name,
                "total_raw_findings": total_raw,
                "verified_jobs": verified_results
            }
            
            logger.info(f"[{repo_name}] Sending results to Reporter (Total Raw: {total_raw})")
            
            # Đẩy vào QUEUE_FINAL (nơi Reporter đang lắng nghe)
            await queue_final.put(reporter_payload)
        
        else:
            logger.warning("Verifier produced no results. Skipping Reporter.")

        queue_verify.task_done()

# ---------------------------------------------------------
# Stage 8: Final Reporter Agent
# Agent Usage: Final_Reporter_Agent
# ---------------------------------------------------------
from pathlib import Path
from typing import Dict, List


def analyze_cwe_folder(cwe_path: str) -> Dict:
    path = Path(cwe_path)

    counters = {
        "TP": 0,
        "FP": 0,
        "FN": 0,
        "TN": 0,
    }

    for label in counters.keys():       # TP / FP / FN / TN
        folder = path / label
        if folder.exists():
            counters[label] = len([
                f for f in folder.rglob("*") if f.is_file()
            ])

    return counters


def evaluate_security_eval(cwe_cases: List[Dict]) -> Dict:
    """
    Input:
        [{"cwe": "CWE-020", "path": ".../CWE-020"}, ...]

    Output:
        {
            "CWE-020": {TP, FP, FN, TN, precision, recall, f1, accuracy},
            ...
            "overall": {...}
        }
    """
    results = {}
    total = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}

    for case in cwe_cases:
        stats = analyze_cwe_folder(case["path"])

        tp = stats["TP"]
        fp = stats["FP"]
        fn = stats["FN"]
        tn = stats["TN"]

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        acc = (tp + tn) / (tp + fp + fn + tn) if (tp+fp+fn+tn)>0 else 0

        results[case["cwe"]] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(acc, 4)
        }

        # Tính tổng
        for k in total.keys():
            total[k] += stats[k]

    # OVERALL:
    tp, fp, fn, tn = total.values()
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    acc       = (tp + tn) / (tp + fp + fn + tn) if (tp+fp+fn+tn)>0 else 0

    results["overall"] = {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": round(precision,4),
        "recall": round(recall,4),
        "f1_score": round(f1,4),
        "accuracy": round(acc,4)
    }

    return results


async def step_reporting(job_payload: Dict) -> Dict:
    """
    Reporter logic unified:
    - Nếu SecurityEval -> đánh giá theo dataset chuẩn (TP/FP/FN/TN)
    - Nếu bình thường -> đánh giá theo verified jobs
    """
    repo_name = job_payload.get("repo_name")
    total_raw_findings = job_payload.get("total_raw_findings", 0)
    verified_jobs = job_payload.get("verified_jobs", [])

    logger.info(f"🔹 [Reporter] Generating final report for {repo_name}...")
    out_man = OutputManager(repo_name=repo_name)
    model_name = os.environ.get("ACTIVE_LLM_MODEL", "gemini-2.0-flash")

    # =============================================================
    # CASE 1: SECURITY EVAL MODE
    # =============================================================
    if job_payload.get("security_eval"):
        sec_eval = job_payload["security_eval_data"]
        cwe_cases = sec_eval["cwe_cases"]

        logger.info("🧪 [SecurityEval] Evaluating Testcases")
        results = evaluate_security_eval(cwe_cases)

        # Lưu lại JSON
        out_man.write_json("A-Agent", "security_eval_metrics.json", results)

        overall = results["overall"]
        logger.info(f"   -> Precision={overall['precision']}, Recall={overall['recall']}, F1={overall['f1_score']}")

        # Trả metrics final
        return {
            "mode": "security_eval",
            "details": results,
            "metrics": overall
        }

    # =============================================================
    # CASE 2: NORMAL MODE (LLM VERIFY)
    # =============================================================
    tp_count = 0
    fp_count = 0
    confirmed_items = []

    for job in verified_jobs:
        status = job.get("verify", {}).get("status", "UNKNOWN").upper()
        if status == "CONFIRMED":
            tp_count += 1
            confirmed_items.append(job)
        else:
            fp_count += 1

    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) else 0
    recall    = tp_count / total_raw_findings if total_raw_findings else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    metrics = {
        "total_candidates": total_raw_findings,
        "sent_to_verify": len(verified_jobs),
        "true_positives": tp_count,
        "false_positives_at_verify": fp_count,
        "precision": round(precision,4),
        "recall_relative": round(recall,4),
        "f1_score": round(f1,4),
        "mode": "normal"
    }

    # Lưu kết quả
    out_man.write_json("A-Agent", "final_metrics.json", metrics)
    logger.info(f"   -> Normal Metrics Calculated: F1={metrics['f1_score']}")

    # VIẾT POC MARKDOWN
    logger.info(f"   -> Writing {len(confirmed_items)} PoC reports using LLM...")

    for idx, item in enumerate(confirmed_items, 1):
        h = item.get("hypothesis", {})
        plan = item.get("test_plan", {})
        exec_res = item.get("exec_result", {})
        
        vuln_id = h.get("vuln_id", f"VULN-{idx}")

        prompt = get_poc_report_prompt(h, plan, exec_res)

        try:
            poc_content = await asyncio.to_thread(
                call_model, model_name, prompt
            )

            file_name = f"PoC_{vuln_id}.md".replace(" ","_")
            out_man.write_markdown(file_name, poc_content)
            logger.info(f"      📝 Written: {file_name}")

        except Exception as e:
            logger.error(f"      ❌ Failed to write PoC for {vuln_id}: {e}")

    return metrics


async def reporter_agent():
    logger.info("=== Reporter Agent Started ===")

    while True:
        payload = await queue_final.get()

        logger.info(f"🔹 [Reporter] Received Report Job for {payload.get('repo_name')}...")

        try:
            result = await step_reporting(payload)
            metrics = result.get("metrics")

            print("\n" + "="*50)
            print(f"=== 🏁 REPORT GENERATED FOR: {payload.get('repo_name')} ===")
            print("="*50)

            # SECURITY EVAL MODE
            if result.get("mode") == "security_eval":
                print("🧪 SECURITY EVAL METRICS (Official Dataset)")
                print(f"TP={metrics['TP']}, FP={metrics['FP']}, FN={metrics['FN']}, TN={metrics['TN']}")
                print(f"Precision={metrics['precision']}, Recall={metrics['recall']}")
                print(f"F1={metrics['f1_score']}, Accuracy={metrics['accuracy']}")

            # NORMAL MODE
            else:
                print("📊 SYSTEM PERFORMANCE (LLM Verification)")
                print(f"Precision:       {metrics['precision']*100:.1f}%")
                print(f"Recall (relative): {metrics['recall_relative']*100:.1f}%")
                print(f"F1-Score:        {metrics['f1_score']:.4f}")

            print("-" * 50)

        except Exception as e:
            logger.error(f"[Reporter] Failed: {e}")

        queue_final.task_done()


# ===========================================================
# FULL PIPELINE AGENT REGISTRY
# ===========================================================

# 0. Dispatcher Agent
AGENT_DISPATCHER = dispatcher_agent

# 1. Scanning Phase Agents
AGENT_CODEQL     = codeql_agent      # Chạy CodeQL
AGENT_LLM_SAST   = LLM_SAST_Agent    # Chạy LLM SAST
AGENT_COLLECTOR  = collector_agent   # Gom kết quả từ 2 scanner

# 2. Analysis Phase Agents
AGENT_DEBATE     = agent_debate      # Ranker & Debate Loop

# 3. Exploitation Phase Agents
AGENT_PLANNER    = agent_planner           # Lập kế hoạch
AGENT_EXECUTOR   = execute_agent           # Viết & Chạy PoC
AGENT_VERIFIER   = verifier_agent           # Kiểm tra lại

# 4. Reporting Phase Agent
AGENT_REPORTER   = reporter_agent          # Viết báo cáo cuối

# 5. Queues (Input & Output)
QUEUE_INPUT = queue_input          # Main gửi Job vào đây
QUEUE_FINAL  = queue_final           # Main nhận kết quả cuối ở đây
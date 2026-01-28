import logging
import json
import os
import asyncio
from typing import List, Dict, Any
from pathlib import Path

# Imports
from src.llm.llm_manager import call_model
# [FIX] Dùng DataProcessor class trực tiếp (Static methods)
from src.utils.data_processors import DataProcessor 
from src.utils.output_manager import OutputManager
from src.prompts.prompt_planner_3strep import get_strategy_prompt, get_payload_prompt, get_refiner_prompt

# RAG Imports
try:
    from langchain_community.vectorstores import FAISS
    from langchain_openai import OpenAIEmbeddings
except ImportError:
    FAISS = None
    OpenAIEmbeddings = None

logger = logging.getLogger("Planner")

# --- CONFIG ---
RAG_INDEX_PATH = "/home/tuananh/Desktop/src2vuln/data/RAG"
EMBEDDING_MODEL_NAME = "BAAI/bge-base-en-v1.5"
_CACHED_VECTOR_STORE = None

# --- HELPERS ---

def _get_vector_store():
    global _CACHED_VECTOR_STORE
    if _CACHED_VECTOR_STORE: return _CACHED_VECTOR_STORE

    if not FAISS or not OpenAIEmbeddings or not os.path.exists(RAG_INDEX_PATH):
        return None
    
    try:
        if not os.environ.get("OPENAI_API_KEY"): return None
        embeddings = OpenAIEmbeddings(model=EMBEDDING_MODEL_NAME)
        _CACHED_VECTOR_STORE = FAISS.load_local(
            RAG_INDEX_PATH, embeddings, allow_dangerous_deserialization=True
        )
        logger.info("[Planner] RAG Loaded.")
        return _CACHED_VECTOR_STORE
    except Exception:
        return None

def _retrieve_rag_context(vector_store, query: str, k=2) -> str:
    if not vector_store: return ""
    try:
        docs = vector_store.similarity_search(query, k=k)
        return "\n\n".join([f"Guide: {d.page_content}" for d in docs])
    except: return ""

def _truncate_code_context(vuln: Dict, max_chars=3000) -> str:
    code_flow = vuln.get("code_flow", [])
    if code_flow:
        flow_str = json.dumps(code_flow, indent=2)
        if len(flow_str) < max_chars:
            return flow_str
        else:
            return json.dumps([code_flow[0], code_flow[-1]], indent=2)
    return vuln.get("details", "")[:max_chars]

# --- CORE LOGIC ---

async def step_planning(confirmed_vulns: List[Dict], job_context: Dict = None) -> List[Dict]:
    """
    Logic chính: Planner với Logging chi tiết (Prompt + Response).
    """
    if not confirmed_vulns:
        return []
    
    # [FIX] Lấy thông tin Repo và Output Path từ job_context
    repo_name = "unknown"
    job_output_dir = None

    if job_context:
        repo_name = job_context.get("name", "unknown")
        job_output_dir = job_context.get("output_dir")
    elif confirmed_vulns:
        # Fallback lấy từ item đầu tiên nếu job_context thiếu
        first_job = confirmed_vulns[0].get("job", {})
        repo_name = first_job.get("name", "unknown")
        job_output_dir = first_job.get("output_dir")

    # [FIX] Truyền artifact_path để OutputManager ghi vào đúng folder con
    out_man = OutputManager(repo_name=repo_name, artifact_path=job_output_dir)
    
    logger.info(f"🔹 [Planner] Planning for {len(confirmed_vulns)} verified items...")
    
    model = os.environ.get("ACTIVE_LLM_MODEL") or os.environ.get("PLANNER_LLM_MODEL") or "gemini-2.0-flash"
    
    # Load RAG (Async)
    vector_store = await asyncio.to_thread(_get_vector_store)
    
    results = []
    
    for idx, h in enumerate(confirmed_vulns):
        vuln_type = h.get('type', 'Unknown')
        
        # 1. Prepare Context
        vuln_context = _truncate_code_context(h)
        rag_info = ""
        if vector_store:
            query = f"{vuln_type} {h.get('cwe', '')} exploitation"
            rag_info = await asyncio.to_thread(_retrieve_rag_context, vector_store, query)

        interaction_trace = []

        try:
            # === STEP 1: STRATEGY ===
            logger.info(f"   [{vuln_type}] Generating Strategy...")
            p1 = get_strategy_prompt(h, rag_info) 
            #logger.info(f"   [Prompt Strategy] {p1}...")  # Log một phần prompt
            # [FIX CALL] Dùng call_model (đã xử lý sync/async bên trong)
            r1 = call_model(model, p1)
            
            # [FIX DATA PROCESSOR] Gọi static method, không cần instance
            strat = DataProcessor.safe_extract_json(r1) or {}
            
            interaction_trace.append({
                "step": "1_Strategy",
                "prompt": p1,
                "raw_response": r1,
                "parsed_json": strat
            })
            
            # === STEP 2: PAYLOAD ===
            logger.info(f"   [{vuln_type}] Generating Payloads...")
            p2 = get_payload_prompt(json.dumps(strat, indent=2))
            #logger.info(f"   [Prompt Payload] {p2}...")  # Log một phần prompt
            r2 = call_model(model, p2)
            pay = DataProcessor.safe_extract_json(r2) or {}
            
            interaction_trace.append({
                "step": "2_Payload",
                "prompt": p2,
                "raw_response": r2,
                "parsed_json": pay
            })
            
            # === STEP 3: REFINEMENT ===
            logger.info(f"   [{vuln_type}] Refining Final Script...")
            p3 = get_refiner_prompt(h, strat, json.dumps(pay))
            #logger.info(f"   [Prompt Refiner] {p3}...")  # Log một phần prompt
            r3 = call_model(model, p3)
            final_plan = DataProcessor.safe_extract_json(r3) or {}
            
            interaction_trace.append({
                "step": "3_Refinement",
                "prompt": p3,
                "raw_response": r3,
                "parsed_json": final_plan
            })
            
            # === ĐÓNG GÓI KẾT QUẢ ===
            plan_data = {
                "hypothesis": h,
                "test_plan": final_plan,
                # [QUAN TRỌNG] Truyền tiếp job_context cho Executor
                "job_context": job_context, 
                
                "meta": {
                    "rag_used": bool(rag_info),
                    "model": model,
                    "interaction_trace": interaction_trace 
                }
            }
            results.append(plan_data)
            
            logger.info(f"   -> Plan generated for {vuln_type}")
            out_man.append_log("Planner-Agent", f"Plan generated for {vuln_type}")

        except Exception as e:
            logger.error(f"   -> [Planner] Plan failed for {vuln_type}: {e}")
            out_man.append_log("Planner-Agent", f"Error: {e}")

    # Lưu kết quả
    if results:
        out_man.save_agent_output("Planner-Agent", results)
        
        # Lưu Log Chi Tiết (Trace)
        debug_log = [
            {
                "vuln": res["hypothesis"].get("type"),
                "trace": res["meta"]["interaction_trace"]
            }
            for res in results
        ]
        out_man.save_agent_output("Planner-Agent", debug_log, filename_suffix="debug_trace")
    
    return results
import logging
import json
import os
import sys
import asyncio
import docker

from pathlib import Path
from typing import List, Dict

# Imports
from src.utils.output_manager import OutputManager
from src.utils.data_processors import DataProcessor
from src.llm.llm_manager import call_model

# Import prompt fix (An toàn)
from src.prompts.prompt_fix_script import get_fix_script_prompt
logger = logging.getLogger("Executor")

# Khởi tạo Docker Client
docker_client = None
try:
    docker_client = docker.from_env()
    docker_client.ping()
except Exception:
    logger.warning("⚠️ Docker daemon is not available. Executor will skip execution.")

MAX_RETRIES = 3 
FALLBACK_IMAGE = "python:3.9-slim" # Image mặc định nếu build thất bại

# --- HELPER: TỰ TẠO DOCKERFILE NẾU THIẾU ---
def _ensure_dockerfile(build_context: Path):
    """Tự động tạo Dockerfile đơn giản nếu repo chưa có."""
    df_path = build_context / "Dockerfile"
    if not df_path.exists():
        logger.info(f"   -> Generating default Dockerfile at {build_context}")
        content = """
FROM python:3.9-slim
WORKDIR /app
COPY . /app
# Cài các lib thông dụng để tránh lỗi import
RUN pip install --no-cache-dir flask requests pyyaml lxml sqlparse || true
# Chạy app.py mặc định, lắng nghe 0.0.0.0 để bên ngoài gọi được
CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0"]
"""
        try:
            df_path.write_text(content)
            return True
        except Exception as e:
            logger.warning(f"   -> Failed to create Dockerfile: {e}")
            return False
    return True

# --- HELPER: CHẠY 1 LẦN THỬ (ATTEMPT) ---
async def _execute_poc_attempt(docker_client, target_image: str, script_content: str, h: Dict, out_man: OutputManager):
    """
    Chạy script tấn công vào target container.
    """
    # --- 1. LẤY TÊN FILE TARGET CHUẨN XÁC ---
    job_info = h.get('_', {})
    full_path_str = job_info.get('path') # /path/to/CWE-020/author_1.py
    
    target_filename = "app.py" # Mặc định
    
    if full_path_str:
        # Cách chuẩn: Lấy tên file từ đường dẫn
        target_filename = Path(full_path_str).name # -> author_1.py
    else:
        # Cách dự phòng: Parse từ tên job (CWE-020_author_1)
        job_name = job_info.get('name', '')
        # Tách phần sau dấu _ đầu tiên: CWE-020_author_1 -> author_1
        parts = job_name.split('_', 1) 
        if len(parts) > 1:
            target_filename = f"{parts[1]}.py"
            
    logger.info(f"   -> Target File identified: {target_filename}")

    # --- 2. TẠO TÊN CONTAINER & ID ---
    raw_vid = h.get("vuln_id", "test")
    if raw_vid is None: raw_vid = "test"
    # Clean ID
    vid = str(raw_vid).lower().replace(":", "").replace(" ", "").replace("_", "-")[-12:]
    container_name = f"run-{vid}"
    container = None
    
    try:
        # 1. Dọn dẹp container cũ
        try:
            old = docker_client.containers.get(container_name)
            old.remove(force=True)
        except: pass

        # 2. Start Target Container
        port_mapping = {
            '5000/tcp': None # Map port ngẫu nhiên để tránh xung đột
        }

        # [QUAN TRỌNG] Truyền biến môi trường để Flask biết chạy file nào
        env_vars = {"FLASK_APP": target_filename}

        container = await asyncio.to_thread(
            docker_client.containers.run,
            target_image,
            detach=True,
            name=container_name,
            ports=port_mapping,
            publish_all_ports=True,
            environment=env_vars, # <-- Inject tên file vào đây
            remove=True
        )
        
        # Chờ server khởi động
        await asyncio.sleep(15) 

        # 3. Run Script (Attacker)
        poc_filename = f"poc_{vid}_temp.py"
        poc_file = out_man.get_poc_dir() / poc_filename
        poc_file.write_text(script_content, encoding="utf-8")

        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(poc_file),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        raw_out = stdout.decode().strip()
        raw_err = stderr.decode().strip()
        
        # Parse output bằng Static Method
        parsed_json = DataProcessor.safe_extract_json(raw_out)
        
        result = {
            "status": "executed",
            "return_code": proc.returncode,
            "stdout": raw_out,
            "stderr": raw_err,
            "parsed_output": parsed_json
        }
        
        is_success = (proc.returncode == 0) and (not raw_err or "Traceback" not in raw_err)

        # ==========================================================
        # [NEW] DEBUG LOG CONTAINER KHI THẤT BẠI
        # ==========================================================
        if not is_success:
            logger.info(f"\n{'!'*20} DEBUG: CONTAINER LOGS ({vid}) {'!'*20}")
            try:
                # Lấy log của container (Target App)
                # Logs này sẽ cho biết tại sao app không phản hồi (ví dụ: thiếu lib, syntax error...)
                container_logs = container.logs().decode('utf-8', errors='replace')
                logger.infon(container_logs if container_logs.strip() else "[Empty Logs - App might have crashed silently]")
                
                # Lưu log container vào kết quả để Report sau này
                result["container_logs"] = container_logs
            except Exception as log_err:
                logger.info(f"Could not fetch logs: {log_err}")
            logger.info(f"{'!'*60}\n")
        # ==========================================================

        return is_success, result

    except Exception as e:
        return False, {"status": "exception", "error": str(e)}
        
    finally:
        if container:
            try: container.stop()
            except: pass


# --- CORE LOGIC: EXECUTION WITH SELF-HEALING ---
async def step_execution(plans: List[Dict]) -> List[Dict]:
    logger.info(f"🔹 [Executor] Processing {len(plans)} plans with Self-Healing...")
    results = []
    
    model_name = os.environ.get("ACTIVE_LLM_MODEL", "gemini-2.0-flash")

    for job in plans:
        if not job: continue 
        try:
            h = job.get("hypothesis", {})
            plan = job.get("test_plan", {})
            current_script = plan.get("script_content")
            
            # --- Lấy Job Context ---
            job_ctx = job.get("job_context")
            if not job_ctx: job_ctx = h.get("job")
            if not job_ctx: 
                logger.warning(f"⚠️ Missing Job Context. Using dummy.")
            
            repo_name = job_ctx.get("name") if job_ctx else "unknown_repo"
            raw_path = job_ctx.get("original_path") or job_ctx.get("path") if job_ctx else None
            
            job_output_dir = job_ctx.get("output_dir") if job_ctx else None

            # Khởi tạo OutputManager với đường dẫn chính xác
            out_man = OutputManager(repo_name=repo_name, artifact_path=job_output_dir)
            
            # 1. Kiểm tra môi trường
            if not docker_client:
                job["exec_result"] = {"status": "skipped", "reason": "No Docker Daemon"}
                results.append(job)
                continue
                
            if not current_script:
                job["exec_result"] = {"status": "skipped", "reason": "No script content"}
                results.append(job)
                continue

            # 2. CHUẨN BỊ IMAGE
            target_image = FALLBACK_IMAGE
            if raw_path:
                path_obj = Path(raw_path)
                if path_obj.exists():
                    build_context = path_obj.parent if path_obj.is_file() else path_obj
                    _ensure_dockerfile(build_context)
                    safe_repo_name = "".join(c for c in repo_name if c.isalnum()).lower()
                    img_tag = f"target-{safe_repo_name}"
                    try:
                        await asyncio.to_thread(docker_client.images.build, path=str(build_context), tag=img_tag, rm=True)
                        target_image = img_tag
                        logger.info(f"   -> Built custom image: {target_image}")
                    except Exception as e:
                        out_man.append_log("Executor", f"Build failed: {e}. Using fallback.")

            # 3. VÒNG LẶP RETRY
            final_exec_result = {}
            
            for attempt in range(MAX_RETRIES + 1):
                vuln_type = h.get('type', 'Vuln')
                vid = str(h.get("vuln_id", "vuln")).replace(" ", "_").replace(":", "")
                
                logger.info(f"   [{vuln_type}] Attempt {attempt + 1}...")
                
                # --- EXECUTE ---
                success, exec_res = await _execute_poc_attempt(docker_client, target_image, current_script, h, out_man)
                final_exec_result = exec_res
                
                # A. Print ra Console để Debug
                print(f"\n{'='*20} EXECUTION RESULT ({vid} - Attempt {attempt+1}) {'='*20}")
                print(json.dumps(exec_res, indent=2, ensure_ascii=False))
                print(f"{'='*60}\n")

                # B. Ghi log vào OutputManager
                log_msg = (
                    f"Attempt {attempt+1}:\n"
                    f"Status: {exec_res.get('status')}\n"
                    f"STDOUT: {exec_res.get('stdout')}\n"
                    f"STDERR: {exec_res.get('stderr')}\n"
                    f"Container Logs: {exec_res.get('container_logs', 'N/A')}"
                )
                out_man.append_log("Executor", log_msg)

                # C. Lưu file JSON
                try:
                    res_filename = f"exec_result_{vid}_attempt_{attempt+1}.json"
                    out_man.write_json("Executor", res_filename, exec_res)
                    logger.info(f"      💾 Saved result to: {res_filename}")
                except Exception as e:
                    logger.error(f"      Could not save JSON result: {e}")
                
                if success:
                    logger.info(f"      ✅ Success at attempt {attempt + 1}")
                    out_man.write_poc(f"PoC_{vid}_FINAL.py", current_script)
                    break 
                
                # Logic gọi LLM fix script
                if attempt < MAX_RETRIES:
                    logger.info("      ❌ Failed. Requesting LLM fix...")
                    error_msg = f"Return Code: {exec_res.get('return_code')}\nSTDERR:\n{exec_res.get('stderr')}\nSTDOUT:\n{exec_res.get('stdout')}\nCONTAINER LOGS:\n{exec_res.get('container_logs', '')}"
                    
                    fix_prompt = get_fix_script_prompt(h, current_script, error_msg)
                    try:
                        fix_resp = call_model(model_name, fix_prompt)
                        fix_data = DataProcessor.safe_extract_json(fix_resp)
                        if fix_data and fix_data.get("script_content"):
                            current_script = fix_data["script_content"]
                            logger.info(f"      🛠️  LLM fixed the script.")
                            plan["script_content"] = current_script
                            plan.setdefault("fix_history", []).append(fix_data.get("fix_explanation", "No reason"))
                        else:
                            # [DEBUG 2] Ghi log lý do tại sao break
                            logger.warning(f"      ⚠️ Fixer failed to generate valid JSON. Raw Output:\n{fix_resp}")
                            break
                    except Exception as e:
                        logger.error(f"      Fixer Agent Error: {e}")
                        break

            results.append({
                "hypothesis": h,
                "test_plan": plan, 
                "exec_result": final_exec_result,
                # [QUAN TRỌNG] Truyền job_ctx để Verifier không bị lỗi KeyError: 'name'
                "job_context": job_ctx
            })

        except Exception as e:
            logger.error(f"❌ Error in executor loop: {e}")
            continue

    return results
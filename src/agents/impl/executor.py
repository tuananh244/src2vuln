import logging
import json
import os
import sys
import asyncio
import docker
from docker.errors import NotFound, APIError

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

MAX_RETRIES = 1

FALLBACK_IMAGE = "python:3.9-slim" # Image mặc định nếu build thất bại

# --- HELPER: XÁC ĐỊNH LOẠI TARGET ---
def _is_web_app(file_path: Path) -> bool:
    """Kiểm tra nếu file code có vẻ là một ứng dụng Web (Flask/Django)."""
    if not file_path.exists():
        return False
    try:
        content = file_path.read_text(encoding="utf-8")
        # Tìm kiếm các từ khóa phổ biến trong web framework
        if "flask" in content.lower() or "@app.route" in content.lower() or "django" in content.lower():
            return True
        return False
    except Exception:
        return False


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
# Mặc định chạy shell để giữ container sống, lệnh run thật sẽ được override bởi Executor
CMD ["/bin/bash"]
"""
        try:
            df_path.write_text(content)
            return True
        except Exception as e:
            logger.warning(f"   -> Failed to create Dockerfile: {e}")
            return False
    return True

# --- HELPER: DỌN DẸP CONTAINER CŨ ---
async def _cleanup_container(docker_client, container_name: str):
    """Dọn dẹp container cũ một cách an toàn."""
    try:
        # Dùng to_thread vì docker-py blocking
        old = await asyncio.to_thread(docker_client.containers.get, container_name)
        await asyncio.to_thread(old.remove, force=True)
        logger.debug(f"   -> Cleaned up old container: {container_name}")
    except NotFound:
        pass # Không có gì để xóa, tốt.
    except Exception as e:
        logger.warning(f"   -> Error cleaning up container {container_name}: {e}")

# --- HELPER: CHẠY 1 LẦN THỬ (ATTEMPT) ---
# --- HELPER: CHẠY 1 LẦN THỬ (ATTEMPT) ---
async def _execute_poc_attempt(docker_client, target_image: str, script_content: str, h: Dict, out_man: OutputManager, specific_target_file: str = None, is_web_app: bool = True):
    """
    Chạy script tấn công BÊN TRONG target container (dùng docker exec).
    """
    raw_vid = h.get("vuln_id", "test")
    if raw_vid is None: raw_vid = "test"
    vid = str(raw_vid).lower().replace(":", "").replace(" ", "").replace("_", "-")[-12:]
    target_filename = specific_target_file if specific_target_file else "app.py"
    container_name = f"run-{vid}"
    container = None
    
    try:
        # 1. Dọn dẹp container cũ
        await _cleanup_container(docker_client, container_name)

        # 2. Start Target Container
        port_mapping = {'5000/tcp': 5000} 
        
        run_kwargs = {
            "image": target_image,
            "detach": True,
            "name": container_name,
            "remove": False, 
            "publish_all_ports": False
        }

        if is_web_app:
            run_kwargs["ports"] = port_mapping
            run_kwargs["environment"] = {
                "FLASK_APP": target_filename,
                "FLASK_RUN_HOST": "0.0.0.0",
                "FLASK_RUN_PORT": "5000"
            }
            # Web: Chạy Flask
            run_kwargs["command"] = f"python3 -m flask run --host=0.0.0.0 --port=5000"
        else:
            # CLI: Giữ container sống để ta exec vào sau
            run_kwargs["command"] = "tail -f /dev/null"

        logger.info(f"   -> Starting container {container_name} (Web: {is_web_app})...")
        container = await asyncio.to_thread(docker_client.containers.run, **run_kwargs)

        # Chờ container khởi động
        await asyncio.sleep(3)
        await asyncio.to_thread(container.reload)
        if container.status != 'running':
            logs = await asyncio.to_thread(container.logs)
            raise RuntimeError(f"Container crashed immediately: {logs.decode('utf-8')}")

        # 3. PREPARE POC (Copy script vào trong Container)
        # Ghi script ra host trước
        poc_filename = f"poc_{vid}_temp.py"
        host_poc_path = out_man.get_poc_dir() / poc_filename
        host_poc_path.write_text(script_content, encoding="utf-8")

        # Copy file từ Host -> Container:/tmp/poc.py
        # Dùng subprocess docker cp cho lẹ (docker-py put_archive hơi phức tạp khâu tar)
        logger.info(f"   -> Copying PoC to container...")
        cp_cmd = ["docker", "cp", str(host_poc_path), f"{container_name}:/tmp/{poc_filename}"]
        cp_proc = await asyncio.create_subprocess_exec(*cp_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await cp_proc.communicate()

        # 4. EXECUTE POC (Chạy lệnh bên trong Container)
        logger.info(f"   -> Executing PoC inside container: python /tmp/{poc_filename}")
        
        # Lệnh chạy python bên trong container
        exec_cmd = ["docker", "exec", container_name, "python", f"/tmp/{poc_filename}"]
        
        proc = await asyncio.create_subprocess_exec(
            *exec_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        raw_out = stdout.decode().strip()
        raw_err = stderr.decode().strip()
        
        # Parse output
        parsed_json = DataProcessor.safe_extract_json(raw_out)
        
        result = {
            "status": "executed",
            "return_code": proc.returncode,
            "stdout": raw_out,
            "stderr": raw_err,
            "parsed_output": parsed_json
        }
        
        # Đánh giá thành công
        is_success = (proc.returncode == 0) and (not raw_err or "Traceback" not in raw_err)
        if parsed_json and "return_code" in parsed_json:
             pass

        # 5. Lấy Logs
        try:
            logs = await asyncio.to_thread(container.logs)
            result["container_logs"] = logs.decode('utf-8', errors='replace')
        except Exception:
            result["container_logs"] = "Failed to fetch logs"

        return is_success, result

    except Exception as e:
        logger.error(f"   -> Execution error: {e}")
        return False, {"status": "exception", "error": str(e)}
        
    finally:
        if container:
            try: 
                await asyncio.to_thread(container.stop)
                await asyncio.to_thread(container.remove, force=True)
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
            raw_initial_script = plan.get("script_content", "")
            current_script = DataProcessor.clean_code_snippet(raw_initial_script)
            
            job_ctx = job.get("job_context")
            if not job_ctx: job_ctx = h.get("job")
            
            repo_name = job_ctx.get("name", "unknown_repo") if job_ctx else "unknown"
            raw_path = job_ctx.get("original_path") or job_ctx.get("path") if job_ctx else None

            build_context = None
            target_filename = "app.py"
            
            # --- PATH HANDLING LOGIC ---
            docker_target_path = "/app/app.py" # Mặc định

            if raw_path:
                path_obj = Path(raw_path)
                if path_obj.exists():
                    if path_obj.is_file():
                        build_context = path_obj.parent
                        target_filename = path_obj.name
                        repo_name = build_context.name 
                        # Đường dẫn file trong Docker (Giả định Dockerfile COPY . /app)
                        docker_target_path = f"/app/{target_filename}"
                    else:
                        build_context = path_obj
                        docker_target_path = f"/app/app.py"

            # --- AUTO FIX PATH IN SCRIPT ---
            # Thay thế đường dẫn Host bằng đường dẫn Docker trong script
            if raw_path and str(raw_path) in current_script:
                logger.info(f"   -> Fixing path in script: {raw_path} => {docker_target_path}")
                current_script = current_script.replace(str(raw_path), docker_target_path)

            job_output_dir = job_ctx.get("output_dir") if job_ctx else None
            out_man = OutputManager(repo_name=repo_name, artifact_path=job_output_dir)
            
            if not docker_client or not current_script:
                job["exec_result"] = {"status": "skipped", "reason": "No Docker or Script"}
                results.append(job)
                continue

            # 2. BUILD IMAGE
            target_image = FALLBACK_IMAGE
            target_is_web_app = False
            
            if build_context and raw_path:
                target_is_web_app = _is_web_app(Path(raw_path))
                safe_repo_name = "".join(c for c in repo_name if c.isalnum()).lower()
                img_tag = f"target-{safe_repo_name}"
                _ensure_dockerfile(build_context) 
                try:
                    await asyncio.to_thread(docker_client.images.build, path=str(build_context), tag=img_tag, rm=True)
                    target_image = img_tag
                except Exception as e:
                    logger.error(f"   -> Image build failed: {e}. Using fallback.")

            # 3. RETRY LOOP
            final_exec_result = {}
            
            for attempt in range(MAX_RETRIES + 1):
                vuln_type = h.get('type', 'Vuln')
                logger.info(f"   [{vuln_type}] Attempt {attempt + 1}/{MAX_RETRIES+1}...")
                
                success, exec_res = await _execute_poc_attempt(
                    docker_client, 
                    target_image, 
                    current_script, 
                    h, 
                    out_man, 
                    specific_target_file=target_filename,
                    is_web_app=target_is_web_app
                )
                final_exec_result = exec_res
                
                # Log & Save
                vid = str(h.get("vuln_id", "vuln")).replace(" ", "_").replace(":", "")
                out_man.append_log("Executor", f"Attempt {attempt+1}: Status={exec_res.get('status')}")
                
                if success:
                    logger.info(f"      ✅ Success at attempt {attempt + 1}")
                    out_man.write_poc(f"PoC_{vid}_FINAL.py", current_script)
                    break 
                
                # Fix Script
                if attempt < MAX_RETRIES:
                    logger.info("      ❌ Failed. Requesting LLM fix...")
                    error_msg = f"Stderr: {exec_res.get('stderr')}\nContainer Logs: {exec_res.get('container_logs', '')}"
                    # Có thể bổ sung nhắc nhở về path cho LLM ở đây
                    error_msg += f"\nNote: The file is located at {docker_target_path} inside the container."
                    
                    fix_prompt = get_fix_script_prompt(h, current_script, error_msg)
                    try:
                        fix_resp = call_model(model_name, fix_prompt)
                        fix_data = DataProcessor.safe_extract_json(fix_resp)
                        if fix_data and fix_data.get("script_content"):
                            current_script = DataProcessor.clean_code_snippet(fix_data["script_content"])
                            # Replace path again for fixed script just in case
                            if raw_path and str(raw_path) in current_script:
                                current_script = current_script.replace(str(raw_path), docker_target_path)
                            plan["script_content"] = current_script
                        else: break
                    except Exception: break

            results.append({
                "hypothesis": h, "test_plan": plan, 
                "exec_result": final_exec_result, "job_context": job_ctx
            })

        except Exception as e:
            logger.error(f"❌ Error in executor loop: {e}")
            continue

    return results
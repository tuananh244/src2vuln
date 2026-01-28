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


# --- HELPER: CHECK IF FILE IS WEB APP ---
def _is_web_app(file_path: Path) -> bool:
    """Đọc file để xem nó có phải web app (Flask/Django) không."""
    try:
        content = file_path.read_text(encoding='utf-8')
        # Kiểm tra các keyword phổ biến của Web Framework
        web_keywords = ['from flask import', 'import flask', 'django', 'bottle', 'fastapi']
        return any(k in content for k in web_keywords)
    except:
        return False

# --- HELPER: CHẠY 1 LẦN THỬ (ATTEMPT) ---
async def _execute_poc_attempt(docker_client, target_image: str, script_content: str, h: Dict, out_man: OutputManager, specific_target_file: str, raw_path: str):
    """
    Chạy script tấn công vào target container.
    """
    # Lấy ID an toàn
    raw_vid = h.get("vuln_id", "test")
    if raw_vid is None: raw_vid = "test"
    # Clean ID để làm tên container hợp lệ
    vid = str(raw_vid).lower().replace(":", "").replace(" ", "").replace("_", "-")[-12:]
    target_filename = specific_target_file if specific_target_file else "app.py"
    container_name = f"run-{vid}"
    # Cần tìm file gốc để check nội dung
    is_web_mode = True # Mặc định
    try:
        logger.info(f"      🚀 Checking if {raw_path} is a web app...")
        is_web_mode = _is_web_app(raw_path)
    except: pass
    
    mode_log = "WEB-SERVER" if is_web_mode else "LIBRARY-FUNCTION"
    logger.info(f"      🚀 Mode: {mode_log} | Target: {target_filename}")
    container = None
    
    try:
        # 1. Dọn dẹp container cũ
        try:
            old = docker_client.containers.get(container_name)
            old.remove(force=True)
        except: pass

        # 2. Start Target Container
        # Lưu ý: Map port ngẫu nhiên để tránh conflict nếu chạy song song
        port_mapping = {
            '5000/tcp': 5000,  # Cho Flask/Python
            '8080/tcp': 8080,  # Cho Tomcat/Java
            '3000/tcp': 3000   # Cho Node.js (nếu có)
        }

        # container = await asyncio.to_thread(
        #     docker_client.containers.run,
        #     target_image,
        #     detach=True,
        #     name=container_name,
        #     ports=port_mapping, # [FIX] Map port 5000 -> 5000
        #     publish_all_ports=False, 
        #     # Không dùng command tail null nữa, để nó chạy CMD mặc định của Dockerfile (start server)
        #     # command="tail -f /dev/null", 
        #     environment={
        #         "FLASK_APP": target_filename,
        #         "FLASK_RUN_HOST": "0.0.0.0",
        #         "FLASK_RUN_PORT": "5000"
        #     },
        #     remove=True
        # )

        if is_web_mode:
            # === WEB MODE (Flask) ===
            # Chạy Flask server, expose port
            container = await asyncio.to_thread(
                docker_client.containers.run,
                target_image,
                detach=True,
                name=container_name,
                ports=port_mapping, # [FIX] Map port 5000 -> 5000
                publish_all_ports=False, 
                # Không dùng command tail null nữa, để nó chạy CMD mặc định của Dockerfile (start server)
                # command="tail -f /dev/null", 
                environment={
                    "FLASK_APP": target_filename,
                    "FLASK_RUN_HOST": "0.0.0.0"
                },
                remove=True
            )
            await asyncio.sleep(5) # Chờ server lên
            
        else:
            # === LIBRARY MODE (Function) ===
            # Chạy container ở chế độ 'ngủ' (idle) để giữ nó sống
            # Ta không chạy Flask, chỉ cần môi trường Python sống
            container = await asyncio.to_thread(
                docker_client.containers.run,
                target_image,
                detach=True,
                name=container_name,
                # Lệnh này giữ container sống vô tận nhưng không làm gì cả
                command="tail -f /dev/null", 
                remove=True
            )
            # Không cần sleep nhiều, chỉ cần container status 'running'
            await asyncio.sleep(2)
        
        # Chờ server khởi động
        #await asyncio.sleep(15) 

        # 3. Run Script (Attacker)
        poc_filename = f"poc_{vid}_temp.py"
        # poc_file = out_man.get_poc_dir() / poc_filename
        # poc_file.write_text(script_content, encoding="utf-8")

        # proc = await asyncio.create_subprocess_exec(
        #     sys.executable, str(poc_file),
        #     stdout=asyncio.subprocess.PIPE,
        #     stderr=asyncio.subprocess.PIPE
        # )
        # stdout, stderr = await proc.communicate()
        
        # raw_out = stdout.decode().strip()
        # raw_err = stderr.decode().strip()

        if is_web_mode:
            # --- CHẠY TỪ BÊN NGOÀI (HOST) ---
            # Ghi file ra máy host
            poc_file = out_man.get_poc_dir() / poc_filename
            poc_file.write_text(script_content, encoding="utf-8")

            # Chạy subprocess tại máy host
            proc = await asyncio.create_subprocess_exec(
                sys.executable, str(poc_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            raw_out = stdout.decode().strip()
            raw_err = stderr.decode().strip()
            return_code = proc.returncode

        else:
            # --- CHẠY TỪ BÊN TRONG (CONTAINER) ---
            # Với dạng function, script tấn công phải nằm cùng folder với code nguồn mới import được
            
            # 1. Tạo file PoC bên trong container
            # Dùng thủ thuật echo nội dung vào file
            escaped_content = script_content.replace('"', '\\"').replace('$', '\\$')
            # Cách an toàn hơn: Copy file từ host vào container (nếu dùng docker SDK xịn), 
            # nhưng dùng exec_run tạo file cho nhanh:
            setup_cmd = f"sh -c 'cat <<EOF > /app/{poc_filename}\n{script_content}\nEOF'"
            container.exec_run(setup_cmd)
            
            # 2. Thực thi PoC bên trong container
            # Lúc này PoC sẽ: import author_1 -> gọi hàm -> in kết quả
            exec_res = container.exec_run(f"python3 /app/{poc_filename}")
            
            raw_out = exec_res.output.decode().strip()
            raw_err = "" # Docker exec_run gộp stdout/stderr, hoặc xử lý riêng tùy lib
            return_code = exec_res.exit_code
        
        # Parse output bằng Static Method
        parsed_json = DataProcessor.safe_extract_json(raw_out)
        
        result = {
            "status": "executed",
            "return_code": return_code,
            "stdout": raw_out,
            "stderr": raw_err,
            "parsed_output": parsed_json
        }
        
        is_success = (return_code == 0) and (not raw_err or "Traceback" not in raw_err)

        # ==========================================================
        # [NEW] DEBUG LOG CONTAINER KHI THẤT BẠI
        # ==========================================================
        if not is_success:
            logger.info(f"\n{'!'*20} DEBUG: CONTAINER LOGS ({vid}) {'!'*20}")
            try:
                # Lấy log của container (Target App)
                # Logs này sẽ cho biết tại sao app không phản hồi (ví dụ: thiếu lib, syntax error...)
                container_logs = container.logs().decode('utf-8', errors='replace')
                logger.info(container_logs if container_logs.strip() else "[Empty Logs - App might have crashed silently]")
                
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

            build_context = None
            target_filename = "app.py" # Default fallback
            
            if raw_path:
                path_obj = Path(raw_path)
                if path_obj.exists():
                    if path_obj.is_file():
                        # TRƯỜNG HỢP: Input là file (VD: CWE-020/author_1.py)
                        build_context = path_obj.parent # Build context là folder cha (CWE-020)
                        target_filename = path_obj.name # Target là author_1.py
                        # Update repo_name để tránh build trùng tên nếu cần, hoặc giữ nguyên để tận dụng cache
                        # Ở đây ta giữ nguyên tên folder làm tên image để tái sử dụng
                        repo_name = build_context.name 
                    else:
                        # TRƯỜNG HỢP: Input là folder
                        build_context = path_obj
                        # Nếu là folder, cần logic để biết chạy file nào. 
                        # Tạm thời lấy file đầu tiên hoặc dựa vào hint từ Job.
                        # Ở đây giả định input sẽ trỏ thẳng vào file nếu dataset chi tiết.
            
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
            if build_context:
                _ensure_dockerfile(build_context)
                # Tên image dựa trên tên folder (VD: target-cwe-020) để dùng chung cho author_1.py, author_2.py...
                safe_repo_name = "".join(c for c in repo_name if c.isalnum()).lower()
                img_tag = f"target-{safe_repo_name}"
                
                try:
                    # Build image (Docker sẽ cache các layer, nên chạy nhiều file cùng folder sẽ rất nhanh)
                    await asyncio.to_thread(docker_client.images.build, path=str(build_context), tag=img_tag, rm=True)
                    target_image = img_tag
                    logger.info(f"   -> Image ready: {target_image} (Context: {build_context})")
                except Exception as e:
                    out_man.append_log("Executor", f"Build failed: {e}. Using fallback.")

            # 3. VÒNG LẶP RETRY
            final_exec_result = {}
            
            for attempt in range(MAX_RETRIES + 1):
                vuln_type = h.get('type', 'Vuln')
                vid = str(h.get("vuln_id", "vuln")).replace(" ", "_").replace(":", "")
                
                logger.info(f"   [{vuln_type}] Attempt {attempt + 1}...")
                
                # --- EXECUTE ---
                success, exec_res = await _execute_poc_attempt(
                    docker_client, 
                    target_image, 
                    current_script, 
                    h, 
                    out_man, 
                    target_filename,
                    raw_path
                )
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
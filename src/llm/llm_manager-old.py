"""
llm_manager.py
- Phiên bản thuần ĐỒNG BỘ (Synchronous).
- Fix lỗi "coroutine never awaited".
- Dùng Threading Semaphore để Rate Limit (chống 429).
- Đã khôi phục scan_models và ping_server.
"""

import os
import time
import yaml
import requests
import threading
from pathlib import Path
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

LLM_DIR = Path(__file__).resolve().parent
FIELDS = ["base_url", "llm_model_name", "api_key"]

# =====================================================================
# 0) CẤU HÌNH RATE LIMITER (THREADING SEMAPHORE)
# =====================================================================
# Dùng BoundedSemaphore của Threading thay vì asyncio.Semaphore
GEMINI_CONCURRENCY_LIMIT = 15
_gemini_semaphore = threading.BoundedSemaphore(GEMINI_CONCURRENCY_LIMIT)

def is_gemini_overloaded(exception):
    """Check lỗi 429 hoặc 5xx từ requests"""
    if isinstance(exception, requests.exceptions.HTTPError):
        # 429: Too Many Requests, 5xx: Server Error
        return exception.response.status_code in [429, 500, 502, 503]
    return False

# =====================================================================
# 1) LOAD & SCAN CONFIGS
# =====================================================================
def load_yaml_files(directory: Path):
    configs = []
    for file in directory.glob("*.yaml"):
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
            cfg = {k: data.get(k) for k in FIELDS}
            configs.append(cfg)
        except Exception:
            pass
    return configs

def load_env_configs():
    configs = []
    if os.environ.get("GEMINI_API_KEY"):
        configs.append({
            "base_url": "https://generativelanguage.googleapis.com/v1/models",
            "llm_model_name": "gemini-2.0-flash",
            "api_key": os.environ["GEMINI_API_KEY"]
        })
        configs.append({
            "base_url": "https://generativelanguage.googleapis.com/v1/models",
            "llm_model_name": "gemini-1.5-flash",
            "api_key": os.environ["GEMINI_API_KEY"]
        })
    
    if os.environ.get("OPENAI_API_KEY"):
        configs.append({
            "base_url": "https://api.openai.com/v1",
            "llm_model_name": "gpt-4.1",
            "api_key": os.environ["OPENAI_API_KEY"]
        })
        
    return configs

def _get_model_config(model_name: str):
    """Helper tìm config"""
    configs = load_yaml_files(LLM_DIR) + load_env_configs()
    for cfg in configs:
        if cfg["llm_model_name"] == model_name:
            return cfg
    raise RuntimeError(f"Model '{model_name}' không tồn tại trong config.")

def detect_provider(base_url: str):
    if "googleapis" in base_url: return "gemini"
    if "openai" in base_url: return "openai"
    return "self-host"

# =====================================================================
# 1.5) SCAN UTILS (ĐÃ KHÔI PHỤC)
# =====================================================================
def ping_server(base_url: str, provider: str):
    try:
        if provider in ("self-host", "openai"):
            r = requests.get(base_url.rstrip("/") + "/models", timeout=5)
            return "OK" if r.status_code == 200 else "FAIL"
        if provider == "gemini":
            r = requests.get(base_url, timeout=5)
            return "OK" if r.status_code in [200, 404, 403] else "FAIL"
    except:
        return "FAIL"
    return "FAIL"

def scan_models():
    """Hàm này được Runner/Coordinator gọi để kiểm tra danh sách model"""
    configs = load_yaml_files(LLM_DIR) + load_env_configs()
    results = []
    for cfg in configs:
        base = cfg.get("base_url", "")
        provider = detect_provider(base)
        status = ping_server(base, provider)
        results.append({
            "model_name": cfg.get("llm_model_name"),
            "provider": provider,
            "status": status,
        })
    return results

# =====================================================================
# 2) CORE WORKERS (Hàm con xử lý request cụ thể)
# =====================================================================

@retry(
    retry=retry_if_exception(is_gemini_overloaded),
    wait=wait_exponential(multiplier=1, min=2, max=60),
    stop=stop_after_attempt(10),
    reraise=True
)
def _execute_gemini_request(base, api_key, model, prompt, temp, max_tokens):
    url = f"{base.rstrip('/')}/{model}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": temp, "maxOutputTokens": max_tokens}
    }
    headers = {"Content-Type": "application/json"}
    
    r = requests.post(url, json=payload, headers=headers, timeout=60)
    r.raise_for_status() 
    return r.json()["candidates"][0]["content"]["parts"][0]["text"].strip()

def _execute_openai_request(base, api_key, model, prompt, temp, max_tokens):
    url = base.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key: headers["Authorization"] = f"Bearer {api_key}"
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temp,
    }
    r = requests.post(url, json=payload, headers=headers, timeout=120)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


# =====================================================================
# 3) PUBLIC INTERFACE (ĐỒNG BỘ - SYNC)
# =====================================================================

def call_model(model_name: str, prompt: str, temperature=0.2, max_tokens=1024):
    """
    Hàm gọi chính. 
    Lưu ý: Đây là hàm DEF thường (Sync), KHÔNG phải ASYNC DEF.
    Nó dùng Threading Semaphore để rate limit.
    """
    cfg = _get_model_config(model_name)
    provider = detect_provider(cfg["base_url"])

    # --- LOGIC RATE LIMIT RIÊNG CHO GEMINI ---
    if provider == "gemini":
        # Dùng 'with' để acquire semaphore (chặn nếu đã full 15 slot)
        with _gemini_semaphore:
            # Ngủ 0.1s để tránh dồn cục request (Burst)
            time.sleep(0.1)
            
            # Gọi trực tiếp hàm worker
            return _execute_gemini_request(
                cfg["base_url"], cfg["api_key"], model_name, prompt, temperature, max_tokens
            )
    
    # --- CÁC MODEL KHÁC ---
    elif provider in ["openai", "self-host"]:
        return _execute_openai_request(
            cfg["base_url"], cfg["api_key"], model_name, prompt, temperature, max_tokens
        )
    else:
        raise RuntimeError(f"Provider {provider} chưa được hỗ trợ.")

# Alias để tương thích ngược nếu code cũ gọi call_model_sync
call_model_sync = call_model
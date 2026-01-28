"""
llm_manager.py
- [UPDATED] Hỗ trợ OpenRouter (Qwen/Free models).
- Phiên bản thuần ĐỒNG BỘ (Synchronous).
- Đã chuyển sang dùng thư viện `google-generativeai` cho Gemini.
- Dùng Threading Semaphore để Rate Limit (chống 429 - Concurrency).
- Hỗ trợ Rotate API Key (Round-Robin).
- Rate Limiter: Giãn cách thời gian gọi.
"""

import os
import time
import yaml
import requests
import threading
import itertools
from pathlib import Path
from typing import List
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

# --- IMPORTS FOR GOOGLE GEMINI ---
import google.generativeai as genai
from google.api_core import exceptions as google_exceptions

LLM_DIR = Path(__file__).resolve().parent
FIELDS = ["base_url", "llm_model_name", "api_key"]

# =====================================================================
# 0) CẤU HÌNH RATE LIMITER & KEY ROTATOR
# =====================================================================

GEMINI_RPM_LIMIT = 15          
GEMINI_CONCURRENCY_LIMIT = 10 
_gemini_semaphore = threading.BoundedSemaphore(GEMINI_CONCURRENCY_LIMIT)

OPENROUTER_RPM_LIMIT = 10 

class RateLimiter:
    """Đảm bảo không gửi quá X request trong Y giây (Token Bucket đơn giản)"""
    def __init__(self, rpm):
        self.rpm = rpm
        self.min_interval = 60.0 / rpm if rpm > 0 else 0
        self.last_call_time = 0
        self._lock = threading.Lock()

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.time()
            elapsed = now - self.last_call_time
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
            self.last_call_time = time.time()

_gemini_rate_limiter = RateLimiter(GEMINI_RPM_LIMIT)
_openrouter_rate_limiter = RateLimiter(OPENROUTER_RPM_LIMIT)

class KeyRotator:
    def __init__(self, keys: List[str]):
        valid_keys = [k.strip() for k in keys if k.strip()]
        if not valid_keys:
            raise ValueError("No valid API Keys provided!")
        self._pool = itertools.cycle(valid_keys)
        self._lock = threading.Lock()
    
    def get_next_key(self):
        with self._lock:
            return next(self._pool)

_rotators = {}

def get_rotator(model_name: str, api_key_config: str) -> KeyRotator:
    global _rotators
    if model_name not in _rotators:
        keys = api_key_config.split(",")
        _rotators[model_name] = KeyRotator(keys)
    return _rotators[model_name]

def is_gemini_overloaded(exception):
    if isinstance(exception, google_exceptions.ResourceExhausted): return True 
    if isinstance(exception, google_exceptions.ServiceUnavailable): return True 
    if isinstance(exception, google_exceptions.InternalServerError): return True 
    if isinstance(exception, requests.exceptions.HTTPError):
        return exception.response.status_code in [429, 500, 502, 503]
    return False

def is_openai_overloaded(exception):
    """Kiểm tra xem lỗi có phải do quá tải (429) hoặc Server (5xx) không"""
    if isinstance(exception, requests.exceptions.HTTPError):
        status_code = exception.response.status_code
        # 429: Too Many Requests, 502/503: Bad Gateway (Upstream error)
        return status_code in [429, 500, 502, 503]
    return False

# =====================================================================
# 1) LOAD & SCAN CONFIGS (UPDATED FOR OPENROUTER)
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
    
    # 1. Gemini Configs
    gemini_keys = os.environ.get("GEMINI_API_KEY", "")
    if gemini_keys:
        configs.append({
            "base_url": "https://generativelanguage.googleapis.com", 
            "llm_model_name": "gemini-2.0-flash",
            "api_key": gemini_keys 
        })
        configs.append({
            "base_url": "https://generativelanguage.googleapis.com",
            "llm_model_name": "gemini-1.5-flash",
            "api_key": gemini_keys
        })
    
    # 2. OpenAI Configs
    if os.environ.get("OPENAI_API_KEY"):
        configs.append({
            "base_url": "https://api.openai.com/v1",
            "llm_model_name": "gpt-4.1",
            "api_key": os.environ["OPENAI_API_KEY"]
        })

    # 3. [NEW] OpenRouter Configs
    # Bạn cần set biến môi trường OPENROUTER_API_KEY
    if os.environ.get("OPENROUTER_API_KEY"):
        configs.append({
            "base_url": "https://openrouter.ai/api/v1",
            "llm_model_name": "qwen/qwen3-coder:free", # Model bạn yêu cầu
            "api_key": os.environ["OPENROUTER_API_KEY"]
        })
        
    return configs

def _get_model_config(model_name: str):
    configs = load_yaml_files(LLM_DIR) + load_env_configs()
    for cfg in configs:
        if cfg["llm_model_name"] == model_name:
            return cfg
    raise RuntimeError(f"Model '{model_name}' is not found.")

def detect_provider(base_url: str):
    if "googleapis" in base_url or "generativelanguage" in base_url: return "gemini"
    if "openrouter" in base_url: return "openrouter"  # [NEW] Detect OpenRouter
    if "openai" in base_url: return "openai"
    return "self-host"

# =====================================================================
# 1.5) SCAN UTILS
# =====================================================================
def ping_server(base_url: str, provider: str):
    try:
        if provider in ("self-host", "openai", "openrouter"):
            # OpenRouter/OpenAI thường ping vào /models ok hơn
            r = requests.get(base_url.rstrip("/") + "/models", timeout=5)
            # OpenRouter có thể trả về 401 nếu ko có key, nhưng server vẫn sống
            return "OK" if r.status_code in [200, 401] else "FAIL"
        if provider == "gemini":
            r = requests.get(base_url, timeout=5)
            return "OK" if r.status_code in [200, 404, 403] else "FAIL"
    except:
        return "FAIL"
    return "FAIL"

def scan_models():
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
# 2) CORE WORKERS
# =====================================================================

@retry(
    retry=retry_if_exception(is_gemini_overloaded),
    wait=wait_exponential(multiplier=1, min=2, max=60),
    stop=stop_after_attempt(10),
    reraise=True
)
def _execute_gemini_request(base, api_key_config, model_name, prompt, temp, max_tokens):
    _gemini_rate_limiter.wait()
    rotator = get_rotator(model_name, api_key_config)
    current_key = rotator.get_next_key()
    
    genai.configure(api_key=current_key)
    clean_model_name = model_name.replace("models/", "")
    model = genai.GenerativeModel(clean_model_name)
    
    generation_config = genai.types.GenerationConfig(temperature=temp, max_output_tokens=max_tokens)
    
    try:
        response = model.generate_content(
            prompt, 
            generation_config=generation_config,
            request_options={"timeout": 120} 
        )
        return response.text.strip()
    except Exception as e:
        raise e

# [UPDATED] Hàm này dùng chung cho OpenAI, OpenRouter và Self-Host
@retry(
    retry=retry_if_exception(is_openai_overloaded), # Chỉ retry khi gặp lỗi 429/5xx
    wait=wait_exponential(multiplier=1, min=4, max=60), # Chờ tăng dần: 4s, 8s, 16s...
    stop=stop_after_attempt(10), # Thử lại tối đa 10 lần trước khi bỏ cuộc
    reraise=True # Nếu vẫn lỗi sau 10 lần thì mới báo lỗi ra ngoài
)
def _execute_openai_request(base, api_key_config, model, prompt, temp, max_tokens):
    """
    Hàm này giờ đã "trâu bò" hơn:
    1. Tự động chờ nếu gọi quá nhanh (_openrouter_rate_limiter).
    2. Tự động đổi Key (KeyRotator).
    3. Tự động thử lại nếu gặp lỗi 429 (Retry).
    """
    
    # 1. Rate Limiting: Chờ một chút trước khi gọi
    _openrouter_rate_limiter.wait()
    
    # 2. Key Rotation logic
    rotator = get_rotator(model, api_key_config)
    current_key = rotator.get_next_key()

    url = base.rstrip("/") + "/chat/completions"
    
    headers = {
        "Content-Type": "application/json",
        # Các header này giúp OpenRouter nhận diện app tốt hơn
        "HTTP-Referer": "https://localhost", 
        "X-Title": "Local Scanner"
    }
    
    if current_key: 
        headers["Authorization"] = f"Bearer {current_key}"
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temp,
    }
    
    # Timeout
    r = requests.post(url, json=payload, headers=headers, timeout=120)
    
    # Debug: In ra lỗi để dễ theo dõi (nhưng @retry sẽ bắt lỗi này và xử lý)
    if r.status_code != 200:
        print(f"⚠️ [Retry warning] {model} returned {r.status_code}. Key ending in ...{current_key[-4:] if current_key else 'None'}")
        
    r.raise_for_status() # Ném lỗi để trigger @retry
    
    return r.json()["choices"][0]["message"]["content"].strip()

# =====================================================================
# 3) PUBLIC INTERFACE
# =====================================================================

def call_model(model_name: str, prompt: str, temperature=0.2, max_tokens=1024):
    cfg = _get_model_config(model_name)
    provider = detect_provider(cfg["base_url"])

    if provider == "gemini":
        with _gemini_semaphore:
            time.sleep(0.05) 
            return _execute_gemini_request(
                cfg["base_url"], cfg["api_key"], model_name, prompt, temperature, max_tokens
            )
    
    # [UPDATED] Gọi hàm OpenAI/OpenRouter với api_key config (để nó tự rotate bên trong)
    elif provider in ["openai", "self-host", "openrouter"]:
        return _execute_openai_request(
            cfg["base_url"], 
            cfg["api_key"], # Truyền nguyên chuỗi config (vd: "key1,key2,key3")
            model_name, prompt, temperature, max_tokens
        )
    else:
        raise RuntimeError(f"Provider {provider} still not supported.")

call_model_sync = call_model
# prompt_planner_test.py
import json

import os
import logging
from pathlib import Path

logger = logging.getLogger("SourceLoader")

def extract_source_code(raw_path) -> str:
    """
    Trích xuất nội dung mã nguồn từ đường dẫn trong hypothesis.
    Args:
        hypothesis (dict): Dictionary chứa thông tin lỗ hổng, bao gồm key 'file_path'.   
    Returns:
        str: Nội dung file code. Trả về chuỗi rỗng "" nếu lỗi hoặc không tìm thấy file.
    """
    
    if not raw_path:
        #logger.warning(f"⚠️ Hypothesis ID {hypothesis.get('vuln_id')} missing 'file_path'.")
        return ""

    try:
        file_path = Path(raw_path).resolve()

        # 2. Kiểm tra file có tồn tại không
        if not file_path.exists():
            logger.error(f"❌ File not found: {file_path}")
            return ""
        
        if not file_path.is_file():
            logger.error(f"❌ Path is not a file: {file_path}")
            return ""

        # 3. Đọc nội dung file
        # Sử dụng errors='replace' để tránh crash nếu file chứa ký tự lạ không phải utf-8
        content = file_path.read_text(encoding="utf-8", errors="replace")
        
        # [Optional] Giới hạn độ dài nếu file quá lớn (ví dụ > 5000 dòng) để tránh tràn Context LLM
        if len(content) > 100000: 
            logger.warning("File too large, truncating...")
            return content[:100000] + "\n# ... [Truncated] ..."

        return content

    except Exception as e:
        logger.error(f"❌ Error reading source code from {raw_path}: {e}")
        return ""

def get_strategy_prompt(hypothesis: dict, rag_context: str) -> str:
    """
    PROMPT: EXPLOIT STRATEGY PLANNER
    Mục tiêu: Phân tích ngữ cảnh code và lỗ hổng để đưa ra vector tấn công chính xác.
    """

    # 1. CLEANING INPUT: Chỉ giữ lại thông tin cốt lõi
    clean_hypothesis = {
        "vuln_type": hypothesis.get("type"),
        "cwe": hypothesis.get("cwe"),
        "file_path": hypothesis.get("file_path"),
        "vuln_details": hypothesis.get("details"),
        "vulnerable_code_snippet": hypothesis.get("code_flow", [])
    }
    
    hypothesis_str = json.dumps(clean_hypothesis, indent=2)
    source_code = extract_source_code(hypothesis.get("file_path", ""))

    prompt = f"""
ROLE:
You are a Senior Exploit Strategy Planner. Your goal is to analyze a static vulnerability report and the corresponding source code to design a concrete verification plan.

TASK:
1. Analyze the "Vulnerability Report" and Knowledge Context (RAG) to understand *what* is wrong.
2. Analyze the "Source Code" to determine *how* to trigger the vulnerability step-by-step.
   - Look for the **Data Flow**: Where does input enter? (Source) -> Where is it used dangerously? (Sink).
   - Determine the **Interface**: Is this a Web App (Flask/Django) or a CLI Script/Library?

INPUT DATA:
1. Vulnerability Report:
{hypothesis_str}

2. Knowledge Context (RAG):
{rag_context}

2. Full Source Code Context:
```python
{source_code}

```
OBJECTIVES:

1. Attack Vector Determination:
    - If Web App: Identify the Endpoint, HTTP Method, and Parameter Name.
    - If CLI/Script: Identify the Class/Function to call, or CLI arguments to pass, or User Input (stdin) required.

2. Verification Strategy:
    - Design the mininum number of logical steps to confirm exploitability.
    - Crucial: Just assigning data to a variable (e.g., self.x = input) is NOT enough. You must find where that variable is USED (e.g., eval(self.x)).
    - If the Sink is not visible in the provided code, state that further static analysis is needed, but propose a strategy to fuzz the known entry point.

3. Search Query Assistance:
   - If context or hypothesis lacks enough technical detail (e.g., parameter not named, no request sample), generate a `search_queries` field.
   - This should include precise keywords useful for further searching in source code or documentation (e.g., “Spring Boot XSS reflected endpoint”, “CWE-79 exploit in JSF”).

RULES:
- Do NOT generate actual payloads or code.
- Focus on logical reasoning steps.
- Keep output format strictly in JSON.

OUTPUT FORMAT (JSON): 
{{ 
  "vulnerability_id": "{hypothesis.get('vuln_id', 'unknown')}", 
  "target_analysis": 
  {{ 
    "app_type": "WEB_APP | CLI_SCRIPT | LIBRARY", 
    "trigger_mechanism": "Describe how to pass input (e.g., 'Send POST to /login', 'Run script with --name arg', 'Call ClassX.methodY')", 
    "sink_identified": "True/False (Is the dangerous function visible in code?)", 
    "inferred_logic": "Explain the flow from Source to Sink" }}, 
    "strategy_logic": 
    [ 
      {{ 
        "step_id": 1, 
        "intent": "What vulnerability type are we testing? (e.g., Command Injection, SQLi)", 
        "step_name": "Initial Probe", 
        "description": "Detailed instruction on what input to send.", 
        "expected_outcome": "What indicates the vulnerability exists?" 
      }}
      // More steps as needed 
    ],
    "search_queries": [
      "..."
      // Only if information is missing
    ] 
  }} 
""" 
    return prompt.strip()

# def get_strategy_prompt(hypothesis: dict, rag_context: str) -> str:
#     """
#     PROMPT: EXPLOIT STRATEGY PLANNER (Enhanced with RAG)
#     Mục tiêu: Phân tích lỗ hổng từ SAST để tạo kế hoạch xác minh tính thực thi (exploitability).
#     """

#     hypothesis_str = json.dumps(hypothesis, indent=2)

#     prompt = f"""
# ROLE:
# You are a Lead Application Security Analyst. Your goal is to verify whether a reported static vulnerability (from SAST) is a true positive or false positive by designing a logical exploit verification plan.

# TASK:
# Given:
# - "Input Hypothesis": A potential vulnerability reported by a static scanner.
# - "Knowledge Context (RAG)": Related security knowledge (e.g., CWE descriptions, common exploit patterns, framework-specific behavior).

# You must analyze and synthesize these inputs to generate a step-by-step exploit verification plan that focuses on confirming exploitability.

# INPUT HYPOTHESIS:
# {hypothesis_str}

# KNOWLEDGE CONTEXT (RAG):
# {rag_context}

# OBJECTIVES:
# 1. Target Analysis:
#    - Identify the likely affected Endpoint, HTTP Method, and Parameter.
#    - If not explicitly provided, infer from CWE patterns or framework behavior.
#    - Explain reasoning in `inferred_logic`.

# 2. Verification Logic:
#    - Design logical steps to confirm exploitability.
#    - Each step must describe: What to test, why, and expected outcome.
#    - Flow should follow: Setup → Execution → Verification.

# 3. Search Query Assistance:
#    - If context or hypothesis lacks enough technical detail (e.g., parameter not named, no request sample), generate a `search_queries` field.
#    - This should include precise keywords useful for further searching in source code or documentation (e.g., “Spring Boot XSS reflected endpoint”, “CWE-79 exploit in JSF”).

# RULES:
# - Do NOT generate actual payloads or code.
# - Focus on logical reasoning steps.
# - Keep output format strictly in JSON.

# OUTPUT FORMAT:
# {{
#   "vulnerability_id": "...",
#   "target_analysis": {{
#     "endpoint": "...",
#     "method": "...",
#     "parameter": "...",
#     "inferred_logic": "Reasoning based on context and patterns"
#   }},
#   "strategy_logic": [
#     {{
#       "step_id": 1,
#       "step_name": "Short step title",
#       "description": "What to do and why",
#       "intent": "Purpose of this step based on CWE/context",
#       "expected_outcome": "What indicates success"
#     }}
#     // More steps as needed
#   ],
#   "search_queries": [
#     "..."
#     // Only if information is missing
#   ]
# }}
# """
#     return prompt.strip()

import json

def get_payload_prompt(strategy_json: str) -> str:
    """
    PROMPT 2: PAYLOAD GENERATOR (Context-Aware)
    Mục tiêu: Tạo dữ liệu tấn công (Payload) chính xác dựa trên cơ chế kích hoạt (Web/CLI/File) đã xác định ở bước Strategy.
    """

    prompt = f"""
ROLE:
You are an Advanced Exploit Payload Specialist. Your task is to generate specific, raw attack data (payloads) based on the provided verification strategy.

INPUT CONTEXT:
You are provided with a "Verification Strategy" JSON which contains:
1. `target_analysis`: Describes the target type (Web vs CLI) and **Trigger Mechanism** (how input enters the system).
2. `strategy_logic`: A list of logical steps to verify the vulnerability.

TASK:
For each step in `strategy_logic`, generate the appropriate payload.

### STEP 1: DETERMINE PAYLOAD DELIVERY METHOD
Analyze `target_analysis` and the specific step to decide the `payload_type`:

- **STDIN**: If the target is a CLI script using `input()`, `sys.stdin`, or `read()`.
  - *Context:* The payload will be piped into the process standard input.
- **CLI_ARG**: If the target is a CLI script using `sys.argv`, `argparse`, or command-line flags.
  - *Context:* The payload will be passed as a command-line argument.
- **HTTP_PARAM**: If the target is a Web App (URL parameter, Form data, JSON body).
- **FILE_CONTENT**: If the attack requires an external file (e.g., XML for XXE, malicious serialized file).
  - *Context:* You must provide the *content* of the file to be created.

### STEP 2: GENERATE CONTENT
- **Constraint:** Generate ONLY the malicious data. Do not generate the command to run it (e.g., do not write `python vuln.py payload`).
- **Safety:** Payloads must be benign/safe (e.g., `whoami`, `id`, `cat /etc/passwd` or safe echo strings, url should be https://example.com) but sufficient to prove the vulnerability.

### OUTPUT FORMAT (STRICT JSON):
{{
  "technical_steps": [
    {{
      "step_id": 1,
      "payload_type": "STDIN", // or "CLI_ARG", "HTTP_PARAM", "FILE_CONTENT"
      "payload_content": "; id", // The raw data string
      "filename_hint": null,     // Only for FILE_CONTENT (e.g., "payload.xml")
      "description": "Command injection payload injected via Standard Input",
      "safety_check": "Safe"
    }},
    {{
      "step_id": 2,
      "payload_type": "FILE_CONTENT",
      "payload_content": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
      "filename_hint": "malicious.xml",
      "description": "XXE payload to read local file",
      "safety_check": "Safe"
    }}
  ]
}}

RULES:
- Maintain the exact order of steps from the input strategy.
- If `target_analysis` says "User Input (stdin)", you MUST use `STDIN` type.
- Do not include explanations outside the JSON.

INPUT STRATEGY:
{strategy_json}
"""
    return prompt.strip()

# def get_payload_prompt(strategy_json: str) -> str:
#     """
#     PROMPT 2: PAYLOAD GENERATOR (Step-specific, no command-line generation)
#     Purpose: Generate a safe payload for each logical step in the provided verification strategy.
#     """

#     prompt = f"""
# ROLE:
# You are a Payload Generation Expert in application security. Your task is to analyze each verification step in a given vulnerability testing strategy and generate a specific, safe payload that aligns with the step’s purpose (intent).

# INPUT:
# You are given a JSON-formatted strategy that contains:
# - A list of verification steps under the field `strategy_logic`.
# - Target analysis information, including endpoint, method, and parameter.

# TASK:
# For every step in `strategy_logic`, do the following:

# For every step in `strategy_logic`:

# 1. Determine the **Payload Type**:
#    - `STRING`: For URL parameters, form data, CLI arguments (e.g., `' OR 1=1`).
#    - `FILE_CONTENT`: If the attack requires uploading or reading a file (e.g., XML External Entity, PHP Shell, Malicious Config).

# 2. Generate the **Payload Content**:
#    - If `STRING`: Generate the exact attack string.
#    - If `FILE_CONTENT`: Generate the **full text content** of the malicious file. 
#      (Example: `<?php system($_GET['c']); ?>` or `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]...>`).

# 3. Provide a clear explanation for each payload in the field `payload_reason`, explaining **why this payload is suitable for the step’s intent**.

# 4. Mark the payload as `"Safe"` in the `safety_check` field.
#    - Payloads must be academic and non-malicious.
#    - DO NOT generate anything dangerous, such as:
#      - Remote code execution payloads
#      - Shells
#      - File deletion
#      - Network calls to attacker servers
#      - Real bypass techniques involving authentication or tokens

# OUTPUT FORMAT (STRICT JSON ONLY):
# {{
#   "technical_steps": [
#     {{
#       "step_id": 1,
#       "payload_type": "STRING",  // or "FILE_CONTENT"
#       "payload_content": "' OR 1=1", // The actual data prompt 3 will use
#       "description": "Standard boolean-based SQL injection",
#       "safety_check": "Safe"
#     }},
#     {{
#       "step_id": 2,
#       "payload_type": "FILE_CONTENT",
#       "payload_content": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>",
#       "description": "XXE payload to read /etc/passwd",
#       "safety_check": "Safe"
#     }}
#   ]
# }}

# ADDITIONAL RULES:
# - Maintain the same number and order of steps as in the input.
# - If any fields in the step are vague, infer the likely vulnerability type from the `intent` field.
# - Do NOT include any command-line examples, scripts, or tool usage (like curl, sqlmap, etc.).
# - Output only valid JSON.

# INPUT STRATEGY:
# {strategy_json}
# """
#     return prompt.strip()


# def get_refiner_prompt(hypothesis: dict, strategy_json: str, payload_json: str) -> str:
#     """
#     PROMPT 3: REFINER & SCRIPT CODER (Enhanced for Verifiable PoC)
#     Nhiệm vụ: Viết script khai thác thực tế, tránh dùng domain ảo gây lỗi kết nối.
#     """
#     hypothesis_str = json.dumps(hypothesis, indent=2)

#     prompt = """
# ROLE:
# You are a Senior Exploit Developer and QA Automation Engineer.
# Your goal is to write a ROBUST, VERIFIABLE Python Proof-of-Concept (PoC) script.

# TASK:
# 1. Synthesize the Hypothesis, Strategy, and Payloads into a Python script.
# 2. Encapsulate this script into a JSON object.

# INPUT DATA:
# 1. Hypothesis:
# {HYP}

# 2. Strategy Plan:
# {STRAT}

# 3. Technical Payloads:
# {PAY}

# ### CRITICAL GUIDELINES FOR PAYLOADS (MUST FOLLOW):
# To ensure the script executes successfully in a sandbox/test environment, follow these rules:

# 1. **OPEN REDIRECT:**
#    - **NEVER** use placeholders like `attacker.com`, `evil.com`, or `example.com.attacker.com` (these cause DNS/Connection errors).
#    - **ALWAYS** use `http://example.com` or `http://google.com` as the redirection target.
#    - **VERIFICATION:** Check if the response status code is 3xx OR if the `Location` header contains the target URL.

# 2. **COMMAND INJECTION / RCE:**
#    - **AVOID** destructive commands (`rm -rf`) or network commands (`curl`, `wget`) if not necessary.
#    - **USE** echo commands with a unique token. Example: `echo "VULN_CONFIRMED_123"`.
#    - **VERIFICATION:** Check if the unique token (`VULN_CONFIRMED_123`) appears in the command stdout.

# 3. **SQL INJECTION:**
#    - **USE** Logic tests (e.g., `' OR '1'='1`) or Union based that injects a specific string.
#    - **VERIFICATION:** Check if the response body size changes significantly OR if a specific string appears compared to a baseline request.

# 4. **XSS (Reflected):**
#    - **PAYLOAD:** `<script>console.log("XSS")</script>` or similar.
#    - **VERIFICATION:** Check if the payload appears **verbatim** (unescaped) in the response text.

# ### SCRIPT SPECIFICATIONS (The content of 'script_content'):
# - Language: Python 3.
# - Libraries: `requests`, `sys`, `json`, `re`, `urllib.parse`.
# - **Execution Flow:**
#   1. Define the `target_url` (construct it from the hypothesis context or default to `http://localhost:5000`).
#   2. Perform a **Baseline Request** (normal input) to understand standard behavior (optional but recommended).
#   3. Send the **Exploit Request** with the payload.
#   4. Analyze the Response (Status Code, Headers, Content).
#   5. Determine `vuln_found` (True/False).
# - **Output Requirement:**
#   - The script MUST print EXACTLY ONE valid JSON line to STDOUT at the very end.
#   - Structure: `{{ "vuln_found": bool, "details": str, "payload_used": str }}`

# ### JSON OUTPUT SCHEMA (Your Response):
# {{
#   "vulnerability_id": "{VULN_ID}",
#   "cwe": "{CWE_ID}",
#   "script_language": "python",
#   "script_content": "import requests\\nimport json\\n\\n# ... YOUR ROBUST PYTHON CODE HERE ...\\n\\nresult = {{'vuln_found': False, 'details': '...'}}\\n# Logic...\\nprint(json.dumps(result))"
# }}

# **IMPORTANT:** script_content must have and Double-escape newlines (`\\n`) and quotes (`\"`) inside `script_content` so the JSON remains valid.

# BEGIN JSON GENERATION:
# """.format(
#         HYP=hypothesis_str, 
#         STRAT=strategy_json, 
#         PAY=payload_json,
#         VULN_ID=hypothesis.get("vuln_id", "unknown"),
#         CWE_ID=hypothesis.get("cwe", "unknown")
#     )
#    return prompt.strip()


# Cai nay cho GEMINI
def get_refiner_prompt(hypothesis: dict, strategy_json: str, payload_json: str) -> str:
  """
  PROMPT 3: REFINER & SCRIPT CODER (Action-Mapping Mode)
  Nhiệm vụ: Chuyển đổi 'payload_type' từ bước trước thành code Python thực thi chính xác.
  """
  
  # ... (Phần xử lý context giữ nguyên) ...
  hyp_context = {
      "vuln_id": hypothesis.get("vuln_id", "unknown"),
      "vuln_type": hypothesis.get("type", "Unknown Vulnerability"),
      "target_file_path": hypothesis.get("file_path"),
  }

  strat_context = {
      "target_config": strategy_json.get("target_analysis", {}),
      "verification_steps": []
  }
  
  for step in strategy_json.get("strategy_logic", []):
      strat_context["verification_steps"].append({
          "step_id": step.get("step_id"),
          "expected_outcome": step.get("expected_outcome") 
      })
      
  hypothesis_str = json.dumps(hyp_context, indent=2)
  strategy_json_str = json.dumps(strat_context, indent=2)
  
  prompt = """
ROLE:
You are a Senior Exploit Automation Engineer. Your goal is to generate a robust Python PoC script.

INPUT DATA:
1. Hypothesis:
{HYP}

2. Strategy:
{STRAT}

3. Payloads:
{PAY}

TASK:
Generate a **JSON Object** containing the final Python script.
The script inside the JSON must be ready to execute directly via `python -c` or `exec()`.

CRITICAL IMPLEMENTATION RULES (MAPPING PAYLOAD TYPES):
You MUST check the `payload_type` field in the "Payloads" input and generate code accordingly:

1. IF `payload_type` == "STDIN":
   - Code Logic: Use `subprocess.run(..., input=payload_content, text=True, timeout=5)`

2. IF `payload_type` == "CLI_ARG":
   - Code Logic: Pass payload in the list: `subprocess.run([sys.executable, target, payload], ...)`

3. IF `payload_type` == "FILE_CONTENT":
   - Code Logic: Use `tempfile` to write payload -> pass path to target -> delete file in `finally`.

4. IF `payload_type` == "HTTP_PARAM":
   - Code Logic: Use `requests.get()` or `requests.post()` targeting `http://localhost:5000/...`.

INTERNAL SCRIPT REQUIREMENTS (The code INSIDE the JSON):
1.  Target Path: Use the `file_path` from input.
2.  Output Capture: Capture STDOUT/STDERR.
3.  **Final Print**: The Python script itself MUST print exactly ONE valid JSON object to STDOUT at the end:
    `print(json.dumps({{"return_code": ..., "raw_output": ..., "payload": ...}}))`
4.  Error Handling: Wrap execution in `try...except`.

STRICT OUTPUT FORMATTING RULES:
1.  **Direct JSON Only**: Your response must be a raw JSON object starting with `{{` and ending with `}}`.
2.  **No Wrapper Code**: DO NOT write a Python script that generates the JSON. DO NOT use `print(json.dumps(...))` for the main response.
3.  **No Markdown**: Do not wrap the output in ```json or ```python tags.
4.  **Escaping**: The `script_content` is a string inside JSON. You must strictly escape newlines (`\\n`) and quotes (`\\"`) inside the script body.

OUTPUT SCHEMA (Expected Response):
{{
  "exploit_metadata": {{
      "execution_type": "SUBPROCESS_STDIN | SUBPROCESS_ARG | FILE_GEN | HTTP_REQ"
  }},
  "script_content": "import sys\\nimport subprocess\\nimport json\\n# ... FULL PYTHON CODE HERE ...\\n# At the end:\\nprint(json.dumps(result))"
}}

BEGIN JSON GENERATION:
""".format(
      HYP=hypothesis_str, 
      STRAT=strategy_json_str, 
      PAY=payload_json
  )
  return prompt.strip()

# import json

# Cai nay cho MISTRAL
# def get_refiner_prompt(hypothesis: dict, strategy_json: dict, payload_json: dict) -> str:
#     """
#     PROMPT 3: REFINER & SCRIPT CODER (Mistral Optimized)
#     Tối ưu: Giảm nhiễu, ép Hardcode giá trị, cung cấp One-Shot Example.
#     """
    
#     # 1. TRÍCH XUẤT GIÁ TRỊ CỤ THỂ (QUAN TRỌNG)
#     # Lấy sẵn string để đưa vào prompt dưới dạng "CONSTANTS"
#     target_path = hypothesis.get("file_path", "/app/unknown_target.py")
    
#     # Lấy payload đầu tiên (nếu có nhiều) để tránh model bị rối
#     # Giả sử payload_json có cấu trúc danh sách hoặc object
#     try:
#         if isinstance(payload_json, list):
#             payload_data = payload_json[0]
#         else:
#             payload_data = payload_json
            
#         # Lấy payload type và content, fallback nếu thiếu
#         p_type = payload_data.get("payload_type", "STDIN")
#         p_content = payload_data.get("payload_content", "whoami")
#     except:
#         p_type = "STDIN"
#         p_content = "whoami"

#     # 2. PROMPT ĐƯỢC RÚT GỌN VÀ CỤ THỂ HÓA
#     prompt = f"""
# ROLE: Senior Exploit Engineer.
# TASK: Write a STANDALONE Python script to execute a specific payload.

# ### CONSTANTS (YOU MUST USE THESE EXACT VALUES):
# - **Target File**: "{target_path}"
# - **Payload Type**: "{p_type}"
# - **Payload Content**: "{p_content}"

# ### REQUIREMENTS:
# 1. **NO PLACEHOLDERS**: Do NOT use variables like `args`, `inputs`, `data['key']`. HARDCODE the values above directly into the script.
# 2. **NO EXTERNAL LIBS**: Use only `subprocess`, `sys`, `os`, `json`.
# 3. **OUTPUT**: The script must print a JSON object to stdout: `print(json.dumps({{"return_code": ..., "raw_output": ..., "payload": ...}}))` at the very end.
# 4. **FORMAT**: Return a JSON Object containing the script. Escape special characters (newlines `\\n`, quotes `\\"`) inside the JSON string.

# ### LOGIC MAPPING:
# - IF type is "STDIN" -> `subprocess.run(..., input="{p_content}", text=True)`
# - IF type is "CLI_ARG" -> `subprocess.run([sys.executable, "{target_path}", "{p_content}"])`

# ### ONE-SHOT EXAMPLE (FOLLOW THIS FORMAT STRICTLY):
# User Input: Target="/tmp/vuln.py", Payload="test", Type="STDIN"
# AI Output:
# {{
#   "exploit_metadata": {{ "execution_type": "SUBPROCESS_STDIN" }},
#   "script_content": "import subprocess\\nimport json\\nimport sys\\n\\ntarget = \\"/tmp/vuln.py\\"\\npayload = \\"test\\"\\ntry:\\n    res = subprocess.run([sys.executable, target], input=payload, text=True, capture_output=True, timeout=5)\\n    print(json.dumps({{\\"return_code\\": res.returncode, \\"raw_output\\": res.stdout, \\"payload\\": payload}}))\\nexcept Exception as e:\\n    print(json.dumps({{\\"return_code\\": 1, \\"raw_output\\": str(e), \\"payload\\": payload}}))"
# }}

# ### YOUR TURN:
# Generate the JSON for the **CONSTANTS** provided above.
# """
#     return prompt.strip()
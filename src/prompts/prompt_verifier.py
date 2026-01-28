import json

def build_verifier_prompt(test_plan: dict, exec_result: dict) -> str:
    # Chuyển dict thành string để nhúng vào prompt
    plan_str = json.dumps(test_plan, indent=2)
    result_str = json.dumps(exec_result, indent=2)

    prompt = f"""
### ROLE
You are an expert Security Analyst and Vulnerability Verifier (V-Agent).
Your task is to analyze the execution logs of a penetration testing script and determine if the vulnerability was successfully exploited.

### INPUT DATA
1. **Test Plan & Success Criteria** (What was expected?):
{plan_str}

2. **Execution Result** (What actually happened?):
{result_str}

### ANALYSIS TASK
Compare the "Execution Result" against the "Test Plan".
- Look for success indicators defined in the plan (e.g., specific strings in stdout, file creation, return codes).
- Analyze `stdout` and `stderr`.
- Note: A script crash (non-zero return code) CAN be a success if the vulnerability is DoS or causes memory corruption (like buffer overflow). Look at the logs context.
- Note: If `stdout` contains the expected sensitive data (e.g., /etc/passwd content, 'uid=0'), it is CONFIRMED.

### OUTPUT FORMAT
Return a SINGLE JSON object. Do not include markdown formatting (```json).

{{
  "status": "CONFIRMED" | "FALSE_POSITIVE" | "EXECUTION_ERROR" | "INCONCLUSIVE",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "reason": "A short, specific explanation referencing the logs. E.g., 'Found uid=0 in stdout matching the test plan'."
}}

### DECISION RULES
- **CONFIRMED**: The execution output matches the success criteria in the test plan (e.g., flag found, RCE successful).
- **FALSE_POSITIVE**: The script ran successfully but the vulnerability did not trigger (e.g., 'Permission denied', '403 Forbidden', or output is clean).
- **EXECUTION_ERROR**: The exploit script failed to run due to syntax errors, missing libraries, or network timeouts (not related to the vuln itself).
- **INCONCLUSIVE**: The output is ambiguous.
"""
    return prompt.strip()

def build_safety_audit_prompt(code_snippet: str, file_path: str = "unknown") -> str:
    prompt = f"""
ROLE:
You are a Senior Security Auditor performing a manual "Double-Check" on source code where automated tools (SAST) failed to find vulnerabilities.

INPUT:
1) File Path: {file_path}
2) Source Code Snippet:

{code_snippet}


TASK:
Critically analyze the provided source code. Automated scanners often miss business logic flaws, complex authorization bypasses, or race conditions.
Determine if this code is genuinely safe or if it contains suspicious patterns that warrant further investigation.

OUTPUT:
Provide a JSON object with the following fields:
- "file_path": The path of the file being audited.
- "status": One of ["SAFE", "SUSPICIOUS"].
- "confidence": One of ["HIGH", "MEDIUM", "LOW"].
- "reason": A brief technical explanation supporting your conclusion.

RULES:
- Output must be a valid JSON object ONLY.
- No explanations outside JSON.
- Be critical: If input validation is missing or logic is ambiguous, mark as "SUSPICIOUS".
- If the code is trivial (e.g., imports only, simple DTOs) or clearly secure, mark as "SAFE".
- Base your assessment solely on the provided code snippet.

EXAMPLE OUTPUT:
{{
  "file_path": "auth/login_handler.py",
  "status": "SUSPICIOUS",
  "confidence": "HIGH",
  "reason": "The password check uses string comparison which may be vulnerable to timing attacks, missed by standard regex scanners."
}}
    """
    return prompt.strip()
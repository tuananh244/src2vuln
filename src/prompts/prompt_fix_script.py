def get_fix_script_prompt(vuln_info, broken_script, error_log):
    return f"""
You are a skilled Python Exploit Developer. You are given a broken Proof-of-Concept (PoC) Python script that failed during execution.

## CONTEXT
- Vulnerability Type: {vuln_info.get('type')}
- Technical Details: {vuln_info.get('details')}

## SCRIPT TO FIX
```python
{broken_script}
ERROR LOG
Copy code
{error_log}
TASK INSTRUCTIONS
Analyze the error log to identify the cause(s) of the failure (e.g., syntax errors, missing modules, wrong payload logic, incorrect usage of requests, etc.).

Apply the correct fix(es) to make the PoC script functional.

Ensure the script is self-contained and concise. It should run without requiring external inputs or modification.

Make no assumptions not supported by the error log or the code context.

OUTPUT FORMAT
Respond only with the following JSON structure:

json
Copy code
{{
  "script_content": "<FULLY FIXED PYTHON SCRIPT>",
  "fix_explanation": "<Brief explanation of what was broken and how you fixed it>"
}}
"""
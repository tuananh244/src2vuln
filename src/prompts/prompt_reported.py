import json

def get_poc_report_prompt(vuln_data, plan, exec_result):
    """
    Prompt yêu cầu LLM viết báo cáo PoC chuyên nghiệp dựa trên dữ liệu kỹ thuật.
    """
    
    # Trích xuất thông tin để đưa vào prompt
    vuln_type = vuln_data.get('type', 'Unknown Vulnerability')
    cwe = vuln_data.get('cwe', 'Unknown CWE')
    file_path = vuln_data.get('file_path', 'Unknown File')
    line = vuln_data.get('location_hint', '?')
    
    # Lấy code exploit và kết quả chạy
    exploit_code = plan.get('script_content', '# No script available')
    
    # Lấy output thực tế (bằng chứng)
    evidence = exec_result.get('parsed_output') or exec_result.get('stdout') or exec_result.get('raw', 'No execution output')
    status = exec_result.get('status', 'unknown')

    return f"""
You are a Senior Security Researcher. Write a **concise, strict, and professional** Proof of Concept (PoC) report.
**Constraint:** Avoid filler words. Be direct. Focus on technical facts.

### TECHNICAL DATA:
- Vuln: {vuln_type} ({cwe})
- Loc: `{file_path}` : {line}
- Details: {vuln_data.get('details')}
- Code:
{exploit_code}
- Result: {status}
- Output: {str(evidence)[:1000]}

### REPORT STRUCTURE (Strict Markdown):

# 🚨 PoC: {vuln_type}
**Severity:** [High/Medium/Low] | **Status:** ✅ Verified

## 1. Executive Summary
(Write exactly 2-3 sentences summarizing the vulnerability and its direct business impact. No technical jargon.)

## 2. Technical Root Cause
* **File:** `{file_path}` (Line {line})
* **Analysis:** (Explain the root cause in 1-2 bullet points. Focus strictly on why the code failed validation.)

## 3. Exploitation Logic
(Briefly explain the payload/method used in 1 sentence.)

## 4. Evidence of Exploitation
### 4.1. Exploit Script
```python
{exploit_code}

4.2. Execution Output
Plaintext

{str(evidence)[:500]}
...

5. Remediation

(Provide the fixed code snippet directly. Add max 1 sentence of explanation.)

Generated for educational purposes. """
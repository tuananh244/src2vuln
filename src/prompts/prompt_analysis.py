# sast_prompt_generator.py

def generate_sast_prompt(language, func_name, file_path, decorators, source_code):
    return f"""
You are an expert Security Code Auditor and Penetration Tester specialized in {language}.
Your specific task is to review the code snippet below (`{func_name}`) and identify **Security Vulnerabilities** using a "Paranoid Trust Model".

### INPUT CONTEXT
- File: `{file_path}`
- Decorators: {decorators}
- **Assumption:** Treat all function arguments, class attributes (`self.x`), and external inputs as **UNTRUSTED/TAINTED** by default, unless explicit sanitization is visible in the snippet.

### CODE SNIPPET
{source_code}

### ANALYSIS INSTRUCTIONS (Step-by-Step)
1.  **Identify Dangerous Sinks:** Immediately scan for high-risk functions specific to {language} (e.g., `eval`, `exec`, `os.system`, `subprocess`, SQL execution, deserialization).
    -   *Crucial:* If `eval()` or `exec()` is found with any variable, flag it as CRITICAL immediately.
2.  **Trace Data Flow (Taint Analysis):**
    -   Check if variables entering these sinks originate from inputs, arguments, or class attributes.
    -   If the source is `self.variable` and you cannot see where it was defined, **ASSUME it is user-controlled** and flag the vulnerability.
3.  **Check for Mitigations:** Look for validation or sanitization. If none exists before the sink, the code is vulnerable.

### OUTPUT REQUIREMENTS
-   Focus on **OWASP Top 10** and **CWE** standards.
-   Be concise but accurate.
-   **Output strictly valid JSON**.

### JSON OUTPUT SCHEMA
{{
  "vulnerabilities": [
    {{
      "cwe_id": "CWE-XX",  // Example: CWE-95 for eval(), CWE-78 for OS Command, etc.
      "type": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
      "severity": "High" | "Critical",
      "reasoning": "The code uses 'eval' on 'self.user_input'. Since 'self.user_input' is treated as untrusted data and there is no visible sanitization, this allows arbitrary code execution.",
      "code_flow": [
        {{
          "file": "{file_path}",
          "line": <extract_line_number_from_snippet>,
          "code": "<vulnerable_code_line>",
          "step_description": "Dangerous sink 'eval' executes potential user input."
        }}
      ]
    }}
  ]
}}

NO PREAMBLE. NO POSTSCRIPT. ONLY JSON.
"""

# def generate_sast_prompt(language, func_name, file_path, decorators, source_code):
#     return f"""
# You are a senior Security Researcher and Code Auditor with deep expertise in {language} secure coding practices.
# Your task is to analyze the following function (`{func_name}`) for potential security vulnerabilities.

# ### CONTEXT
# - File: `{file_path}`
# - Decorators (if any): {decorators}
# - Code is shown with actual file line numbers (e.g., "42 | code"). You **must** refer to these line numbers in your response.

# ### CODE SNIPPET
# {source_code}

# ### INSTRUCTIONS
# Follow this structured process:
# 1. **Trace User Input (Source) to Risky Operations (Sink):** Map data flow from entry points (e.g., request, input, params) to critical operations (e.g., DB calls, command exec).
# 2. **Detect Vulnerabilities:** Focus on OWASP Top 10 and CWE-known issues (e.g., Injection, IDOR, Broken Auth).
# 3. **Contextual Awareness:** Take decorators and surrounding context into account when reasoning about authorization or data validation.

# ### OUTPUT FORMAT (Strict JSON Only)
# Respond with a single JSON object using this structure:

# {{
#   "vulnerabilities": [
#     {{
#       "cwe_id": "CWE-XX",
#       "type": "Descriptive Vulnerability Name",
#       "severity": "High" | "Medium" | "Low",
#       "reasoning": "Explain why this is a vulnerability, what the impact is, and how it could be exploited.",
#       "code_flow": [
#         {{
#           "file": "{file_path}",
#           "line": <line_number>,
#           "code": "<exact line of code>",
#           "step_description": "Explain what happens at this step (e.g., 'User input enters here')"
#         }}
#       ]
#     }}
#   ]
# }}
# Only return valid JSON. Do not include any explanations outside of the JSON object.
# """

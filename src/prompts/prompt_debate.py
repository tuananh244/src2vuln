# src/prompts/prompt_debate.py
import json

def get_ranker_prompt(source_code, candidates):
    """
    Ranker nhận danh sách các lỗ hổng tiềm năng từ nhiều nguồn (CodeQL, LLM Scan).
    Nhiệm vụ: Loại bỏ trùng lặp, đánh giá mức độ nguy hiểm và chọn ra Top lỗ hổng thực sự.
    """
    candidates_str = json.dumps(candidates, indent=2)
    
    return f"""
You are the **Lead Security Architect (Ranker)**.
You have received vulnerability reports from multiple tools (Static Analysis & LLM Detectors) for the following code.

### TARGET CODE:
{source_code}

### CANDIDATE FINDINGS:
{candidates_str}

### YOUR TASK:

1. Deduplicate: Merge findings that point to the same vulnerability (same line number/logic).
2. Filter Noise: Ignore findings that are clearly False Positives (e.g., hardcoded values, test code, unreachable).
3. Rank: Select the Top valid vulnerabilities based on Exploitability and Impact.

### OUTPUT FORMAT (JSON):
Return a list of confirmed vulnerabilities. 
```json
{{ 
    "ranked_vulnerabilities": 
    [ 
        {{ 
            "id": "original_id_or_merged", 
            "cwe": "CWE-ID", 
            "type": "Vulnerability Name", 
            "location": "Line number", 
            "score": 1-10, 
            "reasoning": "Why this is a valid threat and not a false positive." 
        }} 
    ] 
}} 
```
"""

# --- PROMPT CHO RANKER KHI NHẬN FEEDBACK (Vòng lặp) ---
def get_ranker_refinement_prompt(source_code, vulnerability, critic_feedback):
    """
    Ranker nhận feedback từ Critic và phải suy nghĩ lại (Refine).
    """
    vuln_str = json.dumps(vulnerability, indent=2)
    
    return f"""
You are the Lead Security Architect (Ranker).
You previously identified a vulnerability, but the Critic (Reviewer) has disagreed or requested clarification.

### TARGET CODE:
{source_code}

### YOUR PREVIOUS FINDING:
{vuln_str}

### CRITIC'S FEEDBACK:
"{critic_feedback}"

### YOUR TASK:
1. Analyze the Critic's feedback carefully. Did you miss a sanitizer? Is the code unreachable?
2. Re-evaluate: - If the Critic is right -> Admit it's a False Positive (score = 0).
- If the Critic is wrong -> Provide stronger evidence/reasoning to convince them.
- If partial agreement -> Adjust the severity/score.

### OUTPUT FORMAT (JSON):
```json
{{ 
    "id":  "{vulnerability.get('id')}", 
    "status": "CONFIRMED" | "FALSE_POSITIVE", 
    "score": 0-10, 
    "refined_reasoning": "Your new argument responding to the feedback." 
}} 
```
"""

def get_critic_prompt(source_code, vulnerability): 
    """ Critic đóng vai 'Devil's Advocate' (Người phản biện). 
    Nhiệm vụ: Cố gắng tìm lý do tại sao nhận định của Ranker là SAI. 
    """ 
    vuln_str = json.dumps(vulnerability, indent=2)
    return f"""
You are a Lead Security Auditor (The Critic). 
The Ranker (Junior Analyst) has flagged a potential vulnerability in the code below.
Your job is to be EXTREMELY SKEPTICAL. Assume the code is safe until proven otherwise.

### TARGET CODE:
{source_code}

### RANKER'S CLAIM:
{vuln_str}

### INSTRUCTIONS:
1.  **Trace Data Flow:** Follow the variable mentioned in the claim. Look for sanitizers, type casting (int, float), or logic checks that neutralize the threat.
2.  **Verify Context:** Is this a test file? Is the function dead code? Is the input actually user-controlled?
3.  **Constructive Critique:** If you disagree, you must provide a specific hint to help the Ranker find the truth.

### OUTPUT FORMAT:
First, think silently about the code logic step-by-step.
Then, output a SINGLE JSON object:

```json
{{
    "thought_process": "Brief analysis of the data flow and security controls...",
    "verdict": "AGREE" | "DISAGREE",
    "confidence_score": 1-10,
    "feedback_to_ranker": "If DISAGREE: specific instruction on what to check next (e.g., 'Check line 12, the input is cast to int'). If AGREE: Tell the reasoning confirming the vulnerability."
}}
"""

# def get_critic_prompt(source_code, vulnerability): 
#     """ Critic đóng vai 'Devil's Advocate' (Người phản biện). 
#     Nhiệm vụ: Cố gắng tìm lý do tại sao nhận định của Ranker là SAI. 
#     """ 
#     vuln_str = json.dumps(vulnerability, indent=2)
#     return f"""
# You are the Senior Code Reviewer (Critic). The Ranker has identified a vulnerability. 
# Your job is to be SKEPTICAL and try to disprove it.

# ### TARGET CODE:
# {source_code}

# ### RANKER'S CLAIM:
# {vuln_str}

# ### YOUR TASK:
# Analyze the code and the Ranker's reasoning.

# Do you agree with their conclusion?
# - If NO: Point out exactly why (e.g., "Line 15 has int() casting", "This is a test file").
# - If YES: Confirm the finding.
# - If you think it is the same vulnerability but with different severity, mention that.

# ### DECISION:
# If you find a valid defense/mitigation -> REJECT (False Positive).
# If the vulnerability is undeniable -> ACCEPT (True Positive).

# ### OUTPUT FORMAT (JSON):
# ```json
# {{ 
#     "verdict": "AGREE" | "DISAGREE", 
#     "critic_confidence": 1-10, 
#     "feedback": "If DISAGREE, explain exactly what Ranker needs to fix. If AGREE, say 'Verified'." 
# }}
# ```
# """
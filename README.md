# src2vuln — Automated Vulnerability Analysis Agents (Python Only)

**src2vuln** là một framework đa tác tử (multi-agent, bất đồng bộ) được thiết kế để tự động hóa quy trình **phân tích và xác minh lỗ hổng bảo mật cho mã nguồn Python**.

Hệ thống kết hợp:
- Phân tích tĩnh bằng **CodeQL**
- Lập kế hoạch khai thác bằng **LLM**
- Thực thi trong môi trường cô lập **Docker sandbox**
- Xác minh kết quả tự động

---

## 🚀 Tính năng chính

- **Phát hiện Repository & Ngôn ngữ (Python only):**  
  Tự động quét và nhận diện repository chứa mã nguồn Python.  
  - `src/utils/repo_discovery.py`  
  - `src/utils/repo_utils.py`

- **Tích hợp CodeQL:**  
  Wrapper để tự động chạy phân tích tĩnh trên mã Python.  
  - `src/utils/codeql_runner.py`

- **Pipeline Agents bất đồng bộ:**  
  Hệ thống queue điều phối các agent chuyên biệt:
  - **S-Agent (Static Analysis):** Phân tích tĩnh bằng CodeQL  
  - **D-Agent (Discussion / Development):** Lập luận & sinh PoC bằng LLM  
  - **V-Agent (Verification):** Xác minh khai thác trong Docker sandbox  

  Code:  
  - `src/agents/queue_manager.py`

- **Orchestration:**  
  Điều phối toàn bộ luồng công việc phân tích.  
  - `src/agents/coordinator_agent.py`

- **CLI Runner:**  
  Công cụ dòng lệnh để chạy từng module riêng lẻ.  
  - `runner.py`

---

## 📂 Cấu trúc dự án

```text
src2vuln/
├── runner.py                  # CLI Entry point
├── main.py                    # Khởi tạo CoordinatorAgent
├── src/
│   ├── agents/
│   │   ├── coordinator_agent.py   # Điều phối pipeline
│   │   ├── queue_manager.py       # Quản lý S-Agent, D-Agent, V-Agent
│   │   └── archive/               # Các phiên bản cũ
│   ├── utils/
│   │   ├── repo_discovery.py      # Phát hiện repository Python
│   │   ├── repo_utils.py          # Mapping extension -> Python
│   │   └── codeql_runner.py       # Wrapper CodeQL
│   └── llm/
│       ├── model1.yaml            # Cấu hình LLM
│       └── llm_call.py            # Test endpoint LLM
├── data/                        # Input / Output
└── requirements.txt             # Dependencies
```

##🛠 Yêu cầu hệ thống

- Python: 3.10+

- Docker: bắt buộc cho V-Agent (sandbox)

- CodeQL CLI: đã cài và thêm vào PATH

- LLM API Key: (OpenAI, Gemini, v.v.) cho D-Agent

## ⚙️ Cài đặt nhanh

### 1. Clone repository

```code
git clone https://github.com/your-username/src2vuln.git
cd src2vuln
```

### 2. Tạo môi trường ảo & cài dependencies

**Linux / macOS:**
```code
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
**Windows:**
```code
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```
### 3. Cấu hình

- Cập nhật cấu hình LLM tại:
```code
src/llm/model1.yaml
```
- Đảm bảo Docker đang chạy (phục vụ V-Agent)

## ▶️ Hướng dẫn sử dụng
**Chạy Orchestrator (luồng chính)**
```code
python main.py
```
**Sử dụng CLI Runner**

```code
python runner.py
```

## 🎯 Phạm vi hỗ trợ

Framework hiện tại chỉ hỗ trợ phân tích mã nguồn Python, bao gồm:

- Web applications (Flask, Django, FastAPI)

- Script Python
 
- Thư viện Python

> Các ngôn ngữ khác chưa được hỗ trợ.
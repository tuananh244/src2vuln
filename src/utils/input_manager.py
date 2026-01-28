#!/usr/bin/env python3
"""
input_manager.py

Liệt kê repo ở /data/input:
- Lấy tên repo (folder con)
- Lấy loại (tên folder cha)
- Kiểm tra hợp lệ: repo có file hay rỗng
- Cho phép người dùng chọn repo hoặc chọn toàn bộ valid
- Trả về danh sách repo (đã chọn) để pipeline dùng
"""

from pathlib import Path
from typing import Dict, List


# ============================================================
# 1) Kiểm tra repo hợp lệ
# ============================================================

def is_valid_repo(repo_path: Path) -> bool:
    """Repo hợp lệ nếu có ít nhất 1 file."""
    if not repo_path.is_dir():
        return False

    for p in repo_path.rglob("*"):
        if p.is_file():
            return True
    return False


# ============================================================
# 2) Load tất cả repo
# ============================================================

def scan_repositories(base_path: str = "/data/input") -> List[Dict]:
    """
    Trả về list repo:
    [
        {"name": "...", "type": "python", "valid": True/False, "path": "..."},
        ...
    ]
    """
    base_dir = Path(base_path)
    if not base_dir.exists():
        raise FileNotFoundError(f"[input_manager] Folder not found: {base_path}")

    results: List[Dict] = []

    for lang_folder in base_dir.iterdir():
        if not lang_folder.is_dir():
            continue

        repo_type = lang_folder.name.lower()

        for repo in lang_folder.iterdir():
            if not repo.is_dir():
                continue

            repo_name = repo.name
            valid = is_valid_repo(repo)

            results.append({
                "name": repo_name,
                "type": repo_type,
                "valid": valid,
                "path": str(repo.resolve())
            })

    return results

# ============================================================
# 3) Hàm public API cho pipeline
# ============================================================

def get_input_data(base_path: str = "/data/input") -> List[Dict]:
    """Load all repos."""
    return scan_repositories(base_path)


# ============================================================
# 4) NEW: Choose repo(s)
# ============================================================

def choose_repository(repos: List[Dict]) -> Dict:
    if not repos:
        print("❌ No repositories available.")
        return None

    print("\n=== AVAILABLE INPUT REPOSITORIES ===")
    for idx, r in enumerate(repos, start=1):
        status = "valid" if r["valid"] else "invalid"
        print(f"{idx}. {r['name']} - {r['type']} - {status}")

    while True:
        choice = input("\nSelect repository number (or 'q' to quit): ").strip()
        if choice.lower() == "q":
            return None
        if not choice.isdigit():
            print("Invalid input. Enter a number.")
            continue

        choice = int(choice)
        if 1 <= choice <= len(repos):
            selected = repos[choice - 1]
            print(f"\n👉 Selected: {selected['name']} ({selected['type']})")
            return selected
        
        print("Invalid index. Try again.")

# ============================================
# 5) XỬ LÝ ĐẶC BIỆT CHO SECURITYEVAL
# ============================================
def load_security_eval_cases(selected_repo: Dict) -> Dict:
    """
    Nếu repo là SecurityEval, trả về:
    {
        "testcases_root": ".../Testcases_Insecure_Code",
        "cwe_cases": [
            {"cwe": "CWE-020", "path": ".../CWE-020"},
            ...
        ]
    }
    """
    repo_name = selected_repo.get("name")
    repo_path = selected_repo.get("path")

    if repo_name.lower() != "test2":
        return {}

    testcase_root = Path(repo_path) / "Testcases_Insecure_Code"
    if not testcase_root.exists():
        raise FileNotFoundError(f"[SecurityEval] Missing folder: {testcase_root}")

    cwe_list = []
    for item in testcase_root.iterdir():
        if item.is_dir() and item.name.startswith("CWE-"):
            cwe_list.append({
                "cwe": item.name,          # e.g., CWE-020
                "path": str(item.resolve())
            })

    return {
        "testcases_root": str(testcase_root.resolve()),
        "cwe_cases": cwe_list
    }

def get_dataset_files(dataset_path: str = "data/input") -> List[Dict]:
    """
    Quét file lẻ trong dataset và chuẩn hóa tên ngôn ngữ cho CodeQL.
    Ví dụ: file 'test.py' -> type='python' (thay vì 'py').
    """
    base_dir = Path(dataset_path)
    if not base_dir.exists():
        print(f"❌ Dataset folder not found: {dataset_path}")
        return []

    # Bảng Map từ đuôi file sang CodeQL Language Identifier
    CODEQL_LANG_MAP = {
        "py": "python",
        "js": "javascript",
        "ts": "javascript", # TypeScript dùng chung bộ quét JS
        "java": "java",
        "c": "cpp",         # C và C++ chung bộ quét cpp
        "cpp": "cpp",
        "cc": "cpp",
        "cs": "csharp",
        "go": "go",
        "rb": "ruby",
        "swift": "swift"
    }

    file_list = []
    
    # Quét đệ quy tất cả các file
    for file_path in base_dir.rglob("*"):
        if file_path.is_file():
            # Lấy đuôi file (bỏ dấu chấm), ví dụ: .py -> py
            ext = file_path.suffix[1:].lower()
            
            # Chỉ lấy những file có trong danh sách hỗ trợ của CodeQL
            if ext in CODEQL_LANG_MAP:
                lang_id = CODEQL_LANG_MAP[ext]
                
                file_list.append({
                    "name": file_path.name,       # codeql_1.py
                    "stem": file_path.stem,       # codeql_1
                    "type": lang_id,              # "python" (Đã chuẩn hóa)
                    "path": str(file_path.resolve())
                })
            
    return file_list

def get_recursive_files(repo_path: str, extensions: List[str] = None) -> List[Dict]:
    """
    Quét đệ quy toàn bộ thư mục để lấy danh sách file code lẻ.
    Hỗ trợ cấu trúc: Root -> CWE-Folder -> File.py
    """
    root = Path(repo_path)
    if not root.exists():
        return []
    
    if extensions is None:
        extensions = ['.py', '.java', '.c', '.cpp', '.js', '.go', '.php']

    files_list = []
    
    # rglob('*') quét toàn bộ cây thư mục con
    for file_path in root.rglob('*'):
        if file_path.is_file() and file_path.suffix in extensions:
            # Bỏ qua các file ẩn hoặc file init
            if file_path.name.startswith("__") or file_path.name.startswith("."):
                continue
                
            # Lấy tên thư mục cha (VD: CWE-20) để làm Category
            # Nếu thư mục cha là root của repo thì để category là "root"
            if file_path.parent == root:
                category = "root"
            else:
                category = file_path.parent.name

            files_list.append({
                "name": file_path.name,           # filename.py
                "stem": file_path.stem,           # filename
                "path": str(file_path.resolve()), # /abs/path/to/file.py
                "type": file_path.suffix[1:],     # python
                "category": category              # CWE-xxx
            })
            
    # Sắp xếp theo Category rồi đến tên file để chạy có thứ tự
    files_list.sort(key=lambda x: (x['category'], x['name']))
    return files_list

def select_security_eval_folders(repo_path: str) -> List[Dict]:
    """
    Logic đặc biệt cho SecurityEval:
    1. Tìm vào folder 'Testcases_Insecure_Code'.
    2. Liệt kê tất cả CWE folder.
    3. Cho người dùng chọn (VD: 1,2,5 hoặc 'all').
    4. Trả về danh sách các folder được chọn để chạy Batch.
    """
    root = Path(repo_path)
    
    # SecurityEval thường có cấu trúc này, nếu không có thì dùng root
    target_root = root / "Testcases_Insecure_Code"
    if not target_root.exists():
        target_root = root

    # Lấy danh sách các folder CWE
    cwe_folders = [f for f in target_root.iterdir() if f.is_dir() and (f.name.startswith("CWE") or f.name.startswith("test"))]
    cwe_folders.sort(key=lambda x: x.name) # Sắp xếp A-Z

    if not cwe_folders:
        print("❌ No CWE folders found.")
        return []

    print(f"\n=== FOUND {len(cwe_folders)} CWE SCENARIOS ===")
    
    # Hiển thị dạng bảng (2 cột cho gọn)
    for i in range(0, len(cwe_folders), 2):
        f1 = cwe_folders[i].name
        idx1 = i + 1
        
        if i + 1 < len(cwe_folders):
            f2 = cwe_folders[i+1].name
            idx2 = i + 2
            print(f"{idx1:<3}. {f1:<25} | {idx2:<3}. {f2:<25}")
        else:
            print(f"{idx1:<3}. {f1:<25}")

    print("-" * 60)
    print("Options:")
    print(" - Enter 'all' to run EVERYTHING (Warning: Heavy).")
    print(" - Enter numbers separated by comma (e.g., '1, 5, 10') to select specific CWEs.")
    
    selection = input("\nSelect CWEs to scan: ").strip().lower()

    selected_folders = []

    if selection == 'all':
        selected_folders = cwe_folders
    else:
        try:
            # Parse input: "1, 2, 5" -> [1, 2, 5]
            indices = [int(x.strip()) for x in selection.split(",") if x.strip().isdigit()]
            
            for idx in indices:
                if 1 <= idx <= len(cwe_folders):
                    selected_folders.append(cwe_folders[idx - 1])
                else:
                    print(f"⚠ Warning: Index {idx} out of range. Skipped.")
        except Exception as e:
            print(f"❌ Invalid input: {e}")
            return []

    # Chuyển đổi sang format chuẩn cho Batch Runner
    # Format: [{'name': 'CWE-079', 'path': PathObj}, ...]
    batch_items = [
        {'name': f.name, 'path': f} 
        for f in selected_folders
    ]

    print(f"✅ Selected {len(batch_items)} CWE folders for scanning.")
    return batch_items
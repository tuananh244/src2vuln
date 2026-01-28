import os
import subprocess
import logging
import ast
import re
from typing import List, Dict, Optional

# ==========================================
# CẤU HÌNH LOGGING
# ==========================================
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("CodeAnalyzer")

# =========================================================
# PHẦN 1: SMART FILE DISCOVERY (QUÉT FILE)
# =========================================================
class SmartFileDiscovery:
    def __init__(self, root_path: str, language: str = "python"):
        self.root_path = os.path.abspath(root_path)
        self.language = language.lower()
        self.extensions = self._get_extensions()
        
        # Danh sách đen cứng (luôn bỏ qua trong chế độ Local Scan)
        self.blocked_dirs = {
            '.git', '.idea', '.vscode', '__pycache__', 
            'node_modules', 'dist', 'build', 'target', 'out', 
            'venv', '.venv', 'env', '.env', 'migrations'
        }

    def _get_extensions(self) -> List[str]:
        mapping = {
            'python': ['.py'],
            'java': ['.java'],
            'javascript': ['.js', '.jsx', '.ts', '.tsx'],
            'go': ['.go'],
            'cpp': ['.c', '.cpp', '.h', '.hpp']
        }
        return mapping.get(self.language, [])

    def scan(self) -> List[str]:
        """Hàm chính: Tự động chọn chiến lược quét."""
        if not os.path.exists(self.root_path):
            logger.error(f"Path not found: {self.root_path}")
            return []

        # CHIẾN LƯỢC 1: Dùng Git (Ưu tiên cao nhất)
        if self._is_git_repo():
            logger.info("🟢 Git repository detected. Using 'git ls-files'...")
            files = self._scan_via_git()
            if files: return files
            logger.warning("Git scan failed. Falling back to local scan.")

        # CHIẾN LƯỢC 2: Dùng OS Walk thông minh (Fallback)
        logger.info("🟠 Local folder mode. Using Smart OS Walk...")
        return self._scan_via_local_walk()

    def _is_git_repo(self) -> bool:
        return os.path.isdir(os.path.join(self.root_path, ".git"))

    def _scan_via_git(self) -> List[str]:
        valid_files = []
        try:
            cmd = ["git", "ls-files", "--cached", "--others", "--exclude-standard"]
            result = subprocess.run(
                cmd, cwd=self.root_path, capture_output=True, text=True, check=True
            )
            paths = result.stdout.splitlines()
            for p in paths:
                full_path = os.path.join(self.root_path, p)
                if self._is_relevant_file(full_path):
                    valid_files.append(full_path)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None 
        return valid_files

    def _scan_via_local_walk(self) -> List[str]:
        valid_files = []
        for root, dirs, files in os.walk(self.root_path):
            # Pruning folder rác
            dirs[:] = [d for d in dirs if d not in self.blocked_dirs]
            i = 0
            while i < len(dirs):
                d = dirs[i]
                if self._is_garbage_content(os.path.join(root, d)):
                    dirs.pop(i)
                else:
                    i += 1

            for file in files:
                full_path = os.path.join(root, file)
                if self._is_relevant_file(full_path):
                    valid_files.append(full_path)
        return valid_files

    def _is_garbage_content(self, dir_path: str) -> bool:
        try:
            with os.scandir(dir_path) as it:
                for entry in it:
                    if entry.name.lower() == 'pyvenv.cfg': return True
        except Exception: pass
        return False

    def _is_relevant_file(self, file_path: str) -> bool:
        filename = os.path.basename(file_path)
        if not any(filename.endswith(ext) for ext in self.extensions): return False
        if 'test' in filename.lower() and (filename.startswith('test_') or filename.endswith('_test.py') or 'Test' in filename): return False
        if '.min.' in filename: return False
        return True


# =========================================================
# PHẦN 2: FUNCTION EXTRACTOR (ĐỌC HÀM)
# =========================================================
class PythonExtractor:
    def extract(self, file_path: str) -> List[Dict]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
            tree = ast.parse(source_code)
            functions = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_content = ast.get_source_segment(source_code, node)
                    if not func_content: continue
                    
                    decorators = []
                    for dec in node.decorator_list:
                        dec_seg = ast.get_source_segment(source_code, dec)
                        if dec_seg: decorators.append(dec_seg)

                    functions.append({
                        "language": "python",
                        "file_path": file_path,
                        "name": node.name,
                        "start_line": node.lineno,
                        "end_line": node.end_lineno,
                        "line_count": (node.end_lineno - node.lineno) + 1,
                        "decorators": decorators,
                        "code": func_content
                    })
            return functions
        except Exception as e:
            logger.warning(f"Failed to parse Python file {file_path}: {e}")
            return []

class JavaExtractor:
    def extract(self, file_path: str) -> List[Dict]:
        functions = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            
            # Regex tìm method signature cơ bản
            method_pattern = re.compile(r'^\s*(public|private|protected|static|final|native|synchronized|abstract|transient)+\s+[\w\<\>\[\]]+\s+(\w+)\s*\(.*\).*{')
            
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                match = method_pattern.match(line)
                
                if match and "class " not in line and not line.startswith("//"):
                    func_name = match.group(2)
                    start_line = i + 1
                    brace_balance = 0
                    function_lines = []
                    found_start = False
                    
                    for j in range(i, len(lines)):
                        current_line = lines[j]
                        function_lines.append(current_line)
                        open_count = current_line.count('{')
                        close_count = current_line.count('}')
                        if open_count > 0: found_start = True
                        brace_balance += (open_count - close_count)
                        
                        if found_start and brace_balance == 0:
                            functions.append({
                                "language": "java",
                                "file_path": file_path,
                                "name": func_name,
                                "start_line": start_line,
                                "end_line": j + 1,
                                "line_count": len(function_lines),
                                "decorators": [], 
                                "code": "".join(function_lines)
                            })
                            i = j
                            break
                i += 1
            return functions
        except Exception as e:
            logger.warning(f"Failed to parse Java file {file_path}: {e}")
            return []

class FunctionExtractor:
    def __init__(self):
        self.py = PythonExtractor()
        self.java = JavaExtractor()

    def extract_from_file(self, file_path: str) -> List[Dict]:
        if file_path.endswith(".py"): return self.py.extract(file_path)
        if file_path.endswith(".java"): return self.java.extract(file_path)
        return []


# =========================================================
# PHẦN 3: MAIN ORCHESTRATOR (CHẠY THỬ)
# =========================================================
if __name__ == "__main__":
    # --- CẤU HÌNH ---
    # Thay đổi đường dẫn tới repo của bạn ở đây
    TARGET_REPO = "/home/tuananh/Desktop/src2vuln/data/input/python/test"
    TARGET_LANG = "python" # hoặc "python"

    print(f"🚀 Starting Analysis on: {TARGET_REPO}")
    print(f"🎯 Language: {TARGET_LANG.upper()}\n")

    # STEP 1: SCAN FILES
    discovery = SmartFileDiscovery(TARGET_REPO, TARGET_LANG)
    files = discovery.scan()
    print(f"✅ Step 1: Discovered {len(files)} relevant files.")

    # STEP 2: EXTRACT FUNCTIONS
    extractor = FunctionExtractor()
    all_functions = []
    
    print("\n✅ Step 2: Extracting functions...")
    for f in files:
        funcs = extractor.extract_from_file(f)
        all_functions.extend(funcs)

    print(f"📊 Total functions extracted: {len(all_functions)}\n")

    # In thử 5 hàm đầu tiên để kiểm tra
    print("--- PREVIEW TOP 5 FUNCTIONS ---")
    for i, func in enumerate(all_functions[:5]):
        print(f"#{i+1} Name: {func['name']}")
        print(f"   File: {os.path.basename(func['file_path'])}")
        print(f"   Lines: {func['line_count']}")
        print(f"   Preview: {func['code'].strip()[:50]}...")
        print("-" * 30)
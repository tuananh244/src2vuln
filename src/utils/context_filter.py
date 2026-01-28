import logging
import torch
import hashlib
import re
import torch.nn.functional as F
from sentence_transformers import SentenceTransformer, util
from typing import List, Dict, Any

logger = logging.getLogger("SemanticContextFilter")

# --- GLOBAL MODEL CACHE ---
# Cache model để không phải load lại mỗi lần khởi tạo class
_GLOBAL_EMBEDDING_MODEL = None

def get_embedding_model(model_name: str = "BAAI/bge-code-v1"):
    global _GLOBAL_EMBEDDING_MODEL
    if _GLOBAL_EMBEDDING_MODEL is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
        _GLOBAL_EMBEDDING_MODEL = SentenceTransformer(model_name, device=device)
    return _GLOBAL_EMBEDDING_MODEL

def normalize(t: torch.Tensor) -> torch.Tensor:
    if t.dim() == 1: t = t.unsqueeze(0)
    return F.normalize(t, p=2, dim=1)

class SemanticContextFilter:
    def __init__(
        self,
        model_name: str = "BAAI/bge-code-v1",
        threshold: float = 0.35, # Ngưỡng lọc (0.35 là mức cân bằng giữa Precision/Recall)
        batch_size: int = 16
    ):
        self.threshold = threshold
        self.batch_size = batch_size
        self.file_embedding_cache = {}
        self.model = get_embedding_model(model_name)

        # ---------------------------------------------------------
        # 1. DANGEROUS PATTERNS (REGEX - Hard Signals)
        # Bắt chính xác các hàm/thư viện nguy hiểm (High Priority)
        # ---------------------------------------------------------
        self.dangerous_patterns = {
            "RCE/Exec": re.compile(r"(subprocess\.|os\.system|os\.popen|exec\(|eval\(|spawn|popen)"),
            "SQLi_Basic": re.compile(r"(execute|cursor)\s*\(\s*f?[\"'].*(%s|\{|\$)"), 
            "Path_Traversal": re.compile(r"(\.\./|open\(.*mode=|send_file|send_from_directory)"),
            "Secrets": re.compile(r"(api_key|secret|password|token|auth)\s*=\s*['\"][a-zA-Z0-9_\-]{10,}['\"]"),
            "NoSQL_Injection": re.compile(r"(\$where|\$ne|\$gt|\$regex)"),
            "Deserialization": re.compile(r"(pickle\.load|yaml\.load|marshal\.load|shelve\.open)"),
            "XML_XXE": re.compile(r"(lxml\.etree|xml\.sax|minidom\.parse|DocumentBuilder)"),
            "Weak_Crypto": re.compile(r"(md5|sha1|des|rc4|blowfish)", re.IGNORECASE),
            "Debug_Code": re.compile(r"(debug\s*=\s*True|0\.0\.0\.0)"),
        }

        # ---------------------------------------------------------
        # 2. SEMANTIC QUERIES (Soft Signals) - EXPANDED VERSION
        # ---------------------------------------------------------
        self.vuln_queries = [
            # --- A. INJECTION (SQL / NoSQL / LDAP / Command) ---
            "concatenate user input directly into sql query string",
            "execute raw sql query using f-string or format",
            "construct database query without parameterized binding",
            "append variable to sql statement without sanitization",
            "mongodb query using $where clause with user input",
            "pass unsanitized user input to ldap search filter",
            "construct xpath query using string concatenation",
            "format string vulnerability in sql execution",

            # --- B. RCE & COMMAND INJECTION (CWE-78, CWE-77) ---
            "execute system command using subprocess with shell=True",
            "pass unsanitized user argument to os.system or os.popen",
            "call exec or eval on dynamic string from request",
            "import module dynamically based on user input",
            "use __import__ with user controlled arguments",
            "execute arbitrary code using timeit or exec calls",

            # --- C. DESERIALIZATION (CWE-502 - ĐÃ BỔ SUNG KỸ HƠN) ---
            "deserialize untrusted binary data using pickle.load or pickle.loads",
            "load yaml data using unsafe loader or yaml.load without Loader",
            "use marshal.load to deserialize data from untrusted source",
            "reconstruct python object using jsonpickle.decode on user input",
            "read pickle data using pandas.read_pickle from uploaded file",
            "use shelve.open on user controlled filename or database",
            "loading numpy arrays using allow_pickle=True on untrusted data",
            "deserialize xml with xmlrpc.client from external source",

            # --- D. BUFFER OVERFLOW & MEMORY SAFETY (CWE-120 - PYTHON SPECIFIC) ---
            # Python an toàn bộ nhớ, nhưng CWE-120 xảy ra khi dùng ctypes/struct/bytearray
            "write to ctypes buffer or c_char_p without size check",
            "use struct.pack_into without verifying buffer size limits",
            "memory copy using ctypes.memmove with untrusted length",
            "create ctypes array from user input size resulting in overflow",
            "unsafe pointer arithmetic using ctypes.addressof",
            "access bytearray index without bounds checking in loop",
            "read excessive amount of data into memory buffer causing exhaustion",

            # --- E. PATH TRAVERSAL & FILE IO (CWE-22) ---
            "open file path constructed from http request parameters",
            "join directory path with user controlled filename",
            "read file content using path from query string",
            "write user supplied data to file without validation",
            "return file content using send_file without path check",
            "upload file without validating extension or magic bytes",
            "create temporary file with predictable name",
            "extract compressed file zip or tar without validating member paths",

            # --- F. XSS & CLIENT-SIDE (CWE-79) ---
            "render html template with unescaped variable",
            "return user input directly in http response body",
            "write data to dom innerHTML or document.write",
            "bypass autoescaping in jinja2 or django template using safe filter",
            "reflect url parameters in response header or body",
            "disable content security policy or xss protection",

            # --- G. BROKEN AUTH & SESSION MANAGEMENT ---
            "hardcoded aws access key or api token in source code",
            "verify password using simple string comparison instead of constant time",
            "store password in plain text or using weak hashing like md5",
            "generate session id using weak pseudo random number generator",
            "set cookie without httponly or secure flag",
            "implement custom authentication logic bypassing framework tools",
            "missing login required decorator on sensitive route",

            # --- H. CRYPTOGRAPHY (CWE-327, CWE-330) ---
            "use weak hashing algorithm like md5 or sha1 for security",
            "encrypt data using ecb mode or static initialization vector",
            "use hardcoded secret key for cryptographic signing",
            "disable ssl certificate validation verify=False",
            "generate random numbers using random module instead of secrets",

            # --- I. SSRF & NETWORK (CWE-918) ---
            "send http request to url provided by user input",
            "fetch external resource using user supplied domain",
            "connect to internal service or metadata url based on parameter",
            "parse xml document allowing external entity resolution xxe",
            "load xml with resolve_entities set to true",
            "urllib request to user controlled url without filtering",

            # --- J. API SECURITY & MISCONFIGURATION ---
            "configure cors allow origin to wildcard",
            "disable csrf protection for post requests",
            "bind all request parameters to object mass assignment",
            "expose admin interface on public route",
            "debug mode enabled in production configuration",
            "missing rate limiting on login or sensitive endpoints",

            # --- K. LOGIC BUGS & PYTHON IDIOMS ---
            "use assert statement for security check",
            "compare values using is operator instead of equality",
            "catch all exceptions pass without logging",
            "modify loop variable inside for loop",
            "integer overflow or underflow in financial calculation"
        ]

        logger.info("⏳ Embedding queries ...")
        # Mã hóa queries thành vector ngay khi khởi tạo
        q = self.model.encode(self.vuln_queries, convert_to_tensor=True)
        self.query_embeddings = normalize(q)
        logger.info("✅ Query embeddings ready")

    def hash_text(self, text: str) -> str:
        """Tạo hash SHA256 để kiểm tra thay đổi nội dung file."""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def encode_file(self, file_path: str, functions: List[Dict[str, Any]]):
        """
        Mã hóa toàn bộ hàm trong file sử dụng Batching & Caching.
        """
        if not functions: return None

        # 1. Fingerprint file content
        file_concat = "\n".join(f.get("code", "") for f in functions)
        file_hash = self.hash_text(file_concat)

        # 2. Check Cache
        if file_path in self.file_embedding_cache:
            if self.file_embedding_cache[file_path]["hash"] == file_hash:
                return self.file_embedding_cache[file_path]["embeddings"]

        # 3. Recompute
        logger.info(f"📌 Embedding file: {file_path} (recomputed)")
        codes = [f.get("code", "") for f in functions]
        if not codes: return None
        
        all_embeddings = []
        
        # Batch Processing để tránh tràn bộ nhớ GPU/CPU
        for i in range(0, len(codes), self.batch_size):
            batch = codes[i : i + self.batch_size]
            emb = self.model.encode(batch, convert_to_tensor=True)
            all_embeddings.append(normalize(emb))
            
        if not all_embeddings:
            return None

        final_embeddings = torch.cat(all_embeddings, dim=0)

        # Lưu vào Cache
        self.file_embedding_cache[file_path] = {
            "hash": file_hash,
            "embeddings": final_embeddings
        }
        
        return final_embeddings

    def filter(self, functions: List[Dict], top_k: int = 5) -> List[Dict]:
        """
        Lọc các hàm quan trọng dựa trên Regex (Hard) và Semantic (Soft).
        """
        if not functions: return []

        kept = []
        candidates = []

        # ---------------------------------------------------------
        # PHASE 1: KEYWORD & HEURISTIC FILTER
        # ---------------------------------------------------------
        for func in functions:
            code_content = func.get("code", "")
            decorators = func.get("decorators", [])
            # func_name = func.get("name", "").lower() # (Không dùng để tránh warning unused)
            
            # Rule 1: Entry Points (Web Frameworks)
            is_entry = any(k in d.lower() for d in decorators for k in ["route", "get", "post", "mapping", "endpoint", "task"])
            
            # Rule 2: Dangerous Regex Match (Hard Signal)
            regex_hit = None
            for name, pattern in self.dangerous_patterns.items():
                if pattern.search(code_content):
                    regex_hit = name
                    break
            
            # Rule 3: Suspicious Arguments (Heuristic)
            args_str = str(func.get("args", [])).lower()
            tainted_keywords = ["request", "req", "cmd", "command", "sql", "query", "path", "file", "url", "user_input"]
            has_tainted_arg = any(k in args_str for k in tainted_keywords)

            # Logic giữ hàm
            if is_entry:
                func["filter_reason"] = "Entry Point"
                kept.append(func)
            elif regex_hit:
                func["filter_reason"] = f"Dangerous Pattern: {regex_hit}"
                kept.append(func) # Giữ ngay lập tức
            elif has_tainted_arg:
                func["is_heuristic"] = True
                candidates.append(func)
            elif len(code_content.split('\n')) > 4: # Bỏ qua hàm quá ngắn
                candidates.append(func)

        # ---------------------------------------------------------
        # PHASE 2: SEMANTIC SIMILARITY
        # ---------------------------------------------------------
        if candidates:
            # Group by file path
            file_groups = {}
            for f in candidates:
                path = f.get("file_path") or "unknown"
                file_groups.setdefault(path, []).append(f)

            for file_path, funcs in file_groups.items():
                file_embeds = self.encode_file(file_path, funcs)
                if file_embeds is None: continue

                # Tính Similarity
                scores = util.cos_sim(file_embeds, self.query_embeddings)

                for idx, func in enumerate(funcs):
                    max_score = torch.max(scores[idx]).item()
                    
                    # DYNAMIC THRESHOLD
                    current_threshold = self.threshold
                    fname = func.get("name", "").lower()
                    is_risky_name = any(x in fname for x in ["exec", "run", "do", "handle", "process", "fetch", "load"])
                    
                    if func.get("is_heuristic") or is_risky_name:
                        current_threshold = 0.4  # Hạ thấp ngưỡng cho hàm khả nghi
                    
                    if max_score >= current_threshold:
                        func["filter_reason"] = f"Semantic Match ({max_score:.2f})"
                        kept.append(func)

        # Sort ưu tiên: Entry Point > Regex > Semantic > Heuristic
        def sort_priority(f):
            r = f.get("filter_reason", "")
            if "Entry Point" in r: return 0
            if "Dangerous Pattern" in r: return 1
            if "Semantic Match" in r: return 2
            return 3
            
        kept.sort(key=sort_priority)
             
        return kept
import os
import ast
import csv
import collections
import argparse
import statistics
from pathlib import Path

def count_functions(tree):
    """Đếm số lượng hàm trong cây cú pháp AST."""
    return sum(1 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))

def scan_dataset(dataset_path):
    """Quét thư mục, đếm LOC và số hàm."""
    cwe_details = collections.defaultdict(list)
    stats = {
        "total_files": 0,
        "total_errors": 0,
        "total_cwes": 0
    }

    print(f"📊 Scanning dataset at: {dataset_path}...\n")

    for root, _, files in os.walk(dataset_path):
        folder_name = os.path.basename(root)
        
        if folder_name.startswith("CWE"):
            cwe = folder_name
        else:
            if folder_name.startswith(".") or folder_name.startswith("__"):
                continue
            cwe = folder_name 

        for file in files:
            if not file.endswith(".py"): 
                continue
            
            stats["total_files"] += 1
            file_path = os.path.join(root, file)
            
            file_info = {
                "cwe": cwe,
                "name": file,
                "path": file_path,
                "loc": 0,
                "funcs": 0,
                "status": "Valid",
                "note": ""
            }

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                # 1. Đếm LOC
                lines = content.splitlines()
                file_info["loc"] = len(lines)

                # 2. Đếm Hàm
                try:
                    tree = ast.parse(content)
                    file_info["funcs"] = count_functions(tree)
                except SyntaxError:
                    file_info["status"] = "Error"
                    file_info["note"] = "SyntaxErr"
                    stats["total_errors"] += 1

            except Exception as e:
                file_info["status"] = "ReadFail"
            
            cwe_details[cwe].append(file_info)

    stats["total_cwes"] = len(cwe_details)
    return cwe_details, stats

def print_console_report(cwe_details, stats):
    """
    In báo cáo dạng gom nhóm (Grouping) thay vì bảng chi tiết.
    """
    print("="*80)
    print(f"DATASET SUMMARY | Files: {stats['total_files']} | Syntax Errors: {stats['total_errors']}")
    print("="*80 + "\n")

    # 1. Thu thập tất cả file hợp lệ từ các folder CWE
    all_valid_files = []
    for cwe in cwe_details:
        for f in cwe_details[cwe]:
            if f['status'] == 'Valid':
                all_valid_files.append(f)

    if not all_valid_files:
        print("⚠️ No valid files to analyze.")
        return

    # --- Helper để in Grouping ---
    def print_grouping(files, key, label):
        """Hàm phụ trợ để gom nhóm và in ra màn hình"""
        groups = collections.defaultdict(list)
        for f in files:
            val = f[key]
            groups[val].append(f['name'])
        
        sorted_keys = sorted(groups.keys())
        
        print(f"🔹 GROUP BY {label.upper()}")
        print("-" * 40)
        for k in sorted_keys:
            filenames = " ".join(groups[k])
            # Định dạng: Label Value : file1 file2 ...
            print(f"{label} {k:<4}: {filenames}")
        print("\n")

    # 2. In Grouping theo Function (Funcs)
    print_grouping(all_valid_files, key='funcs', label='Funcs')

    # 3. In Grouping theo LOC
    print_grouping(all_valid_files, key='loc', label='LOC')

def export_to_csv(cwe_details, output_path):
    """Xuất dữ liệu ra file CSV."""
    try:
        all_files = []
        for cwe in sorted(cwe_details.keys()):
            sorted_files = sorted(cwe_details[cwe], key=lambda x: (x['status'] == 'Valid', x['loc']))
            all_files.extend(sorted_files)

        with open(output_path, mode='w', newline='', encoding='utf-8') as csv_file:
            fieldnames = ['Category', 'Filename', 'LOC', 'Num_Funcs', 'Status', 'Note', 'Full_Path']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

            writer.writeheader()
            for f in all_files:
                writer.writerow({
                    'Category': f['cwe'],
                    'Filename': f['name'],
                    'LOC': f['loc'],
                    'Num_Funcs': f['funcs'],
                    'Status': f['status'],
                    'Note': f['note'],
                    'Full_Path': f['path']
                })
        
        print(f"✅ Successfully exported CSV to: {output_path}")
        
    except Exception as e:
        print(f"❌ Failed to export CSV: {e}")

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Code Dataset (LOC & Functions)")
    parser.add_argument("dataset_path", help="Path to the dataset directory")
    parser.add_argument("--csv", help="Path to output CSV file", default=None)
    
    args = parser.parse_args()

    if os.path.exists(args.dataset_path):
        data, stats = scan_dataset(args.dataset_path)
        print_console_report(data, stats)
        if args.csv:
            export_to_csv(data, args.csv)
    else:
        print(f"❌ Error: Directory not found: {args.dataset_path}")
#!/usr/bin/env python3
"""
src/utils/codeql_runner.py
Enhanced CodeQL Runner with Phase-aware Progress Bar
"""

import asyncio
import sys
import re
import time
from pathlib import Path

def fmt_eta(sec):
    if sec is None or sec < 0:
        return "--:--"
    m, s = divmod(int(sec), 60)
    return f"{m:02d}:{s:02d}"

async def stream_codeql(proc, phase="Processing"):
    """
    Hiển thị progress bar thông minh.
    - phase: Tên giai đoạn (VD: "DB Init", "Analyzing")
    """
    current = 0
    total = None
    last_msg = "initializing..."
    start = time.time()
    
    # Spinner cho các tác vụ không có % (như Create DB)
    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    spin_idx = 0

    # Mở file log để ghi full chi tiết (không in ra màn hình)
    # Lưu ý: Nên dùng append mode
    with open("codeql_raw.log", "a", encoding="utf-8") as log_file:
        
        async for raw in proc.stderr:
            line = raw.decode("utf-8", "ignore").rstrip()
            log_file.write(f"[{phase}] {line}\n") # Ghi vào file

            # --- LOGIC CẬP NHẬT PROGRESS ---
            
            # 1. Cố gắng tìm pattern [x/y] (Đặc trưng của Analyze)
            m = re.search(r"\[(\d+)/(\d+)", line)
            if m:
                current = int(m.group(1))
                total = int(m.group(2))
                
                # Cập nhật tên query đang chạy nếu có
                if "Starting evaluation of" in line:
                    try:
                        q = line.split("evaluation of")[1].strip().rstrip(".")
                        last_msg = q.split("/")[-1] # Lấy tên file ql
                    except: pass
            
            # 2. Nếu không có số, lấy nội dung dòng log làm message (Cho Create DB)
            elif len(line) > 0 and not line.startswith("["): 
                # Cắt ngắn để không bị tràn dòng
                last_msg = (line[:40] + '..') if len(line) > 40 else line

            # --- LOGIC HIỂN THỊ ---
            
            elapsed = time.time() - start
            
            # ANSI Escape code: \033[K để xóa tàn dư ký tự cũ trên dòng
            clear_line = "\033[K" 

            if total:
                # GIAI ĐOẠN CÓ % (ANALYZE)
                p = current / total
                bar_len = 25
                filled = int(bar_len * p)
                bar = "█" * filled + "░" * (bar_len - filled)
                eta = (elapsed / p) - elapsed if p > 0 else 0
                
                sys.stdout.write(
                    f"\r{clear_line}[CodeQL: {phase}] {p*100:5.1f}% |{bar}| ETA {fmt_eta(eta)} - {last_msg}"
                )
            else:
                # GIAI ĐOẠN KHÔNG CÓ % (CREATE DB)
                spin_char = spinner[spin_idx % len(spinner)]
                spin_idx += 1
                sys.stdout.write(
                    f"\r{clear_line}[CodeQL: {phase}] {spin_char} {last_msg}"
                )
            
            sys.stdout.flush()

    # Kết thúc
    sys.stdout.write(f"\r\033[K[CodeQL: {phase}] ✅ Completed in {time.time()-start:.1f}s.\n")
    sys.stdout.flush()


async def run_command(cmd, progress=False, phase="Task", logger=None):
    """
    Wrapper chạy lệnh subprocess.
    - progress=True: Hiện thanh loading đẹp (ghi đè dòng).
    - phase: Tên hiển thị trên thanh loading.
    """
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    if progress:
        # Chuyển phase vào hàm stream
        await stream_codeql(process, phase=phase)
    else:
        # Logging kiểu cũ (in từng dòng)
        async def read_stream(stream, prefix):
            while True:
                line = await stream.readline()
                if not line: break
                msg = f"[{prefix}] {line.decode(errors='ignore').rstrip()}"
                print(msg) if logger is None else logger.info(msg)

        await asyncio.gather(
            read_stream(process.stdout, "STDOUT"),
            read_stream(process.stderr, "STDERR")
        )

    await process.wait()
    return process.returncode == 0
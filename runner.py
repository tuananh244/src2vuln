#!/usr/bin/env python3
"""
runner.py
Entry point for the agent system.

Responsibilities:
- Set up sys.path
- Parse CLI arguments
- Set Environment Variables based on CLI args
- Call main() from src/main.py
"""

import sys
import os
import argparse
import asyncio
from pathlib import Path

# -------------------------------------------------------
# Path setup
# -------------------------------------------------------
# Lấy đường dẫn thư mục gốc của dự án (nơi chứa runner.py)
BASE_DIR = Path(__file__).resolve().parent

# Thêm thư mục gốc vào sys.path để có thể import dạng "from src.main ..."
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Import main function từ src/main.py
try:
    from src.coordinator_agent import main as agent_main
except ImportError as e:
    print(f"❌ Critical Error: Could not import 'src.coordinator_agent'. Check your directory structure.\nDetails: {e}")
    sys.exit(1)

# -------------------------------------------------------
# CLI Arguments
# -------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Agent System Runner")
    parser.add_argument(
        "--mode", type=str, default="default",
        help="Running mode (default/static/rag/debug)"
    )
    parser.add_argument(
        "--data", type=str, default="data/input",
        help="Path to repository input directory"
    )
    parser.add_argument(
        "--log", type=str, default="info",
        help="Logging level (debug/info/warn/error)"
    )
    return parser.parse_args()

# -------------------------------------------------------
# Environment Setup
# -------------------------------------------------------
def setup_env(args):
    """
    Chuyển đổi CLI args thành Environment Variables
    để các module bên trong src/ có thể truy cập mà không cần truyền tham số quá nhiều tầng.
    """
    os.environ["AGENT_MODE"] = args.mode
    # Nếu src/main.py cần biết input data ở đâu, nó nên đọc từ biến env này
    os.environ["DATA_PATH"] = str(Path(args.data).resolve()) 
    os.environ["LOG_LEVEL"] = args.log.upper()

# -------------------------------------------------------
# Async Entrypoint
# -------------------------------------------------------
async def async_entry():
    args = parse_args()
    setup_env(args)

    print(f"🚀 Starting Runner...")
    print(f"   📂 Data Path: {os.environ['DATA_PATH']}")
    print(f"   ⚙️  Mode:      {args.mode}")
    print(f"   📝 Log Level: {args.log.upper()}\n")

    # Gọi hàm main từ src/main.py
    # Lưu ý: main() ở file trước không nhận tham số, nó tự xử lý logic UI/Config
    await agent_main()

# -------------------------------------------------------
# Main Entrypoint
# -------------------------------------------------------
def main():
    try:
        asyncio.run(async_entry())
    except KeyboardInterrupt:
        print("\n🛑 Runner stopped by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        # import traceback; traceback.print_exc() # Uncomment để debug sâu

if __name__ == "__main__":
    main()
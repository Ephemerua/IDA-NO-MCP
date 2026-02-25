import os
import sys
import argparse
import subprocess
import tempfile
import zipfile
import shutil
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from flask import Flask, request, send_file, jsonify

app = Flask(__name__)

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("IDA-NO-MCP-Server")

# 配置 Configuration
# INP.py 的路径 (默认在当前脚本同目录下)
# Path to INP.py (defaults to the same directory as this script)
INP_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "INP.py")

# 用于执行 INP.py 的 Python解释器
# 如果你的 INP.py 需要特定的 Python 环境 (如 IDA 的 python)，请修改此处或设置环境变量 IDA_PYTHON
# Python interpreter to execute INP.py
# If INP.py requires a specific Python environment (e.g. IDA's python), change this or set IDA_PYTHON env var
PYTHON_EXEC = os.environ.get("IDA_PYTHON", sys.executable)
ANALYZE_LOCK = threading.Lock()
STATUS_LOCK = threading.Lock()
MAX_STATUS_LOG_CHARS = 512 * 1024

TASK_LOGS = {
    "stdout": deque(),
    "stderr": deque(),
}

TASK_LOG_SIZES = {
    "stdout": 0,
    "stderr": 0,
}

TASK_STATUS = {
    "task_id": 0,
    "running": False,
    "phase": "idle",
    "input_filename": None,
    "started_at": None,
    "finished_at": None,
    "exit_code": None,
    "error": None,
    "stdout_truncated": False,
    "stderr_truncated": False,
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def start_task_status(input_filename):
    with STATUS_LOCK:
        TASK_STATUS["task_id"] += 1
        TASK_STATUS["running"] = True
        TASK_STATUS["phase"] = "running"
        TASK_STATUS["input_filename"] = input_filename
        TASK_STATUS["started_at"] = now_iso()
        TASK_STATUS["finished_at"] = None
        TASK_STATUS["exit_code"] = None
        TASK_STATUS["error"] = None
        TASK_STATUS["stdout_truncated"] = False
        TASK_STATUS["stderr_truncated"] = False

        TASK_LOGS["stdout"].clear()
        TASK_LOGS["stderr"].clear()
        TASK_LOG_SIZES["stdout"] = 0
        TASK_LOG_SIZES["stderr"] = 0


def update_task_status(**kwargs):
    with STATUS_LOCK:
        TASK_STATUS.update(kwargs)


def append_task_log(stream_name, chunk):
    if not chunk:
        return

    with STATUS_LOCK:
        dq = TASK_LOGS[stream_name]
        dq.append(chunk)
        TASK_LOG_SIZES[stream_name] += len(chunk)

        truncated_key = f"{stream_name}_truncated"
        while TASK_LOG_SIZES[stream_name] > MAX_STATUS_LOG_CHARS and dq:
            removed = dq.popleft()
            TASK_LOG_SIZES[stream_name] -= len(removed)
            TASK_STATUS[truncated_key] = True


def get_task_status_snapshot():
    with STATUS_LOCK:
        snapshot = dict(TASK_STATUS)
        snapshot["stdout"] = "".join(TASK_LOGS["stdout"])
        snapshot["stderr"] = "".join(TASK_LOGS["stderr"])
        return snapshot


def stream_reader(pipe, stream_name):
    try:
        while True:
            line = pipe.readline()
            if not line:
                break

            append_task_log(stream_name, line)

            stripped = line.rstrip()
            if not stripped:
                continue
            if stream_name == "stdout":
                logger.info(f"INP.py STDOUT: {stripped}")
            else:
                logger.warning(f"INP.py STDERR: {stripped}")
    finally:
        pipe.close()


@app.route("/analyze", methods=["POST"])
def analyze():
    # Check if file is present
    if "file" not in request.files:
        logger.warning("Request missing file part")
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        logger.warning("Request file filename is empty")
        return jsonify({"error": "No selected file"}), 400

    # Only one INP.py task is allowed at a time.
    if not ANALYZE_LOCK.acquire(blocking=False):
        logger.warning("Rejecting concurrent analyze request: server is busy")
        return (
            jsonify(
                {
                    "error": "Server is busy analyzing another file. Please retry later."
                }
            ),
            429,
        )

    # Create temporary directory for processing
    # 使用 TemporaryDirectory 确保处理完后清理中间文件 (除了返回的 zip)
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            input_filename = file.filename
            if not input_filename:
                input_filename = "target_binary"

            start_task_status(input_filename)

            input_path = os.path.join(temp_dir, input_filename)
            output_dir = os.path.join(temp_dir, "output")

            logger.info(f"Receiving file: {input_filename}")
            # Save uploaded file
            file.save(input_path)

            # Prepare command
            cmd = [PYTHON_EXEC, INP_SCRIPT, "-i", input_path, "-o", output_dir]

            logger.info(f"Executing INP.py: {' '.join(cmd)}")
            logger.debug(f"Temp directory: {temp_dir}")

            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            except FileNotFoundError:
                error_msg = f"Could not execute python interpreter: {PYTHON_EXEC}"
                logger.critical(error_msg)
                update_task_status(
                    running=False,
                    phase="failed",
                    finished_at=now_iso(),
                    error=error_msg,
                )
                return jsonify({"error": error_msg}), 500
            except Exception as e:
                error_msg = f"Failed to start INP.py: {str(e)}"
                logger.error(error_msg)
                update_task_status(
                    running=False,
                    phase="failed",
                    finished_at=now_iso(),
                    error=error_msg,
                )
                return jsonify({"error": error_msg}), 500

            stdout_thread = threading.Thread(
                target=stream_reader, args=(process.stdout, "stdout"), daemon=True
            )
            stderr_thread = threading.Thread(
                target=stream_reader, args=(process.stderr, "stderr"), daemon=True
            )
            stdout_thread.start()
            stderr_thread.start()

            return_code = process.wait()
            stdout_thread.join()
            stderr_thread.join()

            if return_code != 0:
                error_msg = f"INP.py failed with exit code {return_code}"
                logger.error(error_msg)
                update_task_status(
                    running=False,
                    phase="failed",
                    finished_at=now_iso(),
                    exit_code=return_code,
                    error=error_msg,
                )
                snapshot = get_task_status_snapshot()
                return jsonify(
                    {
                        "error": error_msg,
                        "stderr": snapshot["stderr"],
                        "stdout": snapshot["stdout"],
                    }
                ), 500

            # Check if output directory exists
            if not os.path.exists(output_dir):
                logger.error("INP.py did not create output directory")
                update_task_status(
                    running=False,
                    phase="failed",
                    finished_at=now_iso(),
                    error="INP.py did not create output directory",
                )
                return jsonify({"error": "INP.py did not create output directory"}), 500

            update_task_status(phase="zipping")

            # Zip the output directory into a temporary file
            # 使用 delete=True，但在 send_file 后才关闭/删除 (依赖 Flask 的处理)
            # Note: on Windows, NamedTemporaryFile generally cannot be opened twice,
            # so we pass the file object directly to ZipFile and send_file.
            zip_file = tempfile.NamedTemporaryFile(suffix=".zip")

            try:
                file_count = 0
                with zipfile.ZipFile(zip_file, "w", zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(output_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            rel_path = os.path.relpath(file_path, output_dir)
                            arcname = os.path.join("ida_export", rel_path)
                            zipf.write(file_path, arcname)
                            file_count += 1

                logger.info(f"Zipped {file_count} files for download")

                # Reset file pointer to beginning
                zip_file.seek(0)
                update_task_status(
                    running=False,
                    phase="completed",
                    finished_at=now_iso(),
                    exit_code=0,
                    error=None,
                )

                return send_file(
                    zip_file,
                    as_attachment=True,
                    download_name=f"{input_filename}_analysis.zip",
                    mimetype="application/zip",
                )

            except Exception as e:
                logger.error(f"Failed to zip or send results: {str(e)}")
                zip_file.close()  # Clean up manually if error
                update_task_status(
                    running=False,
                    phase="failed",
                    finished_at=now_iso(),
                    error=f"Failed to zip or send results: {str(e)}",
                )
                return jsonify({"error": f"Failed to zip or send results: {str(e)}"}), 500
    except Exception as e:
        logger.exception(f"Unexpected analyze error: {str(e)}")
        update_task_status(
            running=False,
            phase="failed",
            finished_at=now_iso(),
            error=f"Unexpected server error: {str(e)}",
        )
        return jsonify({"error": f"Unexpected server error: {str(e)}"}), 500
    finally:
        ANALYZE_LOCK.release()


@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "busy": ANALYZE_LOCK.locked(),
            "inp_script": INP_SCRIPT,
            "python_exec": PYTHON_EXEC,
        }
    )


@app.route("/status", methods=["GET"])
def status():
    snapshot = get_task_status_snapshot()
    snapshot["busy"] = ANALYZE_LOCK.locked()
    return jsonify(snapshot)


if __name__ == "__main__":
    # Check if INP.py exists
    if not os.path.exists(INP_SCRIPT):
        logger.warning(f"INP.py not found at {INP_SCRIPT}")

    parser = argparse.ArgumentParser(description="IDA-NO-MCP HTTP Server")
    parser.add_argument(
        "-H",
        "--host",
        default="127.0.0.1",
        help="Host IP to bind to (default: 127.0.0.1)",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=9753,
        help="Port to bind to (default: 9753)",
    )

    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable DEBUG level logging",
    )

    args = parser.parse_args()

    # Adjust log level based on argument
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)  # Root logger
        logger.debug("Debug logging enabled")

    logger.info(f"Starting IDA-NO-MCP Server on {args.host}:{args.port}")
    logger.info(f"Using Python for INP: {PYTHON_EXEC}")

    # Suppress Flask default request logging if not debug
    if not args.debug:
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

    app.run(host=args.host, port=args.port)

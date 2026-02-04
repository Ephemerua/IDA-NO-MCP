import os
import sys
import argparse
import subprocess
import tempfile
import zipfile
import shutil
import logging
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

    # Create temporary directory for processing
    # 使用 TemporaryDirectory 确保处理完后清理中间文件 (除了返回的 zip)
    with tempfile.TemporaryDirectory() as temp_dir:
        input_filename = file.filename
        if not input_filename:
            input_filename = "target_binary"

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
            # Run INP.py
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Log INP.py output
            if result.stdout:
                logger.info(f"INP.py STDOUT:\n{result.stdout.strip()}")
            if result.stderr:
                logger.warning(f"INP.py STDERR:\n{result.stderr.strip()}")

        except subprocess.CalledProcessError as e:
            error_msg = f"INP.py failed with exit code {e.returncode}"
            logger.error(error_msg)
            if e.stdout:
                logger.error(f"INP.py STDOUT (failed):\n{e.stdout.strip()}")
            if e.stderr:
                logger.error(f"INP.py STDERR (failed):\n{e.stderr.strip()}")

            return jsonify(
                {"error": error_msg, "stderr": e.stderr, "stdout": e.stdout}
            ), 500
        except FileNotFoundError:
            logger.critical(f"Could not execute python interpreter: {PYTHON_EXEC}")
            return jsonify(
                {"error": f"Could not execute python interpreter: {PYTHON_EXEC}"}
            ), 500

        # Check if output directory exists
        if not os.path.exists(output_dir):
            logger.error("INP.py did not create output directory")
            return jsonify({"error": "INP.py did not create output directory"}), 500

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

            return send_file(
                zip_file,
                as_attachment=True,
                download_name=f"{input_filename}_analysis.zip",
                mimetype="application/zip",
            )

        except Exception as e:
            logger.error(f"Failed to zip or send results: {str(e)}")
            zip_file.close()  # Clean up manually if error
            return jsonify({"error": f"Failed to zip or send results: {str(e)}"}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        {"status": "ok", "inp_script": INP_SCRIPT, "python_exec": PYTHON_EXEC}
    )


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

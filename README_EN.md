English | [简体中文](README.md)

# IDA NO MCP

**Say goodbye to the complex, verbose, and laggy interaction mode of IDA MCP.**  

**AI Reverse Engineering, Zero Extra Configuration.**  

Simple · Fast · Intelligent · Low Cost

## Core Philosophy

Text, Source Code, and Shell are LLM's native languages.

AI is evolving rapidly with no fixed patterns—tools should stay simple. Export IDA decompilation results as source files, drop them into any AI IDE (Cursor / Claude Code / ...), and naturally benefit from indexing, parallelism, chunking (for huge decompiled functions), and other optimizations.

## Installation & Usage

### Method 1: As an IDA Plugin (Recommended)

Symlink `INP.py` to IDA's plugins directory to enable auto-loading and hotkey support.

```bash
# Modify paths based on your installation
ln -s /path/to/IDA-NO-MCP/INP.py /Applications/IDA\ Professional\ 9.0/Contents/MacOS/plugins/INP.py
```

- **Hotkey**: `Ctrl-Shift-E`
- **Menu**: `Edit -> AI Export`

### Method 2: Command Line Mode (Headless, IDA 9.x+ only)

Leverage IDA 9.x's Python bindings to run export tasks directly from the terminal.

```bash
python3 INP.py -i <input_file> [-o <output_dir>]
```

- `-i, --input`: **(Required)** Path to the IDB or binary file.
- `-o, --output`: **(Optional)** Specify export directory, defaults to `export-for-ai/` in the IDB directory.
- By default, the script also saves the current IDB to `idb/` under the `INP.py` directory (auto-created if missing).

### Method 3: Script Execution

Copy the entire `INP.py` → Paste into IDA Python console → Press Enter.

### Method 4: HTTP Service Mode (Server/Client)

Useful when IDA runs on a remote server and you submit files from a local client.

**1. Start server**

Install dependencies:
```bash
pip install -r requirements.txt
```

Start server:
```bash
# default: 127.0.0.1:9753
python3 server.py

# custom host/port + debug logs
python3 server.py -H 0.0.0.0 -p 8080 -d
```

> **Note**: If `INP.py` requires a specific IDA Python runtime, set `IDA_PYTHON`.

**2. Client call**

```bash
# basic usage
python3 client_example.py -i ./target_binary

# custom server address
python3 client_example.py -i ./target_binary -H 192.168.1.100 -p 8080 -o result.zip
```

**3. Server APIs**

- `POST /analyze`: upload file and run analysis, returns zip on success.
- `GET /health`: health check (includes `busy`).
- `GET /status`: current/latest task status and streamed `INP.py` output (`stdout` / `stderr`).
- `POST /cancel`: cancel the current task. The server sends a cancel signal to `INP.py`, which immediately saves the database and exits without returning a zip.

Typical `/status` fields:

- `task_id`: incremental task id
- `running`: whether analysis is in progress
- `phase`: `idle` / `running` / `zipping` / `canceling` / `canceled` / `completed` / `failed`
- `busy`: server lock state
- `stdout` / `stderr`: captured output so far
- `stdout_truncated` / `stderr_truncated`: whether output was trimmed

Polling example:

```bash
curl http://127.0.0.1:9753/status
```

> **Concurrency model**: server runs in single-task mode. Concurrent `/analyze` requests are rejected with `429`.

## Exported Content

| File/Directory | Content |
|----------------|---------|
| `decompile/` | Decompiled C code (with call relationships) |
| `strings.txt` | String table |
| `imports.txt` | Import table |
| `exports.txt` | Export table |
| `memory/` | Memory hexdump (1MB chunks) |

## Tips

You can add more context in the IDB directory to give AI a complete picture:

| Directory | Content |
|-----------|---------|
| `apk/` | APK decompilation directory (APKLab one-click export) |
| `docs/` | Reverse engineering reports, notes |
| `codes/` | exp, Frida scripts, decryptor, etc. |

State-of-the-art AI models can leverage all this information and scripts to provide you with the most powerful reverse engineering assistance.

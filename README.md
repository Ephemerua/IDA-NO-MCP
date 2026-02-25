[English](README_EN.md) | 简体中文

# IDA NO MCP

**告别 IDA MCP 复杂、冗长、卡顿的交互模式。**  

**AI 逆向，无需额外配置。**  

Simple · Fast · Intelligent · Low Cost

## 核心理念

Text、Source Code、Shell 是 LLM 原生语言。

AI 飞速发展，没有固定模式，工具应该保持简单。

把 IDA 反编译结果导出为源码文件，直接丢进任意 AI IDE（Cursor / Claude Code / ...），天然适配索引、并行、切片（反编译超大函数）等优化。

## 安装与使用

### 方式 1：作为 IDA 插件（推荐）

将 `INP.py` 软链接到 IDA 的插件目录，即可实现自动加载并使用快捷键触发。

```bash
# 请根据实际安装路径修改
ln -s /path/to/IDA-NO-MCP/INP.py /Applications/IDA\ Professional\ 9.0/Contents/MacOS/plugins/INP.py
```

- **快捷键**：`Ctrl-Shift-E`
- **菜单**：`Edit -> AI Export`

### 方式 2：命令行模式（Headless，仅限 IDA 9.x+）

利用 IDA 9.x 的 Python 绑定，可以直接在终端运行导出任务。

```bash
python3 INP.py -i <输入文件> [-o <导出目录>]
```

- `-i, --input`: **(必填)** IDB 或二进制文件路径。
- `-o, --output`: **(可选)** 指定导出目录，默认为 IDB 所在目录下的 `export-for-ai/`。
- 默认会先保存一次 IDB 到 `INP.py` 所在目录下的 `idb/` 子目录（不存在会自动创建）。

### 方式 3：脚本运行

复制 `INP.py` 全部内容 → 粘贴到 IDA Python 窗口 → 回车。

### 方式 4：HTTP 服务模式 (Server/Client)

适合将 IDA 部署在服务器，本地通过客户端提交文件进行分析。

**1. 启动服务端**

安装依赖：
```bash
pip install -r requirements.txt
```

启动服务（支持指定 IP 和端口）：
```bash
# 默认监听 127.0.0.1:9753
python3 server.py

# 指定 IP 和端口，开启调试日志
python3 server.py -H 0.0.0.0 -p 8080 -d
```

> **注意**：如果 `INP.py` 需要特定的 IDA Python 环境，请设置环境变量 `IDA_PYTHON`。

**2. 客户端调用**

使用示例脚本提交任务，结果将自动下载并保存为 ZIP 包（解压后位于 `ida_export/` 目录）：

```bash
# 基本用法
python3 client_example.py -i ./target_binary

# 指定服务端地址
python3 client_example.py -i ./target_binary -H 192.168.1.100 -p 8080 -o result.zip
```

**3. 服务端接口**

- `POST /analyze`：上传文件并开始分析，完成后返回 zip。
- `GET /health`：健康检查（包含 `busy` 字段）。
- `GET /status`：返回当前/最近一次任务状态与 `INP.py` 实时输出（`stdout` / `stderr`）。
- `POST /cancel`：取消当前任务。服务端会向 `INP.py` 发送取消信号，`INP.py` 收到后会立即保存数据库并退出，不返回 zip。

`/status` 典型字段：

- `task_id`：任务递增 ID
- `running`：是否正在执行
- `phase`：`idle` / `running` / `zipping` / `canceling` / `canceled` / `completed` / `failed`
- `busy`：服务是否正忙（与并发锁一致）
- `stdout` / `stderr`：当前已采集输出
- `stdout_truncated` / `stderr_truncated`：输出过长时是否被截断

你可以在上传后轮询查看进度：

```bash
curl http://127.0.0.1:9753/status
```

> **并发限制**：服务端当前为单任务模式，同一时刻仅允许一个 `/analyze`。并发请求会返回 `429`。

## 导出内容

| 文件/目录 | 内容 |
|-----------|------|
| `decompile/` | 反编译 C 代码（含调用关系） |
| `strings.txt` | 字符串表 |
| `imports.txt` | 导入表 |
| `exports.txt` | 导出表 |
| `memory/` | 内存 hexdump（1MB 分片） |

## Tips

在 IDB 目录下可以同时添加更多上下文，让 AI 获得完整视角：

| 目录 | 内容 |
|------|------|
| `apk/` | APK 反编译目录（APKLab 一键导出） |
| `docs/` | 逆向分析报告、笔记 |
| `codes/` | exp、Frida scripts、decryptor 等脚本 |

最先进的 AI 模型能够利用所有信息与脚本，为你提供最强力的逆向工程辅助。

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

### 方式 3：脚本运行

复制 `INP.py` 全部内容 → 粘贴到 IDA Python 窗口 → 回车。

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

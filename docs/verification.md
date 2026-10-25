# 本地验证记录

初次验证：2026-10-22；本地入口复核：2026-10-23（北京时间）。以下只记录实际运行过的命令及其证据等级；本地临时 flag 不写入仓库。

## 环境

- WSL Ubuntu，Python 3.12.3；Docker 29.1.3；Docker Compose v5.6.1。
- CTFy PyPI 发行版 0.7.0，安装在 WSL 虚拟环境中。该版本的 `ctfy` 有 `agent check`，但没有官网 CTFY-0002 页面所写的 `ctfy authoring check` 和 `ctfy authoring smoke --local` 子命令。使用同一发行版的 `ctfy-admin challenge audit/smoke` 做本地检查；比赛平台自身的审核仍需独立确认。
- 镜像使用本地缓存的 `python:3.11-slim` 构建。CLI 版本、Docker 版本及官网标准可能变动，赛前重新核对。

## 结果

| 验证 | 实际命令摘要 | 结果 | 能证明什么 |
|---|---|---|---|
| 契约及本地 HTTP 闭环 | `python3 -m unittest discover -s tests -v` | 14/14 通过 | 读写契约、关键错误处理、入口到模拟模型/平台提交；模拟平台的接受不是真实成绩 |
| 官方镜像检查 | `ctfy agent check qutagent:dev --json` | `verdict: passed`，`ran_locally: true`，0 findings；2026-10-22 本地镜像 digest `sha256:1fb78bf84a33d06e052ceb02a1d9698fd4caf9959a276f5002b650b499f8d496` | CTFY-0001 本地镜像检查与 dry run 通过；镜像未上传/审核 |
| 题包严格静态审计 | `ctfy-admin challenge audit --all --challenges-dir author/generated --strict --json` | seed 42/43/44/45：4 个题包，0 issues | 0.7.0 的静态规则通过 |
| 题包动态 smoke | `ctfy-admin challenge smoke --all --challenges-dir author/generated --ephemeral-ports --jobs 2 --timeout 180` | seed 42/43/44：3 ok，0 failed | 3 个题包均启动容器、运行参考解、匹配每次新生成的 1/1 动态答案 |
| 离线自动出题流程 | `python3 author/prepare.py --seed 45 --ctfy-admin /home/agentfuzz/qutagent-ctfy-venv/bin/ctfy-admin --smoke-runs 2` | 严格审计 1/1、smoke 2/2 通过 | 自动生成和本地验证流程可运行，报告见 `author/generated/document-desk-45.verification.json`；未上传 |

第一次 smoke 发现 Windows 生成的 `rotate.sh` 使用 CRLF，导致脚本无法启动；生成器已改为写入 LF，新增回归测试。第一次审计发现源码注释含解题提示词，已删除；严格审计重跑为零问题。第一次尝试 smoke 时 WSL 缺少 Compose 插件；安装官方 Compose v5.6.1 后完成动态测试。

## 2026-10-23 入口复核

- Windows `python -X utf8 scripts/run_local.py`：进程退出 0，输出 `schema_version: 2`、`stop_reason: dry_run` 的 `result.json`。脚本使用合成任务与临时目录，不访问真实平台。
- Windows `python -X utf8 -m unittest discover -s tests -v`：14/14 通过；为兼容当前隔离式 Python 发行版，在测试入口显式加入仓库根目录。测试中的模拟 HTTPError 有清理提示，不影响结果。
- WSL `docker build --pull=false --platform linux/amd64 -t qutagent:dev .`：当前源码重新构建成功，本地 image ID `bb751f81c1eb`。
- WSL `/home/agentfuzz/qutagent-ctfy-venv/bin/ctfy agent check qutagent:dev --json`：重新构建后的镜像为 `passed`、`ran_locally: true`、0 findings。CLI 说明 registry manifest 返回 401，因此检查的是本地镜像；不代表已注册到比赛。

## 当前门槛

- G0：公开规则审计及未知项记录已完成；赛道附件仍未找到，已整理可直接发送的 [规则询问清单](rules-request.md)。
- G1：本地构建、dry run 与官方 `agent check` 已通过。
- G2：Windows 全量测试 **141 项 OK（4 skip：2 个 Linux-only + Windows Pwn/XSS 用例）**；镜像内 Linux 全量测试 **141/141（3 skip）**，Pwn 与 XSS（Playwright admin bot）端到端在镜像内执行。包含契约/可靠性/靶题/HTTP 会话/MCP/skills/分类靶题/出题/参赛流程测试。模拟 HTTP 与 mock MCP 不是平台验证。
- G3：**已运行**分类靶题假模型闭环：SQLi（Windows 3/3）、MCP/AI（Windows 3/3）、Pwn（镜像内 3/3）、XSS 反射+admin bot（镜像内 3/3）及原路径穿越（Windows/镜像 3/3），mock 平台均接受动态 flag；真实模型实验因无 `LLM_*` 凭据明确 `blocked`，**没有真实模型成功率，也没有真实 CTFy 平台接受记录**。
- G4：出题包生成/审计/smoke 的本地证据仍在；`author/controller.py` 和 `scripts/platform_flow.py` 默认 dry-run、mock 契约测试通过；**未上传、未审核、未注册、未创建 entry**。
- G5：固定 dev/validation 种子集与统一预算（60s / 8 turns / 8 requests）仍有效；新增分类 playbook/MCP/HTTP 会话，但真实模型对照仍未运行。
- G6（新增）：镜像已装入 Web/Pwn/AI 工具链，WSL Docker 构建成功（3.57 GB 磁盘 / 0.88 GiB 内容），`ctfy agent check` 与 required 工具检查通过；**未上传/审核**。

一键重跑 Windows 本地验收：`python -X utf8 -m unittest discover -s tests -v` + `python -X utf8 scripts/run_lab.py --model fake --set dev`。Linux/Docker 可用时再跑 `bash scripts/verify_local.sh`（需要 `ctfy`、`ctfy-admin`、Docker 与 Compose 在 PATH 上）。

## 2026-10-23 可靠性与 Web 工具复核

本轮修改仅针对求解器 `instance`、`qa`：

- `agent/state.py` 按平台确认、仍可继续、尝试耗尽、未解锁、信息不足区分问题状态。只有明确的整题完成字段，或已知问题全对且 `gated_questions=0`，才置 `fully_solved=true`。提前 `finish`、轮数上限和空待答队列不构成成功。已确认的正确提交会先写入结果，再刷新平台状态。
- `agent/security.py` 给 shell 子进程使用环境变量允许列表，并对已知环境密钥值做结果/事件脱敏；假令牌测试通过。此措施不提供独立 PID、文件系统或网络命名空间，不能阻止同容器读取其他进程或可见文件。
- `agent/budget.py` 的单调时钟截止时间传递至模型、平台、附件、轮询/退避和 shell。慢 HTTP 响应体由有界调用控制；超时后台线程可能继续运行，因此 POST 响应不确定时不盲目重发。提交 POST 会尝试只读状态核对；实例创建 POST 无法凭未知实例 ID 安全重试，写入 `mutation_outcome_unknown`。
- Linux shell 使用独立进程组，执行后清理本次命令及其后台子进程；stdout/stderr 各限制实际缓存量，返回退出码、`timed_out`、`truncated`、采集字节数、耗时及错误类别。Windows 原生 shell 路径仍返回 `shell_requires_linux`。
- 镜像在构建期安装 CA 证书、`curl`、`jq`、`file`；Python 标准库承担 HTTP 会话、HTML/JSON 与编码处理。镜像仍以 UID 10001 运行，评测时不安装软件。版本明细：`curl 8.14.1`、`jq 1.7`、`file 5.46`、Python 3.11（构建时 `/app/tool-versions.txt`）。

| 验证 | 实际结果 | 边界 |
|---|---|---|
| Windows `python -X utf8 -m unittest discover -s tests -v` | 当轮历史快照：24 项执行，22 通过、2 跳过（Linux 命令及其入口）；退出 0；最新全量为 141 项，见下节 | 含状态、假密钥、短预算、慢响应、请求上限、POST 不确定结果 |
| WSL `python3 -m unittest discover -s tests -v` | 24/24 通过，退出 0 | Linux 进程组、命令输出上限和模拟 HTTP 闭环已执行；仍不等于真实靶题解题 |
| Windows `python -X utf8 scripts/run_local.py` | `dry_run`、`fully_solved:false`，退出 0 | 入口/文件契约检查 |
| WSL `docker build --pull=false --platform linux/amd64 -t qutagent:dev .` | 成功；本地 image ID `sha256:20e17c0933e13d3dc04d41599f22a56f433710e7b363b68507e8563f8371a3b3` | 构建期下载 apt 软件包；评测期无需下载 |
| 镜像内 `scripts/check_web_tools.py` | `web_tool_smoke_passed`；UID 10001，基础工具可用 | 自包含 HTTP 会话和文件写入；未连接授权靶题 |
| WSL `/home/agentfuzz/qutagent-ctfy-venv/bin/ctfy agent check qutagent:dev --json` | `verdict: passed`、`ran_locally: true`、`findings: []`；registry manifest 401 后改查**本地镜像** | CTFY-0001 本地检查通过，不是远程镜像审核或比赛接受 |

当轮（2026-10-23 早先）按用户要求跳过隔离 Docker 授权 Web 靶题联调入口，因此当时**假模型驱动靶题实验、真实模型驱动靶题实验均未运行**；该历史结论已被下节替代：后续已运行进程级靶题 + 假模型闭环，真实模型仍因无凭据 blocked。此前入口对模拟 HTTP 平台的测试只检验程序调用链。正式参赛仍需：赛道附件和模型/提交规则确认；真实模型在明确时间、轮数和请求预算下的实验；平台对镜像及答案的正式接受。未进行任何平台注册、镜像上传、题包上传或真实答案提交。

## 2026-10-23 隔离靶题、出题控制器与参赛流程复核

本节只记录实际执行过的命令；没有真实账号 token，没有向真实 CTFy 平台发起请求。详细说明见 [靶题实验记录](lab-experiments.md)、[出题上传](authoring-upload.md)、[参赛流程](participation-flow.md)。

| 验证 | 实际命令/结果 | 证据等级与边界 |
|---|---|---|
| 全量 Windows 测试 | `python -X utf8 -m unittest discover -s tests -v` → **Ran 67 tests, OK (skipped=2)**，退出 0 | 代码/契约/本地闭环；不是平台审核 |
| 假模型 Web 靶题 dev 集 | `python -X utf8 scripts/run_lab.py --model fake --set dev` → exit 0，`fake-dev-20261023T064110Z-2f1a50`，3/3 成功，mock 平台接受 3 个动态 flag，wall 6.708s，tokens 19463/591，15 次模型请求；每例 `turns=5`、`http_calls=4`、`stop_reason=done` | 证明 HTTP 工具、真实 `agent/main.py`、模型 HTTP 客户端、平台提交/判定链路可运行；不证明模型能力或真实平台接受 |
| 真实模型入口 | `python -X utf8 scripts/run_lab.py --model real --set validation` → exit 2，`status=blocked`，缺 `LLM_FLAVOR/LLM_MODEL/LLM_API_KEY`，未发模型请求 | 无真实模型成功率；缺凭据时 fail-closed，不伪造 |
| 出题控制器 dry-run | `python -X utf8 author/controller.py --seed 46 --dry-run` → exit 0，`network_sent=false`、`uploaded=false`、`platform_reviewed=false`，archive sha256 `12a5cc63…c46d651e`，8 文件 | 本地打包/哈希/报告；未上传、未审核 |
| 镜像/entry 流程 dry-run | `python -X utf8 scripts/platform_flow.py register-harness ...` / `enter ...` → exit 0，`network sent: False`，报告 `planned_only` | 只有计划请求形状；未注册、未 probe、未创建 entry |
| 凭据/flag 泄漏扫描 | `artifacts/lab` 与出题报告扫描无 `flag{...}` 明文；mock 提交只存答案 SHA-256 | 仅覆盖本轮实验产物，不等于平台审计 |

环境限制：当轮 Windows 侧无 Docker；WSL 命令返回 `E_ACCESSDENIED`，因此没有做容器级靶题/镜像复跑，也没有重新执行 `ctfy agent check`（此前的 WSL 结果仍是历史证据）。真实模型、真实平台注册/上传/entry 需要用户提供授权凭据与赛道附件；未完成项已列入 [规则询问清单](rules-request.md)。

## 2026-10-25 求解器能力融合与工具链镜像复核

本轮 WSL Ubuntu-24.04 恢复可用（Docker 29.1.3 / Compose v5.6.1），因此补做了镜像级验证；仍然没有真实模型凭据、没有真实平台请求。能力映射见 [solver skills](solver-skills.md)，工具链见 [toolchain](toolchain.md)。

| 验证 | 实际结果 | 证据等级与边界 |
|---|---|---|
| Windows 全量测试 | `python -X utf8 -m unittest discover -s tests -v` → **Ran 141 tests, OK (skipped=4)** | 代码/契约/本地闭环；新增 59 项 skills/loop/HTTP/MCP + 15 项 SQLi/MCP/Pwn/XSS 分类靶题 |
| 镜像内全量测试 | `docker run --rm --user root -v "$PWD:/repo" -w /repo --entrypoint python qutagent:dev -X utf8 -m unittest discover -s tests -v` → **Ran 141 tests, OK (skipped=3)** | Linux 镜像内执行，Pwn/XSS 端到端实际运行；仍不是平台/真实模型验证 |
| 镜像工具链构建 | `docker build --pull=false --platform linux/amd64 -t qutagent:dev .` → 成功，完整 **1078 s** + `ctf-browse`/skills 增量重建，镜像 `sha256:2e1060c9…`，内容 `943,208,224` B ≈ 0.88 GiB，磁盘 3.57 GB | 构建期联网安装；评测期离线 |
| 工具链 required 检查 | `docker run --rm --entrypoint python qutagent:dev /app/scripts/check_toolchain.py` → exit 0，`verdict: passed`，**required_failed: []**，`optional_failed: ["import:angr"]` | 66 项检查；angr 为已知 optional 缺失 |
| 离线检查 | 同上加 `--network none` → exit 0 / passed | 运行期工具链不依赖网络 |
| 官方本地镜像检查 | `ctfy agent check qutagent:dev --json` → `verdict: passed`、`ran_locally: true`、`findings: []` | CTFY-0001 本地 dry run；不是平台审核 |
| 镜像级假模型靶题 | 镜像内 `python -X utf8 scripts/run_lab.py --model fake --set dev` → 3/3，`fake-dev-20261025T101014Z-9cbe02`，wall 7.172s，平台接受 3 个动态 flag | 证明镜像内 agent/HTTP/模型/平台链路可运行；假模型不代表真实模型能力 |
| 分类靶题（SQLi/MCP/Pwn/XSS） | SQLi Windows `fake-web-sqli-20261025T111527Z-4abad1` 3/3；MCP Windows `fake-ai-mcp-20261025T111533Z-d458f8` 3/3；Pwn 镜像内 `fake-pwn-20261025T111942Z-cb82ba` 3/3，wall 12.367s、平台接受 3；XSS 镜像内 `fake-xss-20261025T114243Z-4e26a9` 3/3，wall 29.545s、平台接受 3 | 证明分类 playbook、HttpSession Cookie/重定向、MCP action、Pwn 附件下载/工具链/exploit、XSS 反射+Playwright admin bot+/collect 提交链路可运行；假模型不代表真实模型能力 |
| 真实模型入口 | 仍无 `LLM_*`，`--model real` 返回 exit 2 / `blocked`；新增 `--llm-env-file` 便于在本地 gitignored 文件提供凭据（值不回显） | 无真实模型成功率；未伪造 |
| 平台注册/出题上传 | 无 token；`platform_flow.py`/`author/controller.py` 仍只做 dry-run/mock | 未注册、未 probe、未 entry、未上传、未审核 |

结论：镜像与求解器的**本地可用性**已显著增强（分类 playbook、格式纠错、循环检测、历史压缩、Cookie 会话、同源重定向、MCP、Pwn/Web/AI 工具链），并通过 required 检查与镜像内测试；SQLi/MCP/Pwn 分类靶题的假模型链路见 [分类靶题记录](labs-categories.md)。但**真实模型解题、平台注册/审核、真实平台接受 flag、赛道规则附件**仍是未完成项。

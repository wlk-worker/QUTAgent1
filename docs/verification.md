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

- G0：公开规则审计及未知项记录已完成；赛道附件仍未找到。
- G1：本地构建、dry run 与官方 `agent check` 已通过。
- G2：历史记录中的 14 项测试通过；本轮扩展后的 24 项见下节。模拟 HTTP 服务的闭环不是平台验证。
- G3：真实授权练习题的模型→工具→平台接受答案闭环尚未运行。没有真实接受记录。
- G4：原创 Web 候选题生成器的 4 个 seed 已通过本地严格审计和 smoke，其中 seed 45 连续 smoke 两次；未上传、未审核。当前结构仍是固定题型的参数化生成，赛事是否将其认作合格的自主出题需正式规则确认。
- G5：未建立真实练习题的固定开发集/验证集，也没有成对性能比较。

一键重跑本地验收：`bash scripts/verify_local.sh`（需要 `ctfy`、`ctfy-admin`、Docker 与 Compose 在 PATH 上）。

## 2026-10-23 可靠性与 Web 工具复核

本轮修改仅针对求解器 `instance`、`qa`：

- `agent/state.py` 按平台确认、仍可继续、尝试耗尽、未解锁、信息不足区分问题状态。只有明确的整题完成字段，或已知问题全对且 `gated_questions=0`，才置 `fully_solved=true`。提前 `finish`、轮数上限和空待答队列不构成成功。已确认的正确提交会先写入结果，再刷新平台状态。
- `agent/security.py` 给 shell 子进程使用环境变量允许列表，并对已知环境密钥值做结果/事件脱敏；假令牌测试通过。此措施不提供独立 PID、文件系统或网络命名空间，不能阻止同容器读取其他进程或可见文件。
- `agent/budget.py` 的单调时钟截止时间传递至模型、平台、附件、轮询/退避和 shell。慢 HTTP 响应体由有界调用控制；超时后台线程可能继续运行，因此 POST 响应不确定时不盲目重发。提交 POST 会尝试只读状态核对；实例创建 POST 无法凭未知实例 ID 安全重试，写入 `mutation_outcome_unknown`。
- Linux shell 使用独立进程组，执行后清理本次命令及其后台子进程；stdout/stderr 各限制实际缓存量，返回退出码、`timed_out`、`truncated`、采集字节数、耗时及错误类别。Windows 原生 shell 路径仍返回 `shell_requires_linux`。
- 镜像在构建期安装 CA 证书、`curl`、`jq`、`file`；Python 标准库承担 HTTP 会话、HTML/JSON 与编码处理。镜像仍以 UID 10001 运行，评测时不安装软件。版本明细：`curl 8.14.1`、`jq 1.7`、`file 5.46`、Python 3.11（构建时 `/app/tool-versions.txt`）。

| 验证 | 实际结果 | 边界 |
|---|---|---|
| Windows `python -X utf8 -m unittest discover -s tests -v` | 24 项执行，22 通过、2 跳过（Linux 命令及其入口）；退出 0 | 含状态、假密钥、短预算、慢响应、请求上限、POST 不确定结果 |
| WSL `python3 -m unittest discover -s tests -v` | 24/24 通过，退出 0 | Linux 进程组、命令输出上限和模拟 HTTP 闭环已执行；仍不等于真实靶题解题 |
| Windows `python -X utf8 scripts/run_local.py` | `dry_run`、`fully_solved:false`，退出 0 | 入口/文件契约检查 |
| WSL `docker build --pull=false --platform linux/amd64 -t qutagent:dev .` | 成功；本地 image ID `sha256:20e17c0933e13d3dc04d41599f22a56f433710e7b363b68507e8563f8371a3b3` | 构建期下载 apt 软件包；评测期无需下载 |
| 镜像内 `scripts/check_web_tools.py` | `web_tool_smoke_passed`；UID 10001，基础工具可用 | 自包含 HTTP 会话和文件写入；未连接授权靶题 |
| WSL `/home/agentfuzz/qutagent-ctfy-venv/bin/ctfy agent check qutagent:dev --json` | `verdict: passed`、`ran_locally: true`、`findings: []`；registry manifest 401 后改查**本地镜像** | CTFY-0001 本地检查通过，不是远程镜像审核或比赛接受 |

本轮按用户要求跳过隔离 Docker 授权 Web 靶题联调入口，因此**假模型驱动靶题实验、真实模型驱动靶题实验均未运行**；没有可报告的解题成功率或真实模型用量。此前入口对模拟 HTTP 平台的测试只检验程序调用链。正式参赛仍需：赛道附件和模型/提交规则确认；隔离授权题的完整求解记录；真实模型在明确时间、轮数和请求预算下的实验；平台对镜像及答案的正式接受。未进行任何平台注册、镜像上传、题包上传或真实答案提交。

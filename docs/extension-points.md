# 队友扩展入口与边界

## 运行路径

`Dockerfile` 启动 `agent/main.py` → `agent/contract.py` 读取 `CTFY_WORK_DIR/task.json` 与 `README.md` → `agent/main.py` 根据 `run_mode` 分流 → `agent/loop.py` 调度模型和工具 → `agent/contract.py` 原子写回 `result.json`。

本地无密钥检查：`python scripts/run_local.py`。完整镜像检查：构建镜像后运行 `ctfy agent check <image> --json`；必须看到本地运行检查通过，不能只看 manifest 检查。此检查不证明能解题。

## 协作分工建议

| 改动范围 | 负责内容 | 合并前应验证 |
|---|---|---|
| `agent/contract.py`、`agent/main.py`、`Dockerfile` | CTFY-0001 输入输出、入口和异常结果 | 本地 dry run、契约测试、官方镜像检查 |
| `agent/platform.py` | 平台 REST 适配与反馈、轮询 | 用官方标准/当前 SDK 对照请求字段，跑模拟接口测试 |
| `agent/model.py`、`agent/loop.py`、`agent/state.py` | 模型调用、动作决策、完成判定 | 注入假模型/假平台测试；不得从私人密钥回退，不得把空待答队列当成功 |
| `agent/budget.py`、`agent/security.py`、`agent/tools.py` | 总预算、输出脱敏、命令执行/进程组清理、结构化 HTTP（origin 白名单/同源重定向/Cookie/截断） | 在 Linux 跑慢请求、假密钥、超时子进程和大输出测试；Windows 跑 `test_web_tool.py` |
| `agent/skills.py`、`agent/mcp.py` | 分类 playbook/flag 纪律/格式与循环文本；MCP JSON-RPC HTTP/SSE 客户端 | `test_skills.py`、`test_mcp.py`；分类不得退化为硬编码 payload |
| `toolbox/`、`scripts/check_toolchain.py`、`Dockerfile` | 镜像 Web/Pwn/AI 工具链、辅助命令、离线检查 | 镜像内 `check_toolchain.py` required 全过；`ctfy agent check`；`--network none` 复跑 |
| `labs/`、`scripts/run_lab.py` | 进程级 Web/Pwn/AI 靶题、mock CTFy、假模型、固定预算 | `python -X utf8 scripts/run_lab.py --model fake --set dev`；真实模型 `--llm-env-file` 已在 7 个 set 跑 3/3，缺凭据时仍 `blocked` |
| `author/controller.py` | 赛时出题流程：生成/复用、本地检查、确定性打包、可选上传、只读轮询 | `--dry-run` 零请求；mock 契约测试；未经授权不真实上传 |
| `scripts/platform_flow.py` | 镜像注册、probe、状态、独立 entry；默认 dry-run | dry-run 零请求、fail-closed 预检、mock 契约测试；不能声称已注册/审核 |

优先通过模块边界添加能力，保持 `agent/main.py` 的入口稳定。对尚未实现的 `run_mode` 明确返回不支持；不要在没有赛道规则时猜测赛时出题上传协议。新平台字段要写明对应的官网标准版本，保留可复现的模拟测试。

队友复核顺序（Windows）：`python -X utf8 -m unittest discover -s tests -v`（149 项）→ `python -X utf8 scripts/run_local.py` → `python -X utf8 scripts/run_lab.py --model fake --set dev` → `python -X utf8 author/controller.py --seed 46 --dry-run`。Linux/Docker 可用时再加：`docker build --pull=false --platform linux/amd64 -t qutagent:dev .` → `docker run --rm --entrypoint python qutagent:dev /app/scripts/check_toolchain.py`（required 全过）→ `ctfy agent check qutagent:dev --json`；镜像内全量测试用 `docker run --rm --user root -v "$PWD:/repo" -w /repo --entrypoint python qutagent:dev -X utf8 -m unittest discover -s tests -v`（`--user root` 仅因 `/mnt/c` bind mount 对 UID 10001 不可写；生产镜像仍以 UID 10001 运行）。`agent/state.py` 新增平台状态映射时，应同时补误判完成的回归场景；`agent/platform.py` 新增 POST 时，应先设计响应不确定后的只读核对方法；`labs/` 的新用例必须保持“无凭据时 blocked、不伪造成功率”。

## 当前适配层和待确认点

`agent/contract.py` 是 CTFY-0001 v2 文件边界；`agent/platform.py` 是已公开 REST/SDK 字段的薄适配层。当前求解循环处理 `instance`/`qa`，并新增分类 playbook、有状态 HTTP、MCP 动作、格式纠错/循环检测/历史压缩；其余 run mode 仍在 `agent/main.py` 返回 `unsupported_or_missing_task`。`labs/` 是进程级实验，不是比赛运行环境；`toolbox/`/`Dockerfile` 提供镜像内工具链；`author/controller.py` 与 `scripts/platform_flow.py` 提供赛时出题/镜像/entry 的受控代码路径，默认 dry-run，真实操作仍受账号审核与赛道规则限制。

赛事说明提及的智能体赛道附件尚未核实。镜像注册/提交方式、模型与时间额度、是否强制赛时自主出题及上传接口、解题题型范围、计分与奖项规则，应在拿到附件或平台正式通知后逐项落实；清单见 [规则审计](rules-audit.md)。任何与公开 CTFY-0001/0002 不同的赛道专属流程，先补依据，再改适配层。

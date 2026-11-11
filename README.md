# QUTAgent

一个面向 CTFy / CTF 评测的自主 Agent 原型。它读取平台任务，调用模型网关，使用 shell、HTTP、MCP 等工具解题，最后把结果写回 `result.json`。覆盖 Web、Pwn、AI 安全和 Misc 类题目。

> 本仓库是开发与联调版本。仓库中的 mock 平台、本地靶题和 dry run 不等于真实平台成绩；正式使用前请确认赛事规则、授权范围和模型额度。

## 1. 环境要求

| 依赖 | 用途 |
|---|---|
| Python 3.11+ | 本地入口、测试和实验 |
| Docker（Linux containers） | 构建/运行最终镜像；Windows 可用 Docker Desktop 或 WSL |
| `linux/amd64` 镜像支持 | 最终镜像架构 |
| 真实模型 API | 只有跑真实模型实验时才需要 |

Windows 下建议使用 PowerShell；WSL/Linux 下使用 `python3`。

## 2. 最快开始：不需要密钥

```powershell
python scripts/run_local.py
```

它会在临时目录用 `examples/dry-run/task.json` 启动真实入口，校验任务读取和 `result.json` 写入，不需要 Docker、平台 token 或模型 key。

如果只想检查 Python 代码和本地靶题：

```powershell
python -X utf8 -m unittest discover -s tests -v
python -X utf8 scripts/run_lab.py --model fake --set dev
```

## 3. 构建和检查镜像

在仓库根目录：

```bash
docker build --pull=false --platform linux/amd64 -t qutagent:dev .
docker run --rm --entrypoint python qutagent:dev /app/scripts/check_toolchain.py
```

完全离线检查：

```bash
docker run --rm --network none --entrypoint python qutagent:dev \
  /app/scripts/check_toolchain.py --quiet
```

镜像入口是：

```text
/app/agent/main.py
```

容器工作目录是 `/ctfy/work`。评测时从该目录读取 `task.json`、`README.md`，把结果写回 `result.json`。

## 4. 本地假模型联调

以下命令不需要真实模型：

```powershell
python -X utf8 scripts/run_lab.py --model fake --set dev
python -X utf8 scripts/run_lab.py --model fake --set web-sqli
python -X utf8 scripts/run_lab.py --model fake --set xss
python -X utf8 scripts/run_lab.py --model fake --set pwn
python -X utf8 scripts/run_lab.py --model fake --set ssrf
python -X utf8 scripts/run_lab.py --model fake --set ai-mcp
python -X utf8 scripts/run_lab.py --model fake --set ai-mcp-traversal
```

这些靶题在 `labs/` 中，使用假模型驱动真实工具链，不会请求付费模型。

## 5. 使用真实模型

复制模板，填入你自己的模型配置：

```bash
mkdir -p artifacts
cp examples/llm.env.example artifacts/llm.env
```

编辑 `artifacts/llm.env`：

```text
LLM_FLAVOR=openai
LLM_MODEL=你的模型 ID
LLM_BASE_URL=https://你的模型服务/v1
LLM_API_KEY=你的 API key
```

先检查配置是否完整（不会回显 key）：

```bash
python scripts/check_llm_env.py --env-file artifacts/llm.env
```

跑一个最小验证集：

```bash
python scripts/run_lab.py --model real --set validation --llm-env-file artifacts/llm.env
```

也可以提高复杂题的预算：

```bash
python scripts/run_lab.py --model real --set pwn \
  --llm-env-file artifacts/llm.env --timeout-s 300 --max-turns 16 --max-requests 16
```

`artifacts/` 已在 `.gitignore` 中；不要把 `artifacts/llm.env` 提交到 Git。

## 6. 在 CTFy 平台使用

镜像运行契约（CTFY-0001）：

- 入口：`/app/agent/main.py`
- 工作目录：`/ctfy/work`
- 必需/可选环境变量由平台注入：

| 变量 | 作用 |
|---|---|
| `CTFY_PLATFORM_URL` | 平台 API 地址 |
| `CTFY_TOKEN` | 平台任务 token |
| `LLM_FLAVOR` | `openai` 或 `anthropic` |
| `LLM_MODEL` | 模型 ID |
| `LLM_API_KEY` | 本次运行的模型凭据 |
| `LLM_BASE_URL` | 平台/供应商模型网关地址 |
| `CTFY_WORK_DIR` | 工作目录，默认 `/ctfy/work` |

Agent 会写 `result.json`（`schema_version: 3`），正常退出码为 `0`。

CTFY-0001 v3 的几个关键点：

- 平台**已经启动 target**，`task.json.target_instance` 已存在；不要调用 `POST /api/v1/instances`；
- target 地址在 `target_endpoints`；单 Web endpoint 还会提供 `CTFY_TARGET_URL`；
- challenge 附件已在 `/ctfy/work/attachments/`；`download` 会优先使用本地文件；
- 平台可能在同一工作目录重启最多 5 轮，每轮重新写 `result.json`。

最终校准镜像：

```text
registry.ctfy.io/9c401d0f-7eef-4a29-ad02-bb66841ec0c6/qutagent:v1-final
sha256:8c56c976909c74d5b27af85835eb798b0b699eb725fe089fd9782951c6bedbec
```

构建 `linux/amd64` 镜像并推送到平台 registry：

```bash
bash scripts/push_image.sh artifacts/ctfy.env qutagent:dev v1
```

`artifacts/ctfy.env` 需要包含平台地址和 token，示例见 `examples/platform.env.example`。不要提交真实 token。

推送后，在平台的“新建测评”页面填写：

```text
registry.ctfy.io/<你的命名空间>/qutagent:v1
```

再选择模型并启动。镜像是否允许运行、是否需要人工审核，以平台页面为准。

## 7. 目录结构

```text
agent/       Agent 主循环、模型网关、平台 API、shell/HTTP/MCP 工具、skills
labs/        本地 CTF 靶题、mock 平台、假模型、实验 runner
tests/       不接触真实平台的单元/集成测试
toolbox/     镜像内 CTF 辅助脚本
author/      出题包生成/审计/打包流程
scripts/     构建、推送、实验、平台流程、环境检查脚本
docs/        验证记录、故障排查、工具链、交接说明
examples/    配置模板和 dry-run 输入
```

## 8. 测试与验收

```powershell
python -X utf8 -m unittest discover -s tests -v
```

镜像内运行同一套测试：

```bash
docker run --rm --user root -v "$PWD:/repo" -w /repo \
  --entrypoint python qutagent:dev \
  -X utf8 -m unittest discover -s tests -v
```

当前本地测试规模为 158 项；Windows 和镜像内会有少量与平台/浏览器相关的 skip。测试通过只说明本地契约和工具链可用，不代表真实平台分数。

## 9. 常见问题

### 平台显示“未调用到模型”

先看对应任务的 `/ctfy/work/result.json`：

| 结果特征 | 含义 |
|---|---|
| `stop_reason=deadline`、`category=""` | 卡在平台 challenge 元数据，尚未进入模型 |
| `stop_reason=deadline`、`category` 非空 | 卡在 target/instance 启动等待 |
| `startup_fallback` 存在 | 启动阶段已回退，模型应继续运行 |
| `stop_reason=model_error` | 模型网关/API key 问题 |
| `stop_reason=platform_error` | 平台 API 或工具调用错误 |
| `RemoteDisconnected` / `network_error` | 平台连接不稳定，当前版本会重试幂等 GET |

平台页面提示“检查你的 key”是通用提示；如果模型调用次数为 0，通常不是 key 问题。

### `model gateway must use HTTPS`

旧版本 Agent 会拒绝平台内网 HTTP 网关。当前版本允许内网 HTTP 网关；请使用最新镜像重新构建。

### `download` 报错

`download` 只用于平台附件。target web root 上的文件请用 `http` GET 或 `shell curl`。

### 模型网关返回空内容

在本地环境检查 `LLM_FLAVOR`、`LLM_MODEL`、`LLM_BASE_URL` 和 `LLM_API_KEY` 是否匹配；用 `scripts/check_llm_env.py` 检查配置，不要在日志中打印 key。

### 平台 target 启动失败

如果 `result.json` 显示启动回退、但工具访问 target 全部失败，问题在平台/靶场启动，不在模型 key。保存该任务的 `result.json` 和平台运行 ID，提交给平台侧排查。

## 10. 安全边界

- 不要把真实 token、API key、`.env` 文件提交到 Git。
- `artifacts/`、`runtime/`、`dist/` 已在 `.gitignore` 中。
- 不要在命令行中明文传 token；使用 `scripts/push_image.sh` 读取被忽略的 env 文件。
- 本地 dry run、mock 平台、假模型和真实平台成绩是不同证据等级，不能混用。
- 本仓库不是对任何未授权系统进行测试的授权；只在赛事或明确授权的靶场中使用。

## 11. 更多文档

- [队友交接说明](docs/TEAM_START.md)
- [赛事规则与 CTFY-0001 v3 对照](docs/rules-2026-11-10.md)
- [故障排查与平台记录](docs/platform-upload.md)
- [真实验证记录](docs/verification.md)
- [工具链与构建](docs/toolchain.md)
- [本地靶题实验](docs/lab-experiments.md)
- [能力与参考项目](docs/reference-projects.md)
- [扩展点](docs/extension-points.md)

# QUTAgent：TPCTF 2026 / CTFy 原型

这是 CTFY-0001 求解镜像、CTFY-0002 Web 出题包生成器、进程级 Web 靶题联调器与出题/参赛流程控制器的可用原型。**求解器已融合 SWE-agent v0.7、ctf-agent、Koshary、AWE、PwnAI 的分类 playbook/格式纠错/循环检测/历史压缩/HTTP 会话/MCP 能力；镜像已装入 Web/Pwn/AI 安全工具链（r2、pwntools、gdb、one_gadget、seccomp-tools、sqlmap、ffuf、nuclei、Chromium 等），WSL Docker 构建 3.57 GB（内容 0.88 GiB），`ctfy agent check` 与 required 工具检查均通过，镜像内 146 项测试通过；SQLi/XSS/Pwn/AI-MCP（含 `read_file` 工具目录穿越）分类靶题假模型闭环（SQLi/MCP Windows 3/3，MCP 穿越 Windows/镜像 3/3，Pwn/XSS 镜像内 3/3）。真实模型实验因无凭据仍 `blocked`；尚无真实平台解题成绩、镜像审核、题包审核或平台接受记录。**规则与未确认事项见 [规则审计](docs/rules-audit.md) 和 [规则询问清单](docs/rules-request.md)，求解器能力映射见 [solver skills](docs/solver-skills.md)，工具链见 [toolchain](docs/toolchain.md)，实测证据见 [验证记录](docs/verification.md) 和 [靶题实验记录](docs/lab-experiments.md)。

## 最快本地启动

在项目根目录运行（Windows PowerShell：`python`；WSL/Linux：`python3`）：

```powershell
python scripts/run_local.py
```

脚本用 [合成 dry-run 输入](examples/dry-run/task.json)在临时目录启动真实的 `agent/main.py`，打印并校验 `result.json`，不需要 Docker、平台令牌或模型密钥。它只验证入口和文件契约，不能证明真实解题能力。比赛镜像的入口及工作目录见 `Dockerfile`；队友改动位置见 [扩展说明](docs/extension-points.md)。

## 目录

- `agent/`：读取任务与环境、调用模型网关和平台 API、分类 playbook、shell/HTTP/MCP 工具、写 `result.json`。
- `agent/skills.py`：web/pwn/ai/misc/qa 分类和各类 playbook；`agent/mcp.py`：MCP 客户端；`agent/tools.py`：有状态 HTTP 会话。
- `labs/`：纯标准库的授权 Web 靶题、mock CTFy 平台、OpenAI 兼容假模型和实验 runner。
- `toolbox/`：镜像内 `ctf-checksec`、`ctf-disasm`、`ctf-debug`、`ctf-strings` 辅助命令与 nuclei 起步模板。
- `author/generate.py`、`author/prepare.py`：以 seed 生成原创 Web 题候选包，并做本地审计/smoke 验证。
- `author/controller.py`：赛时出题流程（生成/复用 → 本地检查 → 确定性打包 → 可选上传 → 只读轮询）；默认 dry-run。
- `scripts/run_lab.py`：固定 dev/validation 预算的完整靶题联调入口；`--llm-env-file` 可加载本地 LLM_* 文件（值不回显）。
- `scripts/platform_flow.py`：镜像注册、probe、状态读取和独立 agent entry 的安全流程；默认 dry-run。
- `tests/`：不接触真实平台的契约、靶题、抓取会话、MCP、出题/参赛流程测试（当前 146 项；Windows 4 项 skip，镜像内 3 项 skip）。
- `examples/dry-run/`、`scripts/run_local.py`：无需凭据的本地入口检查。
- `scripts/check_web_tools.py`、`scripts/check_toolchain.py`：镜像内基础 Web 工具/完整工具链检查。
- `_research/ctfy/`、`_research/repos/`：公开标准与参考项目快照，不是运行代码，也不是权威实时规则。
- `docs/solver-skills.md`、`docs/reference-projects.md`、`docs/toolchain.md`、`docs/lab-experiments.md`、`docs/labs-categories.md`、`docs/authoring-upload.md`、`docs/participation-flow.md`：能力映射、参考项目来源、工具链、SQLi/MCP/Pwn 分类靶题和实测证据边界。
- `docs/real-model-runbook.md`：真实模型实验的凭据、预算、判读和平台后续步骤。
- `docs/rules-request.md`：可直接发给组委会的赛道规则询问清单。
- `docs/git-baseline.md`：版本控制范围、凭据排除规则和复现命令。

## 已验证的本地命令

Windows（当前开发机）：

```powershell
python -X utf8 -m unittest discover -s tests -v          # 146 项，OK (skipped=4)
python -X utf8 scripts/run_local.py                      # 入口/dry-run 契约
python -X utf8 scripts/run_lab.py --model fake --set dev # 靶题 + 假模型 3/3
python -X utf8 scripts/run_lab.py --model real --set validation  # 无 LLM_* 时 blocked，不伪造
python -X utf8 scripts/run_lab.py --model real --set validation --llm-env-file artifacts/llm.env  # 可选的本地凭据文件
python -X utf8 author/controller.py --seed 46 --dry-run  # 出题 dry-run，零网络
python -X utf8 scripts/platform_flow.py register-harness --id qutagent `
  --image registry.example/qutagent:dev --display-name QUTAgent --version dev
```

WSL/Linux（Docker 与 `ctfy`/`ctfy-admin` 可用时）：

```bash
cd /mnt/c/Users/lenovo/Desktop/QUTAgent
python3 -m unittest discover -s tests -v
docker build --pull=false --platform linux/amd64 -t qutagent:dev .
ctfy agent check qutagent:dev --json
docker run --rm --entrypoint python qutagent:dev /app/scripts/check_toolchain.py
docker run --rm --network none --entrypoint python qutagent:dev /app/scripts/check_toolchain.py --quiet
docker run --rm --mount type=bind,src="$PWD/scripts/check_web_tools.py",dst=/tmp/check_web_tools.py,readonly --entrypoint python qutagent:dev /tmp/check_web_tools.py
ctfy-admin challenge audit --all --challenges-dir author/generated --strict --json
ctfy-admin challenge smoke --all --challenges-dir author/generated --ephemeral-ports --jobs 2 --timeout 180
```

生成另一个候选题包：

```bash
python3 author/generate.py author/generated/document-desk-46 --seed 46
```

自动准备并验证一个新候选题包（建议在 WSL 中运行）：

```bash
python3 author/prepare.py --smoke-runs 2
```

如需重跑仓库的全部本地验收，可在 `ctfy`、`ctfy-admin`、Docker 与 Compose 均可用时运行 `bash scripts/verify_local.sh`。

生成器拒绝覆盖非空目录。`--seed` 只调整表面路径与文件名；每队答案由 CTFy 提供的 `ANSWER_FLAG` 注入，不由 seed 决定。生成题包后应按当前 CLI 帮助核对命令与版本，并完成静态审计和动态 smoke。当前公开的 CTFy 0.7.0 包尚未提供标准页面提到的 `ctfy authoring check/smoke --local`，上面的 `ctfy-admin challenge audit/smoke` 是该版本的可执行本地替代。未经明确授权，不向真实比赛上传。

## 下一阶段

1. **真实模型实验**：`scripts/run_lab.py --model real --set validation` 需要 `LLM_FLAVOR`、`LLM_MODEL`、`LLM_API_KEY`（可选 `LLM_BASE_URL`），也可用 `--llm-env-file artifacts/llm.env` 从 gitignored 本地文件加载；当前无凭据，故只有 `blocked` 记录，没有真实成功率。
2. **平台流程**：`scripts/platform_flow.py` 与 `author/controller.py` 默认 dry-run；真实镜像注册/probe/entry/题包上传需要账号 token、运营方审核与赛道规则授权，当前均未发生。
3. **赛道规则**：附件仍未取得；按 [规则询问清单](docs/rules-request.md) 向组委会确认模型额度、运行限制、镜像截止、出题计分/窗口与 entry/奖项归属。
4. **镜像固定**：当前基础镜像为浮动 `python:3.11-slim`，赛前建议按 digest 固定；真实模型/平台验证后再做最终重建。

不要把本地 smoke、mock 平台判定或 dry-run 计划视为平台审核/比赛接受。

## 运行契约

容器入口是绝对路径 `/app/agent/main.py`，工作目录 `/ctfy/work`。`CTFY_EVAL_DRY_RUN=1` 时，即使没有 token/key 也应写入 `result.json`。一般任务需要 `CTFY_PLATFORM_URL`、`CTFY_TOKEN`、`LLM_FLAVOR`、`LLM_MODEL`、`LLM_API_KEY`，可有 `LLM_BASE_URL`。镜像不包含私人 key；不在运行期下载依赖。

| 配置 | 来源与作用 |
|---|---|
| `CTFY_WORK_DIR` | 平台给出的可写目录，默认 `/ctfy/work`；入口从这里读取 `task.json`、`README.md` 并写回 `result.json`。本地脚本自动设置临时目录。 |
| `CTFY_EVAL_DRY_RUN` | 平台镜像检查设为 `1`；此模式无平台令牌和模型密钥。 |
| `CTFY_PLATFORM_URL`、`CTFY_TOKEN` | 普通评测由平台注入，用于平台 REST 请求；本地 dry run 不需要。 |
| `LLM_FLAVOR`、`LLM_MODEL`、`LLM_API_KEY`、`LLM_BASE_URL` | 普通评测由平台注入的模型协议、模型、凭据、可选网关地址；密钥为空时直接报错，不读取私人备份密钥。 |
| `CTFY_EVAL_MAX_TURNS` | 平台可给软预算；当前代码在未给出时采用自身的 64 轮上限。 |
| `QUT_RUN_TIMEOUT_S` | 本地实验额外的运行时间上限（秒）；与任务时间限制取较小值，最多 10800 秒。仅用于受控联调，不代表比赛额度。 |
| `QUT_MODEL_MAX_REQUESTS` | 本地额外的模型请求上限，默认 64、最多 500；每次重试也计入。 |
| `QUT_WEB_ONLY` | 仅用于 `labs/` 实验：设为 `1` 时禁用 shell，只保留受 origin 白名单约束的 HTTP 工具、平台提交/刷新/下载；不是比赛配置。 |

本项目不自动读取 `.env` 文件，也不在仓库中存放真实凭据。普通评测的地址、密钥及题目由平台注入；请勿把本地合成 dry run 当作真实平台任务。

当前求解器只执行 `instance`、`qa` 两种模式；模型以 JSON 动作驱动 shell、有状态 HTTP（Cookie/同源重定向）、MCP、提交、刷新和附件下载，并按 category 注入 Web/Pwn/AI/Misc/QA playbook。其他模式会记录不支持。`fully_solved` 只在平台明确确认整题完成，或已知问题全部正确且平台任务明确给出 `gated_questions=0` 时为真；模型提前结束、轮数耗尽、无待答问题均不算完成。`solved` 保留平台确认正确的问题，但最终计分仍以平台成绩记录为准。

Linux shell 使用环境变量允许列表，只保留运行需要的 PATH、语言和临时目录等变量，不继承平台或模型密钥；超时和命令结束时清理该命令进程组，限制实际采集的 stdout/stderr 字节数。结果和事件记录会按已知密钥值脱敏。**环境过滤不是进程隔离**：同容器内的 `/proc`、共享文件和网络权限仍由运行环境决定，不能把此措施解释为密钥或目标范围的完整防护。HTTP 请求的总预算可令调用方及时返回；极慢的后台请求线程可能晚些才退出，故超时后的 POST 按“结果不确定”处理，不自动重试。正式使用前仍需授权靶题与比赛平台联调。

镜像在构建期安装 Web/Pwn/AI 安全工具链（pwntools、gdb、r2、one_gadget、seccomp-tools、sqlmap、ffuf、nuclei、Chromium、mcp 等），版本清单保存在 `/app/tool-versions.txt`；评测期不下载软件。当前已有**镜像内** 146 项测试与 SQLi/XSS/Pwn/AI-MCP（含 read_file 工具穿越）假模型分类靶题闭环（`labs/` 仍是进程级隔离，不是容器级），但真实模型解题实验因缺凭据仍为 `blocked`，平台注册/审核/接受答案仍未发生；这些能力与正式赛道细则仍是后续工作。

## 评测约束

未来比较模型循环或工具改动时，固定题集、模型、额度和时间预算；分开开发题与验证题，保存每题平台判定和失败类别。mock 测试、构建成功、扫描器输出、参考解 smoke 与真实平台接受 flag 属于不同证据等级，不能混为一谈。此方法参考 scientific-critical-thinking、experimental-design 技能；技能出处：Kassis 等，《[Scientific Agent Skills: A Library of Procedural Knowledge for Research Agents](https://doi.org/10.48550/arXiv.2609.00065)》，2026。

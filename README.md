# QUTAgent：TPCTF 2026 / CTFy 原型

这是 CTFY-0001 求解镜像与独立 CTFY-0002 Web 出题包生成器的早期实现。**官方镜像本地检查已通过，4 个不同 seed 的题包通过本地严格审计和动态 smoke；尚无真实比赛解题成绩或题包审核结果。**求解器当前已为 `instance`、`qa` 加入保守的完成判定、统一时间预算和 Linux 命令进程组清理。规则与未确认事项见 [规则审计](docs/rules-audit.md)，实测命令与证据等级见 [验证记录](docs/verification.md)。

## 最快本地启动

在项目根目录运行（Windows PowerShell：`python`；WSL/Linux：`python3`）：

```powershell
python scripts/run_local.py
```

脚本用 [合成 dry-run 输入](examples/dry-run/task.json)在临时目录启动真实的 `agent/main.py`，打印并校验 `result.json`，不需要 Docker、平台令牌或模型密钥。它只验证入口和文件契约，不能证明真实解题能力。比赛镜像的入口及工作目录见 `Dockerfile`；队友改动位置见 [扩展说明](docs/extension-points.md)。

## 目录

- `agent/`：读取任务与环境、调用模型网关和平台 API、执行有限时长的命令、写 `result.json`。
- `author/generate.py`：以 seed 生成原创 Web 题候选包，答案由 CTFy 每队生成。
- `author/generated/document-desk-42/` 至 `45/`：四个不同 seed 的示例候选包，未经比赛平台审核。
- `author/prepare.py`：离线自动生成、严格审计、多次 smoke，并写不含 flag 的验证报告；不调用上传接口。
- `tests/`：不接触真实平台的契约与故障场景测试。
- `examples/dry-run/`、`scripts/run_local.py`：无需凭据的本地入口检查。
- `scripts/check_web_tools.py`：在镜像内验证 HTTP 会话、HTML/JSON/编码处理、写入分析文件及基础命令。
- `_research/ctfy/`：公开资料的本地快照，不是运行代码，也不是权威的实时规则。

## 已验证的本地命令

在 WSL Ubuntu 中执行：

```bash
cd /mnt/c/Users/lenovo/Desktop/QUTAgent
python3 -m unittest discover -s tests -v
docker build --pull=false --platform linux/amd64 -t qutagent:dev .
ctfy agent check qutagent:dev --json
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

镜像注册、真实练习题、比赛 entry 和题包上传仍需赛道规则、平台可用时段及相应授权。当前出题器是赛前离线模板生成器；若赛事要求赛时由程序自主选择、验证并上传题目，还需按正式规则补出题控制器。不要把本地 smoke 视为平台审核。

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

本项目不自动读取 `.env` 文件，也不在仓库中存放真实凭据。普通评测的地址、密钥及题目由平台注入；请勿把本地合成 dry run 当作真实平台任务。

当前求解器只执行 `instance`、`qa` 两种模式；模型以 JSON 动作驱动 shell、提交、刷新和附件下载。其他模式会记录不支持。`fully_solved` 只在平台明确确认整题完成，或已知问题全部正确且平台任务明确给出 `gated_questions=0` 时为真；模型提前结束、轮数耗尽、无待答问题均不算完成。`solved` 保留平台确认正确的问题，但最终计分仍以平台成绩记录为准。

Linux shell 使用环境变量允许列表，只保留运行需要的 PATH、语言和临时目录等变量，不继承平台或模型密钥；超时和命令结束时清理该命令进程组，限制实际采集的 stdout/stderr 字节数。结果和事件记录会按已知密钥值脱敏。**环境过滤不是进程隔离**：同容器内的 `/proc`、共享文件和网络权限仍由运行环境决定，不能把此措施解释为密钥或目标范围的完整防护。HTTP 请求的总预算可令调用方及时返回；极慢的后台请求线程可能晚些才退出，故超时后的 POST 按“结果不确定”处理，不自动重试。正式使用前仍需授权靶题与比赛平台联调。

镜像在构建期安装 `curl`、`jq`、`file`、CA 证书；HTTP 会话、HTML/JSON、编码解码使用 Python 3.11 标准库，版本清单保存在镜像内 `/app/tool-versions.txt`。不在评测运行时下载软件。当前没有集成 Pwn/逆向工具链，也没有隔离 Docker 靶题或真实模型解题实验入口；这些能力与正式赛道细则仍是后续工作。

## 评测约束

未来比较模型循环或工具改动时，固定题集、模型、额度和时间预算；分开开发题与验证题，保存每题平台判定和失败类别。mock 测试、构建成功、扫描器输出、参考解 smoke 与真实平台接受 flag 属于不同证据等级，不能混为一谈。此方法参考 scientific-critical-thinking、experimental-design 技能；技能出处：Kassis 等，《[Scientific Agent Skills: A Library of Procedural Knowledge for Research Agents](https://doi.org/10.48550/arXiv.2609.00065)》，2026。

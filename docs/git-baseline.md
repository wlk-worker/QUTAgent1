# 协作基线（Git / 环境 / 证据）

更新：2026-10-25。基线提交：`bbde74a chore: establish local prototype baseline`；历史功能提交：`255c262 feat: add isolated web lab, http tool, and authoring/participation flows`；本轮融合提交：`d682dfb feat: integrate CTF agent skills, MCP and Web/Pwn/AI toolchain`；分类靶题提交：`3d058df`、`23fa5e0`、`8ccba36`；后续证据文档提交：`22dbfab`、`cefe5d0`、`b934810`。

## 1. 当前纳入版本控制的内容

已提交：

- `agent/`：CTFY-0001 入口、契约、模型/平台客户端、循环、预算、安全、shell/HTTP/MCP 工具、skills playbook。
- `labs/`：进程级授权 Web 靶题、mock CTFy、假模型与固定预算 runner。
- `author/__init__.py`、`author/generate.py`、`author/prepare.py`：离线 Web 候选题生成与本地验证。
- `author/controller.py`：赛时出题流程（默认 dry-run，可选出题包上传 + 只读轮询）。
- `toolbox/`：镜像内 `ctf-checksec`/`ctf-disasm`/`ctf-debug`/`ctf-strings`/`ctf-browse` 与 nuclei 起步模板。
- `tests/`：契约、集成、可靠性、靶题、HTTP 会话、MCP、skills、出题/参赛流程测试（当前 144 项；Windows 4 项 skip，镜像内 3 项 skip）。
- `scripts/`：本地 dry run、镜像内 Web/工具链检查、一键验收、`run_lab.py`、`platform_flow.py`。
- `examples/dry-run/`：无凭据的合成任务。
- `docs/`：验证记录、规则审计/询问、登录后查阅、扩展入口、solver skills、参考项目、工具链、靶题实验、出题上传、参赛流程、协作基线。
- `Dockerfile`、`.dockerignore`、`.gitattributes`、`requirements.lock`。

不纳入版本控制（见 `.gitignore`）：

- `_research/`、`research/`：公开资料快照与本地研究，非运行代码。
- `author/generated/`：题包生成物与 smoke 报告，可由 seed 重新生成。
- `artifacts/`：实验证据（靶题日志、result、experiment.json），按次生成。
- `__pycache__/`、`*.pyc`、虚拟环境、构建产物。
- `.env`、`secrets/`、`*.pem`、`*.key`、`*.token`：凭据/密钥永不入库。
- 日志、`*.tar.gz`、本地数据库。

## 2. 复现命令

Windows（Python 3.14）：

```powershell
python -X utf8 -m unittest discover -s tests -v
python -X utf8 scripts/run_local.py
python -X utf8 scripts/run_lab.py --model fake --set dev
python -X utf8 author/controller.py --seed 46 --dry-run
python -X utf8 scripts/platform_flow.py status --competition-id <id>
```

Linux/WSL（有 Docker 时）：

```bash
python3 -m unittest discover -s tests -v
docker build --pull=false --platform linux/amd64 -t qutagent:dev .
docker run --rm --entrypoint python qutagent:dev /app/scripts/check_toolchain.py
docker run --rm --network none --entrypoint python qutagent:dev /app/scripts/check_toolchain.py --quiet
docker run --rm --user root -v "$PWD:/repo" -w /repo --entrypoint python qutagent:dev -X utf8 -m unittest discover -s tests -v
ctfy agent check qutagent:dev --json
bash scripts/verify_local.sh
```

当前开发机：Windows + WSL Ubuntu-24.04（Docker 29.1.3）；镜像已实际构建并通过 required 工具检查。`labs/` 靶题仍是进程级隔离，镜像级假模型实验已跑通；**真实模型/真实平台证据仍需凭据**。

## 3. 提交前检查（队友与 Lead 都适用）

1. `git status --short`：确认没有 `author/generated/`、`artifacts/`、`_research/`、`__pycache__`、密钥文件被加入。
2. `git diff --cached --stat`：逐文件确认改动属于本次任务；不要混入无关格式化。
3. 跑测试：Windows 至少 `python -X utf8 -m unittest discover -s tests -v`；涉及 Linux shell/镜像的改动需在 Linux 复跑。
4. 检查凭据：`git diff --cached` 中不得出现 `sk-`、`ghp_`、`Bearer` 真值、私钥、平台 token；示例 token 只能是 `fixture-*`/`fake-*`。
5. 检查生成物：题包、tar.gz、实验报告应写到 `artifacts/` 或 `author/generated/`，不入库。
6. 提交信息说明“改了什么/证据等级”，不要把 mock、smoke、真实平台接受混为一谈。

## 4. 证据等级（写文档时必须标注）

| 等级 | 例子 | 能证明 |
|---|---|---|
| E0 静态/模拟 | 单测、mock HTTP、dry run | 代码路径和契约，不证明真实解题 |
| E1 本地合成靶题 | `labs/` 假模型或真实模型 + 动态 flag | 求解器能在受控目标上完成闭环；仍非比赛平台 |
| E2 真实授权练习题 | 真实模型在隔离靶题上固定预算运行 | 真实模型解题成功率/用量；非比赛平台 |
| E3 平台镜像审核 | `ctfy agent check` 通过、平台 operator 审核 | 镜像可被平台调度；不证明题解能力 |
| E4 平台接受答案 | 比赛/练习平台实际判分记录 | 真实成绩 |

当前最高等级：E0（单测/dry run/本地镜像检查）+ E1 的假模型靶题闭环（3/3，mock 平台判定）；真实模型 E2 与平台 E3/E4 未完成（无凭据/未注册/未审核），见 [验证记录](verification.md) 与 [靶题实验记录](lab-experiments.md)。

## 5. 环境待办

- [ ] 在可用 WSL/Docker 环境重跑镜像构建、`ctfy agent check`、`scripts/verify_local.sh`。
- [ ] 若 WSL 仍不可用，改用一台 Linux amd64 构建机/CI，避免在 Windows 上宣称 Docker 证据。
- [ ] 赛前复核 CI 中的 Python/CLI 版本与 `requirements.lock`。

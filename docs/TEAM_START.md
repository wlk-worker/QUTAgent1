# QUTAgent 队友交付说明

这是供队友开发、复现和联调的测试版。解题器覆盖 Web / Pwn / AI 安全的模型与工具调用；正式比赛运行仍须平台镜像审核、可用模型/额度和相应赛事 entry。此前的本地成功记录不是比赛成绩。10 月 28 日仓库记录显示镜像已注册、等待人工审核，本交付包没有替队友注册或启动任何评测。

## 先准备两样东西

1. Python 3.11 或更新版本（用于运行统一入口）。
2. Docker Linux 容器环境：Windows 可以使用已启动的 Docker Desktop（Linux containers）或在可用的 WSL/Linux 中运行。Docker daemon 必须可访问。镜像为 linux/amd64；ARM 主机需要 Docker 的 amd64 模拟支持，速度可能较慢，本包尚未在 ARM 主机验证。

这些系统软件需要在接收方自己的电脑准备。启动脚本会检查它们；不会安装系统组件、修改系统权限、读取本机已有私人密钥。

请把压缩包**完整解压**到一个普通可写目录，再运行命令。所有命令均在解压后的项目根目录执行；无需和作者使用相同盘符、路径或用户名。

## 第一次启动：不需要密钥

Windows：双击 `start.cmd`，或在 PowerShell 运行：

```powershell
.\start.cmd
```

WSL/Linux：

```bash
bash start.sh
```

跨平台等价命令：

```text
python scripts/team.py smoke
```

完整包的 `runtime/qutagent-linux-amd64.tar.gz` 是已构建镜像。启动脚本会在镜像尚未安装时自动 `docker load`，核对 image ID，然后在禁用外网的容器中完成：

1. 工具链检查；
2. 镜像真实入口 dry run，并验证完整 `result.json`；
3. 假模型驱动本地 Web 靶题 dev 集（3 个用例，每例 60 秒 / 8 轮 / 8 次模型请求）。

全部成功会出现 `team_smoke_passed`。这一步不会请求付费模型或连接真实比赛平台。实验产物在 `artifacts/`，不应转发为源码的一部分。

轻量源码包没有镜像。可以把完整包中的 `runtime/` 目录复制进来，或显式重建：

```text
python scripts/team.py build
python scripts/team.py smoke --image qutagent:local
```

重建会联网安装工具，耗时和流量较大；多项上游依赖尚未完整固定版本，因此重建结果可能与随包镜像不同。`requirements.lock` 不是完整工具链安装清单，不能靠 `pip install -r requirements.lock` 代替构建镜像。

如果暂时没有 Docker，可先运行 `python scripts/team.py local`，仅检查 Python 入口和文件契约；它不代表 Pwn、浏览器或完整工具链可用。

## 更多验证命令

```text
python scripts/team.py doctor
python scripts/team.py load
python scripts/team.py tests
python scripts/team.py lab --model fake --set web-sqli
python scripts/team.py lab --model fake --set pwn
python scripts/team.py lab --model fake --set xss
python scripts/team.py lab --model fake --set ai-mcp-traversal
```

`tests` 在容器内运行现有完整套件，会按环境跳过少数测试；以最终 `Ran ... / OK / skipped` 为准。工具链允许已记录的 optional 缺失，例如 angr；required 项失败才算工具链失败。

`load` 可强制重新加载随包镜像：导入前校验压缩文件 SHA-256，导入后核对 image ID，适用于镜像标签被本地重建覆盖后的恢复。

Docker 镜像中的 `/app/agent` 是已发布版本。`lab` 和 `tests` 会把这份源码挂载到 `/repo`，测试当前解压目录里的代码；`doctor` 与入口 dry run 检查镜像自身。队友改完源码后，应重建 `qutagent:local` 并重新验证，再生成新的交付包，不能拿旧镜像 ID 声称已包含新改动。

## 使用队友自己的真实模型

创建 `artifacts/`，把 `examples/llm.env.example` 复制为 `artifacts/llm.env`，填入模型协议、模型 ID、网关 URL 和自己的 API key。例子中的地址是 DeepSeek OpenAI 兼容接口；可以根据模型服务商换成兼容配置。不要把模型 key 写入源码、镜像或聊天。

```text
python scripts/team.py lab --model real --set validation --timeout-s 180 --max-turns 10 --max-requests 10
```

该命令会调用队友配置的真实模型，可能产生费用。`validation` 有 3 个用例，上限是**每例** 180 秒 / 10 轮 / 10 次模型请求，整组最多 30 次模型请求，重试也计入。其他 set：`dev`、`web-sqli`、`pwn`、`xss`、`ssrf`、`ai-mcp`、`ai-mcp-traversal`。Pwn/XSS 较复杂时可显式提高至 `--timeout-s 300 --max-turns 16 --max-requests 16`。

实验 runner 只从明确提供的 `artifacts/llm.env` 加载模型配置；缺配置或仍为占位符会停止，不读取其他私有备份密钥。真实模型实验仍连接本地合成靶题和模拟判题平台，不能称为真实 CTFy 接受。

本地实验只是同容器中的进程/端口/临时目录隔离，不是互不信任进程之间的安全沙箱。Docker 实验会挂载整个解压目录，目录里只应放项目文件及本次需要的配置，不要混入私人材料。

## 正式平台接入

普通赛时求解不是只填模型 key：平台还要提供 `task.json`、`README.md`、`CTFY_PLATFORM_URL`、`CTFY_TOKEN` 等任务信息，并在允许的 entry 中调度获批镜像。现有 `scripts/platform_flow.py` 与 `author/controller.py` 默认 dry run，不会在首次启动时注册、上传或报名。

平台令牌与模型密钥不同。`examples/platform.env.example` 仅供可选平台操作参考；只有获得相应账号授权后，才按 `docs/participation-flow.md`、`docs/platform-upload.md`、`docs/authoring-upload.md` 执行。不要直接运行历史文档中的占位命令。

## 队友扩展位置

| 目录/文件 | 用途 |
|---|---|
| `agent/loop.py` | 模型决策与工具动作循环、格式纠错、重复动作检测 |
| `agent/skills.py` | Web/Pwn/AI 等题型分类与解题指引 |
| `agent/tools.py`、`agent/mcp.py` | HTTP 会话、命令执行、MCP 客户端 |
| `agent/platform.py`、`agent/contract.py` | 平台 API 与输入输出契约 |
| `labs/`、`tests/` | 本地靶题、模拟平台、回归与集成验证 |
| `author/` | 独立的出题包生成/检查/上传流程；未接入一个统筹赛时出题解题的总控制器 |

历史 `docs/` 和 README 的部分段落保留了旧状态；本包首次使用以本说明及 `HANDOFF_VERIFICATION.md` 为准。`HANDOFF_MANIFEST.json` 记录基线 Git commit、逐文件 SHA-256 和镜像 ID；本包新增交付入口可能还未提交到 Git，以该清单中的文件哈希为准。

## 转发与故障定位

本包不带 `.git/` 历史、本地凭据、原实验产物、生成题包或用户 registry 登录配置。接收方新增自己的 `artifacts/*.env` 后，不要再直接压缩整个目录转发。重新发布请使用 `scripts/package_handoff.py`，或仅导出已审查的源码。

若失败，请给队友提供命令、退出码和停止原因，避免附带 env 文件或完整密钥。常见情况：Docker 未启动；运行在 Windows containers；镜像尚未加载；实际 image ID 与清单不同；模型 ID/协议不匹配；真实模型额度不足。`HANDOFF_VERIFICATION.md` 只代表作者在交付目录的复跑结果，不替代接收方首次启动验收。

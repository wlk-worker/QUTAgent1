# 隔离 Web 靶题实验记录

记录日期：2026-10-23（北京时间），2026-10-25 补充真实模型结果。本轮补的是 **G3/G5 的本地联调证据**：一个真实的授权 HTTP 靶题、真实 `agent/main.py` 调用链、mock CTFy 平台的真实 flag 判定、固定开发/验证集和真实模型入口。**没有真实比赛平台成绩**；2026-10-25 用 DeepSeek `deepseek-flash` 在本地 validation/SQLi/XSS/Pwn/SSRF/AI-MCP/MCP 穿越 7 个 set 上均 3/3（见 §2），但仍不是真实 CTFy 平台接受。

## 证据等级

| 证据 | 能证明 | 不能证明 |
|---|---|---|
| 假模型 + mock 平台 + 本地靶题闭环（3/3） | HTTP 工具、`loop.py` 动作分发、`model.py` 的 OpenAI 兼容客户端、`platform.py` 的实例/提交路径整体可运行；mock 平台按动态 flag 真实判定 | 模型解题能力、真实 CTFy 平台会接受答案、真实比赛成绩 |
| 本地靶题被路径穿越攻破 | 靶题实现与“编码后可绕过朴素前缀检查”的利用链符合设计 | 真实题目可解，或真实环境的隔离强度 |
| `--model real` 返回 `blocked`（退出码 2） | 无凭据时不伪造结果、不读取私有 key、不发起模型请求 | 真实模型的任何成功率/用量 |
| 155 项单元/集成测试通过 | Windows 与镜像内 Linux 的调用链与边界行为 | 官方镜像检查、平台审核或比赛接受 |

## 实验环境与隔离限制（重要）

- 首次实验在 Windows 主机、Python 3.14.6（`platform: win32`）上运行；当时 WSL 返回 `E_ACCESSDENIED`、无 Docker。2026-10-25 WSL Ubuntu-24.04 恢复可用后，同一命令也在 `qutagent:dev` 容器内（Python 3.11.17，`platform: linux`）跑通 3/3；`labs/` 本身的隔离仍是同主机进程级，不是容器/VM 级。
- 每个实验用例启动 **4 个独立子进程**：`labs/target.py`（靶题）、`labs/mock_platform.py`（平台）、`labs/fake_model.py`（假模型，仅 fake 实验）、`agent/main.py`（被真实入口调用的求解器）。靶题/平台/模型各自绑定 `127.0.0.1` 的临时端口；求解器工作目录是 `artifacts/lab/_work/` 下的临时目录，运行结束即删除。
- **这是进程 + 端口 + 临时目录级隔离，不是容器/VM 级隔离**。所有进程与 runner 同主机、同用户，没有 PID/文件系统/网络命名空间；对恶意求解器不构成安全边界。`agent/security.py` 的环境变量允许列表、`QUT_WEB_ONLY=1` 禁用 shell、HTTP 工具 origin 白名单都只是收敛工具面，不能替代容器隔离。
- 求解器只拿到 `task.json`、`README.md`、目标地址、平台端点和模型端点；靶题的真实 `flag` 文件位于求解器工作目录之外的靶题临时根目录，**不传给求解器**。mock 平台作为 grader 读取该文件做判定。
- 固定预算（`labs/runner.py::EXPERIMENTS`）：`timeout_s=60`、`max_turns=8`、`max_requests=8`，dev 与 validation 相同；每次运行写入 `experiment.json`。

## 实现组成

| 文件 | 作用 |
|---|---|
| `agent/tools.py::http_request` | 结构化 GET/POST；只允许显式 origin 集合；禁止跳转（3xx 返回 `redirect_blocked`，不跟随）；响应体上限/截断标记；超时/网络错误作为观察值返回；返回 status、headers、body preview、耗时 |
| `agent/tools.py::HttpSession` | 求解循环使用的有状态 HTTP：Cookie jar、同源安全重定向（≤5 跳）、header allowlist/CRLF 防护、平台/模型密钥头拒发、截断/超时 |
| `agent/skills.py` | web/pwn/ai/misc/qa 分类与分类 playbook、flag 纪律、格式纠错/循环警告文本 |
| `agent/mcp.py` | 纯标准库 MCP JSON-RPC HTTP/SSE 客户端；loop 的 `mcp` action 用于 AI 安全的 MCP 工具发现/调用 |
| `agent/loop.py` | `{"action":"http"}` 使用 `HttpSession`；`mcp` action；分类 prompt、格式纠错、循环检测、历史压缩；`QUT_WEB_ONLY=1` 时 shell 在真正执行前被拒绝 |
| `labs/target.py` | 纯标准库授权靶题：`/download?name=` 先校验**原始**查询串（拒绝字面 `..` 与前导 `/`），再 `unquote` 并拼接，`%2e%2e/private/flag.txt` 可穿越；有根目录包含检查防止读到宿主文件；每个进程生成独立随机 flag，请求日志不记录响应体 |
| `labs/mock_platform.py` | `GET /api/v1/challenges/{id}`、`POST /api/v1/instances`、`GET /instances/{id}/status`、`GET /instances/{id}`、`POST /submissions`；真实比较 flag；提交日志只保存答案 SHA-256 与判定 |
| `labs/fake_model.py` | OpenAI 兼容 `POST /v1/chat/completions`；脚本化但**依据观察自适应**：发现目标 → 列目录 → 正常下载 → 编码穿越 → 提取 flag → 提交；遇到 403/404 会尝试其他编码 |
| `labs/runner.py`、`scripts/run_lab.py` | 启动/回收子进程、固定预算、采集 `result.json`/`events.jsonl`/提交与目标/平台/模型日志、脱敏 flag、生成实验汇总 |
| `tests/test_web_tool.py`、`tests/test_lab.py`、`tests/test_skills.py`、`tests/test_mcp.py` | 新增 59 项测试：origin 允许/拒绝、截断、超时、禁止跳转、Cookie/重定向、格式纠错/循环检测/历史压缩、分类 playbook、MCP JSON/SSE、假模型闭环、turn 预算、真实模型 blocked、真实 flavor 透传、动态 flag 与穿越 |

靶题漏洞是**有意且受限**的：`/download` 的朴素检查在 `unquote` 之前执行，因此 `%2e%2e/private/flag.txt` 绕过前缀/穿越检查；但解码后仍强制 `resolved.is_relative_to(target_root)`，无法读取靶题临时根之外的文件。`/files/<name>` 不解码输入，是安全的对照路由。

## 固定数据集

| 集合 | seeds | 用途 |
|---|---|---|
| `dev` | 101, 102, 103 | 开发迭代（本轮实际跑通） |
| `validation` | 201, 202, 203 | 留出验证（本轮仅用于 real blocked 入口检查） |

每个用例的 flag 都是该靶题进程独立随机生成（`flag{32 hex}`）；seed 只决定 challenge id 与日志标签。`experiment.json` 记录每个用例的 flag **SHA-256**，不记录 flag 明文。

## 实际运行命令与结果

### 1. 假模型 dev 集（主证据）

命令（仓库根目录）：

```powershell
python -X utf8 scripts/run_lab.py --model fake --set dev
```

结果：退出码 `0`，`status=completed`，`fake-dev-20261023T063907Z-0d1a77`。Lead 复核时（06:41Z）以同一命令复跑，得到 `fake-dev-20261023T064110Z-2f1a50`，同样 3/3 成功、平台接受 3 个 flag、wall 6.708s；`artifacts/lab/experiment.json` 指向最新一次运行，旧运行目录仍保留在 `artifacts/lab/runs/`。

| case | 平台接受 flag | stop_reason | turns | http 调用 | 耗时 | tokens (in/out) |
|---|---|---|---|---|---|---|
| `fake-dev-101` | 是 | `done` | 5 | 4 | 2.247 s | 6489 / 197 |
| `fake-dev-102` | 是 | `done` | 5 | 4 | 2.194 s | 6489 / 197 |
| `fake-dev-103` | 是 | `done` | 5 | 4 | 2.186 s | 6487 / 197 |

汇总（与 `artifacts/lab/experiment.json` 一致）：`success_rate = 1.0 (3/3)`、`platform_accepted_flags = 3`、`wall_seconds_total = 6.658`、`model_requests_total = 15`、token 合计 `input 19465 / output 591`。三个用例的 flag SHA-256 分别为 `3c77b7d3…`、`779d8876…`、`d550adc5…`（完整值在 experiment.json/case.json 中）。

固定链路（每个用例的 target 请求日志一致）：

```
GET /                                     200
GET /files/                               200
GET /download?name=files/quote.txt        200   # 正常文件读取
GET /download?name=%2e%2e/private/flag.txt 200  # 编码穿越拿到 flag
POST /api/v1/submissions                   200   # 平台判定 correct=true
```

证据路径：

- `artifacts/lab/experiment.json`（最新一次运行的主汇总）
- `artifacts/lab/runs/fake-dev-20261023T063907Z-0d1a77/experiment.json`
- `.../cases/dev-101/{task.json,result.json,events.jsonl,submissions.jsonl,target_requests.jsonl,platform_requests.jsonl,model_calls.jsonl,agent_stdout.txt,agent_stderr.txt,case.json}`（dev-102/103 同构）
- `result.json` 关键字段：`stop_reason: done`、`fully_solved: true`、`solved: ["flag"]`、`http_calls: 4`、`model_requests: 5`
- `submissions.jsonl` 每条只含 `answer_sha256`、`correct`、`challenge_fully_solved`，不含 flag 明文

### 2. 真实模型（DeepSeek `deepseek-flash`）—— 7 个 set 全部 3/3

用户提供 DeepSeek API 凭据后，使用本机 gitignored `artifacts/llm.env`（`--llm-env-file`，值不回显、不入库）：

```powershell
python -X utf8 scripts/check_llm_env.py --env-file artifacts/llm.env
python -X utf8 scripts/run_lab.py --model real --set validation --llm-env-file artifacts/llm.env
```

| set | experiment_id | 结果 | wall | tokens in/out | requests |
|---|---|---|---|---|---|
| validation（路径穿越） | `real-validation-20261025T122621Z-a71aa6` | 3/3 | 26.016s | 40930/2007 | 16 |
| web-sqli | `real-web-sqli-20261025T124259Z-ec18bc` | 3/3 | 50.847s | 119195/3757 | 32 |
| web-ssrf | `real-ssrf-20261025T123345Z-1c7ab0` | 3/3 | 22.437s | 33907/1233 | 13 |
| xss（镜像内） | `real-xss-20261025T124051Z-e6a994` | 3/3 | 77.005s | 102210/3481 | 28 |
| pwn（镜像内） | `real-pwn-20261025T124212Z-5f7c9f` | 3/3 | 43.737s | 66457/2900 | 24 |
| ai-mcp | `real-ai-mcp-20261025T123412Z-1f6e9a` | 3/3 | 21.421s | 28970/1212 | 13 |
| ai-mcp-traversal | `real-ai-mcp-traversal-20261025T123435Z-9bcfb0` | 3/3 | 27.496s | 26718/2447 | 12 |

真实模型调优保留失败记录：SQLi 1/3→2/3→3/3（格式错误/空响应/列名猜测），XSS 0/3→2/3→3/3（admin bot 外带 payload）；失败 run 在 `artifacts/lab-real/runs/`，未删除。**mock 平台不是真实 CTFy**，不能当作比赛成绩。此前“无凭据 → blocked”的历史记录仍保留在 `artifacts/lab/blocked-real-validation.json`，说明 fail-closed 行为没有被删除。

### 3. 测试

```powershell
python -X utf8 -m unittest discover -s tests -v
```

结果：Windows `Ran 155 tests`、`OK (skipped=4)`；4 项 skip 为 2 个既有 Linux-only shell/进程组测试 + Windows 下 Pwn Linux 用例 + Windows 无 Playwright 的 XSS 用例。镜像内（`--user root`，bind mount 对 UID 10001 不可写）同一套件 **155/155 通过（skipped=3）**，包含 SQLi/MCP/Pwn/XSS 分类靶题。新增测试不使用持久凭据，也不访问真实平台；临时文件由测试/实验目录管理。

## 证据文件说明

| 文件 | 内容 | flag 处理 |
|---|---|---|
| `task.json` | 交给求解器的合成任务（含目标 origin、scope、预算） | 无 flag |
| `result.json` | 真实入口写出的结果（脱敏后的副本） | 无 flag明文 |
| `events.jsonl` | 每轮 action/observation（脱敏副本） | `flag{...}` 已替换为 `flag{[REDACTED]}` |
| `submissions.jsonl` | mock 平台收到的提交 | 仅 `answer_sha256`、正确性和剩余次数 |
| `target_requests.jsonl` | 靶题 HTTP 请求（方法/路径/状态/字节数） | 不记录响应体 |
| `platform_requests.jsonl` | 平台 REST 请求轨迹 | 无 token/答案 |
| `model_calls.jsonl` | 假模型每次调用的 action、耗时、token 估计 | 不记录消息体 |
| `experiment.json` + `case.json` | 汇总、预算、环境、证据路径、flag SHA-256 | 不写 flag 明文 |

复核示例（应无输出）：

```powershell
Get-ChildItem artifacts\lab -Recurse -File | Select-String -Pattern 'flag\{[0-9a-fA-F]{16,}\}'
```

## 边界与后续

- 本轮证明的是**调用链和平台判定可运行**，不是模型的真实 Web 解题能力；假模型是脚本化的，不能用于比较模型强弱。
- 靶题只有单题、单 flag；求解器侧 HTTP 工具已有 Cookie jar/同源重定向，但靶题本身没有多题、附件或 Pwn/AI 目标。靶题隔离是同主机进程级，不是 Docker 容器级。
- 真实比赛成绩、镜像注册/审核、赛道附件规则仍需外部信息；在获得授权凭据前，真实模型条目保持 `blocked`。可用 `--llm-env-file <gitignored file>` 提供 `LLM_*`，值不会回显。
- 2026-10-25 已在 `qutagent:dev` 镜像内（Python 3.11.17，linux）重跑同一命令，**3/3 成功**，见 `artifacts/lab/experiment.json` 的 `fake-dev-20261025T101014Z-9cbe02`；该运行仍是进程级靶题，不是把三个服务拆进独立容器。
- 未来可把 `labs/` 三个服务放入独立容器/网络命名空间；当前镜像级验证已证明 agent/工具链可在 Linux 容器内运行。

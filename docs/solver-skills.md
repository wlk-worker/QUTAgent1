# 求解器分类能力与参考项目映射（solver skills）

本文说明 `agent/skills.py`、`agent/loop.py`、`agent/tools.py`、`agent/mcp.py` 增强的来源、映射关系、安全/证据边界与验证方式。

一句话总结：把这些开源 CTF 智能体的**流程与提示结构**（分类 playbook、格式纠错、循环检测、历史压缩、HTTP 会话、MCP 工具调用）融入现有单 Agent 求解器；**不搬运 payload 库**，具体 payload 仍由模型针对授权范围内的真实目标生成，并用平台判定和原始观测作为证据。

## 1. 参考项目 → 本项目映射

| 参考项目/文件 | 借鉴的能力 | 本项目落点 |
|---|---|---|
| SWE-agent v0.7 `config/ctf/*.yaml`（web/pwn/rev/...） | 按 category 切换 system/instance 模板；命令文档；`Last5Observations` 历史裁剪；`submit`/`exit_forfeit` 终止语义 | `agent/skills.py` 分类 + 分类 playbook；`agent/loop.py` `compress_history()`（保留 briefing + 最近观测，旧观测摘要）；既有 `submit`/`finish` 语义保持不变 |
| SWE-agent `config/commands/{decompile,disassemble,debug,connect}.py/.sh` | 二进制/交互式服务的批处理式使用方式（Ghidra 反编译、反汇编、gdb 批处理、pwntools 连接） | `agent/skills.py` PWN playbook：checksec→静态→动态（`gdb -batch -ex ...`）→偏移→泄漏→本地/远程；提示写脚本而非开交互式工具 |
| SWE-agent `sweagent/agent/history_processors.py`（`FormatError`、`LastNObservations`） | 解析失败显式反馈、保留最近 N 条观测 | `agent/loop.py` 格式错误反馈 + 最多 3 次重试；`compress_history()` |
| ctf-agent `backend/prompts.py`（`ChallengeMeta`/分类/flag 纪律） | 从 `category/name/tags/description` 组织提示；禁止占位 flag；先验证再提交 | `agent/skills.py:classify()` / `classify_task()`；`FLAG_DISCIPLINE` |
| ctf-agent `backend/loop_detect.py` | 动作签名去重，3 次警告、5 次强制打断 | `agent/loop.py:LoopDetector`（窗口 12，warn=3，break=5） |
| ctf-agent `backend/tools/core.py` | 大输出截断、二进制文件转 `file/xxd/strings` 提示、web 抓取边界 | `agent/tools.py` 既有截断 + `HttpSession` 截断；playbook 里的输出预算与大输出处理 |
| ctf-agent `backend/tools/flag.py` | 只提交真实 flag；先 submit 验证再报告 | `FLAG_DISCIPLINE` + 既有平台 submit 语义（不改完成判定） |
| Koshary `prompts/web.txt`、`prompts/pwn.txt` | 分类提示结构：目标/连接信息/文件/历史/下一步优先具体动作；只输出完整 flag | `agent/skills.py` 各分类 playbook 的"目标—基线—验证门"结构 |
| Koshary `prompts/fullpwn.md` | 服务发现→Web 枚举→凭据→立足点→提权→flag 的攻击链与攻击路径日志 | `agent/skills.py` MISC/PWN "先侦察后利用"顺序；"把发现写入工作目录文件" |
| AWE `src/{sqli,xss,ssrf,ssti,command_injection,idor}_agent` | 每个 Web 漏洞类先建基线，再用差分/确定证据确认，再升级利用；检测器负责验证而非盲打 payload | `agent/skills.py:WEB_PLAYBOOK` 的九类漏洞"探针→确认→利用→证据"清单 |
| PwnAI `pwnai/agents/{reversing,debugging,exploitation}_agent.py` + `tools/` | reversing→debugging→exploitation 的流水线与工具（r2/gdb/pwntools） | `agent/skills.py:PWN_PLAYBOOK` 的七步流水线；shell 工具负责实际执行 |

## 2. 分类规则（`agent/skills.py`）

`classify()` 输出五个分类之一：`web / pwn / ai / misc / qa`。

优先级：

1. `run_mode == "qa"` → `qa`（平台问答模式决定交互形态）；
2. 平台 `challenge.category` 命中别名表（如 `web exploitation`、`sqli`、`rev`、`crypto`、`llm`、`mcp`）→ 对应分类；
3. 否则按 `tags(权重4) > name(3) > category 原文(5) > description(1) > README(1)` 做带词边界的加权计分，取最高分；
4. 无信号 → `misc`（安全默认，不猜测）。

`classify_task(task, challenge)` 会把 `task.raw["challenge"]` 与平台 challenge 合并后分类；分类结果写入 `result["category"]`，并放入模型 briefing 的 `category` 字段。

## 3. 分类 playbook 与统一纪律

每个分类给出**流程导引**而非 payload：

- **Web**：先枚举 home/robots/JS/表单/参数/Cookie 基线，再逐类验证 SQLi、XSS、SSRF、上传、SSTI、路径穿越/LFI、IDOR、JWT/会话、命令注入；每类都要求"差分/确定性证据"后才升级利用。
- **Pwn**：triage（checksec/readelf/file）→ 静态 → 动态（批量 gdb）→ 偏移（cyclic）→ 泄漏 → ret2win/ret2libc/ROP → 本地验证 → 远程；禁止交互式工具、禁止盲爆破。
- **AI**：梳理 chat/tool/MCP 面；`mcp` 动作列工具与 schema；直接/间接提示注入、系统提示/密钥抽取、工具滥用、MCP 只读调用；模型声称不算证据，必须有真实工具/API 响应。
- **Misc**：附件/服务清点、crypto 识别、forensics 时间线、只读探测。
- **QA**：精确匹配题目要求的答案文本/列表；不能核实时 `refresh` 后说明限制，不猜。

统一的 `TOOL_GUIDE` 描述 7 种 action（`shell/http/mcp/refresh/download/submit/finish`）与输出预算；`FLAG_DISCIPLINE` 要求只提交真实完整 flag、禁止占位符/凭据、`evidence` 必填、禁止爆破提交。`policy_sections(category)` 会把这些附加到 `loop.SYSTEM` 之后。

## 4. 求解循环增强（`agent/loop.py`）

保留：`instance/qa` 两种 run mode、`state.assess` 完成判定、平台 submit/`mutation_outcome_unknown` 核对、`answers` 不重复提交、turn/deadline/model-request 预算。

新增：

- **分类 prompt**：`SYSTEM + 分类 playbook + 工具说明 + flag 纪律`。
- **格式纠错**：JSON 解析失败不再静默变成 `{"error":"ValueError"}`，而是追加一条 `Format error (n/3)` 反馈（含 7 种合法 action schema）并重试；连续 3 次失败 `stop_reason="format_error_limit"`，不会无限循环。
- **循环检测**：`LoopDetector` 对动作签名（忽略 `why`）计数；第 3 次重复警告（警告文本与观测一起送入模型），第 5 次强制换策略（该轮不执行工具），若继续重复则 `stop_reason="loop_detected"`。
- **历史压缩**：`compress_history()` 在消息数 > 24 时保留 briefing + 最近 12 条消息，旧动作/观测压缩成元数据摘要（URL/status/error，不复制 body）；事件日志记录 `history_compressed`。
- **HTTP 会话**：`http` action 改由 `HttpSession` 执行，同一 run 内 Cookie 持久化；跨域重定向仍拒绝。
- **MCP action**：`{"action":"mcp","url":...,"op":"list_tools|call","tool":...,"arguments":{}}`，origin 与 http 共用平台 scope，按 URL 复用会话。
- **结果字段**：新增 `category`、`format_errors`、`loop_warnings`、`mcp_calls`、`history_compressions`；原有字段不变。

新增 stop_reason：`format_error_limit`、`loop_detected`（`agent/main.py` 无需修改，结果原样写回）。

## 5. 结构化 HTTP 会话（`agent/tools.py:HttpSession`）

`http_request` 保留原行为（从不跟随重定向、origin 白名单、只允许 GET/POST、截断），用于兼容与既有测试。新增有状态 `HttpSession`：

- **Cookie jar**：同一 run 内 `Set-Cookie` 自动带回（urllib `HTTPCookieProcessor`），重定向响应上的 Cookie 也显式提取。
- **同源安全重定向**：最多 5 跳，且每一跳必须仍等于**原始请求 origin**；跨域跳转直接拒绝（返回 `redirect_blocked`）且不会发出请求。303 与 301/302 的 POST→GET 语义按浏览器约定处理。
- **请求头 allowlist**：只允许 `Accept/Accept-Language/Authorization/Cache-Control/Content-Type/Cookie/Origin/Referer/User-Agent/X-CSRF-Token/X-Requested-With/X-XSRF-Token`；拒绝 `Host/Content-Length/Transfer-Encoding/Connection/...`、非法头名、CR/LF 注入和超长值。
- **凭据边界**：任何请求头值若包含环境中的平台/模型密钥（名称含 KEY/TOKEN/SECRET/PASSWORD 且长度 ≥6）则拒绝发送（`secret_in_header`，错误里不回显值）；响应 body/headers/Location 会按同一规则脱敏。
- **截断与超时**：body 上限（默认 64KB，可调 256B–1MB）、每次请求受剩余 wall-clock 预算约束（`bounded_call`），超时/网络错误返回结构化 error。
- 新增字段：`redirects`（已跟随的跳转列表）、`cookie_count`。

## 6. MCP 客户端（`agent/mcp.py`）

纯标准库实现 MCP Streamable HTTP 客户端：

- `initialize`（协议版本 `2024-11-05`、clientInfo）→ `notifications/initialized` → `tools/list` / `tools/call`；
- 同时接受 `application/json` 与 `text/event-stream`（SSE `data:` 行解析，按 JSON-RPC id 选消息）；
- 支持 `Mcp-Session-Id` 会话头并在后续请求回传；
- URL 必须属于平台提供的 origin allowlist（否则构造即 `ValueError`，loop 转为 `mcp_url_rejected` 观测）；不跟随重定向；
- 响应上限（默认 64KB）与超时；工具描述/入参 schema/返回内容分块截断（`max_content_chars`，默认 12K）；
- JSON-RPC error（code/message）与 HTTP 错误都转成结构化观测，不让异常穿透 loop；
- 工具输出中的平台/模型密钥值会被脱敏。

loop 中的 `mcp` action 与 `http` 共用平台 scope；`list_tools`/`call` 之外的操作返回 `unknown_mcp_op`。

## 7. 验证与证据

本次改动的验证命令与结果（Windows，无真实平台/模型凭据）：

```bash
python -X utf8 -m unittest discover -s tests -v
python -X utf8 scripts/run_lab.py --model fake --set dev
```

- 全量单元测试：149 个测试（原 67 + 求解器/工具链 61 + 分类靶题 21），Windows OK（4 skip：2 个既有 Linux-only + Windows 下 Pwn/XSS 用例）；镜像内 149/149（3 skip）。
- `tests/test_skills.py`：分类、playbook 覆盖（Web 九类、Pwn 七步、AI/MCP、Misc/QA）、"playbook 不含硬编码 payload"、格式纠错/重试上限、循环警告与强制换策略、历史压缩保留 briefing/最近观测、提交语义不变。
- `tests/test_web_tool.py`：Cookie 持久化、同源 1/2 跳重定向、跨域重定向拒绝且未发出请求、header allowlist/注入拒绝、平台/模型密钥头拒绝、响应截断与脱敏、超时、scope 刷新；并断言 `http_request` 仍不跟随重定向。
- `tests/test_mcp.py`：本地 mock MCP 服务上的 initialize/session、JSON 与 SSE 两种传输、list/call、JSON-RPC error、origin 拒绝、重定向拒绝、响应过大、超时；loop 中 `mcp` 的 list→call→submit 闭环、越权 URL 拒绝、未知 op、无 scope 情况。
- 本地 fake 模型 Web 靶场：`--model fake --set dev` 仍为 3/3（`done`，平台接受 flag，无 shell 使用）；未使用真实模型或真实平台。

## 8. 证据边界（重要）

- **无真实凭据**：本次验证只用本地 mock 平台/模型/MCP 与假模型；`--model real` 在缺少 `LLM_*` 时仍返回 `blocked`（不伪造成功率）。
- **playbook 不是 payload 库**：分类文本只描述流程、验证门与证据要求；代码中没有 SQLi/XSS/SSRF/SSTI 等 payload 字符串（有测试断言）。实际 payload 由模型根据授权目标生成。
- **本地靶场不是安全隔离**：`labs/` 是进程/端口/目录级实验，不是容器或 VM 边界；`HttpSession`/MCP 是 scope 与输出卫生控制，不是 OS 隔离。
- **MCP 覆盖有限**：mock 服务覆盖 JSON 与 SSE 的基本流程；未对真实第三方 MCP 服务器做兼容性/认证矩阵测试（例如 OAuth、stdio 传输、旧版协议）。
- **分类启发式**：依赖平台字段质量；显式 `category` 最可靠，纯文本分类可能把边缘题分到 `misc`，此时仍可通过通用 misc playbook 工作。
- **本任务未修改的边界**：`agent/main.py`、`agent/platform.py`、`agent/state.py`、`author/`、`labs/`、README 未改动，完成判定与提交语义保持原状；`Dockerfile`/`toolbox` 由并行的 toolchain-engineer 升级，不属于本文件描述的能力改动。
- **未提交 git**：改动仅在工作区，合并/提交由 Lead 决定。

## 9. 剩余风险与后续

1. 真实 DeepSeek `deepseek-flash` 已测 7 个 set 全部 3/3；仍需在真实平台模型/额度上复测，不能把本地 mock 结果当作平台成绩。
2. 历史压缩摘要可能与"最近 12 条消息"边界交互（例如连续格式错误占满窗口），建议真实长局样本观察，必要时调 `HISTORY_KEEP_RECENT`。
3. 同源重定向放宽可能影响依赖"绝对不跳转"的旧有假设；`http_request` 保持不跳转，只有 loop 的 `http` action 使用会话语义。
4. MCP 兼容性（认证、SSE 断线重连、通知流）尚未覆盖；AI 题若使用 stdio 传输需另加适配层。
5. 循环检测只看动作签名，不看结果是否变化；对合法的轮询型交互可能提前警告，阈值可通过 `LoopDetector` 参数调整。

# 分类靶题实验：SQLi / MCP(AI) / Pwn / XSS / MCP read_file

记录时间：2026-10-25（北京时间）。这一轮把单一路径穿越靶题扩展为多类本地授权靶题，SQLi、MCP(AI)、Pwn、XSS、MCP `read_file` 都做了假模型闭环：SQLi/MCP/MCP read_file 在 Windows 真跑 3/3；Pwn 在 `qutagent:dev` Linux 镜像内真跑 **3/3**（Windows 原生仍会正确 `blocked`）；XSS（反射 + Playwright admin bot + `/collect`）在 `qutagent:dev` 镜像内真跑 **3/3**（Windows 原生无 Playwright 时正确 `blocked`）；新增的 MCP `read_file` 靶题用真实的 tool 参数目录穿越（没有 `get_flag` 直读工具）取 flag。XSS 第一次镜像运行 0/3 暴露了 `/report` 二次 `unquote` 的 bug，修正后重跑 3/3；相关证据都保留。实验仍处于**进程级/合成靶题/无真实平台**的证据等级。

## 1. 固定数据集与预算

| `--set` | 题型 | seeds | timeout | max_turns | max_requests | web-only |
|---|---|---|---|---|---|---|
| `web-sqli` | Web SQL 注入 | 301, 302, 303 | 60 s | 10 | 10 | 是（shell 禁用） |
| `ai-mcp` | AI / MCP（直接 get_flag） | 401, 402, 403 | 60 s | 8 | 8 | 是（shell 禁用） |
| `ai-mcp-traversal` | AI / MCP `read_file` 目录穿越 | 701, 702, 703 | 60 s | 8 | 8 | 是（shell 禁用） |
| `pwn` | Linux amd64 ret2win | 501, 502, 503 | 90 s | 12 | 12 | 否（需要 shell 跑 exp） |
| `xss` | 反射 XSS + admin bot | 601, 602, 603 | 60 s | 10 | 10 | 是（shell 禁用；bot 在靶题侧） |
| `dev` / `validation` | 原路径穿越 | 101–103 / 201–203 | 60 s | 8 | 8 | 是 |

每个用例的 flag 由对应靶题进程独立随机生成（`flag{32 hex}`）；seed 决定 challenge id、SQLi 路由变体与日志标签，不决定 flag。实验证据写入 `artifacts/lab-categories/`（`.gitignore` 的 `artifacts/` 下），flag 明文不落盘，只记录 SHA-256。

## 2. 题型与靶题实现

### 2.1 SQLi Web（`labs/sqli_target.py`）

- 纯标准库 `http.server` + `sqlite3`，动态 flag 存在独立 `secrets` 表，另有 `users`/`notes` 表。
- 两条故意脆弱路径都用字符串拼接：登录查询 `SELECT id FROM users WHERE username = '%s' AND password = '%s'`；搜索查询 `SELECT title FROM notes WHERE title LIKE '%%%s%%'`。
- solver 链路：访问 `/` 从链接发现 seed 专属路由 → `' OR '1'='1' --` 登录（服务端下发 `lab_session` Cookie，agent 的 `HttpSession` 自动保持）→ 搜索页 `' UNION SELECT flag FROM secrets --` 取出 flag。布尔盲注也成立（`' OR (SELECT substr(flag,1,1) FROM secrets)='f' --`），测试中已验证 true/false 行数差异。
- 路由随 seed 变化（301→`/signin`+`/query`，302→`/auth/login`+`/find`，303→`/login`+`/search`）；`/` 页面含链接与“SQL 仍是字符串拼接”的开发提示，真实 solver 可靠发现。
- 平台 challenge：`category=web`，`tags=["sqli","web","lab"]`。

### 2.2 AI / MCP（`labs/mcp_target.py`）

- 纯标准库 HTTP JSON-RPC（MCP 2024-11-05）服务：`initialize`、`notifications/initialized`、`tools/list`、`tools/call`。
- 只读工具：`read_note(name=policy|about)` 返回策略/说明；`get_flag` 返回动态 flag（同时放在 `content[].text` 与 `structuredContent.flag`）。`tools/call` 用 `text/event-stream` 响应，真实走 agent 的 SSE 解析路径；会话头 `Mcp-Session-Id` 也真实返回。
- solver 使用 agent 的 `mcp` action：`list_tools` → `read_note(policy)` → `get_flag` → `submit`，不经过 HTTP 直连、也不在 Python 侧注入 flag。
- 平台 challenge：`category=ai`，`tags=["mcp","agentic_ai","ai","lab"]`。

### 2.3 Pwn Linux amd64（`labs/pwn_target.py`）

- 提供 `vuln.c`：64 字节栈缓冲 + `fgets(buffer, 512, stdin)` 栈溢出，`win()` 读取 `flag.txt` 并打印；编译参数 `gcc -O0 -fno-stack-protector -fno-pie -no-pie`，返回地址偏移 72（buffer 64 + saved rbp 8）。
- 服务暴露：优先 `socat TCP-LISTEN:...,fork EXEC:./attachments/vuln`；无 socat 时用同等语义的纯标准库 TCP 桥（每连接一个子进程，stdin/stdout 转发）。
- 附件 `vuln`、`vuln.c` 经 mock 平台附件接口下发给 solver（`/api/v1/instances/{id}/attachments/{name}`），flag 文件在靶题根目录、不在 solver 工作目录。
- 假模型链路：`download vuln` → `download vuln.c` → `shell` 用 toolbox `ctf-checksec`/`ctf-disasm`/`ctf-debug` + `nm` 定位 `win` → 写 exploit 脚本（优先 `pwn.remote`/`pwn.ELF`，无 pwntools 时回退纯 socket/`nm`）并运行 → 从输出提取 flag → submit。runner 对该 set 传 `QUT_WEB_ONLY=0`，允许 shell。
- **执行前提**：POSIX + gcc + ELF 运行时（WSL 或 `qutagent:dev` 镜像）。Windows 原生宿主会得到 `blocked`，不会伪造成功。

### 2.4 XSS（`labs/xss_target.py` + `labs/fake_xss_model.py`）

- 纯标准库 Web 靶题：搜索参数 `q` 被**未转义**反射进 HTML（text/html），即反射型 XSS。**路由随 seed 变化**：601→search `/greet` + report `/review`；602→`/hello` + `/report`；603→`/` + `/report`；home 表单与链接给出真实路径，fake model 从页面自动发现。
- 靶题侧 admin bot：`<report_path>?url=<same-origin URL>` 只接受本 target origin、非 report/collect 的 URL；Playwright headless Chromium 以 `lab_admin_flag=<动态 flag>` 非 HttpOnly Cookie 访问该 URL（`--no-sandbox`，同源校验防止 SSRF；bot 内再用 `page.route` 拒绝一切外网请求，最多 5 次 visit）。
- 收集端点：XSS 在 bot 浏览器里把 `document.cookie` 发到 `/collect?c=`；`GET /collect`（别名 `/collected`）回读已收集数据。solver 读取后提交 flag。
- 假模型链路：`GET /` 发现搜索参数与 report 表单 → 构造 `<script>fetch('/collect?c='+encodeURIComponent(document.cookie))</script>` 反射 URL → 交给 report（同步等待 bot）→ 轮询 `/collect` → 提取 flag → submit；失败时切换 `<img onerror>` 等 payload 变体。
- **执行前提**：Python Playwright + Chromium（`qutagent:dev` 镜像已装）。没有浏览器时 target 仍可启动并允许检查反射/收集，但 `/report` 返回 `xss_requires_browser`，runner 对整个 set 返回 `blocked`（reason=`xss_requires_browser`），不伪造成功。
- 平台 challenge：`category=web`，`tags=["xss","web","admin-bot","lab"]`。

### 2.5 MCP `read_file` 目录穿越（`labs/mcp_traversal_target.py` + `labs/fake_mcp_traversal_model.py`）

- 新的 AI/MCP 靶题暴露 `read_file(path)`（文档称读取 notes 目录）与一个**明确 denied** 的 `get_flag`（防止直接取 flag）；flag 位于 `<root>/private/flag.txt`，notes 目录是 `<root>/notes`。
- 漏洞是真实工具参数处理错误：`read_file` 把 caller-controlled `path` 直接拼到 `<root>/notes/` 上，没有做 notes 根包含检查；`read_file({"path":"../private/flag.txt"})` 即真实 MCP `tools/call` 参数目录穿越，不是 HTTP 路径或直接 flag 工具。为防读到宿主文件，仍保留 deployment-root 包含检查与 absolute path 拒绝。
- tool 结果：`read_file` 用 SSE 返回 `content[].text` + `structuredContent`；`get_flag` 返回 `isError=true` 的 `direct flag access denied`。
- 假模型链路：`list_tools` → `read_file("policy.txt")`（正常读取）→ `read_file("../private/flag.txt")`（失败时尝试 `./../private/flag.txt` 等变体）→ 从 tool 响应取 flag → submit；全程使用 agent 的 `mcp` action，且不调用 `get_flag`。
- 平台 challenge：`category=ai`，`tags=["mcp","tool-traversal","agentic_ai","lab"]`；纯标准库，Windows 与镜像都可跑。

## 3. 实际运行命令与结果（2026-10-25）

### 3.1 SQLi（Windows，真实执行）✅

```powershell
python -X utf8 scripts/run_lab.py --model fake --set web-sqli --out artifacts\lab-categories
```

- 退出码 `0`；`experiment_id = fake-web-sqli-20261025T111527Z-4abad1`；`status=completed`，**3/3 成功**。
- 汇总：`wall_seconds_total=6.255`，`tokens={input:36893, output:589}`，`model_requests_total=15`，`platform_accepted_flags=3`。
- 每例：`turns=5`、`http_calls=4`、`stop_reason=done`；flag SHA-256 前缀分别 `3eb6bbc8…`/`0ea9a3d0…`/`140d1c70…`（均不同，动态 flag）。
- 目标日志（301）：`GET /` → `GET /signin` → `POST /signin`（SQLi 登录 200）→ `GET /query?q=%27%20UNION%20SELECT%20flag%20FROM%20secrets%20--%20`（200，返回 flag）→ `POST /submissions` correct。
- 证据：`artifacts/lab-categories/runs/fake-web-sqli-20261025T111527Z-4abad1/`（`experiment.json` 与 `cases/web-sqli-301..303/{task.json,result.json,events.jsonl,submissions.jsonl,target_requests.jsonl,platform_requests.jsonl,model_calls.jsonl,agent_stdout.txt,agent_stderr.txt,case.json}`）。

### 3.2 MCP / AI（Windows，真实执行）✅

```powershell
python -X utf8 scripts/run_lab.py --model fake --set ai-mcp --out artifacts\lab-categories
```

- 退出码 `0`；`experiment_id = fake-ai-mcp-20261025T111533Z-d458f8`；`status=completed`，**3/3 成功**。
- 汇总：`wall_seconds_total=6.154`，`tokens={input:23355, output:468}`，`model_requests_total=12`，`platform_accepted_flags=3`。
- 每例：`turns=4`、`mcp_calls=3`、`stop_reason=done`；flag SHA-256 前缀 `0f4526b5…`/`2c915659…`/`6c034942…`。
- 目标日志（401）：`initialize` → `notifications/initialized`(202) → `tools/list` → `tools/call`（read_note）→ `tools/call`（get_flag，SSE）→ `POST /submissions` correct。
- 证据：`artifacts/lab-categories/runs/fake-ai-mcp-20261025T111533Z-d458f8/`（同结构，含 `mcp_calls` 字段）。

### 3.3 Pwn（Windows 原生：正确 blocked；镜像内：3/3 成功）✅

Windows 原生没有 Linux ELF 运行时，runner 正确返回 `blocked`（不伪造）：

```powershell
python -X utf8 scripts/run_lab.py --model fake --set pwn --out artifacts\lab-categories
# exit 2, status=blocked, reason=pwn_requires_linux_elf_runtime, cases=[]
```

镜像内实际执行（Lead 复核；`qutagent:dev` 已包含 gcc/pwntools/gdb/socat）：

```powershell
docker run --rm --user root -v "${PWD}:/repo" -w /repo --entrypoint python qutagent:dev `
  -X utf8 scripts/run_lab.py --model fake --set pwn --out artifacts/lab-categories
```

- 退出码 `0`；`experiment_id = fake-pwn-20261025T111942Z-cb82ba`；`status=completed`，**3/3 成功**。
- 汇总：`wall_seconds_total=12.367`，`tokens={input:33959, output:1782}`，`model_requests_total=15`，`platform_accepted_flags=3`。
- 每例：`turns=5`、`tool_calls_made=4`、`stop_reason=done`；下载附件 `vuln`、`vuln.c`，写出 `exploit.py`；flag 由 ret2win 服务输出并经平台判定 correct。
- 证据：`artifacts/lab-categories/runs/fake-pwn-20261025T111942Z-cb82ba/`（cases/pwn-501..503，含 attachments、result/events/submissions/target/platform/model 日志）。
- Windows blocked 的旧证据仍保留：`artifacts/lab-categories/blocked-fake-pwn.json`、`pwn-environment-probes.txt`。

### 3.4 XSS（Windows 原生：正确 blocked；镜像内：3/3 成功）⛔/✅

Windows 本会话没有 Python Playwright/Chromium（且 DSH 沙箱不允许启动浏览器子进程），runner 正确返回 `blocked`，不伪造：

```powershell
python -X utf8 scripts/run_lab.py --model fake --set xss --out artifacts\lab-categories
# exit 2, status=blocked, reason=xss_requires_browser, cases=[]
```

- `experiment_id = fake-xss-20261025T114227Z-42bbc7`；`xss_preflight.probes = {os_name: nt, playwright_module: false, browsers_path: "", chromium: null, chromium_exists: false}`。
- 证据：`artifacts/lab-categories/blocked-fake-xss.json`、`artifacts/lab-categories/runs/fake-xss-20261025T114227Z-42bbc7/experiment.json`、`artifacts/lab-categories/xss-environment-probes.txt`（`python -c "import playwright"` 失败、`docker` 命令不存在、`wsl` 返回 `Wsl/E_ACCESSDENIED`）。

镜像内实际执行（由具备 Docker 的 Lead 运行；`qutagent:dev` 已含 Playwright/Chromium）：

```powershell
docker run --rm --user root -v "${PWD}:/repo" -w /repo --entrypoint python qutagent:dev `
  -X utf8 scripts/run_lab.py --model fake --set xss --out /repo/artifacts/lab-categories
```

- 退出码 `0`；`experiment_id = fake-xss-20261025T114243Z-4e26a9`；`status=completed`，**3/3 成功**（最终代码：seed 路由变体 + `/collect?c=` + 60 s 预算）。
- 汇总：`wall_seconds_total=29.545`，`tokens={input:29308, output:566}`，`model_requests_total=12`，`platform_accepted_flags=3`。
- 每例：`turns=4`、`http_calls=3`、`stop_reason=done`；三例 wall 分别 10.277/9.139/9.076 s，flag SHA-256 前缀 `014b59b0…`/`ea897bb9…`/`a0df91e5…`。
- 目标日志体现 seed 路由变体：601 为 `GET /`(home) → bot `GET /greet`(反射 payload) → bot `GET /collect`(cookie 外带) → `GET /review` → solver `GET /collect`(含 flag)；602 使用 `/hello` + `/report`；603 使用 `/` + `/report`；三例 `POST /submissions` 均 correct，证据中无 flag 明文。
- 证据：`artifacts/lab-categories/runs/fake-xss-20261025T114243Z-4e26a9/`（cases/xss-601..603，含 target/platform/model/result/events/submissions 日志）。
- 首轮镜像 0/3（`fake-xss-20261025T113554Z-88ad04`）暴露 `/report` 对已解码 URL 二次 `unquote`，`%2B`→`+` 后被 query parser 当空格，XSS 语法失效；修正为不再二次 `unquote` 后 3/3。后续补齐 seed 路由变体/`?c=`/错误码/60 s 预算后的最终 3/3 为上表 `4e26a9`；中间 `08e11f` 也保留。失败运行目录保留作为修复依据，未删除。

### 3.5 MCP `read_file` 目录穿越（Windows 真跑 3/3；镜像真跑 3/3）

Windows 实测（纯标准库 MCP 服务，无浏览器/无 Linux 依赖）：

```powershell
python -X utf8 scripts/run_lab.py --model fake --set ai-mcp-traversal --out artifacts\lab-categories
```

- 退出码 `0`；`experiment_id = fake-ai-mcp-traversal-20261025T115419Z-901ae1`；`status=completed`，**3/3 成功**。
- 汇总：`wall_seconds_total=6.467`，`tokens={input:25035, output:513}`，`model_requests_total=12`，`platform_accepted_flags=3`。
- 每例：`turns=4`、`mcp_calls=3`、`stop_reason=done`；三例 wall 2.151/2.126/2.163 s，flag SHA-256 前缀 `4b26c106…`/`d3c5113e…`/`4c67ca67…`。
- 真实 tool 调用链：`initialize` → `notifications/initialized` → `tools/list` → `tools/call read_file {"path":"policy.txt"}` → `tools/call read_file {"path":"../private/flag.txt"}` → 平台 correct；工具集含 `get_flag` 但**明确 denied**，fake model 全程不调用它；目标日志含 `tools/list` 与两次 `tools/call`，事件记录中无 flag 明文。
- 证据：`artifacts/lab-categories/runs/fake-ai-mcp-traversal-20261025T115419Z-901ae1/`（cases/ai-mcp-traversal-701..703，含 target/platform/model/result/events/submissions 日志）。

镜像内实测（Lead 复核，同一命令加 `docker run`）：

```powershell
docker run --rm --user root -v "${PWD}:/repo" -w /repo --entrypoint python qutagent:dev `
  -X utf8 scripts/run_lab.py --model fake --set ai-mcp-traversal --out /repo/artifacts/lab-categories
```

- 退出码 `0`；`experiment_id = fake-ai-mcp-traversal-20261025T115446Z-089539`；`status=completed`，**3/3 成功**。
- 汇总：`wall_seconds_total=8.693`，`tokens={input:25032, output:513}`，`model_requests_total=12`，`platform_accepted_flags=3`；每例 `turns=4`、`mcp_calls=3`、`stop_reason=done`（wall 4.065/2.180/2.226 s）。
- 证据：`artifacts/lab-categories/runs/fake-ai-mcp-traversal-20261025T115446Z-089539/`（cases/ai-mcp-traversal-701..703，target 日志含 `tools/list` + 两次 `tools/call`，平台 correct）。

## 4. 测试

```powershell
python -X utf8 -m unittest discover -s tests -v
```

结果：Windows `Ran 144 tests`、`OK (skipped=4)`（跳过 2 个既有 Linux-only shell 测试 + Pwn Linux E2E + XSS Playwright E2E）；镜像内（`--user root`）`Ran 144 tests`、`OK (skipped=3)`，Pwn/XSS 端到端实际执行。本轮新增 `tests/test_labs_categories.py` 共 18 项（其中 XSS 7 项、MCP read_file 3 项）：

- SQLi 靶题：登录 SQLi + `UNION` 取 flag；布尔 oracle true/false 差异；seed 路由变化与动态 flag。
- MCP 靶题：`initialize`/`tools/list`/`read_note`/`get_flag`，JSON 与 SSE 两种响应，flag 与 SHA 对应。
- runner 端到端：`web-sqli`、`ai-mcp` 假模型闭环成功，平台真实接受；证据无 flag 明文。
- Pwn：Windows 下 runner 必须 `blocked`（非伪造）；Pwn 假模型的下发/三连/exp 脚本语法与提交流程做静态回归；Linux+gcc 下 target/runner 端到端测试（本机 skip）。
- XSS：未转义反射与 `/collect` 存取（`c`/`data` 两种参数）、seed 路由变体与动态 flag、越权 URL 被 400 拒绝、无浏览器时 `/report` 返回 `xss_requires_browser`、Windows runner 必须 `blocked`、XSS 假模型 payload/report/collect/submit 静态回归；Playwright 可用时跑 target/runner 端到端（本机 skip）。
- MCP `read_file`：工具集含 `read_file` + denied 的 `get_flag`（断言 get_flag 被拒绝且不泄露 flag）、`read_file("policy.txt")` 正常读取、`read_file("../private/flag.txt")` 让真实 tool 参数穿越取 flag、absolute path 与 deployment-root escape 被拒、runner E2E（`--set ai-mcp-traversal`）走 `mcp` action、不调用 get_flag 并得到平台 correct。

## 5. 证据边界与限制

- 隔离仍是**同主机独立子进程 + 127.0.0.1 临时端口 + 独立临时目录**，不是 Docker/容器级隔离；Pwn 的 socat/纯 Python TCP 桥同样只是本地进程。Pwn 在 `qutagent:dev` 镜像内运行，但 labs 靶题本身仍与 runner 同主机。
- 假模型是脚本化的“链路验证器”，成功只证明 **模型 HTTP 协议 → agent 工具（http/mcp/shell/download）→ mock 平台提交** 的全链路在本地靶题上可运行，**不代表任何真实模型的解题能力**。
- mock 平台真实比较动态 flag 并记录 `correct=true`，但它是**本地合成平台**，不是真实 CTFy 平台接受，也不是比赛成绩。
- SQLi/MCP 在 Windows 上真实运行；Pwn、XSS 在 `qutagent:dev` Linux 镜像内真实运行 3/3；Windows 原生无法执行 Linux ELF、无 Playwright 时，分别正确返回 `blocked`。
- MCP `read_file` 在 Windows 与 `qutagent:dev` 镜像内都真实运行 3/3：`get_flag` 被明确拒绝，flag 只通过 `read_file` 的 `../private` tool 参数穿越读取；Windows 6.467 s / 镜像 8.693 s 的独立 run 均记录在证据表。
- XSS 在镜像内 3/3 由真实 Playwright headless Chromium 完成：admin bot 访问反射页并在浏览器内执行 payload、把 Cookie 写回 `/collect`，平台据此判定 flag；Windows 原生无浏览器时 blocked，不伪造。
- 未访问真实平台、未使用真实模型凭据、未提交 Git。真实模型入口仍沿用 `--model real`：缺 `LLM_*` 时 blocked，不伪造。

## 6. 证据文件

| 路径 | 内容 |
|---|---|
| `artifacts/lab-categories/experiment.json` | 最近一次已落盘的成功运行（当前为镜像 `ai-mcp-traversal`，3/3） |
| `artifacts/lab-categories/runs/fake-web-sqli-*/` | SQLi 3 用例的 task/result/events/submissions/target/platform/model 日志 |
| `artifacts/lab-categories/runs/fake-ai-mcp-*/` | MCP 直接 get_flag 3 用例同类证据（含 `mcp_calls`） |
| `artifacts/lab-categories/runs/fake-ai-mcp-traversal-20261025T115419Z-901ae1/` | MCP read_file 目录穿越 Windows 3/3 证据（get_flag denied、tool 参数穿越、平台 correct） |
| `artifacts/lab-categories/runs/fake-ai-mcp-traversal-20261025T115446Z-089539/` | MCP read_file 目录穿越镜像 3/3 证据（同上，Lead 复核） |
| `artifacts/lab-categories/runs/fake-pwn-20261025T111942Z-cb82ba/` | 镜像内 Pwn 3 用例证据（下载附件、exploit.py、平台 correct） |
| `artifacts/lab-categories/runs/fake-xss-20261025T114243Z-4e26a9/` | 镜像内 XSS 最终 3/3 证据（seed 变体路由、bot 反射页访问、`/collect?c=` 外带、平台 correct） |
| `artifacts/lab-categories/runs/fake-xss-20261025T113805Z-08e11f/` | 变体/参数最终调整前的中间 3/3 证据（保留） |
| `artifacts/lab-categories/runs/fake-xss-20261025T113554Z-88ad04/` | 首轮 XSS 0/3 失败证据（二次 unquote 根因，修复后 3/3） |
| `artifacts/lab-categories/blocked-fake-pwn.json` | Pwn Windows blocked 及环境探测结果 |
| `artifacts/lab-categories/pwn-environment-probes.txt` | Pwn `docker`/`wsl`/`gcc`/preflight 原始探测输出 |
| `artifacts/lab-categories/blocked-fake-xss.json` | XSS Windows blocked（`xss_requires_browser`） |
| `artifacts/lab-categories/runs/fake-xss-20261025T114227Z-42bbc7/` | XSS Windows blocked 运行记录（cases 为空） |
| `artifacts/lab-categories/xss-environment-probes.txt` | XSS `playwright`/`docker`/`wsl`/preflight 原始探测输出 |

复核 flag 未泄露：

```powershell
Get-ChildItem artifacts\lab-categories -Recurse -File |
  Select-String -Pattern 'flag\{[0-9a-fA-F]{16,}\}'
# 期望无输出；本记录生成时无输出
```

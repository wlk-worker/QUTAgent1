# 分类靶题实验：SQLi / MCP(AI) / Pwn

记录时间：2026-10-25（北京时间）。这一轮把单一路径穿越靶题扩展为三类本地授权靶题，SQLi、MCP(AI)、Pwn 都做了假模型闭环：SQLi/MCP 在 Windows 真跑 3/3；Pwn 在 `qutagent:dev` Linux 镜像内真跑 **3/3**（Windows 原生仍会正确 `blocked`）。实验仍处于**进程级/合成靶题/无真实平台**的证据等级。

## 1. 固定数据集与预算

| `--set` | 题型 | seeds | timeout | max_turns | max_requests | web-only |
|---|---|---|---|---|---|---|
| `web-sqli` | Web SQL 注入 | 301, 302, 303 | 60 s | 10 | 10 | 是（shell 禁用） |
| `ai-mcp` | AI / MCP | 401, 402, 403 | 60 s | 8 | 8 | 是（shell 禁用） |
| `pwn` | Linux amd64 ret2win | 501, 502, 503 | 90 s | 12 | 12 | 否（需要 shell 跑 exp） |
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

## 4. 测试

```powershell
python -X utf8 -m unittest discover -s tests -v
```

结果：Windows `Ran 134 tests`、`OK (skipped=3)`（跳过 2 个既有 Linux-only shell 测试 + Windows 下的 Pwn blocked 用例）；镜像内（`--user root`，因 `/mnt/c` bind mount 对 UID 10001 不可写）`Ran 134 tests`、`OK (skipped=1)`，Pwn Linux 端到端实际执行。本轮新增 `tests/test_labs_categories.py` 8 项：

- SQLi 靶题：登录 SQLi + `UNION` 取 flag；布尔 oracle true/false 差异；seed 路由变化与动态 flag。
- MCP 靶题：`initialize`/`tools/list`/`read_note`/`get_flag`，JSON 与 SSE 两种响应，flag 与 SHA 对应。
- runner 端到端：`web-sqli`、`ai-mcp` 假模型闭环成功，平台真实接受；证据无 flag 明文。
- Pwn：Windows 下 runner 必须 `blocked`（非伪造）；Pwn 假模型的下发/三连/exp 脚本语法与提交流程做静态回归；Linux+gcc 下 target/runner 端到端测试（本机 skip）。

## 5. 证据边界与限制

- 隔离仍是**同主机独立子进程 + 127.0.0.1 临时端口 + 独立临时目录**，不是 Docker/容器级隔离；Pwn 的 socat/纯 Python TCP 桥同样只是本地进程。Pwn 在 `qutagent:dev` 镜像内运行，但 labs 靶题本身仍与 runner 同主机。
- 假模型是脚本化的“链路验证器”，成功只证明 **模型 HTTP 协议 → agent 工具（http/mcp/shell/download）→ mock 平台提交** 的全链路在本地靶题上可运行，**不代表任何真实模型的解题能力**。
- mock 平台真实比较动态 flag 并记录 `correct=true`，但它是**本地合成平台**，不是真实 CTFy 平台接受，也不是比赛成绩。
- SQLi/MCP 在 Windows 上真实运行；Pwn 在 `qutagent:dev` Linux 镜像内真实运行 3/3；Windows 原生无法执行 Linux ELF，正确返回 `blocked`。
- 未访问真实平台、未使用真实模型凭据、未提交 Git。真实模型入口仍沿用 `--model real`：缺 `LLM_*` 时 blocked，不伪造。

## 6. 证据文件

| 路径 | 内容 |
|---|---|
| `artifacts/lab-categories/experiment.json` | 最近一次成功运行（当前为镜像内 `pwn`，3/3）的完整汇总 |
| `artifacts/lab-categories/runs/fake-web-sqli-*/` | SQLi 3 用例的 task/result/events/submissions/target/platform/model 日志 |
| `artifacts/lab-categories/runs/fake-ai-mcp-*/` | MCP 3 用例同类证据（含 `mcp_calls`） |
| `artifacts/lab-categories/runs/fake-pwn-20261025T111942Z-cb82ba/` | 镜像内 Pwn 3 用例证据（下载附件、exploit.py、平台 correct） |
| `artifacts/lab-categories/blocked-fake-pwn.json` | Pwn blocked 及环境探测结果 |
| `artifacts/lab-categories/pwn-environment-probes.txt` | `docker`/`wsl`/`gcc`/preflight 原始探测输出 |

复核 flag 未泄露：

```powershell
Get-ChildItem artifacts\lab-categories -Recurse -File |
  Select-String -Pattern 'flag\{[0-9a-fA-F]{16,}\}'
# 期望无输出；本记录生成时无输出
```

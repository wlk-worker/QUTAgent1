# 镜像工具链：Web / Pwn / AI 安全

本轮（2026-10-25，北京时间）把比赛镜像从「python:3.11-slim + curl/jq/file」升级为可实战的
Web / Pwn / AI 安全工具链，并在 WSL Ubuntu-24.04 的 Docker 中**实际构建、实际运行自检**。
本文只记录实际执行过的命令和观测结果；证据等级见文末。

## 结论速览

| 项 | 实测值 |
|---|---|
| 构建命令 | `docker build --pull=false --platform linux/amd64 -t qutagent:dev .` |
| 基础镜像 | `python:3.11-slim`（构建时解析为 Debian 13 trixie；本地 ID `cce12316475d`，见下方 digest） |
| 最终镜像 | `qutagent:dev`，ID `sha256:7ef94cc730f08e935f6bad1e3728c41fa8fa35856b21cf651e73c12ab5698ba1`（含 skills/MCP auth header/`ctf-browse` 的最终层）；历史 `15d3989d…`/`78d1b491…`/`2e1060c9…` 为上一版 |
| 最终完整重建耗时 | **1078 s（约 18 分钟）**，8 vCPU WSL；BuildKit 复用了 apt 层缓存，radare2 / Python / Playwright 层重建。追加 `ctf-browse` 后仅 COPY 层失效，增量重建 **39.8 s** |
| 镜像内容大小 | `943,220,542` 字节 ≈ **900 MiB / 0.88 GiB**（`docker image inspect .Size`，压缩层合计） |
| 容器磁盘占用 | `docker images` DISK USAGE ≈ **3.57 GB**（Docker 29 containerd 存储口径，解包后） |
| 镜像架构 / 用户 | `linux/amd64`；UID 10001（`agent`），工作目录 `/ctfy/work` |
| 入口 | `ENTRYPOINT ["python", "/app/agent/main.py"]`（绝对路径，未改运行契约） |
| `scripts/check_toolchain.py` | 退出码 0，`verdict: passed`；66 项检查 65 通过，`required_failed: []`，`optional_failed: ["import:angr"]` |
| 离线自检 | `docker run --rm --network none … check_toolchain.py --quiet` 仍退出 0（工具链运行期不需要联网） |
| `ctfy agent check qutagent:dev --json` | `verdict: passed`、`ran_locally: true`、`findings: []`（registry manifest 返回 401，检查的是本地镜像） |
| 辅助命令冒烟 | `SMOKE_FAILURES=0`（ctf-checksec / ctf-disasm / ctf-debug / ctf-strings / ctf-browse、r2、pwntools、Chromium 启动等全部 PASS） |

基础镜像本地 digest：`python@sha256:cce12316475d7d56d605f76e1d811d0dc4e7227f2d4afd29951521264f504ff8`。
`python:3.11-slim` 是浮动 tag（当前指向 Debian 13 / trixie），**提交前建议改为按 digest 固定**。

## 构建与验证命令（可直接复现）

```bash
# Windows 上通过 WSL 执行；项目根目录 = /mnt/c/Users/lenovo/Desktop/QUTAgent
wsl.exe -d Ubuntu-24.04 bash -lc 'cd /mnt/c/Users/lenovo/Desktop/QUTAgent && docker build --pull=false --platform linux/amd64 -t qutagent:dev .'

# 工具链自检（镜像 ENTRYPOINT 是 python /app/agent/main.py，必须覆盖 entrypoint）
docker run --rm --entrypoint python qutagent:dev /app/scripts/check_toolchain.py
docker run --rm --entrypoint python qutagent:dev /app/scripts/check_toolchain.py --quiet
docker run --rm --network none --entrypoint python qutagent:dev /app/scripts/check_toolchain.py --quiet

# 官方本地镜像检查
/home/agentfuzz/qutagent-ctfy-venv/bin/ctfy agent check qutagent:dev --json

# 辅助命令快速冒烟（容器内 UID 10001）
docker run --rm --entrypoint bash qutagent:dev -c '
  printf "int main(void){return 0;}\n" > /tmp/t.c && gcc -o /tmp/t /tmp/t.c &&
  ctf-checksec /tmp/t && ctf-disasm /tmp/t main &&
  ctf-debug /tmp/t "show version" && ctf-strings /tmp/t | head -5 &&
  r2 -v | head -1 && pwn checksec --file /tmp/t | head -8'
```

镜像内版本清单：`/app/tool-versions.txt`（pip / dpkg / gem 全量）；工具速查：`/app/toolchain.txt`。

## 工具清单（版本为 2026-10-25 实际构建结果）

### Pwn / 逆向

| 工具 | 镜像内命令 / import | 版本 |
|---|---|---|
| pwntools | `pwn`、`import pwn` | 4.15.0 |
| gdb / gdbserver | `gdb`、`gdbserver` | 16.3（Debian） |
| binutils（readelf/objdump/strings/nm） | `readelf` 等 | 2.44 |
| libc 调试符号 | `libc6-dbg` 2.41-12+deb13u4 | — |
| radare2 | `r2`、`rabin2`、`rasm2` 等 | 5.9.8（源码构建） |
| ROPgadget | `ROPgadget` | 7.7 |
| one_gadget | `one_gadget` | 2.1.1（Ruby gem） |
| seccomp-tools | `seccomp-tools` | 1.7.1（Ruby gem） |
| checksec | `checksec`（checksec.sh） | 2.5.0 |
| patchelf | `patchelf` | 0.18.0 |
| z3 | `import z3` | 5.3.1.0 |
| capstone | `import capstone` | 6.0.0a11 |
| pyelftools | `import elftools` | 0.33 |
| socat / netcat | `socat`、`nc` | 1.8.0.3 / OpenBSD 1.229 |
| angr | `import angr` | **未安装**，理由见下文 |

### Web

| 工具 | 镜像内命令 / import | 版本 |
|---|---|---|
| curl / wget | `curl`、`wget` | 8.14.1 / 1.25.0 |
| nmap | `nmap` | 7.95 |
| sqlmap | `sqlmap` | 1.9.6（Debian 包，离线不更新） |
| ffuf | `ffuf` | 2.1.0 |
| gobuster | `gobuster` | 3.6.0 |
| nikto | `nikto` | 2.6.1（Perl，上游源码 + Debian Perl 依赖） |
| nuclei | `nuclei` | v3.11.1（内置 3 个起步模板） |
| requests / httpx / bs4 / lxml | `import requests, httpx, bs4, lxml` | 2.34.2 / 0.28.1 / 4.15.0 / 6.1.3 |
| Playwright + Chromium | `import playwright`；`python -m playwright` | 1.64.1 / chromium-1248 |

### AI 安全 / API

| 工具 | 镜像内命令 / import | 版本 |
|---|---|---|
| MCP Python SDK | `import mcp` | 2.3.0 |
| websocket-client | `import websocket` | 1.9.2 |
| PyJWT | `import jwt` | 2.15.1 |
| grpcurl | `grpcurl` | v1.9.4 |
| openssl / jq | `openssl`、`jq` | 3.5.7 / 1.7 |

### 通用

`python` 3.11.17、`git` 2.47.3、`gcc/g++` 14.2.0、`make` 4.4.1、`ruby` 3.3.8、`gem` 3.6.7、
`file` 5.46、`xxd`（2024-12-07）、`hexdump`（util-linux 2.41.5）、`unzip` 6.00、`zip` 3.0、
`binwalk` v2.4.3（`x` 解包依赖有限，复杂固件可能需要额外工具）、`patch`、`strace`、`ltrace`。

## 辅助命令（`toolbox/bin` → `/usr/local/bin`）

全部由 Dockerfile `COPY toolbox/bin/ /usr/local/bin/` 安装并 `chmod 0755`，以 UID 10001 运行。
共同约定：**输出截断、错误信息明确、只处理本地普通文件、不通过 shell 求值用户输入**。

| 命令 | 行为 |
|---|---|
| `ctf-checksec <binary>` | 优先 `pwn checksec`，否则 `readelf -h -l -d` 摘要；默认最多 6000 字节（`CTF_CHECKSEC_MAX_BYTES`）；非 ELF / 不存在 → 退出 2；**不执行目标**。 |
| `ctf-disasm <binary> [symbol\|address]` | `objdump -d`；带符号且 objdump 无结果时回退 `r2 -q -c 'aaa; pdf @ <sym>'`；符号只允许 `[A-Za-z0-9_.$@:+-]` 且 ≤128 字符（防 r2 命令注入）；默认最多 400 行 / 20000 字节（`CTF_DISASM_MAX_LINES` / `CTF_DISASM_MAX_BYTES`）；非 ELF → 退出 2。 |
| `ctf-debug <binary> [gdb command ...]` | 只走 `gdb -q -batch -nx`，stdin 关闭，`pagination/confirm/height/width` 预设；最多 12 条命令、单条 ≤400 字符、禁止换行；默认 `info file` + `info functions`；默认 120 s 超时、最多 12000 字节；**不支持交互**；缺文件 → 退出 2。 |
| `ctf-strings <file> [min-length]` | `strings -a -n`，默认最多 8000 字节（`CTF_STRINGS_MAX_BYTES`），最小长度 1..64。 |
| `ctf-browse <url> [--wait-ms N] [--screenshot PATH]` | 用 Playwright/Chromium 渲染 http(s) 页面，输出 title/final URL/可见文本/DOM 预览/console/pageerror，可截图；只允许 http(s)，输出截断；用于 DOM XSS/JS 页面观察。 |

注意：`ctf-debug` 会按 gdb 命令执行（包括运行目标二进制），这是调试功能本身；
只对授权的题目附件使用。所有命令的完整输出仍可直接调用底层工具获取。

## 镜像内自检 `scripts/check_toolchain.py`

- 位置：镜像内 `/app/scripts/check_toolchain.py`（仓库 `scripts/check_toolchain.py`）。
- 检查三类固定能力：命令存在 + 版本探测（25 s 超时）、Python import + 发行版版本、关键文件/目录；
  另有 5 个固定探针：`/ctfy/work` 可写、gdb batch、`pwn checksec`（含 PLT 退化检测）、
  entrypoint import、headless Chromium 启动。不执行任何题目输入。
- 输出 JSON：

```json
{
  "schema_version": 1,
  "generated_at": "…Z",
  "image": {"platform": "linux", "machine": "x86_64", "python": "3.11.17", "uid": 10001, "cwd": "/ctfy/work"},
  "summary": {
    "verdict": "passed",
    "total": 66, "ok": 65, "failed": 1,
    "required_failed": [],
    "optional_failed": ["import:angr"],
    "by_category": {"general": {"total": 14, "ok": 14, "failed": 0}, "…": {}},
    "elapsed_s": 4.31
  },
  "checks": [
    {"id": "r2", "kind": "command", "name": "r2", "required": true,
     "category": "pwn", "note": "radare2", "ok": true,
     "detail": {"path": "/usr/local/bin/r2", "version": "radare2 5.9.8 1 @ linux-x86-64"}},
    {"id": "import:angr", "kind": "import", "name": "angr", "required": false,
     "category": "pwn", "note": "symbolic execution", "ok": false,
     "detail": {"error": "ModuleNotFoundError", "message": "No module named 'angr'"}}
  ]
}
```

- 退出码：`0` = 全部 required 通过；`1` = 有 required 缺失/损坏；`2` = 报告本身失败。
- 选项：`--output PATH` 额外写文件；`--quiet` 只打印 summary。
- 当前结果：`verdict: passed`、`required_failed: []`、`optional_failed: ["import:angr"]`。
  把 `angr` 保持为 optional，是按要求将其视为「体积/构建可控才装」的可选能力，不是掩盖缺失。

## 未安装项、受限项与理由

| 项 | 状态 | 理由 / 证据 |
|---|---|---|
| `angr` | 未安装（optional 缺失） | 该环境依赖解析不兼容：默认解析后 `pyvex` 报 `AttributeError: module 'bitstring' has no attribute 'ConstBitStream'`；固定 `bitstring==4.2.3` 后改为 `pycparser` 3.x 的 `TypeError: 'CLexer' object is not callable`；再固定 `pycparser<3` 时 angr wheel 构建失败。属于「构建不可控」，因此不装，`check_toolchain` 如实报告为 optional 缺失，镜像内任何逻辑不得假定 angr 可用。 |
| `pwndbg` | 未安装 | Debian 13 无 `pwndbg` 包；PyPI 无 `pwndbg` 发行版（`pip index versions pwndbg` → No matching distribution）；上游 `setup.sh` 非 hermetic（运行时拉依赖/写 `~/.gdbinit`），与「构建期装好、评测期离线」冲突。替代：`gdb 16.3` + `pwntools` + `ctf-debug`（batch 模式，已验证）。 |
| nuclei 官方模板库 | 只内置 3 个起步模板 | 官方模板体量大且需持续更新，不符合体积与离线约束。镜像内 `/opt/nuclei-templates` 含：`.git/config` 泄露、`.env` 泄露、目录列表；`nuclei -validate -duc -t /opt/nuclei-templates` 实测 `All templates validated successfully`。自定义模板可 `-t <dir>`。 |
| Playwright 官方模板/多浏览器 | 仅 Chromium | 只装 Chromium（1 个浏览器约 1.22 GB 层）；Firefox/WebKit 未装以控制体积。启动已实测（标题回读 `qutagent`）。 |
| Ghidra / IDA / SageMath / hashcat / john / podman | 未安装 | 不在本轮要求内；体积或授权成本高；Pwn 反编译用 radare2 + objdump + gdb 覆盖基础场景。 |
| 运行时联网/安装 | 禁止 | 所有工具在构建期装入；`apt` 列表已删除；`check_toolchain` 在 `--network none` 下仍通过。sqlmap 的 "version outdated"、nuclei 的更新提示都只是离线提示，不影响功能。 |

## 赛时离线约束与注意事项

1. 评测期不联网、不安装：镜像内 `apt`、`pip`、`gem` 均可离线使用已装内容；不要在解题脚本里安装包。
2. `nuclei` 建议加 `-duc`（禁用更新检查）；`sqlmap` 本身不自动更新（只提示）。
3. Playwright 浏览器固定于 `/opt/playwright`（`PLAYWRIGHT_BROWSERS_PATH`），不要设置到不可写目录。
4. nuclei 模板路径用 `/opt/nuclei-templates`（`NUCLEI_TEMPLATES` 环境变量已设，但 nuclei CLI 仍以 `-t` 为准）。
5. 目标/平台范围的授权边界仍由求解器 `agent/` 的 origin 白名单与平台规则控制；本工具链不放宽任何授权范围。
6. 容器内是 UID 10001 非 root：依赖 root 的扫描模式（如 nmap SYN 扫描）不可用，使用默认 connect 扫描。

## 构建过程中的实际失败与修复（保留证据）

| 轮次 | 现象 | 修复 |
|---|---|---|
| 1（149 s 失败） | `apt-get` 成功后 `command -v xxd` 失败 | Debian 13 把 `xxd` 拆成独立包（`vim-common` 不再提供），改为显式安装 `xxd` |
| 2（175 s 失败） | radare2 `configure` 报 "c compiler required"、`patch` 缺失 | `--no-install-recommends` 未带 `libc6-dev`（C 头文件）与 `patch`，显式安装 |
| 3（688 s 失败） | `import angr` 因 `bitstring` API 不兼容失败 | 固定 `bitstring<4.3` 后仍与 `pycparser` 冲突；最终不装 angr（见上表） |
| 4（658 s 成功但有缺陷） | `r2`/`rabin2` 在最终镜像中不存在；`pwn checksec` 报 `No module named 'pkg_resources'` | radare2 `sys/install.sh` 默认 symstall，链接指向 `/tmp/radare2`，构建末尾删除后失效 → 改 `sys/install.sh --install`（拷贝）；`setuptools` 84 移除 `pkg_resources` → 固定 `setuptools<81` |
| 5（1078 s 成功，最终） | 无构建失败 | 另修：`gdb 16.3` 不支持 `info version`（探针改 `show version`）；`check_toolchain` 的 import 探针用 `io.StringIO` 无 `fileno`（改为 `os.devnull` 文件对象） |

## 风险与后续

- **可复现性**：构建期从 Debian 13、PyPI、RubyGems、GitHub Releases（`grpcurl`/`nuclei` 取 latest）下载，未全部固定版本；本次实际版本已记录在 `/app/tool-versions.txt` 与上文。提交前建议固定基础镜像 digest 与关键二进制版本。
- **体积**：内容约 900 MiB、容器磁盘占用约 3.57 GB，远低于 8 GiB 参考上限；最大层是 Playwright/Chromium（约 1.22 GB，未压缩）。若赛前给出更严格的体积上限，优先移除 Playwright 层（删除 Dockerfile 第 6 节并重建），Web 题退化为 curl/httpx。
- **能力边界**：本文件只证明「工具已装、可执行、离线自检通过」，**不证明**任何真实 Pwn/Web/AI 题目被解出；没有运行真实平台/模型请求，也没有镜像上传或平台审核。
- **ctfy 检查范围**：`ctfy agent check` 因 registry manifest 401 只检查本地镜像并跑 dry run；`verdict: passed` 不是远程镜像审核通过。
- **攻击性工具**：镜像含扫描/利用工具，仅可在明确授权的比赛靶题/平台范围内使用。

## 证据等级

| 验证 | 命令 | 结果 | 能证明什么 |
|---|---|---|---|
| 镜像构建 | `docker build --pull=false --platform linux/amd64 -t qutagent:dev .` | 成功，ID `sha256:7ef94cc7…`，完整 1078 s + 多次增量重建（最近一次 MCP auth header 层） | Dockerfile 可从当前源码构建出 linux/amd64 镜像 |
| 工具链自检 | `docker run --rm --entrypoint python qutagent:dev /app/scripts/check_toolchain.py` | exit 0，`verdict: passed`，`required_failed: []` | 66 项 required/optional 能力实际在镜像内可用；angr 为唯一 optional 缺失 |
| 离线自检 | `docker run --rm --network none …` | exit 0，`verdict: passed` | 工具链运行不依赖联网 |
| 官方镜像检查 | `ctfy agent check qutagent:dev --json` | `passed`、`ran_locally: true`、0 findings | CTFY-0001 本地 dry run/契约通过；不是平台审核 |
| 辅助命令冒烟 | 容器内 gcc + ctf-* + r2 + pwntools + Chromium | `SMOKE_FAILURES=0` | 辅助命令与关键工具在 UID 10001 下真实可运行 |

未进行：真实 CTF 题目解题、真实平台/模型请求、镜像上传/注册、平台审核。不要把本页的本地结果当作比赛成绩或平台接受。

# 赛时出题包上传：控制器、命令与证据边界

本文件描述 `author/controller.py` 的可用命令、请求形状、dry-run 与授权上传的区别，以及“上传 ≠ 审核 ≠ 发布 ≠ 进入比赛题集”的边界。当前只做了本地实现、mock HTTP 契约测试和 dry-run 实跑：**没有向真实平台上传任何题包，也没有任何题包通过人工审核**。平台字段依据 CTFy 0.7.0 源码快照 `_research/ctfy/pypi/extracted`，以及 2026-10-23 登录后网页观察；两者都不能替代赛道附件。

## 快速命令

```powershell
# 默认 dry-run：生成/复用 seed 题包 -> 本地检查（可用时）-> tar.gz + sha256 -> 报告；零网络请求
python -X utf8 author/controller.py --seed 46 --dry-run

# 复用已有题包（不重新生成）
python -X utf8 author/controller.py --package author/generated/document-desk-45 --dry-run

# 带 competition id 的 dry-run 计划（仍不发请求）
python -X utf8 author/controller.py --seed 46 --competition-id <competition_id> --dry-run

# 仅作示例，本轮未执行：显式授权上传需要环境变量中的 URL 与 token
$env:CTFY_PLATFORM_URL = "https://<platform-host>"
$env:CTFY_TOKEN = "<from account settings; never put on the command line>"
python -X utf8 author/controller.py --seed 46 --authorized --competition-id <competition_id> --poll --wait-seconds 120
```

`--authorized` 才会构造并发送 HTTP；单独 `--dry-run`、或两者都不给时一律 dry-run。token 只从 `CTFY_TOKEN` 读取，不提供命令行参数，不写入报告；`CTFY_PLATFORM_URL` 指向平台根地址，客户端自行拼接 `/api/v1`。退出码：`0` 成功（dry-run、上传被接受、轮询完成）；`1` 本地检查失败；`2` 被安全闸门阻塞（缺 token / URL / competition id）；`3` 平台拒绝或传输结果未知。

## 一次流程做什么

1. **选择/生成题包**：`--package` 复用已有目录；否则按 `--seed` 调用 `author/generate.py`，已有同名非空目录则复用并记录 `package_source`。生成器拒绝覆盖，控制器也不覆盖。
2. **本地审计 / smoke**（检测实际可用命令，见下节）。
3. **打包**：生成确定性的 `.tar.gz`——包装目录一层（服务端会剥掉）、成员排序、`PAX` 格式、mode `0644`、mtime `0`；排除 `.git`、`__pycache__`、`node_modules`、`.venv`、`.DS_Store` 和符号链接/非普通文件；文本扩展名与 `Dockerfile` 的 CRLF 归一为 LF（生成器曾因 Windows CRLF 的 `rotate.sh` 导致 smoke 启动失败）。输出 sha256 与成员清单。
4. **写报告**：报告包含包路径、检查记录、归档 sha256/大小/成员、上传请求计划或结果、只读轮询结果、证据等级。报告不含 flag 值、不含任何 token；写入前再做一次已知密钥值扫描，命中则替换为安全占位。
5. **可选上传**：仅 `--authorized` 且 URL/token 齐备时发送一次 `POST`；失败按响应码/拒绝码记录，不自动重试（transport 失败标记 `mutation_outcome_unknown`）。
6. **只读轮询**：`--poll`/`--wait-seconds` 时只发 `GET` 列表与 audit，不重复上传；`review_status` 为 `approved`/`rejected` 时提前结束。

## 本地检查：优先命令不存在时如何记录

CTFY-0002 标准页面写的是 `ctfy authoring check` / `ctfy authoring smoke --local`，但本项目已核对的 PyPI `ctfy 0.7.0` 没有这两个子命令。控制器按以下顺序检测并记录“实际使用的命令与版本”：

1. 若 `ctfy` 存在，执行 `ctfy --version` 与 `ctfy authoring --help`；只有帮助文本同时显示 `check` 和 `smoke --local` 时，才用 `ctfy authoring check <pkg>` / `ctfy authoring smoke <pkg> --local`（`source` 记为 preferred CLI）。
2. 否则若 `ctfy-admin` 存在，回退 `ctfy-admin challenge audit <pkg> --challenges-dir <root> --strict --json` 和 `ctfy-admin challenge smoke ... --ephemeral-ports --timeout 180`，并记录 `ctfy-admin --version`。
3. 两者都不在 PATH 时，检查状态为 `local_checks_unavailable`：题包仍会打包、哈希并生成报告，但明确标记“未本地校验”，不会把它说成通过审核。
4. 检查子进程使用移除 `CTFY_TOKEN`/`LLM_*` 等凭据后的环境；检查 stdout/stderr 摘要会脱敏，且最多保留尾部 1200 字符。检查失败（非零退出）会停止上传路径，保留归档供排查，退出码 1。

> 本轮 Windows 环境没有 `ctfy`/`ctfy-admin`，因此实跑 dry-run 的本地检查为 `local_checks_unavailable`；此前 WSL 中的 4 个 seed 严格审计/smoke 结果见 [验证记录](verification.md)，不能迁移为本次证据。

## 上传请求形状（来自 0.7.0 源码）

| 项目 | 值 | 源码依据 |
|---|---|---|
| 方法/路径 | `POST /api/v1/competitions/{competition_id}/authored-challenges` | `ctfy/sdk/resources/authoring.py` `upload()`；服务端路由 `ctfy/server/routes/authoring.py` |
| multipart 字段 | `slug`（作者标签）+ `file`（`<slug>.tar.gz`，`application/gzip`） | `authoring.py` 中 `data={"slug": slug, **declared}`、`files={"file": (filename, archive, "application/gzip")}` |
| 响应 | 201 + 行对象：服务端铸造 `id`（`AUTHORED-<hex>`）、`review_status`（新建为 `pending`）、`auto_smoke`、`file_count`/`total_bytes`、`smoke_verdict` 等 | `ctfy/server/models/authoring.py` `AuthoredChallengeInfo`、`AuthoredAutoSmoke` |
| 只读列表 | `GET /api/v1/competitions/{competition_id}/authored-challenges`（本队范围） | `authoring.py` `list()`；`ctfy/server/routes/authoring.py` |
| 只读审计 | `GET /api/v1/competitions/{competition_id}/authored-challenges/{challenge_id}/audit` | `authoring.py` `audit()` |
| 标签规则 | 折叠大小写/空白/连续破折号后须匹配 `^[A-Z0-9]+(-[A-Z0-9]+)*$` | `ctfy/core/authored_challenges.py` `authored_challenge_slug()` |
| 认证 | `Authorization: Bearer <CTFY_TOKEN>` | `ctfy/sdk/base.py` |

控制器只发送 `slug` + `file` 两个 multipart 字段。若赛事启用了贡献者协议，平台会在读取归档前返回 `authoring_terms_not_accepted` / `authoring_terms_changed` / `authored_declarations_incomplete`；本实现不猜测 `license`/`provenance`/`ai_assisted`/`accepted_terms_version` 的取值，而是保留拒绝码，等赛道规则确认后再补。`authored_destination_refused` 同理。

已知拒绝码（用于读报告，不用于重试判断）：`authoring_not_enabled`、`authoring_not_open_yet`、`authoring_closed`、`authoring_requires_verified_email`、`authoring_cooldown`、`authored_challenge_bad_slug`、`authoring_terms_not_accepted`、`authoring_terms_changed`、`authored_declarations_incomplete`、`authored_destination_refused`、`authoring_queue_full`、`authoring_capacity_reached`、`authored_challenge_upload_empty`、`authored_challenge_upload_too_large`、`authored_challenge_already_reviewed`；审计侧另有 `authored_challenge_not_found`。来源：`ctfy/server/routes/authoring.py`。

## dry-run 报告示例

2026-10-23 在 Windows 实跑 `python -X utf8 author/controller.py --seed 46 --dry-run`，关键字段（完整文件在 `artifacts/authoring/`，已被 `.gitignore` 忽略）：

```json
{
  "mode": "dry_run",
  "status": "dry_run",
  "exit_code": 0,
  "seed": 46,
  "package_source": "generated",
  "slug": "document-desk-46",
  "local_checks": {
    "planned": 0, "executed": 0, "passed": null,
    "available": false, "evidence": "local_checks_unavailable",
    "note": "no ctfy/ctfy-admin on PATH; local audit and smoke did not run, so this package is packaged and hashed but not locally validated"
  },
  "archive": {
    "path": "artifacts/authoring/document-desk-46.tar.gz",
    "sha256": "12a5cc63bd2cca91830cc4321d4d7a4ec70246e233a8ad7770677ad4c46d651e",
    "size_bytes": 2178,
    "file_count": 8,
    "wrapping_directory": "document-desk-46"
  },
  "upload": {
    "attempted": false,
    "uploaded": false,
    "review_status": null,
    "platform_reviewed": false,
    "request": {
      "method": "POST",
      "path": "/api/v1/competitions/{competition_id}/authored-challenges",
      "multipart_fields": ["slug", "file"]
    }
  },
  "network_sent": false,
  "uploaded": false,
  "platform_reviewed": false,
  "evidence_level": "local_packaged_unsubmitted",
  "flag_included_in_report": false,
  "secrets_in_report": false
}
```

同一命令在缺 URL/token 时使用 `--authorized` 会得到 `status=blocked`、`blocked.reason=missing_platform_url|missing_token`、退出码 2，且报告 `network_sent=false`——这是“被安全闸门挡住”，不是“上传失败”。

## 审核边界与证据等级

| 证据 | 能证明 | 不能证明 |
|---|---|---|
| mock HTTP 契约测试（`tests/test_authoring_flow.py`） | multipart 形状、路径、slug、Authorization 头、拒绝码解析、dry-run 零请求、token 脱敏、GET-only 轮询 | 真实平台接受、审核、发布、可解 |
| 本地审计 / smoke（若 CLI 可用） | 该 CLI 版本下的静态规则与动态可解性 | 平台审核、进入比赛题集 |
| dry-run 报告 + sha256 | 本地题包内容与哈希、上传计划 | 已上传；报告 `uploaded=false` |
| `--authorized` 上传且平台 201 | 平台已接收该上传，`review_status` 以响应为准（通常 `pending`） | 已审核、已批准、已发布、已进题集、能计分 |
| 只读轮询看到 `approved` | 平台运营方审核状态为 approved | 已发布 / 已 curate 进本场题集（`in_catalog` 与 `curation` 是另外两个字段） |

平台侧步骤在源码中是分开的：上传（`review_status=pending`）→ 自动审核/自动 smoke（`auto_smoke`，`None` 表示“服务器没说”，不是“没 smoke”）→ 运营方人工 review（`approved`/`rejected` + note）→ publish（进入 catalog，`in_catalog`）→ 运营方 curation（进入某场比赛题集，`curation`）→ 选手可见。更新已批准的题要走新 revision，而不是同名覆盖。普通上传还要求账号邮箱已验证（`authoring_requires_verified_email`）。**本仓库没有任何一步在真实平台发生。**

## 赛时窗口与配额：待确认项

2026-10-23 登录后“出题”页面观察到：下一窗口 2026-11-21 10:00；最多 3 个待审题包；最近 2 小时上传上限 5 次、当时余 5；上传暂停：无；本场 smoke 不计次；未发布主题；已上传 0 题。这些是**当次 UI 状态**，不是承诺，也**不能**解释为“每窗口可提交 5 道计分题”。仍需赛道附件/组委会确认：

1. 智能体赛道是否强制赛时自主出题、上传次数与**实际计分题数**的关系、出题计分与原创性规则；
2. 出题窗口的精确起止、时区、是否允许赛前准备模板、窗口外能否 revision；
3. 是否启用贡献者协议、要求的 `license`/`provenance`/`ai_assisted`/`accept-terms` 字段；
4. 自动审核与自动 smoke 是否对 TPCTF 2026 启用、自动 smoke 的每日预算；
5. 审核时限、批准后是否自动发布、发布后是否会被 curate 进本场题集；
6. `agent_author` token 的授权方式与权限范围；本文的 token 方案仅按通用 `CTFY_TOKEN` 设计。

在拿到赛道附件前，本实现保持 dry-run 默认、只做通用 CTFY-0002 路由，不硬编码窗口/配额，也不把 UI 数字写成断言。

## 本轮实际验证命令与结果

- `python -X utf8 -m unittest discover -s tests -p "test_authoring_flow.py" -v`：26/26 通过；本机 `python` 是 `python314._pth` 隔离模式，点号 `-m unittest tests.test_authoring_flow` 不能 import 仓库包，需用 `discover`（或在普通非隔离 Python 下运行）。
- `python -X utf8 -m unittest discover -s tests -v`（分类靶题合入后复跑）：**141 项，OK（skipped=4）**；出题/参赛流程 26 项、既有 contract/reliability 与靶题/HTTP/MCP/skills/分类靶题测试全部通过；4 项 skip 为 2 个 Linux-only shell 测试 + Windows 下 Pwn/XSS 浏览器用例。
- 上述命令的前提：本机 PATH 上的 `python` 使用 `python314._pth`（隔离模式，`ignore_environment=1`、`safe_path=True`），不能直接 import 仓库包；`discover -s tests` 会自行加入测试目录，测试模块再显式加入仓库根目录。`tests/test_authoring_flow.py` 顶部另有一个仅 Windows 生效的测试环境兼容 shim：DSH 沙箱会把 POSIX mode `0o700` 映射成沙箱进程自己不可写的 ACL，导致 `tempfile` 目录不可用；shim 只把该模式改为 `0o750`，不改变产品代码，也不改变测试断言。

**结论：未上传、未审核。** 本文件中的任何“通过”均指本地代码/契约或本地 CLI 检查，除非明确写出平台响应；当前没有平台响应。

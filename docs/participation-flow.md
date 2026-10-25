# 镜像注册与独立 Agent 评测 entry：命令、字段与安全闸门

`scripts/platform_flow.py` 覆盖“注册评测 harness（agent 镜像）→ probe → 只读状态 → 以独立参赛者进入评测”的代码路径。所有子命令**默认 dry-run、零 HTTP 请求**；只有显式 `--authorized` 且环境中有 `CTFY_PLATFORM_URL` / `CTFY_TOKEN` 时才发请求。token 不提供命令行参数，不打印、不写入报告。也可以把两个值放到 gitignored 的本地文件并用 `--env-file artifacts/ctfy.env` 加载（只读取 `CTFY_PLATFORM_URL`/`CTFY_TOKEN`，值不回显；模板 `artifacts/ctfy.env.example`）。当前没有真实账号 token：**没有注册任何镜像、没有 probe 任何镜像、没有创建任何 entry**，也没有平台审核记录。

字段以 CTFy 0.7.0 源码快照 `_research/ctfy/pypi/extracted` 为准（路径与行号见下表），不按官网页面文字猜测。

## 命令

```powershell
# 1) 计划注册（dry-run，默认）
python -X utf8 scripts/platform_flow.py register-harness --id qutagent `
  --image registry.example/qutagent:dev --display-name QUTAgent --version dev

# 2) 计划 probe：dry-run 只展示“先 GET 解析 id、再 POST probe”
python -X utf8 scripts/platform_flow.py probe --harness-id qutagent

# 3) 计划读取状态：dry-run 只列出 3 个 GET 计划
python -X utf8 scripts/platform_flow.py status --competition-id <competition_id>

# 4) 计划 entry（dry-run 展示 POST /eval/entries 的 JSON）
python -X utf8 scripts/platform_flow.py enter --harness-id qutagent `
  --model-id <model_id> --competition-id <competition_id>

# 显式授权（本轮未执行；需环境变量，绝不在命令行传 token）
$env:CTFY_PLATFORM_URL = "https://<platform-host>"
$env:CTFY_TOKEN = "<from account settings>"
python -X utf8 scripts/platform_flow.py status --competition-id <competition_id> --authorized
python -X utf8 scripts/platform_flow.py probe --harness-id qutagent --authorized --wait-seconds 300
python -X utf8 scripts/platform_flow.py enter --harness-id qutagent --model-id <model_id> `
  --competition-id <competition_id> --authorized

# 或：从 gitignored artifacts/ctfy.env 读取（推荐，避免 shell history）
python -X utf8 scripts/platform_flow.py status --competition-id <competition_id> `
  --authorized --env-file artifacts/ctfy.env
```

退出码：`0` 成功/计划生成；`2` 安全闸门阻塞（缺 URL/token、缺必填项、harness 不存在、未审核、模型不可用）；`3` 平台拒绝或传输失败。报告默认写到 `artifacts/participation/`（gitignored），`--json` 打印完整报告；所有响应字段在写入前对已知 token 值再次脱敏。

## 源码字段依据

| 能力 | 请求 | 关键字段与规则 | 源码位置 |
|---|---|---|---|
| 注册 harness | `POST /api/v1/eval/harnesses` | `{id, image, display_name, version, notes}`；`id` 只是**裸名**，服务端存为 `<owner_user_id>/<name>`，并强制 `review_status="pending"`；名字规则 `^[a-z0-9][a-z0-9._-]{0,63}$`；每账号最多 50 个；重复名 409 `harness_id_taken` | `ctfy/server/routes/eval_public.py:398-469`；`ctfy/sdk/resources/eval.py:62-91`；名字/上限常量同文件 `:111`、`:117` |
| 我的 harness 列表 | `GET /api/v1/eval/harnesses` | 只返回调用者自己的行；含 `review_status`、`approved_digest`、`conformance_status` | `eval_public.py:384-396` |
| probe | `POST /api/v1/eval/harnesses/{harness_id}/probe` | 返回 `TaskState`（`id`/`status`），异步；结果写回 harness 行的 `conformance_*` 字段；不携带任何平台凭据或模型 key；不改变 `review_status` | `eval_public.py:547-575`；`ctfy/server/tasks/handlers.py:1798-1832`；`ctfy/sdk/resources/eval.py:571-589` |
| 静态 conformance（未在本脚本实现） | `POST /api/v1/eval/harnesses/{harness_id}/conformance` | 只读镜像清单，**是证据不是闸门**，不会改变 review 状态 | `eval_public.py:508-545` |
| entry 计划/创建 | `POST /api/v1/eval/entries` | `EvalEntryRequest` = `{harness_id, model_id, competition_id, num_samples}`，另有可选 `timeout_s`/`max_turns`（`0`=继承部署设置，只能缩短）；`num_samples` 服务端夹到 1..5；服务端盖 `tier="self_reported"`、`trigger="user"`，客户端不能设置 tier | `ctfy/server/models/eval.py:423-455`；`eval_public.py:982-1132`；`ctfy/sdk/resources/eval.py:259-291` |
| entry 列表 | `GET /api/v1/eval/entries?competition_id=...` | 分页 `{items,total,limit,offset}`；只列 `trigger=user` 的本人 entry | `eval_public.py:1134-1168`；`eval.py:293-312` |
| 可进入模型 | `GET /api/v1/eval/models` | 只列出 approved + active 的模型；entry gate 会拒绝未批准模型 | `eval_public.py:943-980`；`eval.py:247-257` |
| dispatchable 判定 | — | `review_status == "approved"` 且 `approved_digest` 非空，才可被派发；平台自有行（owner 为空）例外。改 `image` 会把行重置回 `pending` 并清空 digest | `ctfy/core/state/models.py:4437-4467`；`eval_public.py:1170-1230` |
| entry 拒绝码 | `409` | `not_your_agent`、`agent_not_dispatchable`、`model_not_approved`、`agents_not_allowed`、`no_challenges`、`already_running`、`unfunded`；该 code 就是可操作原因（等审核 / 加 key / 换赛事） | `ctfy/core/eval_entry.py:65-135`；`eval_public.py:1006-1061` |

## 本脚本比 SDK 更保守的地方（fail-closed 预检）

`enter` 在 POST 前先做两个只读 GET，任一不满足就**不发 POST**、报告 `blocked`：

1. `GET /eval/harnesses` 解析裸名/完整 id；要求该行 `review_status == "approved"` 且 `approved_digest` 非空，否则 `blocked.reason=agent_not_dispatchable`。理由：未审核镜像进入 entry 会在 dispatch 阶段全部失败，白耗节点时间，也会让参赛者误以为 agent 坏了。
2. `GET /eval/models` 要求目标 `model_id` 出现在平台提供的 approved+active 列表；不在则 `blocked.reason=model_not_approved`。这是平台 entry gate 的预检，不是替代它。

`probe` 同样先 `GET /eval/harnesses` 把裸名解析为服务端存储的完整 id（含 `/`），未找到则 `blocked.reason=harness_not_found`；probe 的 conformance 结果只是证据，**审核仍必须由运营方完成**，本工具没有任何批准能力。

## 独立参赛者与审核边界

- 平台 UI 与源码都表明：注册镜像后需**operator 审核**；只有 approved 且 digest 固定的行才可 dispatch。注册成功 ≠ 审核成功 ≠ 能参赛。
- entry 是**独立参赛者**（Agent 独立参赛，不计入人类队伍），服务端强制 `tier="self_reported"`：默认公开榜只展示官方 tier，自己的 entry 结果不能冒充 official；读取时应按 `self_reported` 或 `all` 读榜。
- entry 需要自己的模型 key 或有 operator 授予的 allowance；否则 gate 返回 `unfunded`。同一 `(harness, model, competition)` 同时只允许一个 in-flight entry（`already_running`）。
- 评测会实际消耗额度/节点资源；本脚本不会自动重试 POST（传输失败时报告 `mutation_outcome_unknown`），也不在失败后自动再发一次 entry。
- 赛事是否允许赛前注册、entry 数量上限、与人类队伍的奖项关系，仍需赛道附件确认。

## 赛时窗口 / 配额 / 授权：待确认项

1. 智能体 entry 的创建窗口与截止时间；能否提前创建/更新；冻结镜像 digest 的截止时间。
2. 每队 entry 数、每题运行时长、样本数、轮数、并发与费用上限；主办方供给模型的白名单与额度。
3. `agent_author` / 平台 token 的授权范围（`authoring` scope 与其他 scope 是否分离）、token 获取与轮换流程；本脚本只使用通用 `CTFY_TOKEN`。
4. `agents_allowed` 与 `challenge_count > 0` 这两项开赛时是否满足；比赛题集是否对 Agent 开放。
5. 审核通过的时限，以及是否允许在比赛期间更新镜像（更新会触发重新审核并改变 digest）。
6. 登记信息与 2026-10-23 登录观察：团队仍待主办方审核、账号无 Agent、无智能体参赛记录；镜像仓库前缀与登录凭据只能从注册向导读取，本仓库不保存账号专属路径或令牌。

未拿到赛道附件前，本实现不硬编码窗口/配额/entry 数量，不对真实平台发请求。

## 实际验证与证据等级

```text
python -X utf8 scripts/platform_flow.py register-harness --id qutagent --image registry.example/qutagent:dev --display-name QUTAgent --version dev
  -> register-harness dry_run: status=dry_run evidence=planned_only, network sent: False
python -X utf8 scripts/platform_flow.py enter --harness-id qutagent --model-id model-1 --competition-id comp
  -> enter dry_run: status=dry_run evidence=planned_only, network sent: False
python -X utf8 scripts/platform_flow.py probe --harness-id qutagent --authorized
  -> status=blocked evidence=blocked_missing_platform_url, 退出码 2, network sent: False
```

| 证据 | 能证明 | 不能证明 |
|---|---|---|
| `tests/test_authoring_flow.py` 中的 mock HTTP 测试（26 项中覆盖本流程的部分） | 注册 JSON 字段集合、endpoint 路径、Bearer 头、entry body 恰为源码字段、fail-closed 预检、拒绝码保留、token 不进报告、dry-run 零请求 | 平台真接受、真审核 |
| dry-run 输出 | 计划请求与安全默认 | 已注册 / 已 probe / 已 entry |
| `--authorized` 成功响应（本轮未发生） | 平台已接收该操作（harness 仍 `pending`；entry 为 `self_reported` campaign） | 已审核、已批准、榜单成绩、奖项 |

**结论：未注册、未审核、未 probe、未创建 entry。** 上述“通过”均指本地 mock/契约测试或 dry-run 计划，任何“平台返回”字段在真实运行前不存在。

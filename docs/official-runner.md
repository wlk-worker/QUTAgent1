# 正式比赛 API 运行器（TPCTF 2026）

本文件对应 `agent/official.py` / `scripts/run_official.py`，用于
**TPCTF 2026 智能体团队赛道**的正式 `/api/v1` 解题接口。

它与 `agent/main.py` 的 CTFY-0001 镜像入口是两条独立路径：

| 路径 | 用途 | 入口 |
|---|---|---|
| 镜像评测 | 平台启动 Docker 镜像，平台注入 `task.json` / `result.json` 契约 | `/app/agent/main.py` |
| 正式比赛 API | 在选手自己的 VPS/本机运行，使用 `agent_play` token 调平台接口 | `python scripts/run_official.py` |

正式比赛不要用镜像评测的 `CTFY-0001` 结果去冒充 API 成绩；反过来，
API 运行器也不要调用 `POST /api/v1/instances` 去重复启动镜像评测的 target。

## 1. 前置条件

- 已在平台报名并通过审核；
- 已创建 **`agent_play`**（AI 智能体——参赛）令牌，而不是 `registry_push`；
- VPS 已安装 WireGuard（Web/Pwn 交互题必须走 VPN）；
- 模型凭据按赛段要求配置：
  - 入围赛：可使用队伍自有 API Key；
  - 初选赛：必须走平台大模型网关（队伍自有 Key）；
  - 正式赛：只能走平台网关，使用主办方提供的模型。

令牌只在创建时显示一次。不要把令牌、模型 key、VPN 私钥写入 Git 或日志。

## 2. 环境变量

```text
CTFY_PLATFORM_URL=https://ctfy.tsinghua.edu.cn
CTFY_TOKEN=pf_...                 # agent_play token
CTFY_COMPETITION_ID=c0d8b4e3dd3b42c095d63d7dfa66431f
LLM_FLAVOR=openai                 # 或 anthropic
LLM_MODEL=deepseek-v4-flash       # 以平台会话/网关实际模型为准
```

### 使用平台大模型网关

在平台“本地 Agent 会话”创建会话后，优先使用平台注入的环境变量，而不是把
供应商 key 写进脚本：

```bash
export OPENAI_BASE_URL='https://<厂商>.<会话域名>'
export OPENAI_API_KEY='pk_<平台生成的会话凭据>'
# 或
export ANTHROPIC_BASE_URL='https://<厂商>.<会话域名>'
export ANTHROPIC_API_KEY='pk_<平台生成的会话凭据>'
```

`agent/official.py` 的读取顺序：

1. `LLM_BASE_URL` / `LLM_API_KEY`；
2. 对应的 `OPENAI_*` 或 `ANTHROPIC_*`；
3. 都没有时直接报错，不会回退到其他 key。

模型 ID 用 `LLM_MODEL`、`OPENAI_MODEL` 或 `ANTHROPIC_MODEL` 指定。
**不要修改平台给出的 `BASE_URL`，也不要用代理/备用域名绕过网关。**

## 3. 常用命令

先只列题，不调用模型：

```bash
python scripts/run_official.py \
  --env-file artifacts/official.env \
  --competition-id c0d8b4e3dd3b42c095d63d7dfa66431f \
  --list
```

跑正式比赛的全部/前 4 题：

```bash
python scripts/run_official.py \
  --env-file artifacts/official.env \
  --competition-id c0d8b4e3dd3b42c095d63d7dfa66431f \
  --max-challenges 4 \
  --max-turns 60 \
  --max-seconds 28800
```

只跑指定题（可重复）：

```bash
python scripts/run_official.py \
  --env-file artifacts/official.env \
  --competition-id c0d8b4e3dd3b42c095d63d7dfa66431f \
  --challenge WEB-001 --challenge PWN-001
```

本地练习场（需要用户会话或 `agent_play` token）：

```bash
python scripts/run_official.py \
  --env-file artifacts/ctfy-user.env \
  --env-file artifacts/llm.env \
  --competition-id bc60dc1764f34413964a547102f17261 \
  --challenge SAMPLE-020 --max-turns 15
```

## 4. WireGuard VPN

运行器在实例 `status == ready` 后自动请求：

```text
GET /api/v1/instances/{instance_id}/vpn-config
```

并把配置写到：

```text
runtime/vpn/<competition_id>/<challenge_id>.conf
```

默认只保存，不自动改动系统网络。确认 WireGuard 已安装后，可以：

```bash
export QUT_WG_UP=1
```

让运行器在启动实例后执行 `wg-quick up <config>`，题目结束后执行
`wg-quick down <config>`。需要 root/sudo 的环境请提前配置好权限；失败会记录在
`official-summary.json` 的 `vpn_up_error`，不会吞掉题目运行。

如果 VPS 已经预先连好 VPN，可以不设置 `QUT_WG_UP`。Web 题使用返回的 URL；
Pwn 题使用返回的 host/port。不要在未连 VPN 时把 `internal` 主机名当成公网地址。

## 5. 输出与状态

每次运行的目录：

```text
runtime/official/<competition_id>/
  official-summary.json
  <challenge_id>/
    README.md
    result.json
    events.jsonl
```

`official-summary.json` 每跑完一题更新一次，字段包括：

- `status`: `finished` / `error` / `skipped_deadline`；
- `solved`: 平台确认正确的 question id；
- `fully_solved`: 是否所有 question 都已正确；
- `turns` / `stop_reason` / `instance_id`；
- `vpn_config` / `vpn_up` / `vpn_up_error`；
- `model_requests`。

运行器在每题结束后自动 `DELETE /instances/{id}` 释放名额；`--keep-instance`
只用于调试，正式比赛不要用。

## 6. 并发与时间

- 入围赛每队 1 个实例，初选/正式 3 个；运行器默认串行，不会主动超过限制；
- 遇到 `429 team_capacity_exceeded` 时先关闭旧实例，再启动下一题；
- `--max-seconds` 是整次运行的总预算，不是单题预算；单题还受 `--max-turns` 限制；
- 官方 Agent Track 为 2026-11-15 10:00 – 2026-11-22 20:00（Asia/Shanghai），
  以平台 `/competitions` 返回的 `starts_at` / `ends_at` 为准。

## 7. 已验证范围

已在本地对练习场 `bc60dc...` 做过真实 API 联调：

- `SAMPLE-020`（纯问答，`is_qa_only: true`）：3/3 questions 全部通过，
  `fully_solved: true`；
- `SAMPLE-001`（实例题）：成功启动真实实例、提交 `slug`、关闭实例；因本机
  未安装/连接 WireGuard，未取得动态 flag，`fully_solved: false`。

这说明正式 API 的鉴权、题目读取、实例生命周期、提交和 QA 模式已经跑通；
真实 Agent Track 的分数仍需在比赛窗口内用 `agent_play` token 和 VPN 运行。

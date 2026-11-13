# 2026-11-13 Web/Pwn 练习场验证记录

本次运行使用最新版官方 API runner（`scripts/run_official.py`）和 `agent_play` token，
只测试 Platform Playground（`bc60dc1764f34413964a547102f17261`）中的 Web/Pwn 题目。

## 运行范围

```text
Web:  SAMPLE-006, 007, 008, 009, 019, 022, 023, 024
Pwn:  SAMPLE-016, 021
```

`SAMPLE-001` 已经 fully solved，本轮跳过；reverse/misc/QA 不在本次范围。

## 结果

| 题目 | 类别 | 结果 | 轮次 | 说明 |
|---|---|---|---|---|
| `SAMPLE-016` | pwn | **新解出** | 19 | `flag`，`stop_reason=done` |
| `SAMPLE-022` | web | **新解出** | 40 | `flag`、`gate`，两个 question 全解 |
| `SAMPLE-024` | web | **新解出** | 8 | `flag`，OOB 外带 |
| `SAMPLE-006` | web | 利用成功，提交丢失 | 36 | banner 已 deface，随后 `submit` 返回 `mutation_outcome_unknown`，平台未记解 |
| `SAMPLE-008` | web | 启动失败 | 0 | 实例启动阶段 `mutation_outcome_unknown`，未进入模型 |
| `SAMPLE-021` | pwn | 启动超时 | 0 | `instance_wait_deadline`，未进入模型 |
| `SAMPLE-007` | web | 未解出 | 60 | `turn_limit`，未提交正确结果 |
| `SAMPLE-009` | web | 未解出 | 60 | `turn_limit`，未提交正确结果 |
| `SAMPLE-019` | web | 未解出 | 60 | `turn_limit`，未提交正确结果 |
| `SAMPLE-023` | web | 未解出 | 60 | `turn_limit`，未提交正确结果 |

净新增 **3 道** fully solved：`SAMPLE-016`、`SAMPLE-022`、`SAMPLE-024`。
加上此前的 `SAMPLE-001`、`SAMPLE-020`，练习场已确认 fully solved **5 道**。

## 结论

1. **阶段门和工具配方对简单 Web/Pwn 有效**：`ctf-pwn-triage` 帮助 19 轮解出 pwn check-in；
   多服务 Web 与 OOB 题分别用 40/8 轮解出。
2. **失败分成两类，不能混为一谈**：
   - `SAMPLE-006`、`008`、`021` 是平台实例启动/提交响应丢失；
   - `SAMPLE-007`、`009`、`019`、`023` 是 60 轮内没有完成验证和收敛。
3. **SAMPLE-006 的利用本身是正确的**：agent 已用 `POST /api/banner` +
   `X-Internal-Request: true` 改掉 banner，并用 GET 确认持久化；失败点在提交阶段。
4. 这轮仍不能代表正式赛成绩；练习场 `eval_standard: false`，题目难度与正式比赛不同。

## 后续改进

- 提交可靠性：对 `POST /submissions` 的 `network_error` / `mutation_outcome_unknown`
  做带退避的有限重试，并在重试前读取题目 solved 状态，避免“已利用成功但未记解”。
- 启动可靠性：保留 `QUT_STARTUP_SECONDS` 调大和实例启动后的多次 reconcile；
  对连续启动失败的题单独重跑，而不是当作模型失败。
- 复杂 Web：对 `007/009/019/023` 单题提高 turn/时间预算，先看 `events.jsonl`
  和 `.obs/notes.md` 判断是卡在侦察、验证还是提交。
- 正式赛仍需使用平台模型网关和 WireGuard；不能把练习场的直连 key 带到正式 VPS。

## 原始汇总

```text
runtime/official/bc60dc1764f34413964a547102f17261/official-summary.json
```

该目录被 `.gitignore` 忽略，不提交到仓库。

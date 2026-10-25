# 真实模型实验 Runbook

目标：在固定时间/轮数/请求预算下，用真实模型跑 `labs/` 的授权 Web 靶题，得到可核验的 `experiment.json`（动作、工具观察、提交判定、耗时、token）。**没有真实凭据时保持 `blocked`，不伪造成功率。**

## 1. 准备凭据（不要发到聊天/仓库）

```powershell
Copy-Item artifacts\llm.env.example artifacts\llm.env
# 用编辑器填写 artifacts\llm.env，不要用聊天/命令行 history 传 key
```

`artifacts/` 已 gitignore；`--llm-env-file` 只读取以下变量，值不会回显、不会写入证据：

- `LLM_FLAVOR`：`openai` 或 `anthropic`
- `LLM_MODEL`：平台/供应商的模型 id
- `LLM_API_KEY`：密钥
- `LLM_BASE_URL`：可选，OpenAI/Anthropic 兼容网关

## 2. 运行 validation 集（推荐先跑 3 题）

先检查字段是否齐全（只显示 set/MISSING，不回显值）：

```powershell
python -X utf8 scripts/check_llm_env.py --env-file artifacts\llm.env
```

再运行：

```powershell
python -X utf8 scripts/run_lab.py --model real --set validation --llm-env-file artifacts\llm.env
```

固定预算：`timeout_s=60`、`max_turns=8`、`max_requests=8`（见 `labs/runner.py::EXPERIMENTS`）。单个 case 成功条件：

1. 真实模型通过 `agent/main.py` 的 `/ctf/work` 契约运行；
2. 它用 `http`/`shell` 找到靶题动态 flag；
3. mock CTFy 平台收到并判定 `correct=true`；
4. `result.json` 中 `stop_reason=done`、`fully_solved=true`；
5. `experiment.json` 记录 turns、http_calls、model_requests、tokens、wall_seconds、flag_sha256。

## 3. 看结果

- `artifacts/lab/experiment.json`（最新汇总）
- `artifacts/lab/runs/<experiment_id>/cases/<set-seed>/`：`result.json`、`events.jsonl`、`submissions.jsonl`、`target_requests.jsonl`、`model_calls.jsonl`
- 判断标准：`status=completed` 且 `summary.succeeded/3`；不要只看单题。
- 失败时先看 `stop_reason`（`deadline`/`turn_limit`/`format_error_limit`/`model_error`/`platform_error`）和 `error`，不要直接归因于“模型弱”。

## 4. 常见问题

| 现象 | 处理 |
|---|---|
| `blocked: missing_credentials` | `artifacts/llm.env` 缺字段或路径不对；确认四个键存在且非空 |
| `model HTTP 401/403` | key 与 `LLM_BASE_URL`/`LLM_FLAVOR` 不匹配；不要重试到预算耗尽 |
| `model HTTP 429/5xx` | 代码有有限退避；仍失败时降低并发/换额度，不要硬编码重试 |
| `stop_reason=deadline` | 模型/网关慢或上下文过长；检查 token 用量与 prompt 长度 |
| `format_error_limit` | 模型不遵循 JSON action；检查 gateway 是否支持对应 wire protocol |
| 真实模型成功了但 mock 平台没接受 | 看 `submissions.jsonl` 的 `correct`/`answer_sha256` 与 `target_requests.jsonl`；这通常是答案格式/上下文问题，不是平台 bug |

## 4.1 已完成的真实模型结果（2026-10-25）

模型：DeepSeek `deepseek-flash`（OpenAI 兼容接口）；凭据只在本机 gitignored `artifacts/llm.env`。

| set | 结果 | wall | requests | 备注 |
|---|---|---|---|---|
| validation（路径穿越） | 3/3 | 26.0s | 16 | `real-validation-20261025T122621Z-a71aa6` |
| web-sqli | 3/3 | 50.8s | 32 | `real-web-sqli-20261025T124259Z-ec18bc` |
| web-ssrf | 3/3 | 22.4s | 13 | `real-ssrf-20261025T123345Z-1c7ab0` |
| xss（镜像 Playwright） | 3/3 | 77.0s | 28 | `real-xss-20261025T124051Z-e6a994` |
| pwn（镜像 ret2win） | 3/3 | 43.7s | 24 | `real-pwn-20261025T124212Z-5f7c9f` |
| ai-mcp | 3/3 | 21.4s | 13 | `real-ai-mcp-20261025T123412Z-1f6e9a` |
| ai-mcp-traversal | 3/3 | 27.5s | 12 | `real-ai-mcp-traversal-20261025T123435Z-9bcfb0` |

真实模型也暴露过失败：SQLi 首轮 1/3、XSS 首轮 0/3；修复 JSON 动作提取/空响应重试/SQLi schema 提示/XSS 外带提示后达到上表。失败 run 保留在 `artifacts/lab-real/runs/`。**这些是本地 mock 平台结果，不是真实 CTFy 平台成绩。**

## 5. 之后的真实平台步骤（需要 token/规则）

1. 用 `scripts/platform_flow.py register-harness` 注册 `qutagent:dev`（先 `--authorized`，token 从环境/本地文件读取）；
2. 等运营方审核，确认 `review_status=approved` 且 `approved_digest` 非空；
3. 用 `scripts/platform_flow.py enter` 创建独立 agent entry；
4. 赛时窗口内用 `author/controller.py` 上传题包（如规则要求）。

当前这些真实平台步骤**未执行**：队伍仍待审核、没有 token、赛道规则附件未取得。任何“已上传/已审核/已参赛”的说法都必须有平台响应作为证据。

# TPCTF 2026 / CTFy 规则核对记录

核对日期：2026-10-23（北京时间）重新读取赛事说明、登录后相关页面与 CTFY-0001 v2、CTFY-0002 v1；下方公开配置文件快照仍来自 2026-10-22。本文件区分官方公开标准、页面实时观察、配置快照和仍需赛道附件确认的事项。公开配置可能修改，赛前必须复核。

补充：2026-10-23 约 13:15–13:20 已通过用户登录的 Edge 重新查阅比赛详情、队伍、消息、收件箱、题目、出题、我的智能体及开发者文档。最新结果见 [登录后查阅记录](official-site-review-2026-10-23.md)。队伍仍待审核；账号无 Agent、无智能体参赛记录；未找到独立赛道规则附件下载入口。

## 已由公开官网或 CTFy 标准确认

| 事项 | 当前依据 | 工程含义 |
|---|---|---|
| 智能体团队赛道由同一法人单位不超过 4 人组成；程序独立完成出题与解题，运行期间无人工介入 | [比赛规则](https://ctfy.tsinghua.edu.cn/competitions/c0d8b4e3dd3b42c095d63d7dfa66431f/rules) | 比赛运行进程不能依赖人工临场输入 |
| 智能体赛道**出题**方向限在线交互类 | 同上 | 不能由此推出解题范围也只限在线题 |
| 11 月 15 日初选赛、11 月 21–22 日正式比赛的公开时段 | 同上 | 在实际比赛页面及赛道附件中再次核实 |
| 自定义镜像按 CTFY-0001 读取 `/ctfy/work/task.json`、`README.md`，结果写入 `result.json`，stdout 不作为结果 | [CTFY-0001](https://ctfy.tsinghua.edu.cn/docs/standards/CTFY-0001) §1–3 | 镜像使用绝对路径 ENTRYPOINT、原子写结果 |
| dry run 可能没有平台 token、模型 key 和 mcp.json | CTFY-0001 §3.1 | 不以访问平台作为 dry run 的条件 |
| `LLM_API_KEY` 可能为空；`LLM_BASE_URL` 与 key 配套 | CTFY-0001 §1.1 | 不回退到私人 key |
| `instance` 可启动实例，`qa` 不启动实例；已提供 `target_instance` 时须优先使用 | CTFY-0001 §2 | 分模式处理 |
| 早期 API 提交可得到反馈并解锁 gated questions；`solved` 字段不是计分依据 | CTFY-0001 §3 | 以平台接受的提交为依据，正确后重读题目 |
| `ctfy agent check` 包含清单与本地 dry run 两部分；无 Docker 服务时只能完成清单部分 | CTFY-0001 §7 | 完整合规须官方工具判定 |
| 镜像默认资源边界为 8 GiB 内存、2 CPU、512 pids；实际值由运行任务的 `limits` 给出，互联网访问不保证 | CTFY-0001 §4 | 不硬编码默认值，不在运行期下载依赖 |
| Web/Pwn 上传题需 compose、每队生成答案及参考解；类别枚举未包含 `ai` | [CTFY-0002](https://ctfy.tsinghua.edu.cn/docs/standards/CTFY-0002) §1–6 | AI 安全题归类须赛事确认 |
| `ctfy authoring smoke --local` 会启动目标、执行参考解并核对生成答案 | CTFY-0002 §6.7 | 题包生成不等于可解，必须做 smoke |

## 仅由公开配置快照得到，尚非赛事最终承诺

来源：`_research/ctfy/data/competition.json`，须在登录后与当前比赛详情重核。

| 字段 | 快照值 | 注意 |
|---|---|---|
| `registration_ends_at` | `2026-11-13T12:00:00Z`（北京时间 20:00） | 报名页最终时限以实时状态为准 |
| `format` / `challenges_withheld` | `questions` / `true` | 题目数量、类别和具体题未公开 |
| `internet_policy` / `tcp_access` | `deny` / `tls_sni` | 镜像必须离线具备依赖，TCP 接入以题目给出的服务为准 |
| `max_instances_per_team_effective` | 1（2026-10-23 复核；10-22 快照为 3） | 运行时尊重平台响应和容量限制；不要并发起多个实例 |
| `authoring_windows` | 11 月 21 日 10–12、14–16、18–20 时 | 旧快照中的每窗口一次上传不能作为当前承诺；10 月 23 日 UI 显示最近 2 小时上传上限 5 次、待审最多 3，下一窗口为 11 月 21 日 10:00。窗口配额与上传频率可能是不同限制，尚未核实其关系 |
| `entrants_are_agents` | `false` | 与规则页“AI Agent 独立参与”的文字看似不一致，不能据此推断 entry/成绩归属方式 |
| `ordering` | `flags_solved`、`solved`、`last_solve_at` | 不等于确认所有奖项只按该榜计算 |

## 需赛道附件、登录后页面或组委会明确

1. 镜像提交、人工审核、更新、digest 固定的比赛专属流程和截止时间。
2. 模型白名单、额度、每题运行时长、样本数、轮数和并发数。
3. 解题范围：是否包含离线附件类；具体题数仍被隐藏。
4. 出题是否强制、怎样计分、能否赛前准备模板、出题程序应如何独立运行、`agent_author` token 的授权流程。
5. AI 安全在线题应选用的 CTFY-0002 类别/标签。
6. 智能体 entry 数量、能否提前创建、与人类报名队伍及奖项的关系。
7. 入围测试、晋级人数与正式比赛的运行方式。

需要用户提供的最小材料：登录后可下载的《智能体赛道赛事规则》附件，或其链接/截图；真实平台练习、报名或上传还需相应账号授权。本仓库不会把公开页面无法确认的值写成程序硬编码。

## 当前工程证据与缺口

- `qutagent:dev` 已在 WSL Docker 中构建，`ctfy agent check qutagent:dev --json` 返回 `passed`、`ran_locally: true`、0 findings。这是本地标准检查，不是平台镜像审核。
- 2026-10-23 的最新求解器测试为 WSL 24/24 通过，含入口对模拟模型与平台的 HTTP 闭环、短预算、凭据过滤和 Linux 进程组；原先的 14 项是此前快照。没有真实平台接受答案的证据，详见 [验证记录](verification.md)。
- `document-desk-42/43/44` 三个候选题包由 CTFy 0.7.0 的 `ctfy-admin challenge audit --strict` 检查为 0 issues，`ctfy-admin challenge smoke` 为 3 ok、0 failed；离线流程另生成 seed 45，并严格审计一次、动态 smoke 两次通过。官网 CTFY-0002 文档列出的 `ctfy authoring check/smoke --local` 子命令在当前 PyPI 0.7.0 CLI 中不存在，不能声称执行过它们。
- 登录后的赛事说明页仅以文字提及“智能体赛道附件中的赛事规则文档”，比赛详情、队伍、消息、出题页未显示该附件入口；当前报名状态显示等待主办方审核，附件是否在审核后开放尚不能确认。主办方新闻跳转的页面被浏览器安全策略阻止，未绕过。详情见 [验证记录](verification.md)；G3、G5 仍未验证。

## 2026-10-23 匿名 API 复核

- 报名数由 10-22 的 109 增至 **140**（赛事说明中的上限为 150 支）；报名审核与截止时间未变。
- `max_instances_per_team_effective` 由 3 变为 **1**：agent 不应并发创建实例，遇到容量错误只能退避/串行。
- 比赛说明附件仍为空（`/competitions/{id}/attachments` 返回空列表），`handbook_updated_at` 仍为 2026-10-20；不能在代码中硬编码“附件不存在”或“审核后必然开放”。
- 出题页的实际 UI 曾显示“最近 2 小时最多 5 次上传、最多 3 个待审”，而公开配置快照为“每窗口 1 次、待审 0（平台默认）”；二者可能是不同维度，**不得把任一数字当作计分题数承诺**。赛时以页面实时值和正式附件为准。
- 规则附件、模型额度、镜像提交截止、entry 与奖项归属仍是阻塞项。最小问询清单与可直接发送的询问文本见 [规则询问清单](rules-request.md)。


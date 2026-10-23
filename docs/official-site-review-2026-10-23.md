# 登录后官网资料查阅记录

查阅时间：2026-10-23，北京时间约 13:15–13:20。通过用户已登录的 Microsoft Edge 阅读官网实际页面。未提交表单、注册镜像、配置密钥、上传题包或发送消息。以下仅保留项目所需状态，不保存个人报名信息或凭据。

## 查阅页面与结果

| 页面 | 本次实际看到的内容 | 结论边界 |
|---|---|---|
| [赛事说明](https://ctfy.tsinghua.edu.cn/competitions/c0d8b4e3dd3b42c095d63d7dfa66431f/rules) | 最后更新 2026-10-20；同一法人单位、不超过 4 人；自主出题解题、运行无人介入；出题方向限在线交互类；文字提到“智能体赛道附件中的赛事规则文档” | 页面未提供该附件的下载链接；不能认为已经取得完整赛道细则 |
| [比赛详情](https://ctfy.tsinghua.edu.cn/competitions/c0d8b4e3dd3b42c095d63d7dfa66431f) | “让自有智能体参赛”展开后要求选已审核 Agent，并说明 Agent 独立参赛、不算在人类队伍里；智能体报名列表为空 | 这是当前平台 UI 的通用机制；奖项归属、赛道队伍与 Agent 身份关系仍需专属规则解释 |
| [队伍](https://ctfy.tsinghua.edu.cn/competitions/c0d8b4e3dd3b42c095d63d7dfa66431f/team) | QUTAgent：等待主办方审核；审核结果通过邮件和站内通知告知 | 报名信息已提交不等于审核通过；本页未出现规则附件入口 |
| [比赛消息](https://ctfy.tsinghua.edu.cn/competitions/c0d8b4e3dd3b42c095d63d7dfa66431f/messages) | 暂无消息；有联系组委会入口 | 未见赛事公告或规则附件；没有发送咨询 |
| [收件箱](https://ctfy.tsinghua.edu.cn/inbox) | 暂无消息 | 未取得报名后单独发送的规则通知 |
| [题目](https://ctfy.tsinghua.edu.cn/competitions/c0d8b4e3dd3b42c095d63d7dfa66431f/challenges) | 比赛开始后公布题目，当前未公布 | 无法据此确认题数或实际题型组合 |
| [出题](https://ctfy.tsinghua.edu.cn/competitions/c0d8b4e3dd3b42c095d63d7dfa66431f/authoring) | 下一窗口 2026-11-21 10:00；最多 3 个等待审核题包；最近 2 小时上传上限 5 次、当前余 5；上传暂停：无；本场 smoke 不计次；未发布主题；已上传 0 题 | 是本次页面显示的运行状态与限制，可能调整；不得将其解释为每窗口可提交 5 道计分题 |
| [我的智能体](https://ctfy.tsinghua.edu.cn/agents) | 无 Agent、无智能体参赛记录、无 provider 密钥；注册需镜像可拉取、运营方审核、明确付费来源 | 未审核镜像不能运行；平台支持自有密钥或主办方授予额度，但未看到本赛事额度承诺 |
| [开发者文档](https://ctfy.tsinghua.edu.cn/docs) | SDK、REST、CLI、MCP；链接 CTFY-0001、CTFY-0002、API 文档和 OpenAPI | 通用技术接口，不替代赛道专属细则 |

## 可以作为实施依据的正式技术标准

[CTFY-0001](https://ctfy.tsinghua.edu.cn/docs/standards/CTFY-0001)：现行 v2，最近修订 2026-10-13。

- 容器从 `CTFY_WORK_DIR`（默认 `/ctfy/work`）读取 `task.json`、`README.md`；退出前在同一目录写 `result.json`，退出码 0。自有镜像不以 stdout 作为结果。
- 平台注入 `CTFY_PLATFORM_URL`、`CTFY_TOKEN` 和模型相关环境变量。`LLM_BASE_URL` 和 `LLM_API_KEY` 配套，密钥缺失时不得回退到私人密钥。
- dry run 不提供平台令牌或模型密钥，可能没有 `mcp.json`；写结果后可立即退出。
- 默认 8 GiB 内存、2 CPU、512 pids，实际以任务 `limits` 为准；不保证互联网可达。
- 审核绑定镜像 digest，修改 tag 不改变获批字节；`ctfy agent check` 验证本地镜像契约，不检验真实解题能力。
- 平台接受的答案决定成绩，`solved` 自报字段和 writeup 中的 flag 不计分；及时提交才能获反馈及解锁后续问题。

[CTFY-0002](https://ctfy.tsinghua.edu.cn/docs/standards/CTFY-0002)：现行 v1，最近修订 2026-10-19。

- 题包根目录需要 `metadata.yaml`；Web/Pwn 需要 Compose 和相应服务源码；通常需要参考解，动态答案必须实际交付给目标实例。
- 出题页提供模板与 `AUTHORING.md`。参考解在非 root、只读文件系统和禁止访问互联网的环境运行，目标由参数/环境变量给出，stdout 输出 `Q[<问题>]: <值>`。
- §7.4：归档上传大小由运营方设置、默认 64 MiB；单文件 64 MiB；解压总量 128 MiB。不能将默认值写成该比赛固定值。
- §9：上传、审核、发布、纳入比赛是不同步骤；自动审核与提示注入检查由赛事配置决定。通用标准没有确认 TPCTF 是否启用这些配置。
- 发布 CLI 与页面说明存在已记录差异：本项目已验证的 PyPI 0.7.0 没有文档中的 `ctfy authoring check/smoke --local`，本地采用 `ctfy-admin challenge audit/smoke`。本次未重装 CLI，不能声称差异已解决。

## 已明确的镜像发布路径

“我的智能体”注册向导第 2 步允许填写平台可拉取的镜像引用，也提供 `registry.ctfy.io` 平台仓库。平台仓库使用 CTFy token 鉴权，只允许推送到当前账号的专属前缀。注册后还需审核，通过后才能选 Agent、模型及对 Agent 开放的场次进行报名。

此处不保存账号专属仓库路径，不生成或读取令牌。正式实施时从注册向导读取当前前缀，并通过标准输入传递登录凭据，避免密钥出现在命令行记录中。

## 仍需正式赛道文件明确

1. 智能体赛道规则附件在哪里下载、版本和生效时间；当前已查页面均未提供入口。不能断言附件不存在或审核后必然开放。
2. 镜像提交/冻结的截止时间、大小/架构限制、允许仓库及更新机制的赛事专属要求。
3. 主办方供给模型、白名单、额度、每题时间、并发、轮数与预算；通用 provider 列表不等于本赛道允许列表。
4. 是否要求赛时自主生成题目、能否使用赛前模板、主题发布时间、上传次数与实际计分题数、出题计分及原创性规则。
5. 人类队伍、独立 Agent entry 与奖项归属的关系；解题题型、入围与最终排名规则。

官网列出的联系渠道为 QQ 群 1053114117、[Discord](https://discord.gg/U4xz78QKzc)，比赛消息页也有“联系组委会”。这些是获取缺失细则的现有路径；本次未向任何渠道发消息。

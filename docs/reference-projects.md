# 参考项目与融合记录（2026-10-25）

本文件记录本轮从 GitHub 调研并融合到 QUTAgent 的项目、实际采用的能力，以及刻意没有采用的复杂部分。原则：**不直接搬运第三方代码/payload 库**，只融合流程、提示结构、工具边界和验证方法；具体 payload 由模型针对授权目标生成。

## 1. 已融合

| 项目 | 链接 | 融合到本项目的能力 | 落点 |
|---|---|---|---|
| SWE-agent v0.7（Princeton/Stanford） | https://github.com/SWE-agent/SWE-agent/tree/v0.7 | CTF 配置的 category system/instance 模板；命令文档；`Last5Observations` 历史裁剪；`FormatError` 反馈；`submit`/`exit_forfeit` 终止语义；CTF 辅助命令（decompile/disassemble/debug/connect）的批处理思路 | `agent/skills.py` 分类 playbook；`agent/loop.py` 格式重试/历史压缩；`toolbox/bin/ctf-*`；Pwn playbook |
| ctf-agent（Veria Labs，BSidesSF 2026 冠军） | https://github.com/verialabs/ctf-agent | `ChallengeMeta` 分类；flag 占位符纪律；`LoopDetector` 3 次警告/5 次打断；工具输出截断；web_fetch/文件工具形态 | `agent/skills.py`、`agent/loop.py`；`agent/tools.py::HttpSession` |
| Koshary | https://github.com/ahmedreda38/Koshary | 按 category 组织提示（目标/连接/文件/历史/下一步）；只输出完整 flag；fullpwn 攻击链 | `agent/skills.py` 各分类 playbook |
| AWE（Adaptive Web Exploitation） | https://github.com/stuxlabs/AWE | 每个 Web 漏洞类“基线→差分/确定性确认→利用”的验证门；XSS/SQLi/SSRF/SSTI/命令注入/IDOR 的检测器与记忆思路 | `agent/skills.py::WEB_PLAYBOOK` |
| PwnAI | https://github.com/hal3002/pwnai | reversing→debugging→exploitation 流水线；r2/gdb/pwntools 工具组合 | `agent/skills.py::PWN_PLAYBOOK`；镜像工具链 |
| ctf-agent sandbox / SWE-agent CTF tools | 同上 | 离线 CTF 工具清单（pwntools、r2、gdb、one_gadget、seccomp-tools、sqlmap、ffuf、nuclei、Chromium） | `Dockerfile`、`toolbox/`、`scripts/check_toolchain.py` |
| NYU-LLM-CTF / `nyuctf_agents` | https://github.com/NYU-LLM-CTF/nyuctf_agents | CTF 的 command/observation 循环、分类任务上下文、把工具输出写入工作目录供后续回合读取 | `agent/loop.py` 的 evidence 保留、`http save_as`、`agent/skills.py` 的 Solving protocol |
| EnIGMA（NYU CTF 交互工具研究） | https://github.com/NYU-LLM-CTF/EnIGMA | 交互式工具（调试器/REPL/浏览器）优先于一次性大命令；分类工具选择 | `toolbox/bin/ctf-browse` + `browse` action；Pwn playbook 的 gdb/REPL 流程 |
| OpenHands（All Hands AI） | https://github.com/All-Hands-AI/OpenHands | agent runtime、浏览器/DOM 观察、工具结果事件化 | `browse` action、`events.jsonl`、`HttpSession` 的观察结构 |
| CAI（Cybersecurity AI） | https://github.com/aliasrobotics/cai | 工具权限/作用域分离、安全 agent 的工具表 | `HttpSession` origin allowlist、MCP origin allowlist、shell env allowlist |
| PyRIT（Microsoft） | https://github.com/Azure/PyRIT | prompt injection/越狱策略的测试矩阵、评分与证据 | `AI_PLAYBOOK` 的直接/间接注入、MCP 工具滥用和“模型声明不是证据”门 |
| AgentDojo（ETH Zurich） | https://github.com/ethz-spylab/agentdojo | 间接注入、工具调用攻击、跨信任边界测试 | `AI_PLAYBOOK` 的间接注入、工具参数注入、MCP 工具描述信任边界 |
| Cybench / NYU CTF Bench | https://github.com/NYU-LLM-CTF/NYU_CTF_Bench | CTF 任务分类与评测方法；不引入运行时依赖 | `labs/` 分类靶题和 `docs/verification.md` 的证据边界 |

## 2. 调研但未直接引入运行时依赖

这些项目的**流程/提示/评测方法**已参考，但没有把其完整框架或大依赖装进镜像：

| 项目 | 链接 | 处理方式 |
|---|---|---|
| PyRIT（Microsoft） | https://github.com/Azure/PyRIT | prompt injection 策略用于 `AI_PLAYBOOK`；不引入 Python 框架 |
| AgentDojo（ETH Zurich） | https://github.com/ethz-spylab/agentdojo | 间接注入/工具攻击测试矩阵用于 playbook；不引入基准依赖 |
| CAI（Cybersecurity AI） | https://github.com/aliasrobotics/cai | 工具权限/作用域分离用于 allowlist 设计；不复制其代码 |
| garak（NVIDIA） | https://github.com/NVIDIA/garak | LLM 扫描器，镜像体积/依赖较大，暂不装入 |
| Cybench / XBOW / CyberGym | 见 [验证记录](verification.md) | 评测基准，非运行时依赖；用于训练/练习/对照 |

## 3. 融合后的代码结构

- `agent/skills.py`：分类 + playbook + 工具/flag 纪律；不含 payload。
- `agent/loop.py`：分类 prompt、格式纠错、循环检测、历史压缩、`http`/`mcp` action。
- `agent/tools.py`：无状态 `http_request`（兼容旧行为）+ 有状态 `HttpSession`（Cookie/同源重定向/header 安全）。
- `agent/mcp.py`：纯标准库 MCP JSON-RPC HTTP/SSE 客户端。
- `toolbox/`：镜像内 `ctf-checksec`/`ctf-disasm`/`ctf-debug`/`ctf-strings`。
- `Dockerfile`：构建期装入 Web/Pwn/AI 工具链；评测期离线。

## 4. 证据与边界

- 能力融合的证据：`python -X utf8 -m unittest discover -s tests -v` → 158 项 OK（Windows 4 skip）；镜像内同一套件 158/158（3 skip）；假模型靶题 3/3（Windows 与镜像内，含 SQLi/XSS/Pwn/SSRF/AI-MCP/MCP 工具穿越）。
- 真实 DeepSeek `deepseek-flash` 已在本地 7 个 set 上各 3/3；这仍不是真实 CTFy 平台成绩，不能替代平台接受记录。
- 任何第三方项目的安全工具只能在赛事明确授权的范围内使用；本仓库的 `labs/` 是合成靶题。

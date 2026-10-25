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

## 2. 调研但未直接融合（避免过度工程/依赖）

| 项目 | 链接 | 原因 |
|---|---|---|
| PyRIT（Microsoft） | https://github.com/Azure/PyRIT | 面向 LLM 红队的完整框架；当前 AI 安全题用 `HttpSession` + MCP 客户端 + playbook 已能覆盖主要交互，暂不引入大依赖 |
| garak（NVIDIA） | https://github.com/NVIDIA/garak | 偏 LLM 扫描器；镜像体积/依赖较大，暂不装入 |
| AgentDojo | https://github.com/ethz-spylab/agentdojo | prompt injection 评测基准；可作为后续 AI 安全练习集，不影响赛时 agent |
| CAI（Cybersecurity AI） | https://github.com/aliasrobotics/cai | 通用安全 agent 框架；其工具/权限分离思路已参考，未复制其代码 |
| Cybench / XBOW / CyberGym | 见 [验证记录](verification.md) | 评测基准，非运行时依赖；用于训练/练习/对照 |

## 3. 融合后的代码结构

- `agent/skills.py`：分类 + playbook + 工具/flag 纪律；不含 payload。
- `agent/loop.py`：分类 prompt、格式纠错、循环检测、历史压缩、`http`/`mcp` action。
- `agent/tools.py`：无状态 `http_request`（兼容旧行为）+ 有状态 `HttpSession`（Cookie/同源重定向/header 安全）。
- `agent/mcp.py`：纯标准库 MCP JSON-RPC HTTP/SSE 客户端。
- `toolbox/`：镜像内 `ctf-checksec`/`ctf-disasm`/`ctf-debug`/`ctf-strings`。
- `Dockerfile`：构建期装入 Web/Pwn/AI 工具链；评测期离线。

## 4. 证据与边界

- 能力融合的证据：`python -X utf8 -m unittest discover -s tests -v` → 144 项 OK（Windows 4 skip）；镜像内同一套件 144/144（3 skip）；假模型靶题 3/3（Windows 与镜像内，含 SQLi/MCP/Pwn/XSS/MCP 工具穿越）。
- 这些证据**不证明真实模型解题能力**，也不证明平台接受；真实模型实验仍因无 `LLM_*` 凭据 `blocked`。
- 任何第三方项目的安全工具只能在赛事明确授权的范围内使用；本仓库的 `labs/` 是合成靶题。

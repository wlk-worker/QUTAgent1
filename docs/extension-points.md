# 队友扩展入口与边界

## 运行路径

`Dockerfile` 启动 `agent/main.py` → `agent/contract.py` 读取 `CTFY_WORK_DIR/task.json` 与 `README.md` → `agent/main.py` 根据 `run_mode` 分流 → `agent/loop.py` 调度模型和工具 → `agent/contract.py` 原子写回 `result.json`。

本地无密钥检查：`python scripts/run_local.py`。完整镜像检查：构建镜像后运行 `ctfy agent check <image> --json`；必须看到本地运行检查通过，不能只看 manifest 检查。此检查不证明能解题。

## 协作分工建议

| 改动范围 | 负责内容 | 合并前应验证 |
|---|---|---|
| `agent/contract.py`、`agent/main.py`、`Dockerfile` | CTFY-0001 输入输出、入口和异常结果 | 本地 dry run、契约测试、官方镜像检查 |
| `agent/platform.py` | 平台 REST 适配与反馈、轮询 | 用官方标准/当前 SDK 对照请求字段，跑模拟接口测试 |
| `agent/model.py`、`agent/loop.py`、`agent/state.py` | 模型调用、动作决策、完成判定 | 注入假模型/假平台测试；不得从私人密钥回退，不得把空待答队列当成功 |
| `agent/budget.py`、`agent/security.py`、`agent/tools.py` | 总预算、输出脱敏、命令执行与进程组清理 | 在 Linux 跑慢请求、假密钥、超时子进程和大输出测试 |
| `author/` | 独立出题候选包，尚非赛时出题控制器 | 严格审计与动态 smoke；不能称为比赛审核 |

优先通过模块边界添加能力，保持 `agent/main.py` 的入口稳定。对尚未实现的 `run_mode` 明确返回不支持；不要在没有赛道规则时猜测赛时出题上传协议。新平台字段要写明对应的官网标准版本，保留可复现的模拟测试。

队友复核顺序：`python3 -m unittest discover -s tests -v` → `python3 scripts/run_local.py` → `docker build --pull=false --platform linux/amd64 -t qutagent:dev .` → `ctfy agent check qutagent:dev --json`。镜像基础 Web 工具可用 `scripts/check_web_tools.py` 按 README 中的 Docker 命令单独检查。`agent/state.py` 新增平台状态映射时，应同时补误判完成的回归场景；`agent/platform.py` 新增 POST 时，应先设计响应不确定后的只读核对方法。

## 当前适配层和待确认点

`agent/contract.py` 是 CTFY-0001 v2 文件边界；`agent/platform.py` 是已公开 REST/SDK 字段的薄适配层。当前求解循环仅处理 `instance` 和 `qa`，其余模式在 `agent/main.py` 返回 `unsupported_or_missing_task`。`author/` 只做赛前离线候选题包生成和验证，没有赛时上传接口。

赛事说明提及的智能体赛道附件尚未核实。镜像注册/提交方式、模型与时间额度、是否强制赛时自主出题及上传接口、解题题型范围、计分与奖项规则，应在拿到附件或平台正式通知后逐项落实；清单见 [规则审计](rules-audit.md)。任何与公开 CTFY-0001/0002 不同的赛道专属流程，先补依据，再改适配层。

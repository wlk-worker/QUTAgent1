# 本地 dry run 示例

此目录是开发者自建的最小测试输入，不是比赛平台下发的真实任务。`task.json` 只使用 CTFY-0001 v3 已公开的 `schema_version` 和 `dry_run` 字段。

运行 `python scripts/run_local.py`；脚本把此目录复制到临时工作目录，以真实入口启动一次，再检查 `result.json`。实际赛事运行时由平台提供 `/ctfy/work` 和环境变量，不读取这个示例目录。

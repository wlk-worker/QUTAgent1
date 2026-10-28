# 把 Agent 镜像上传到 CTFy 并创建测评

本页记录 2026-10-28 从登录后的 CTFy 页面（`/evals/new?target=...`）实际看到的流程。**不是官方规则文档**；官方规则仍在“智能体赛道附件”中，尚未取得。

## 1. 生成 registry push token

平台镜像仓库 `registry.ctfy.io` 用 **CTFy API token** 作为 Docker 密码，不是 DeepSeek key。

Edge：

1. `https://ctfy.tsinghua.edu.cn/settings` → **API 令牌**
2. **生成新令牌**
3. 模板选 **推送智能体镜像**（权限：`profile: read`, `registry: write`）
4. 起名、选有效期、创建
5. 平台要求再次输入账号密码；成功后**明文 token 只显示一次**，立即复制

如果已有“AI agent”token 且权限包含 `registry: write`，也可直接用；页面上的旧 token 只显示前缀，不能恢复明文。

## 2. 填本地 env 文件

`artifacts/ctfy.env` 已 gitignored：

```ini
CTFY_PLATFORM_URL=https://ctfy.tsinghua.edu.cn
CTFY_TOKEN=<registry push token>
CTFY_REGISTRY_NAMESPACE=<页面 /evals/new 显示的 registry.ctfy.io/ 后的前缀>
CTFY_REGISTRY=registry.ctfy.io
CTFY_REGISTRY_USER=qutagent
```

## 3. push 镜像

WSL/Linux：

```bash
scripts/push_image.sh artifacts/ctfy.env qutagent:dev v1
```

脚本只读取 `CTFY_*`，不打印 token；等价手动命令：

```bash
docker login registry.ctfy.io -u qutagent --password-stdin
docker tag qutagent:dev registry.ctfy.io/<namespace>/qutagent:v1
docker push registry.ctfy.io/<namespace>/qutagent:v1
```

镜像为 `linux/amd64`，入口 `/app/agent/main.py`，本地已通过：

```bash
ctfy agent check qutagent:dev
```

推送后建议再检查 registry 引用（需要 registry 登录态）：

```bash
ctfy agent check registry.ctfy.io/<namespace>/qutagent:v1
```

## 4. 在网页创建测评

打开（target 来自页面参数）：

```text
https://ctfy.tsinghua.edu.cn/evals/new?target=d35cc057773c44f79eec192b54551327
```

1. **镜像地址**：`registry.ctfy.io/<namespace>/qutagent:v1`
2. **模型**：选择平台提供的模型
3. **开始**：页面提示“最后一步之前不会运行任何东西”；确认后平台拉取镜像并运行

页面当前 target 为 **CYBENCH**；不同 target 可能对应不同评测集。是否允许完整测评/需要访问批准，以页面提示为准。

## 5. 安全边界

- 不把 token 写进镜像、Git、文档或聊天；
- 不用 `docker login -p` 在命令行明文传 token（会进 shell history/process list）；
- `artifacts/` 是 gitignored；
- 本地真实模型 key（`artifacts/llm.env`）与 CTFy token 是两套凭据，不能混用。

## 6. 当前状态

- 本地镜像已 tag 为 `registry.ctfy.io/<namespace>/qutagent:v1`；
- 尚未 `docker login`/`docker push`，因为 `artifacts/ctfy.env` 的 `CTFY_TOKEN` 仍为空；
- 平台 token 创建需要账号密码二次确认，不能替用户输入；
- 填好 token 后运行 `scripts/push_image.sh`，再到网页填镜像地址即可。

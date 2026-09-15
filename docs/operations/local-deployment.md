# 本机配置、代码发布与证据

> 类型：操作规程。范围：已有网络的管理配置、代码快速发布和证据存放。
> 网络协议见[控制面规范](../distributed-control-plane.md)；源码能力见[实现对照](../implementation.md)。
> 当前任务明确授权发布时才执行发布步骤。文档整理、参数迁移和 `--plan` 不代表生产发布。

## 信息放在哪里

| 内容 | 正式来源 | 维护方式 |
|---|---|---|
| 发布节点别名、路径及发布参数 | 仓库根 `.env` | 本机私有输入；模板见[.env.example](../../.env.example)，禁止提交真实值 |
| SSH 地址、用户、跳板和身份文件 | `.ssh_config` | 环境文件引用它，不再复制一份连接地址表 |
| 网络成员、职责、授权 | 既有 SSOT / certified authority | 发布目标列表不能替代网络授权或变更 Head |
| 签名密钥、CA 和管理员材料 | 既有受保护密钥/证书目录 | 环境文件只保存定位路径；保留原网络和身份 |
| 放行的制品及签名发布状态 | `LOOM_RELEASE_DIR`、分发目录和 `LOOM_PUBLISH_HISTORY` | 由 `loom release` / `loom publish` 管理；不靠手写状态文档重建 |
| 实际激活结果、必要的实机证据 | `deploy/evidence/` 或 `LOOM_ACCEPTANCE_DIR` | 原始回执须标明提交、制品、操作范围和结果；旧回执不证明当前仍在运行 |
| 可再生构建与开发检查输出 | `out/` / `dist/` | 不作为唯一恢复来源；过期且无用途时清理 |

源码、工具和配置模板分别归对应模块、`scripts/` 与测试 fixture，不能放进文档或证据目录。
历史流水账不承担现状查询；当前缺口在实现对照中原位更新，设计理由进入具体决策记录。

## 环境文件契约

正式消费者是 [deploy-code](../../scripts/deploy-code/)。它把 `.env` 当数据解析，拒绝重复键和无效部署参数，
不执行 `source` / `eval`，不展开命令或变量，不将 DNS token 传给子命令。路径相对 `.env` 所在目录解析。

| 参数 | 含义 |
|---|---|
| `LOOM_DEPLOY_HOSTS` | 空格分隔的部署节点别名，必须与当前源码支持的 SSOT 发布范围一致 |
| `LOOM_LOCAL_NODE` | 构建/控制本机对应的节点别名；全远端发布时为空 |
| `LOOM_SSH_CONFIG` | SSH 配置文件 |
| `LOOM_DEPLOY_SOURCE` | 当前受管网络的 SSOT 输入路径 |
| `LOOM_RELEASE_DIR` | 与 publisher 相同的制品放行目录 |
| `LOOM_SIGNING_KEY` | 既有平台签名私钥文件路径 |
| `LOOM_PUBLISH_OUTPUTS` | JSON 字符串数组，沿用实际 publisher 的本地及 SSH 分发目标；至少有一个本地目录用于验签 |
| `LOOM_PUBLISH_HISTORY` / `LOOM_PIN_DIR` | 与 publisher 相同的历史及 pin 目录 |
| `LOOM_DEPLOY_COMMAND` | 执行正式 `release` / `publish` 的 Loom 程序路径 |

`LOOM_ADMIN_DIR`、`LOOM_CONTROL_STATE_DIR`、`LOOM_ACCEPTANCE_DIR` 和 `LOOM_CONTROL_WORKTREE`
只定位管理员交付材料、控制状态、已有验收产物及其他实现工作区。它们不自动授权访问、修改 daemon
配置或宣称另一工作区已经合入；调用对应 CLI 时显式使用相应参数。

新增机器或换配置时从模板填写；已有 `.env` 应保留原凭据并只更新相关键。文件使用 `0600` 权限。
本仓库版本的 `loom backup` 默认包含 `.env`、`.ssh_config` 和精选 `deploy/evidence/`，继续使用既有加密备份或
显式受信任明文边界。已安装旧程序不会因源码更新而改变；需要使用本版本规则时可从仓库运行
`go run ./cmd/loom backup` 并提供正常备份参数。外部路径上的身份和控制状态仍须按[控制面备份规程](../control-plane-operations.md)成组备份，
保存路径字符串不能代替备份文件内容。

## 代码发布

默认范围包括 Linux 生产代码和嵌入二进制的 Web UI / favicon。由所选精确、干净 commit 只构建一次制品，
本机和远端使用同一份字节。Android 双包另按[交付规程](../android-client-delivery-prompt.md)执行。

先以现成制品进行本地计划检查：

```bash
go run ./scripts/deploy-code --env .env --commit "$release_commit" \
  --binary dist/loom-linux-amd64 --reason "本次已审核修改" --plan
```

`release_commit` 必须是构建该制品的完整提交。`--plan` 检查配置、节点集合、SSH 别名、制品与签名材料，
不执行发布或连接节点。实际已获授权的发布使用相同参数去掉 `--plan`，工具依次执行：

1. 用正式 `loom release` 放行指定制品，立即用一次性 `loom publish` 固化 signed current。
2. 验证本地分发树的签名 current、节点 assignment、manifest 与制品绑定；pin 仍指向旧制品时拒绝直发。
3. 对当前节点并行 SSH/SCP，写入 `/usr/local/bin/loom` 同目录临时文件，校验 SHA-256 后原子替换。
4. 本机也安装同一制品；每个节点只重启实际运行的 Loom 常驻服务。哪个节点命令失败，就报告哪个节点。

发布完成后，工具在既有发布事务锁内重读 pin、放行记录及 signed current，再完成激活；
如果授权已改变或另一个事务持锁，明确失败，不轮询等待，也不覆盖为过时制品。

v1 `reverse_only` 只约束相关 WireGuard 边的发起方向，v2 则按每条 link intent 固定发起方、transport
与可达性。它们都不能推导管理 SSH 是否可达，也不能成为等待节点 pull 的理由。

默认只等待 SSH/SCP/激活命令返回，不额外探测 SSH、不等 publisher/pull 轮询、不做全网收敛检查。
变更要求的正常业务验收按本次范围执行；仅 favicon 等静态资源变化不默认启动 headless 浏览器。
signed release/pull 继续提供持久记录、离线补齐与纠偏，快速发布不能绕过 SSOT、秘密或签名边界。

## DNS 凭据、NAT 与 Linux 安装

- Gandi LiveDNS Personal Access Token 由根 `.env` 的 `GANDI_PAT_TOKEN` 提供，用于受限记录管理和 ACME DNS-01。
  仅检查进程环境会漏掉尚未导出的 `.env`；需要时先只判断声明存在：

  ```bash
  grep -Eq '^[[:space:]]*(export[[:space:]]+)?GANDI_PAT_TOKEN=' .env
  ```

  实际值由目标进程的受保护 dotenv/环境边界注入，不输出、不启用 `set -x`，不放进命令参数、tracked 文件、日志或证据。
  代码发布工具不负责 DNS 修改，读取环境配置不意味着已接通 DNS provider。
- NAT/光猫/路由器管理不属于开发或验收范围。只按操作者提供的 signed public/local tuple 从外部验证真实流量；
  禁止登录网关、调用 UPnP/NAT-PMP/供应商接口修改映射。丢映射、池耗尽、协议和 offset 错误使用合成 intent 与故障注入验证。
- Linux 管理 SSH 与 Enrollment 独立。SSH/ProxyJump 可达时由操作者运行页面上的同一 shell bootstrap；
  不可达时通过云控制台、串口/IPMI 或本地终端执行，由节点主动访问 distribution/bootstrap/私有 Enrollment。
  控制面不保存 SSH 地址、账号或密钥；不能根据 direction/NAT 类型推断管理连通性。
- `forward` Device 安装完成与公网 listener 就绪分别显示。外部 tuple 尚未验证时保留 `preparing`，不 advertise endpoint；
  仅提示检查主机防火墙、确认既有映射或重新创建不含 `forward` 的 Device，不静默降级、不扫描邻近端口。

## 证据保留与清理

保留仍支撑当前交付验收、身份恢复或故障定位的原始结果，并写清采集对象、提交和制品；原始报告失败也必须如实保留。
一次发布的回执只证明当次命令结果，签名 current 只证明已发布意图，都不能单独证明节点现在运行该版本。
需要当前结论时按任务范围核对实际激活版本和正常业务结果，不自动扩大为全网轮询。

旧制品、重复配置树、临时证书、缓存和已失效协议的验收程序在确认无依赖后删除。
设备恢复包进入相应平台的受保护备份目录；精选证据中不得混入可执行脚本和操作密钥。
开发检查默认输出 `out/evidence/`；需要作为正式交付证据时，连同精确提交、制品及适用范围收录到受保护的验收目录。

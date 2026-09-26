# 本机部署配置模型

[设计入口](../README.md) · [白名单](../migration-whitelist.md)

仓库根 `.env` 保留，用来描述**这台管理工作站如何找到并部署现有节点**，并保留操作者明确要求的
Gandi provider token。它是本机私有输入，
不是控制面 SSOT、认证状态、daemon 运行状态、发布历史、验收证据或临时操作记录。节点稳定身份与职责的
认证绑定、`ControlConfig` 成员关系、`EndpointGeneration`、`TransportResource`、显式 `NetworkLink`
及其授权来自已验证的签名事实所确定的 `Projection`；本机监听与私钥由节点受保护的运行输入提供。
`.env` 不能创建或修改这些事实。

本文只定义仓库根 `.env`。节点上的 systemd environment 和 Android 签名文件各有独立消费者与权限边界，
不得合并进根文件。`GANDI_PAT_TOKEN` 是唯一例外：它保留在根文件，但当前核心服务不会读取或使用它。

## 一个领域实体

本模型只有一个有生命周期的领域实体：`LocalDeploymentConfig`。

```text
LocalDeploymentConfig {
  deploy_hosts    set<NodeAlias>
  local_node      optional<NodeAlias>
  ssh_config      AnchoredPath
  publish_outputs set<PublishTarget>
  signing_key     SecretRef
  gandi_pat_token optional<SecretValue>
}
```

`NodeAlias`、`AnchoredPath`、`PublishTarget`、`SecretRef` 和 `SecretValue` 只是经过校验的值类型，不拥有状态机。
删除 `LocalDeploymentConfig` 会使管理工作站无法确定发布范围、SSH 映射和签名/分发位置；增加第二个
inventory、目录配置或 credential store 则只会制造冲突，因此都不允许。

字段语义如下：

| 字段 | 保存的事实 | 不保存的事实 |
|---|---|---|
| `deploy_hosts` | 本机获准尝试部署的节点别名集合 | `ControlConfig` 成员、设备职责、在线状态或可达性 |
| `local_node` | 若构建机也是部署目标，其对应别名 | control leader、权威写入者或默认出口 |
| `ssh_config` | `.ssh_config` 的定位路径 | SSH 地址、用户、跳板、密钥正文 |
| `publish_outputs` | immutable release 的分发目标 | 已发布、已激活或已验收结论 |
| `signing_key` | 签名能力的路径或不透明引用 | 私钥正文、解锁口令或 shell 命令 |
| `gandi_pat_token` | Gandi API 的不透明 secret，供独立 DNS 工作项以后使用 | 当前 DNS 状态、证书状态或执行授权 |

真实节点地址、用户、ProxyJump 和 SSH identity 只写入被引用的 `.ssh_config`；网络节点及权限来自
已验证的 `Projection`。三者以同一个稳定 `NodeAlias` 联结，但没有谁能从另外两者反向生成。

## 长期变量白名单

当前根 `.env` 只接受以下六个既有键。它是受限 dotenv 数据，不是 shell 脚本；解析器只识别
单行 assignment，不执行 `source`、`eval`、命令替换、变量展开或转义拼接。

| 键 | 类型 | 必填 | 规则 |
|---|---|---:|---|
| `GANDI_PAT_TOKEN` | opaque secret | 当前部署保留 | 非空；只允许独立 DNS executor 显式读取，其他命令不得导出或透传 |
| `LOOM_DEPLOY_HOSTS` | `NodeAlias` 列表 | 是 | 非空、去重；语义上是集合，不表达优先级 |
| `LOOM_LOCAL_NODE` | `NodeAlias` | 否 | 非空时必须属于 `LOOM_DEPLOY_HOSTS` |
| `LOOM_SSH_CONFIG` | path | 否 | 默认 `.ssh_config`，相对路径以 `.env` 所在目录为锚点 |
| `LOOM_SIGNING_KEY` | path/ref | 是 | 只允许受支持的文件路径或硬件/secret-store 引用，不允许私钥正文 |
| `LOOM_PUBLISH_OUTPUTS` | target 列表 | 是 | 非空、去重，只允许已定义的 local/SSH target |

规范编码沿用现有最小格式：`GANDI_PAT_TOKEN` 是不带换行的安全 token；其余值使用单引号包围，
`LOOM_DEPLOY_HOSTS` 以 ASCII 空白分隔别名，`LOOM_PUBLISH_OUTPUTS` 以逗号分隔目标。别名和目标内部
不得含分隔符。decoder 只接受上表当前六键的规范顺序和规范排序集合；旧顺序须由一次性迁移器
重写，不能作为常驻读取兼容。encoder 按同一顺序输出。

节点顺序不表达优先级。解析后按规范别名排序，发布执行可以并行；某个节点失败只形成该次操作结果，
不得回写列表或把节点永久标成不可用。

release、history、pin、admin、imports、evidence、control data 和 client release store 的路径由
仓库布局、packaging 或对应一次性命令确定，不再各设环境变量。

Linux 节点从认证 `NetworkIntent` 内的 `TransportResource` 投影 WG、Hy2 或现有私有
TLS tunnel 的共享传输资源；显式 `NetworkLink` 只描述获授权的中继邻接，不承担每个设备的首跳或管理连接。
资源 ID、公开端点和允许的下一跳是认证数据，不是本机 `.env` 值。
本机仅保存资源执行所需的私钥、已有证书和启动成员验证所需的受保护定位输入。
定位输入不授予成员资格或业务权限，必须在建立资源后同认证节点身份核对，也不能倒写 Projection。

WG 资源由 HostAdapter 在节点本机事务安装 interface、peer、精确地址与路由；Linux 私钥固定为
`/etc/wireguard/node.key`，权限 `0600`、root 持有。Ubuntu 的 `wg` AppArmor profile 只允许读取
`/etc/wireguard/**`，因此短期 rollback config 只能在 `/etc/wireguard/.loom-rollback-*` 中以
`0700/0600` 创建，事务提交或回滚后删除；不得移到 `/tmp`、`/run` 或 `/etc/loom/secrets`，
也不得放宽 AppArmor。

Hy2 资源由节点的受保护本机证书、私钥与连接凭据引用执行；认证 `TransportResource` 只携带
可公开验证的节点身份和资源参数，不携带私钥路径、私钥正文或口令。现有 Linux 转发/出网数据面
适配器默认从 `/etc/loom/tls/node.crt` 与 `/etc/loom/tls/node.key` 读取 TLS 材料；该默认位置
不成为新资源的规范字段或所有节点的固定路径。对端按认证节点 ID、证书身份和该用途的授权校验；
按 access/policy 派生的业务用户密码不能充当 control 成员身份。现有私有 TLS tunnel 的
本机成员 TLS leaf/key 保存在受保护的 `node.json`，其成员身份仍由 `ControlConfig` 验证。
这些都是适配器的本机执行输入，不进入根 `.env`、公开 Artifact 或 Web，也不形成资源权威。

`.env` 必须是普通文件、权限不宽于 `0600`，且不得指向工作区外未经操作者明确选择的软链接。
它可以随受保护备份保存，但不能进入 Git、日志、证据正文、Web 响应或子进程的完整环境。

## 同构边界

设领域值为 `D`，规范 `.env` 字节为 `E`，`.env` 所在目录为锚点 `A`，临时 typed config 为 `T`：

```text
decode_env(encode_env(D, A), A) = D
typed(decode_env(E, A))         = T
domain(T)                       = D
encode_env(decode_env(E, A), A) = E             // E 是被接受的规范字节
```

相对路径在 `A` 下规范化；`encode_env` 按上表固定顺序输出键、按规范顺序输出集合，并显式写出默认值。
因此同一领域配置只有一种规范字节表示。`decode_env` 对未知键、重复键、重复集合项、未知 target、
空别名、控制字符、命令替换、变量展开和换行失败，不能静默忽略“别的工具的变量”。
`GANDI_PAT_TOKEN` 的原文参与往返但在日志、错误、plan 和 UI 中始终以 secret 处理。

只有 domain ↔ env ↔ typed config 是可逆的。下列关系都是单向投影：

```text
DeployPlan = plan(LocalDeploymentConfig, ControlConfig, Projection, Release, OperationInput)
RunResult  = execute(DeployPlan, SSHResolver, LocalHost)
UIStatus   = redact(DeployPlan, RunResult)
```

`DeployPlan`、`RunResult` 和 `UIStatus` 都不能反推或覆盖 `.env`。发布历史由签名 release store 保存，
激活回执与业务验收写入受保护证据；进程退出后 typed config 可以丢弃并重新加载。

| 层 | 表达 | 是否可逆回领域值 | 边界 |
|---|---|---:|---|
| domain | `LocalDeploymentConfig` | 是 | 本机部署输入的唯一语义 |
| env wire | 六个规范 dotenv assignment | 是 | `0600` 私有文件；未知键失败 |
| typed config | 六个已校验字段及派生路径 | 是 | 仅存在于一次命令进程内 |
| persistent result | release store、pin、history、evidence | 否 | 保存操作结果，不保存另一份 config |
| runtime | `DeployPlan`、逐节点 `RunResult` | 否 | 同一 config 仍会因当前认证事实、制品和本次操作不同而变化 |
| UI | redacted readiness/result | 否 | 不显示 path/ref，不提供整份配置写回 |

## 节点信息与权威状态的连接

正常部署前执行一次严格 join：

```text
LocalDeploymentConfig.deploy_hosts
  ├─ 每个远端别名必须能由 .ssh_config 精确解析
  ├─ local_node 只允许命中当前机器且不走 SSH
  └─ 每个别名必须命中本次有效成员表与签名事实所确定的 Projection 中允许部署的同一节点
```

`.env` 表示“这台工作站准备操作哪些节点”，Projection 表示“当前权威允许哪些节点接受什么配置”。
两者不一致时整次计划失败，不取交集、不自动补节点，也不改变 control membership。`reverse_only`、
公网 ingress 声明和客户端路径观测均不能推导 SSH 可达性；SSH 失败也不能改变这些认证事实。

## 正常加载与执行链

1. 操作者为命令显式选择 `.env`；工具检查文件类型、owner 和权限。
2. strict parser 只读取六个白名单键，生成规范 `LocalDeploymentConfig`；进程环境不覆盖文件值，也不把 Gandi token 注入普通子进程。
3. resolver 读取所指 `.ssh_config`，只解析本次节点别名，不复制连接信息到领域状态。
4. 工具通过私有认证入口验证当前成员表链、相关签名事实与 `Projection`，并完成节点 join。
5. 操作者为本次命令显式提供精确 commit、制品和操作理由；工具验证 release 与签名引用。
6. planner 产生一个可脱敏回读的 `DeployPlan`；只有获得本次发布授权后才执行。
7. executor 发布同一制品并记录每个目标的真实结果；证据、LKG 和 UI 从结果投影，不回写 `.env`。

读取配置、生成 plan 或显示 readiness 都不构成生产发布授权。配置陈旧只会让下一次命令失败，不能改变
已经运行的 daemon。

常驻 publisher 使用同一个严格 loader：`loom publisher -env <path> -control-socket <path>` 只从
`LocalDeploymentConfig` 取得 signing key 引用、publish targets 与 SSH config，不能再同时传
`-key`、`-target` 或 `-ssh-config` 形成第二份输入。分发后的读取验证 URL 不来自 `.env`，而随当前
认证的 `NetworkIntent.nodes[].distribution_urls` 进入 `PublisherInput`；因此事实前沿变化时
验证集合也原子变化，旧 systemd unit 中手写的 URL 不能继续成为发布事实。

## 失败语义

- 配置文件缺失、权限过宽、未知/重复键或非法值：在读取其他私有材料前失败；
- 节点别名缺少 SSH 映射、与 Projection 不符或本机别名错误：整次计划失败，不做部分发布；
- signing key ref 无法解析：失败关闭，不提示或回显秘密正文，不尝试把字符串当命令执行；
- Gandi token 缺失不阻塞核心重建；独立 DNS executor 被显式调用时若缺失则失败关闭，且不得回显；
- 分发目标重复、不可解析或缺少可验证的本地目标：计划失败，旧 signed current 保持不变；
- 尚未实现的能力出现配置键：报告该阶段未激活并拒绝，不能先永久保留“以后可能用到”的变量；
- 运行中单节点失败：保留逐节点结果并停止宣称整体激活，但不删除节点、不改 authority、不循环探测全网。

## 阶段输入不是常驻配置

首次 bootstrap、恢复 custody、一次性 request ID、传输资源的本机密钥、listener 端口和
WG 地址都不进入长期 `.env`：

- bundle、custody/key ref 和一次性 request ID 由对应命令参数或受保护输入文件提供；事务开始后写入其
  正式 store，resume 读取同一事务；
- control 成员资格与验证键只来自有效 `ControlConfig`；`TransportResource` 提供可复用的数据及私有服务承载，
  `NetworkLink` 仅授权指定的中继邻接。control 差量同步、成员管理、设备配置与报告使用各自端到端身份认证，
  可复用现有传输，不以创建 `NetworkLink` 为前提，也不各自维护邻居或新开公网端口。本机 listener 与引导定位
  由节点受保护的安装输入提供，不能由旧 report 配置或根 `.env` 反推成员和链路权威；
- 首次受限 bootstrap 使用认证 `EndpointGeneration` 的地址、TLS/SPKI 和 capability 边界，
  不依赖设备尚未取得的共享资源；事务完成后的设备认证入口使用同一 generation 的设备认证模式，
  不重复消费 capability。数据入口失效时，设备仍可在端到端认证的私有服务上领取由当前签名事实和
  `DeviceAuthorization` 确定的修复 `DeviceView`、报告 unknown；它不接受旧协议或形成第二份权威。
  设备配置与报告可在获授权的共享传输上承载，无需显式中继 `NetworkLink`。
  `EndpointGeneration` 仍决定对应私有服务入口的身份和生命周期，而非各配一套端口；
- 公网 DNS provider 与 ACME 自动签发/续期不属于当前核心范围；`.loom` 精确 overlay DNS 记录来自认证网络意图。
  `GANDI_PAT_TOKEN` 只为保留既有操作者配置而常驻；以后启用时仅由获授权的
  隔离 executor 按需读取。它的存在不表示当前允许修改 DNS、签发或续期证书；
- 某阶段尚未实现时，其 parser 和 key 都不存在。实现、正常入口和清理规则一起交付后才激活该输入。

这保证“按阶段启用”不是把未来字段长期堆在根文件中。

## 现有变量的瘦身迁移

迁移器只运行一次，安全读取旧文件但不打印值；成功写入 `0600` 临时文件、重新解码核对后原子替换。
旧文件进入受保护备份，不作为 daemon fallback。

| 现有键 | 结果 |
|---|---|
| `GANDI_PAT_TOKEN` | 保留；仍是 secret，不得进入普通 deploy plan、日志或 UI |
| `LOOM_DEPLOY_HOSTS`、`LOOM_LOCAL_NODE`、`LOOM_SSH_CONFIG` | 保留并严格解析，节点列表去重且规范排序 |
| `LOOM_PUBLISH_OUTPUTS`、`LOOM_SIGNING_KEY` | 保留；前者是不可变发布目标，后者只保存 path/ref |
| `LOOM_RELEASE_DIR`、`LOOM_PUBLISH_HISTORY`、`LOOM_PIN_DIR`、`LOOM_ADMIN_DIR`、`LOOM_ACCEPTANCE_DIR` | 删除；由仓库布局、packaging 或本次命令确定 |
| `LOOM_DEPLOY_COMMAND` | 删除；本次运行的 exact tool/binary 由命令入口确定 |
| `LOOM_DEPLOY_SOURCE` | 删除；正常部署只读取现行有效成员表与签名事实所确定的 `Projection`，不导入历史 Material 或旧 SSOT |
| `LOOM_CLIENT_RELEASE_SOURCE` | 删除；使用确定性默认目录或本次 release 命令参数 |
| `LOOM_CLIENT_RELEASE_STORE`、`LOOM_CONTROL_STATE_DIR` | 从 packaging/service 配置取得，不再由管理工作站根 `.env` 控制 |
| `LOOM_CONTROL_WORKTREE` | 删除；工作树由当前命令上下文或显式一次性参数确定 |
| `LOOM_V2_BOOTSTRAP_INPUT`、`LOOM_V2_RECOVERY_CUSTODY`、`LOOM_V2_BOOTSTRAP_OBSERVER_KEY` | 删除；当前首次 bootstrap 若需相同性质的输入，只由正式命令接受现行受保护值，旧 bundle 不作为解码输入 |
| `LOOM_V2_BOOTSTRAP_PLAN` | 删除；当前操作的输入、结果和证据各归原有边界，不维护 plan 文件为权威 |
| `LOOM_V2_MIGRATION_INPUT`、`LOOM_V2_MIGRATION_MATERIAL_INDEX`、`LOOM_V2_MIGRATION_REQUEST_ID` | 删除；历史 Material 不进入现行 decoder、重放或 importer |
| `LOOM_V2_CONFIG_PORT`、`LOOM_V2_ENROLL_PORT`、`LOOM_V2_REPORT_PORT`、`LOOM_V2_CONTROL_TUNNEL_PORT`、`LOOM_V2_CONTROL_TUNNEL_CLIENT_PREFIX`、`LOOM_V2_CONTROL_TUNNEL_SERVER_PREFIX` | 删除，不逐项迁成新端口或前缀；私有服务入口由 `EndpointGeneration` 定义，共享资源由认证 `TransportResource` 定义，显式中继由 `NetworkLink` 定义，本机监听由受保护安装输入提供；`ControlConfig` 不含地址/端口 |
迁移完成后，旧键必须成为未知键并硬失败。不得为了让旧 `.env` 继续通过而在 parser 中留下别名；需要
重跑迁移时从受保护备份显式执行同一个一次性转换器。

## 最小必要测试

1. 一个包含六个键的配置完成 domain → env → domain 往返，默认值、集合排序和相对路径锚定得到唯一字节；
2. 对未知键、重复键、shell 展开、宽权限和非法 target 各用同一表驱动 decoder 断言失败；
3. 两个节点中一个缺少 SSH alias 或认证节点身份时，plan 在任何发布副作用前整体失败；全部匹配时
   只产生两个目标且不因 `reverse_only` 或网络观测改变；
4. signing key ref、Gandi token、真实 SSH 地址和本机路径不出现在脱敏 plan、普通子进程环境、UI 或日志；一次节点执行失败只
   记录该次结果，不修改配置或 authority；
5. 一份旧键集合经一次性迁移得到新规范配置；所有移除键在正常 loader 中均被拒绝。

不为节点数、路径组合、provider、端口和平台建立笛卡尔测试矩阵。核心测试锁定的是边界、同构和一次
正常部署链，不是用分支数量代替模型。

## 禁止恢复

- 把 `.env` 当 shell 脚本 source，或允许 process environment 静默覆盖正式值；
- 除明确保留的 `GANDI_PAT_TOKEN` 外，在根文件中保存其他 token、私钥、口令、证书正文、命令字符串或脚本片段；
- 为每个目录、端口、prefix、阶段坐标和 receipt 新增变量；
- 用 `.env` 的节点列表代替 `ControlConfig`、设备职责或当前可用性；
- 把发布结果、在线状态、探测样本、认证事实前沿、floor、latch 或验收结论回写 `.env`；
- 为兼容旧变量保留永久 alias、双 parser 或第二份 typed config；
- 在 Web UI 展示 secret/path/ref，或让 UI 编辑并回写整个 `.env`。

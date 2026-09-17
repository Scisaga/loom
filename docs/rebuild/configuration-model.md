# 本机部署配置模型

[重建入口](README.md) · [白名单](migration-whitelist.md)

仓库根 `.env` 保留，用来描述**这台管理工作站如何找到并部署现有节点**。它是本机私有输入，
不是控制面 SSOT、认证状态、daemon 运行状态、发布历史、验收证据或临时操作记录。节点身份、职责、
成员关系、EndpointGeneration、端口和授权仍来自 certified Projection；`.env` 不能创建或修改它们。

本文只定义仓库根 `.env`。节点上的 systemd environment、Android 签名文件和将来的 DNS executor
凭据文件各有独立消费者与权限边界，不得合并进根文件。

## 一个领域实体

本模型只有一个有生命周期的领域实体：`LocalDeploymentConfig`。

```text
LocalDeploymentConfig {
  deploy_nodes    set<NodeAlias>
  local_node      optional<NodeAlias>
  ssh_config      AnchoredPath
  private_dir     AnchoredPath
  publish_targets set<PublishTarget>
  signing_key     SecretRef
}
```

`NodeAlias`、`AnchoredPath`、`PublishTarget` 和 `SecretRef` 只是经过校验的值类型，不拥有状态机。
删除 `LocalDeploymentConfig` 会使管理工作站无法确定发布范围、SSH 映射和签名/分发位置；增加第二个
inventory、目录配置或 credential store 则只会制造冲突，因此都不允许。

字段语义如下：

| 字段 | 保存的事实 | 不保存的事实 |
|---|---|---|
| `deploy_nodes` | 本机获准尝试部署的节点别名集合 | ControlSet 成员、设备职责、在线状态或可达性 |
| `local_node` | 若构建机也是部署目标，其对应别名 | control leader、权威写入者或默认出口 |
| `ssh_config` | `.ssh_config` 的定位路径 | SSH 地址、用户、跳板、密钥正文 |
| `private_dir` | 本机私有材料的共同根目录 | 目录中对象的当前状态或完成度 |
| `publish_targets` | immutable release 的分发目标 | 已发布、已激活或已验收结论 |
| `signing_key` | 签名能力的路径或不透明引用 | 私钥正文、解锁口令或 shell 命令 |

真实节点地址、用户、ProxyJump 和 SSH identity 只写入被引用的 `.ssh_config`；网络节点及权限来自
certified Projection。三者以同一个稳定 `NodeAlias` 联结，但没有谁能从另外两者反向生成。

## 长期变量白名单

重建后的根 `.env` 只接受以下六个键。右值是 JSON literal，不是 shell 语法；解析器不执行
`source`、`eval`、命令替换、变量展开或转义拼接。

| 键 | 类型 | 必填 | 规则 |
|---|---|---:|---|
| `LOOM_DEPLOY_NODES` | JSON string array | 是 | 非空、去重；每项是规范 `NodeAlias`，语义上是集合 |
| `LOOM_LOCAL_NODE` | JSON string 或 `null` | 否 | 非空时必须属于 `LOOM_DEPLOY_NODES` |
| `LOOM_SSH_CONFIG` | JSON string path | 否 | 默认 `.ssh_config`，相对路径以 `.env` 所在目录为锚点 |
| `LOOM_PRIVATE_DIR` | JSON string path | 否 | 默认 `deploy`；所有本机私有子目录从此确定性派生 |
| `LOOM_PUBLISH_TARGETS` | JSON string array | 是 | 非空、去重，只允许已定义的 local/SSH target URI |
| `LOOM_SIGNING_KEY_REF` | JSON string | 是 | 只允许受支持的文件路径或硬件/secret-store 引用，不允许秘密正文 |

节点顺序不表达优先级。解析后按规范别名排序，发布执行可以并行；某个节点失败只形成该次操作结果，
不得回写列表或把节点永久标成不可用。

`private_dir` 下的 `released/`、`release-history/`、`pinned/`、`admin/`、`imports/` 和 `evidence/`
是固定派生路径，不再各设环境变量。远端二进制、control data 和 client release store 的路径由
packaging 固定或由对应一次性命令显式传入，不属于本机节点 inventory。

`.env` 必须是普通文件、权限不宽于 `0600`，且不得指向工作区外未经操作者明确选择的软链接。
它可以随受保护备份保存，但不能进入 Git、日志、证据正文、Web 响应或子进程的完整环境。

## 同构边界

设领域值为 `D`，规范 `.env` 字节为 `E`，`.env` 所在目录为锚点 `A`，临时 typed config 为 `T`：

```text
decode_env(encode_env(D, A), A) = D
typed(decode_env(E, A))         = T
domain(T)                       = D
encode_env(decode_env(E, A), A) = canonical(E)
```

相对路径在 `A` 下规范化；`encode_env` 按上表固定顺序输出键、按规范顺序输出集合，并显式写出默认值。
因此同一领域配置只有一种规范字节表示。`decode_env` 对未知键、重复键、重复集合项、未知 URI scheme、
非 JSON 右值、空别名、控制字符、`$`、反引号和换行失败，不能静默忽略“别的工具的变量”。

只有 domain ↔ env ↔ typed config 是可逆的。下列关系都是单向投影：

```text
DeployPlan = plan(LocalDeploymentConfig, CertifiedHead, Projection, Release, OperationInput)
RunResult  = execute(DeployPlan, SSHResolver, LocalHost)
UIStatus   = redact(DeployPlan, RunResult)
```

`DeployPlan`、`RunResult` 和 `UIStatus` 都不能反推或覆盖 `.env`。发布历史由签名 release store 保存，
激活回执与业务验收写入受保护证据；进程退出后 typed config 可以丢弃并重新加载。

| 层 | 表达 | 是否可逆回领域值 | 边界 |
|---|---|---:|---|
| domain | `LocalDeploymentConfig` | 是 | 本机部署输入的唯一语义 |
| env wire | 六个规范 JSON assignment | 是 | `0600` 私有文件；未知键失败 |
| typed config | 六个已校验字段及派生路径 | 是 | 仅存在于一次命令进程内 |
| persistent result | release store、pin、history、evidence | 否 | 保存操作结果，不保存另一份 config |
| runtime | `DeployPlan`、逐节点 `RunResult` | 否 | 同一 config 仍会因 Head、制品和本次操作不同而变化 |
| UI | redacted readiness/result | 否 | 不显示 path/ref，不提供整份配置写回 |

## 节点信息与权威状态的连接

正常部署前执行一次严格 join：

```text
LocalDeploymentConfig.deploy_nodes
  ├─ 每个远端别名必须能由 .ssh_config 精确解析
  ├─ local_node 只允许命中当前机器且不走 SSH
  └─ 每个别名必须命中本次 CertifiedHead 所认证 Projection 中允许部署的同一节点
```

`.env` 表示“这台工作站准备操作哪些节点”，Projection 表示“当前权威允许哪些节点接受什么配置”。
两者不一致时整次计划失败，不取交集、不自动补节点，也不改变 control membership。`reverse_only`、
公网 ingress 声明和客户端路径观测均不能推导 SSH 可达性；SSH 失败也不能改变这些认证事实。

## 正常加载与执行链

1. 操作者为命令显式选择 `.env`；工具检查文件类型、owner 和权限。
2. strict parser 只读取六个白名单键，生成规范 `LocalDeploymentConfig`；进程环境不覆盖文件值。
3. resolver 读取所指 `.ssh_config`，只解析本次节点别名，不复制连接信息到领域状态。
4. 工具通过私有认证入口读取当前 CertifiedHead 与 Projection，并完成节点 join。
5. 操作者为本次命令显式提供精确 commit、制品和操作理由；工具验证 release 与签名引用。
6. planner 产生一个可脱敏回读的 `DeployPlan`；只有获得本次发布授权后才执行。
7. executor 发布同一制品并记录每个目标的真实结果；证据、LKG 和 UI 从结果投影，不回写 `.env`。

读取配置、生成 plan 或显示 readiness 都不构成生产发布授权。配置陈旧只会让下一次命令失败，不能改变
已经运行的 daemon。

## 失败语义

- 配置文件缺失、权限过宽、未知/重复键或非法值：在读取其他私有材料前失败；
- 节点别名缺少 SSH 映射、与 Projection 不符或本机别名错误：整次计划失败，不做部分发布；
- secret ref 无法解析：失败关闭，不提示或回显秘密正文，不尝试把字符串当命令执行；
- 分发目标重复、不可解析或缺少可验证的本地目标：计划失败，旧 signed current 保持不变；
- 尚未实现的能力出现配置键：报告该阶段未激活并拒绝，不能先永久保留“以后可能用到”的变量；
- 运行中单节点失败：保留逐节点结果并停止宣称整体激活，但不删除节点、不改 authority、不循环探测全网。

## 阶段输入不是常驻配置

Bootstrap 导入、v1→v2 迁移、恢复 custody、observer key、material index、request ID、listener 端口和
WG prefix 都不进入长期 `.env`：

- bundle、custody/key ref 和一次性 request ID 由对应命令参数或受保护输入文件提供；事务开始后写入其
  正式 store，resume 读取同一事务；
- control tunnel、Enrollment、config/report 端口和 prefix 来自认证的 ControlConfig 或
  EndpointGeneration；
- DNS/ACME 当前不属于核心重建。以后启用时，由获授权 executor 使用独立、严格、最小的 credential
  文件，只引用 provider secret；根 `.env` 不保存 provider token；
- 某阶段尚未实现时，其 parser 和 key 都不存在。实现、正常入口和清理规则一起交付后才激活该输入。

这保证“按阶段启用”不是把未来字段长期堆在根文件中。

## 现有变量的瘦身迁移

迁移器只运行一次，安全读取旧文件但不打印值；成功写入 `0600` 临时文件、重新解码核对后原子替换。
旧文件进入受保护备份，不作为 daemon fallback。

| 现有键 | 结果 |
|---|---|
| `LOOM_DEPLOY_HOSTS` | 转换为 `LOOM_DEPLOY_NODES`，去重并规范排序 |
| `LOOM_LOCAL_NODE`、`LOOM_SSH_CONFIG` | 保留语义并按新格式重写 |
| `LOOM_PUBLISH_OUTPUTS` | 转换为 `LOOM_PUBLISH_TARGETS` |
| `LOOM_SIGNING_KEY` | 转换为 `LOOM_SIGNING_KEY_REF`；只保留 path/ref |
| `LOOM_RELEASE_DIR`、`LOOM_PUBLISH_HISTORY`、`LOOM_PIN_DIR`、`LOOM_ADMIN_DIR`、`LOOM_ACCEPTANCE_DIR` | 若位于同一私有树，折叠为一个 `LOOM_PRIVATE_DIR`；不一致时要求操作者先归并，不猜测 |
| `LOOM_DEPLOY_COMMAND` | 删除；本次运行的 exact tool/binary 由命令入口确定 |
| `LOOM_DEPLOY_SOURCE` | 删除；正常部署读取 `CertifiedHead` 所认证的 `Projection`，旧源只可作为显式 importer 输入 |
| `LOOM_CLIENT_RELEASE_SOURCE` | 删除；使用确定性默认目录或本次 release 命令参数 |
| `LOOM_CLIENT_RELEASE_STORE`、`LOOM_CONTROL_STATE_DIR` | 从 packaging/service 配置取得，不再由管理工作站根 `.env` 控制 |
| `LOOM_CONTROL_WORKTREE` | 删除；工作树由当前命令上下文或显式一次性参数确定 |
| `LOOM_V2_BOOTSTRAP_INPUT`、`LOOM_V2_MIGRATION_INPUT`、`LOOM_V2_RECOVERY_CUSTODY`、`LOOM_V2_BOOTSTRAP_OBSERVER_KEY` | 移为对应阶段命令的 bundle/path/ref 输入，完成后不常驻 |
| `LOOM_V2_BOOTSTRAP_PLAN`、`LOOM_V2_MIGRATION_MATERIAL_INDEX`、`LOOM_V2_MIGRATION_REQUEST_ID` | 移入正式事务/证据或本次 operation input，不再手工维护 |
| `LOOM_V2_CONFIG_PORT`、`LOOM_V2_ENROLL_PORT`、`LOOM_V2_REPORT_PORT`、`LOOM_V2_CONTROL_TUNNEL_PORT`、`LOOM_V2_CONTROL_TUNNEL_CLIENT_PREFIX`、`LOOM_V2_CONTROL_TUNNEL_SERVER_PREFIX` | 从认证 ControlConfig/EndpointGeneration 消费，根文件中删除 |
| `GANDI_PAT_TOKEN` | 从根文件移除；DNS 阶段若启用，只给隔离 executor 一个 provider secret ref |

迁移完成后，旧键必须成为未知键并硬失败。不得为了让旧 `.env` 继续通过而在 parser 中留下别名；需要
重跑迁移时从受保护备份显式执行同一个一次性转换器。

## 最小必要测试

1. 一个包含六个键的配置完成 domain → env → domain 往返，默认值、集合排序和相对路径锚定得到唯一字节；
2. 对未知键、重复键、shell 展开、秘密正文、宽权限和非法 URI 各用同一表驱动 decoder 断言失败；
3. 两个节点中一个缺少 SSH alias 或 certified identity 时，plan 在任何发布副作用前整体失败；全部匹配时
   只产生两个目标且不因 `reverse_only` 或网络观测改变；
4. secret ref、真实 SSH 地址和本机路径不出现在脱敏 plan、子进程环境、UI 或日志；一次节点执行失败只
   记录该次结果，不修改配置或 authority；
5. 一份旧键集合经一次性迁移得到新规范配置；所有移除键在正常 loader 中均被拒绝。

不为节点数、路径组合、provider、端口和平台建立笛卡尔测试矩阵。核心测试锁定的是边界、同构和一次
正常部署链，不是用分支数量代替模型。

## 禁止恢复

- 把 `.env` 当 shell 脚本 source，或允许 process environment 静默覆盖正式值；
- 在根文件中保存 token、私钥、口令、证书正文、命令字符串或脚本片段；
- 为每个目录、端口、prefix、阶段坐标和 receipt 新增变量；
- 用 `.env` 的节点列表代替 ControlSet、Device/Server authority 或当前可用性；
- 把发布结果、在线状态、探测样本、当前 head、floor、latch 或验收结论回写 `.env`；
- 为兼容旧变量保留永久 alias、双 parser 或第二份 typed config；
- 在 Web UI 展示 secret/path/ref，或让 UI 编辑并回写整个 `.env`。

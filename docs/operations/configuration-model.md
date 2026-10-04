# 本机部署配置模型

[设计入口](../README.md) · [白名单](../migration-whitelist.md)

仓库根 `.env` 保留，用来描述**这台管理工作站如何找到并部署现有节点**，并保留操作者明确要求的
Gandi provider token。它是本机私有输入，
不是控制面 SSOT、认证状态、daemon 运行状态、发布历史、验收证据或临时操作记录。节点稳定身份与职责的
认证绑定、`ControlConfig` 成员关系、`EndpointGeneration`、`TransportResource`、显式 `NetworkLink`
及其授权来自已验证的签名事实所确定的 `Projection`；本机监听与私钥由节点受保护的运行输入提供。
`.env` 不能创建或修改这些事实。

本文只定义仓库根 `.env`。节点上的 systemd environment 和 Android 签名文件各有独立消费者与权限边界，
不得合并进根文件。`GANDI_PAT_TOKEN` 是唯一允许直接保存的 provider secret；已有值继续保留，
未配置时可省略，当前核心服务不会读取或使用它。
网站根私钥由操作者在与所有 control 隔离的离线签发介质保管；它不属于 `LocalDeploymentConfig.signing_key`
（发布签名私钥），也不进入根 `.env`。网站叶私钥由承载 control 在本机受保护输入中生成并保管，
操作者只取 CSR、手工签回证书链；续签不新增根 `.env` 配置键。

## 一个领域实体与两个文件

本模型只有一个领域实体 `LocalDeploymentConfig`。用户已确认 `.env` 指向 YAML 是正式输入；
把节点、签名引用和发布目标重新塞回六个 dotenv 变量是实现漂移，必须删除，不能作为兼容入口保留。

```text
LocalDeploymentConfig {
  deploy_hosts set<NodeAlias>
  local_node optional<NodeAlias>
  nodes list<NodeNetwork>
  ssh_config AnchoredPath
  signing_key SecretRef
  publish_outputs set<PublishTarget>
  gandi_pat_token optional<SecretValue>
}
.env --LOOM_DEPLOY_CONFIG--> 唯一部署 YAML
```

`NodeNetwork`、`IngressMapping`、`PortRange` 和文件引用只是该配置的值，不增加独立 inventory、
状态机或网络权限。删除 nodes 会丢失操作者已经提供且不能从控制面推导的宿主地址与公网端口映射。
节点别名仍由 `.ssh_config` 解析实际 SSH 连接；YAML 中的 management_host/management_port 是
操作者给定的基础设施坐标，用于核对，不能覆写 SSH 解析结果或制造设备身份。存在差异须明确回读。

## 唯一 dotenv 白名单

| 键 | 类型 | 必填 | 含义 |
|---|---|---:|---|
| `GANDI_PAT_TOKEN` | opaque secret | 否 | 有值才写入；不得向普通部署子进程透传 |
| `LOOM_DEPLOY_CONFIG` | path | 是 | 单引号包围的 YAML 文件引用，相对 `.env` 所在目录定位 |

`.env` 是数据，不执行 shell、变量展开、命令替换或转义拼接。规范编码先写可选的 token，
再写唯一文件引用，末尾 LF；未知键、重复键、空值、非规范编码和 shell 表达式拒绝。
省略 token 不影响核心部署。旧六键 reader 和把配置迁回六键的命令都删除。

## YAML 字段与基础设施映射

本机 YAML 延续已部署文件的 `schema: 1`；这是用户确认保留的本机输入格式，不是签名控制协议版本。
它不进入 schema 3 Authority，也不因软件发布而改号。唯一字段如下：

| 字段 | 表达与约束 |
|---|---|
| `schema` | 固定 1 |
| `deploy_hosts` | 非空、唯一、按别名排序的部署目标集合 |
| `local_node` | 可选且属于 deploy_hosts；对应管理地址为 loopback 或 localhost |
| `nodes` | 按 id 排序，节点集合与 deploy_hosts 完全相同 |
| `ssh_config` | SSH 配置文件引用；相对 YAML 所在目录定位 |
| `signing_key` | 发布签名能力的文件/不透明引用，不保存秘密正文 |
| `publish_outputs` | 唯一、排序的 local/SSH 发布目标 |

每个 nodes 项固定为 `id,management_host,management_port,host_addresses,ingress`。
`host_addresses` 是唯一、排序的规范 IP 集合。ingress 是显式数组，项固定为
`purpose,protocol,public_host,public_ports,host_address,host_ports`；两组端口各有 first/last，
范围为 1～65535，前后数量相同，protocol 只允许 tcp/udp，host_address 必须属于本节点。
相同协议及公网主机的映射范围不能重叠。按 protocol、public_host、public_ports.first、purpose 排序。
这些值只消费操作者已有的映射，不授权登录或修改 NAT、路由器、防火墙，也不赋予 Loom 职责或服务权限。

YAML 只接受一个文档、规定字段与字符串/整数值；未知/重复键、anchor、alias、自定义 tag、
空值、重复节点、非法端口及非规范排序拒绝。规范编码使用固定字段顺序、四空格缩进、LF；
读取后编码须还原相同字节，不能静默丢掉字段。相对引用以各自文件为锚点，进程 cwd/environment 不覆盖它。

两个文件均须为 owner-only 普通文件。读取有大小上限并核对打开前后的文件身份；不打印秘密或路径值。
部署结果只进入受保护证据，不回写输入；失败不删除节点、不改变映射，也不把节点永久标为离线。

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

Hy2 资源由节点的受保护本机证书、私钥与连接凭据引用执行，与 Gandi provider token 无关；
认证 `TransportResource` 只携带
可公开验证的节点身份和资源参数，不携带私钥路径、私钥正文或口令。现有 Linux 转发/出网数据面
适配器默认从 `/etc/loom/tls/node.crt` 与 `/etc/loom/tls/node.key` 读取 TLS 材料；该默认位置
不成为新资源的规范字段或所有节点的固定路径。对端按认证节点 ID、证书身份和该用途的授权校验；
按 access/policy 派生的业务用户密码不能充当 control 成员身份。现有私有 TLS tunnel 的
本机成员 TLS leaf/key 的文件引用保存在受保护的 `node.json`，其成员身份仍由 `ControlConfig` 验证。
这些都是适配器的本机执行输入，不进入根 `.env`、公开 Artifact 或 Web，也不形成资源权威。

现行 Linux 一跳 Hy2 执行以 `loom client run -resource-inputs <file>` 定位一份 owner-only 规范
schema 3 本机输入：`{"schema":3,"listeners":[...]}`，listeners 按 resource_id 排序，项恰好为
`resource_id,listen,certificate_file,key_file`。listen 是明确 IP 与非零端口；两个文件引用为规范绝对路径。
只有当前认证 View 中由本节点承载的资源才能消费对应项，保留的未引用定位项不启动 listener 或授予权限。
私钥不进入认证资源；公开 CA 和校验名只来自该资源的 authentication，不从本机 trust 文件补权。
正式启动校验证书/私钥匹配、CA、校验名、用途与有效期；资源报告再从真实 listener 的 QUIC/TLS 与认证回读。
纯服务节点不启动 access capture；当前 hybrid 只支持显式 Mixed，共享进程中的 server listener 不能跟随
TUN 进入 access namespace，未接入分离生命周期前对此组合拒绝。该输入不增加根 `.env` 键。
资源删除后未引用的本机输入仍可保留，但没有资源的纯服务节点停止数据面，只维持私有配置与报告通道。
旧 generation 的进程退出须已回读后才可启动替代配置；父进程异常退出由 Linux 父死亡信号终止子进程，
创建线程保持到子进程退出，以免 Go 线程生命周期造成误杀或遗留。Mixed capture 与 Hy2 listener 不拥有宿主
route/rule 对象；同节点的认证 WG 资源只拥有上述精确接口路由，不取得默认路由、策略规则或其他 underlay 的所有权。

`.env` 必须是普通文件、权限不宽于 `0600`，且不得指向工作区外未经操作者明确选择的软链接。
它可以随受保护备份保存，但不能进入 Git、日志、证据正文、Web 响应或子进程的完整环境。

## 同构边界

### 私有入口的节点执行输入

control 根目录的 `node.json` 是唯一规范 schema 3 本机身份输入，固定字段为
`schema,network_id,control_id,node_id,genesis_id,signing_key_file`，可选 `browser_tls,peer_tls`
各引用证书、私钥和根证书文件。genesis_id 固定网络初始签名材料的摘要，私钥文件必须为受保护的
PKCS8 Ed25519 材料；不把密钥正文、第二份 Projection 或旧认证 floor 写入这个值。
`loom control init` 只接受显式提供且验签成立的初始材料和空目录，并同时建立空的 schema 3
`observations.json`。已有 node 或报告锁而报告文件缺失时必须拒绝重新初始化，不能丢失设备报告序列高水位。
旧权威目录或部分初始化不能被自动覆盖；原字节保留，等待验证前向映射。

`EndpointGeneration` 只声明公开坐标、证书与 SPKI 摘要、模式和签名阶段。本机通过
`loom control endpoint-inputs` 提供 `listen,certificate_file,key_file` 三个精确字段；文件引用必须为
规范绝对路径，私钥与输入文件受 owner-only 权限保护。命令验证证书 DER、SPKI、名称、用途、有效期与
私钥匹配，再按 `SHA256(C({id,generation}))` 定位 control 根目录内的 `endpoint-inputs/<hex>.json`。
相同代只能写入相同字节；更新证书使用新代。它只定位执行材料，不改变入口阶段或授权。
daemon 从已验证的入口事实读取这些输入，无法匹配时本代失败关闭。新 prepared 代绑定失败或与旧代
监听冲突时，保留旧 serving listener；只有正式入口 TLS 预检成立，管理操作才可推进 serving。
draining 停止新会话，到签名截止期关闭剩余会话；运行时不按时钟签发阶段事实。
操作者提供的公网映射只作为已存在的拨号坐标消费，不修改路由器或 NAT。
当现有映射终止在单独 edge 节点时，`loom control edge -listen <address> -target <private-address>`
只转发 TCP 密文字节；目标必须是既有私有地址。坐标是本次 adapter 的显式执行输入，不生成
certified head、edge plan 或新的完成状态，edge 不持有设备及 control 签名密钥。

私有成员传输的本机输入固定为 `schema=3,node,listen,peers`；listen 是排序的私有 IP:port 集合，
peers 是按稳定 node 排序的 `{node,addresses}` 集合，每组地址同样排序。这些坐标只用于尝试连接，
TLS 之后仍须按当前成员表验证目标 control 身份与公钥；输入不能产生成员资格。它不从旧 report 配置导入。

设领域配置为 D，规范 dotenv 引用值为 E，规范部署 YAML 为 Y，各自目录为锚点：

```text
decode_env(encode_env(E)) = E
encode_env(decode_env(E)) = E
decode_yaml(encode_yaml(D)) = D
encode_yaml(decode_yaml(Y)) = Y
Load(.env) = decode_env(.env) + decode_yaml(LOOM_DEPLOY_CONFIG)
```

token 只来自 dotenv，部署字段只来自 YAML，不双写。typed config 可在命令结束后丢弃重建。

| 层 | 唯一表达 | 关系 |
|---|---|---|
| domain | LocalDeploymentConfig 与基础设施值 | 无派生运行状态 |
| wire / persistent | `.env` 的秘密及文件引用、YAML 部署值 | 两个分工明确的文件，规范往返 |
| typed config | 经过验证的 Config | 可逆，不形成第二份配置 |
| runtime | 本次部署动作及逐节点结果 | 单向投影，不能倒写配置 |
| UI / CLI | 脱敏数量和执行结果 | 不暴露秘密或文件引用 |

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
2. strict parser 读取唯一文件引用和可选 token，再严格读取该 YAML，生成 `LocalDeploymentConfig`；进程环境不覆盖文件值，也不把 token 注入普通子进程。
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

### 签名发布记录到实际运行的闭环

2026-10-04 的正式替换按用户明确授权直接安装精确制品，见
[现网字节与生产切换](../core/current-contract.md#现网字节与生产切换)。它保留旧发布 floor，退出旧发布入口，
不使用 schema 3 catalog 作为激活依据，也不声称已完成下面的自动签名发布链。

以下是目标操作顺序，不表示现有 publisher、节点或客户端已完成 schema 3 发布验收。
现网 signed-current floor 与新 catalog 的一次性反重放切换尚无批准并验证的办法；**在此之前
不得把 schema 3 `current` 用作生产激活依据**，也不得重置旧 floor。

1. 操作者沿同一正式发布入口提供本次精确 commit、制品、目标和理由。planner 从严格 `.env`、
   受保护安装信任输入中的发布验签公钥及当前认证 `Projection` 生成计划，核对签发密钥对应公钥、
   受众、组件/平台、generation、制品摘要、长度及媒体类型；计划只给出脱敏结果，
   不改变 `current` 或期望事实。
2. publisher 用 YAML 的 `signing_key` 引用签署不可变 manifest 与 catalog。executor 先把同一内容
   摘要的制品和签名记录写入全部获准目标，再从认证分发地址读回字节，逐项验签和验摘要；相同
   摘要已存在时必须逐字节一致。公开分发端只可取得签名标为通用公开受众的制品。
3. 全部目标的 catalog 与引用制品读回通过后，才逐目标把可变 `current` 指向该 catalog。
   每次推进须由目标端以原子条件更新，或在覆盖所有发布者的独占锁内比较计划读取的旧指针并
   原子替换；单独“先读再写”不能防并发覆盖。条件不成立或目标端没有这种门禁时停止推进，
   重新读取、重新计划。该并发门禁目前也属于待实现与验收的目标流程。
   推进后再次读回指针、签名 catalog 和实际制品；消费方仍须依经批准的单调发布规则验收，
   不能因指针可读而跳过验签、摘要或反重放检查。部分指针推进失败时逐目标记录结果，
   不把整体写成已激活，也不把已推进的指针倒退到较旧 generation。
4. 全部目标的发布读回成立后，管理员再经私有认证控制写入入口，为需更新的节点签发“期望组件”
   普通事实，只引用已核验 catalog 中对应组件/平台的制品摘要。control 本地接受、持久化和同步后，
   `Projection` 才改变期望；发布者、`.env` 或 `current` 都不能自动写入该事实。
5. executor 在已授权节点安装精确制品，按职责完成安全 preflight、运行时应用及重启回读；节点和设备
   从实际进程与文件报告组件、平台、制品摘要及版本。控制面分别显示签名发布、认证期望、实际运行
   和报告是否新鲜；只有实际摘要与期望相符且必要运行回读成功才显示“已应用”。

任一步失败都保留不可变记录和逐目标结果供同一输入重试；重启后从签名 release store、当前认证
事实和节点实际回读重建状态，不从缓存、指针或上次 plan 猜测完成。部分目标已推进时须逐一展示
真实状态，不以一次总开关掩盖差异。上述流程仍受[唯一现行契约的生产切换门禁](../core/current-contract.md#往返与拒绝)
限制；实施进度与证据见[实施状态](../progress.md)。

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
  隔离 executor 按需读取。它的存在不授权调用 DNS provider、DNS-01 或 ACME 自动签发/续期；
  网站叶证书的操作者离线手工续签使用独立网站根，与该 token 无关；
- 某阶段尚未实现时，其 parser 和 key 都不存在。实现、正常入口和清理规则一起交付后才激活该输入。

这保证“按阶段启用”不是把未来字段长期堆在根文件中。

## 最小必要测试

1. 含 token 与不含 token 的 `.env` 分别往返；YAML 完成值和规范字节往返，路径分别由两层文件目录定位。
2. 正式 `loom config check -env` 加载完整节点、端口映射和发布输入，输入文件摘要保持不变；六键格式拒绝。
3. 未知/重复字段、shell 表达式、YAML anchor/tag、多文档、非法端口、映射重叠和不匹配节点集合拒绝。
4. 两层任一文件权限过宽、软链接或打开身份变化拒绝；错误不包含原始秘密或私有输入值。
5. 正常执行保留全部基础设施信息，token 不进入执行参数/环境/输出；运行失败不改配置。

## 禁止恢复

- 把 `.env` 当 shell 脚本 source，或允许 process environment 静默覆盖正式值；
- 除明确保留的 `GANDI_PAT_TOKEN` 外，在根文件中保存其他 token、私钥、口令、证书正文、命令字符串或脚本片段；
- 为每个目录、端口、prefix、阶段坐标和 receipt 新增变量；
- 用 `.env` 的节点列表代替 `ControlConfig`、设备职责或当前可用性；
- 把发布结果、在线状态、探测样本、认证事实前沿、floor、latch 或验收结论回写 `.env`；
- 为兼容旧变量保留永久 alias、双 parser 或第二份 typed config；
- 在 Web UI 展示 secret/path/ref，或让 UI 编辑并回写整个 `.env`。

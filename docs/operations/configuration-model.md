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

WG 接收资源由同一原生数据面进程执行，固定私钥仍来自 root 持有、0600 的
`/etc/wireguard/node.key`，启动前核对资源公钥。普通接入 peer 和业务地址仅在用户态路由器中，
不添加宿主路由或防火墙。已有 Link 管理流量使用原精确接口地址、peer 与返回路由；新执行器
创建并回读本 generation 的 TUN 接口及精确管理路由，不使用 auto_route、默认路由或 policy rule。
为兼容拒绝在线改名的内核，完成进程所有权核对后，只将新建的临时接口置为 down、改为认证名称并
重新置为 up，然后才添加管理返回路由；这不操作既有接口，也不改宿主网络服务。
systemd 按已认证的本节点 Link 投影 `/dev/net/tun` 设备访问；这仅满足原生管理 endpoint 的
执行要求，Mixed 不因此获得隔离 capture 的 `CAP_SYS_ADMIN` 或初始 netns 文件描述符。
旧内核 WG 安装器删除，只有识别旧所有权记录的 compare-and-delete 清理用于一次切换。
已有身份、公钥与管理地址不变；未知现存对象不能被接管，清理失败保持 failed/inactive。

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
纯服务节点不启动 access capture；hybrid 的 server listener 留在原 underlay，显式隔离 TUN 的 access
进程另行监督，两者消费同一认证 View。安装与部署结果见[实施状态](../progress.md)。该输入不增加根 `.env` 键。
资源删除后未引用的本机输入仍可保留，但没有资源的纯服务节点停止数据面，只维持私有配置与报告通道。
旧 generation 的进程退出须已回读后才可启动替代配置；父进程异常退出由 Linux 父死亡信号终止子进程，
创建线程保持到子进程退出，以免 Go 线程生命周期造成误杀或遗留。Mixed capture 与 Hy2 listener 不拥有宿主
route/rule 对象；同节点的认证 WG 资源只拥有上述精确接口路由，不取得默认路由、策略规则或其他 underlay 的所有权。

正常停止可能与配置刷新并发：停止信号已经关闭数据面和它持有的 TUN 时，刷新中的运行回读
可以发现原接口消失。退出结果先完成同 generation 的精确清理；只有清理成功且调用方已取消，
才将这种运行期所有权回读归入 stopped。持久化错误、清理失败或仍存的未知替代对象仍须
保持 failed/inactive；不能用停止信号跳过清理，也不能在未取消的运行中吞掉所有权错误。
此处只修正运行退出的判断顺序，不改变任何领域、wire、持久值、网络权限或 UI 状态种类。

Linux 合成名称缓存从唯一设备状态文件推导路径，保存在相同受保护状态目录，不能放在随 service
停止被删除的 `/run` 目录。隔离 capture 与管理接收器各使用固定后缀；正式身份仍只有一份。
缓存不赋权，但正常停止、异常退出和重启必须保留已有合成地址到原名称的对应，避免远端缓存地址
在重启后被重新分配给另一名称。配置、PID、监听与所有权回执仍是可清理的进程投影。

`.env` 必须是普通文件、权限不宽于 `0600`，且不得指向工作区外未经操作者明确选择的软链接。
它可以随受保护备份保存，但不能进入 Git、日志、证据正文、Web 响应或子进程的完整环境。

## 同构边界

### 私有入口的节点执行输入

control 根目录的 `node.json` 是唯一规范 schema 3 本机身份输入，固定字段为
`schema,network_id,control_id,node_id,genesis_id,signing_key_file`，可选 `browser_tls,peer_tls`
各引用证书、私钥和根证书文件。genesis_id 固定网络初始签名材料的摘要，私钥文件必须为受保护的
PKCS8 Ed25519 材料；不把密钥正文、第二份 Projection 或旧认证 floor 写入这个值。
`loom control init` 只接受显式提供且验签成立的初始材料和空目录，并同时建立空的 schema 3
`observations.db`。已有 node 或报告锁而报告库缺失时必须拒绝重新初始化，不能丢失设备报告序列高水位。
原 schema 3 JSON 集合仅由显式 `loom control migrate-reports` 在停服后逐条校验、保全和迁移；
启动不读双容器或自动重建，见[报告原件的事务持久化](../core/current-contract.md#报告原件的事务持久化)。
旧权威目录或部分初始化不能被自动覆盖；原字节保留，等待验证前向映射。

计划成员换键先用 `loom control prepare-key -state-dir ... -node-config ...` 提供下一份同格式
NodeConfig。它必须保留 network/genesis/control/node 身份和浏览器入口，引用已准备的新 Ed25519
私钥及与该公钥、ControlID 匹配、由既有成员传输根签发的 TLS 叶证书。准备命令不生成 CA、不改变
成员资格、不停止旧键；输入缺失或不匹配时换键请求必须在封笔前拒绝。规范输入暂存为本机
`node-next.json`，只是待消费的执行文件，不是第二份成员权威或运行 fallback。

成员证书决定该新键后，下次 `control serve` 启动先验证原证书链及仍有效的新成员键，保全原 node.json
到 control-retired 内，再原子替换 node.json、删除已消费的暂存文件；仍使用原事实、报告与承诺目录。
中途失败可从原证书和同一准备输入继续，旧键封笔不可取消，新键未取得多数资格前不能激活。旧私钥与
原证书保留为受保护证据。新增操作成本为准备已有传输根签发的新叶和重启该 control；不会因仅写入
公钥便把新成员传输或实际服务报告为可用。

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

### Linux 本机管理入口的异常退出恢复

目标是在原身份、事实、报告和高水位保留的情况下，沿原 `loom control serve` 入口恢复本机管理服务。
现有正常退出会移除 Unix socket，但进程被强制终止后可能遗留 socket 文件，使再次启动因地址占用失败。
最小变化只接管同一受保护本机入口，不重建身份、不迁移权威，也不改变 systemd 的 `Restart=no`。

socket 与其固定 `.listen.lock` 文件属于 runtime 的本机互斥和监听资源，均从既有 `admin-socket` 路径派生；
默认路径仍由 control 根目录确定。锁文件内容为空，不保存 PID、阶段、完成状态或业务值；内核锁随进程
退出释放，文件本身不在运行中删除。domain、签名 wire 和权威 persistent 值完全不变；UI/CLI 只消费
原管理请求及回读，不出现新配置、新 store 或重启完成标记，也不增加 `.env` 键。

启动先核对规范路径、目录类型、当前用户归属及 owner-only 权限，再取得该 socket 的排他文件锁，监听
存在期间保持锁。锁获取有有限等待且可取消；失败不能触碰现有入口。路径已存在时只接受当前用户拥有的
owner-only Unix socket；普通文件、链接、其他用户对象均拒绝。连接成功说明仍有监听者，保留原入口并
拒绝本次启动；只有明确的连接拒绝才能继续。超时、权限问题及其他不确定错误均不能作为删除依据。
删除前再次比较文件身份，仅移除刚刚确认失效的同一 socket，然后绑定同一路径并设为 owner-only。
正常关闭先关闭监听，再 compare-and-delete 自己创建的 socket，最后释放锁；路径被替换则保留替代物并
报告清理失败。强制终止由内核释放锁，下一次显式启动重复上述核对，不依赖上次进程留下的成功标记。

反例是另一个仍在运行的 control 或并发启动者：不能因连接慢或旧文件存在就删除它的入口。原实现留下的
活 socket 即使没有锁文件，也必须通过真实连接被识别并保留。最小验证覆盖真实服务强制退出后的同身份
恢复及正式管理读写、并发/仍存活监听者拒绝、普通文件/链接/错误归属拒绝，以及关闭时的替代物保全。
生产完成须核对精确运行制品、原始权威字节、报告高水位、正式认证访问和真实业务；孤立绑定成功不算完成。

### 部署节点与认证身份

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

当前 Linux client 与 control 共用同一程序路径，control unit 的启动前检查通过该路径读取 client 状态。
若本次修订改变了 `/run` 下可删除状态投影的字段，须先沿正常 service 入口启动同制品 client，
由它从原身份和 LKG 重建当前状态，再启动 control。不能让新检查器读取仍由旧进程写入的临时格式，
也不能手改临时状态、放宽 decoder 或增加旧格式 fallback 使检查通过。此顺序不迁移认证原件、
floor 或身份；只重启 control 时，仍运行 client 的 WG 对象继续由该 client 拥有和维护。

读取配置、生成 plan 或显示 readiness 都不构成生产发布授权。配置陈旧只会让下一次命令失败，不能改变
已经运行的 daemon。

私有控制面的 SSH 自动交付可显式传入 `loom control serve -deployment-env <path>`，经同一严格 loader
读取 `.env` 与唯一 YAML。可选目标来自 deploy_hosts，SSHConfig 解析连接，local_node 在本机执行而不绕行 SSH；
每次操作重新读取输入并回读 SSH 解析与 management 坐标的差异，不倒写配置。该参数只定位操作者已经选择的
本机输入，不进入 Invite 或增加 dotenv 键。未配置的 control 不提供 SSH 自动执行。连接使用既有主机密钥、
非交互认证和密码免交互 sudo；私钥不上传浏览器，provider token 不进入子进程。检查与安装均使用经过验证的
同一通用公开制品；安装仍受 [SSH 同事务执行](../core/enrollment-endpoint-model.md#ssh-目标只读检查与同事务执行)
及宿主网络门禁约束。

正式签名与分发命令使用同一个严格 loader：stage 只从 `LocalDeploymentConfig` 取得 signing key 引用，
publish 只从它取得 publish targets 与 SSH config；不能再同时传 `-key`、`-target` 或 `-ssh-config`
形成第二份部署输入。读取验证 URL 不来自 `.env`，而从当前认证的
`DeviceAuthorization.distribution_urls` 投影；相关授权改变时本次分发停止并重新读取。旧 publisher
与 systemd unit 中手写的 URL 不恢复为发布事实；本轮没有增加常驻循环发布或自动安装。

### 签名发布记录到实际运行的闭环

#### 本地签名交付审查与私有下载

`loom release stage -env .env -pubkey <带外公钥> -generation <显式代> -o <本地审查目录> <已签包...>`
严格读取同一 YAML 的 signing_key，核对其与独立公钥一致，验证每份原包，再生成
[唯一 schema 3 catalog](../core/current-contract.md#签名-catalog-与安装包运行文件的对应)。更新已有审查目录
还须 `-expected-current <计划读取的摘要>`；排他锁内比较旧指针，拒绝陈旧计划、降代和同代异值。
同 catalog 重试幂等，已有不可变摘要路径不覆盖异值；文件和目录耐久写入、完整回读后才更新本地 current。
`loom release verify -root <目录> -pubkey <公钥>` 在独立进程重新验证指针、签名、原 manifest 和整包字节。
stage 不执行 YAML 的 publish_outputs，不写设备期望事实，不改变生产安装代；它不是生产 publish 命令。
输入包含 Linux 包时，同次确定性生成一个通用 bootstrap 脚本及其独立签名 manifest，并引用同一 catalog
的精确 Linux 包。脚本不包含邀请，生成和读取均不改写那些原包的签名字节；未提供的平台在目标端明确拒绝。

Android 应用先使用 `loom release package-android -env .env -pubkey <带外公钥> -apk <正式 APK>
-aar <原始 AAR> -sdk <本机 SDK 绝对目录> -generation <应用代> -o <新输出目录>`。
它沿同一 YAML 定位发布签名能力，固定 SDK 验证 APK 签名及实际包身份，共享读取器核对编入版本、
源码提交、AAR 和两种原生库，再生成 APK 旁的规范 `.manifest.json` 与 `.sig`；不重新签 APK、安装或改变身份。
将输出的 `loom-android.apk` 传入同一 stage，严格读取同名两个附件并验签；缺少附件拒绝，不猜测版本。
应用目录只定位本次文件，不成为第二发布 store。节点验签和下载不依赖 SDK，SDK 仅用于工作站签发前审查。

Windows 使用 `loom release package-windows -env .env -pubkey <带外公钥> -artifact <原 MSI 或 ZIP>
-edition <installed|portable-tun|portable-mixed> -arch <amd64|arm64> -generation <应用代> -o <新输出目录>`。
Installed 还须 `-bundle <构建该 MSI 的原 Installed ZIP>`，工作站需安装 msitools 与 bubblewrap；
只读检查 MSI，并在隔离临时文件系统提取后与原 ZIP 逐字节比较。便携版直接核对原 ZIP。工具读取实际
源码、PE 架构及原数据面签名，产生同名 `.manifest.json` 和 `.sig`；输出原文件传入同一 stage。
Installed ZIP 只是构建输入，不作为安装版下载。节点读取和公开下载无需安装检查工具。此发布签名不替代
Windows Authenticode，现有 preview 标记及真实 MSI 版本不改变，也不修改本机 DPAPI、身份或安装代。

单个分发目标使用 `loom release import -source <临时上传目录> -catalog <精确摘要> -root <目标目录>
-pubkey <独立公钥> [-expected-current <旧摘要>]` 验证并接受已经签署的同一目录。上传只携带公开制品和
原签名字节，发布私钥不离开工作站；source 的 current 不用于选择版本。import 与 stage 共用目标端排他锁、
耐久写入和旧指针比较，完成后沿 verify 重新回读。root 由正式部署调用方从 YAML publish_outputs 解析，
source、catalog 和 expected-current 只是本次执行参数，不形成另一份节点配置。单目标 import 不代替全部
目标分发/HTTPS 回读的总体结果，也不授权消费节点改变已有发布 floor 或应用运行制品。

### 全目标签名分发的正式执行入口

目标是一次发布覆盖 YAML 中的全部 publish_outputs：之前的单目标 import 已能验证原包并比较旧指针，
跨目标次序及实际 HTTPS 回读却仍由仓库外的临时脚本执行。最小变化是将这些操作接到
`loom release publish -env .env -source <审查目录> -catalog <精确摘要> -pubkey <带外公钥>
-control-socket <私有管理 socket> -reason <本次理由>`；不增加常驻配置、发布事务或完成记录。
source 和 catalog 固定本次已经签署的原始内容，发布命令不读取 source/current 选择版本，也不重新签包。
操作者的新增成本仅为提供本次精确 catalog 和理由；节点、目标和 SSH 坐标继续来自原 YAML。

独立节点必须并行发布。原 executor 的逐节点循环使独立 SSH、上传和 HTTPS 等待累加；最小修正是
每轮最多同时执行八个节点，同一节点的多个发布根按 YAML 顺序处理。身份核对、原指针读取、缺失文件
准备、认证 HTTPS 正文验证、条件切换及最终回读各轮之间保留依赖；全部身份和原指针核对通过才上传，
全部准备与 HTTPS 校验通过才允许任何 current 推进。HTTPS 按独立分发根并行，同根内逐制品核验，
避免同一入口被重复大文件下载占满。节点安装的独立分发也须并行；共享 control 重启仍保持管理入口可用。

并发只改变本次执行调度，不增加配置键、权威实体或持久任务。每轮收集已启动操作的结果并等待退出；
失败不进入下一轮，同节点失败不再执行该轮后续根，其他节点的真实结果仍记录。取消遵守原有超时及
条件写入规则；SSH 中断仍是远端结果未确认，不能推断没有写入。重试重新读取全部实际指针。配置与
授权读取回调、CLI 输出分别串行保护，节点 I/O 保持并发。CLI 每条事件携带本次调用的单调累计毫秒数，
并报告实际发送与复用量；这些只是诊断投影，不用于授权或完成判定。操作者无需增加参数。
本次工作站执行器的源码及精确摘要另存受保护证据；调度修订仅需构建并调用该 CLI。目标端仍消费原有
验签 import/target 入口，未改动的客户端程序不因此重新构建、发布或重启。

| 层 | 对应关系 |
|---|---|
| domain / wire / persistent | 原 schema 3 Catalog、manifest、制品及目标 current；字段和签名字节不变 |
| 本机执行输入 | 原 LocalDeploymentConfig；source、catalog、公钥和理由仅为本次命令参数 |
| daemon 回读 | 私有管理员接口从当前 Authority 单向投影网络锚、有效节点公钥和认证 distribution_urls；不含 RuntimeKey |
| runtime | 本次进程中的目标列表、原指针和逐项执行结果；失败后重新读实际文件与 Authority，不恢复任务状态 |
| UI / CLI | 保留 Releases 精确下载；发布命令输出节点/目标/分发根序号、验证结果、操作、耗时及实际传输量，不输出秘密或私有坐标 |

正常执行先独立验证 source 的精确 catalog 与全部包。YAML deploy_hosts 中每个节点都须经本机或原 SSH
通道回读唯一设备身份，网络锚、NodeID 和公钥与 daemon 的有效授权严格相等；publish_outputs 的别名须
属于该集合，本地目标只属于 local_node。SSH 解析坐标差异明确回读，不能由 YAML 覆盖。任一 join 不成立
即在上传前整次失败。公开地址只取同一 Authority 的有效设备授权中 distribution_urls 的规范去重集合。

随后读取各目标现有指针并独立验签，作为本次条件写入的 expected-current。完整目录不要求重复上传全部文件：
发布器从本次已验签目录派生唯一的相对路径、长度和摘要清单，沿原管理通道逐目标只读核对已有普通文件，
只上传缺失条目。相同路径上的异值、非普通文件或逃出发布根目录的链接拒绝，不自动覆盖或清理。
复用清单只存在于本次调用中，不保存同步数据库，也不从旧指针推测文件存在。上传前重新核对复用内容；
目标使用既有 GNU tar 在本次私有临时目录组合收到的文件与已核对的本地文件，然后仍交给同一完整 tar
接收器和单目标 import 验签。源文件变化、复用文件变化、缺项和额外条目均不能绕过完整验证。
只有完整目录通过现有排他锁和不可变写入，以 prepare-only 保留原指针；全部落盘回读后，
从每个认证 HTTPS 根完整下载每件公开制品，比较长度和摘要。公开站点必须已经提供此明确公开的制品路径，
本命令不修改 Nginx、网络或认证配置；路由缺失即失败并保留原指针。站点预置的静态路径仅映射
受保护 release root 下 `bin/<64 位小写十六进制摘要>` 的普通文件；该目录只由验签并核对 public 受众
的发布入口写入，不映射整个 release root、catalog、manifest、current 或设备目录。首次替换旧的逐文件
location 时，须逐一核对已有 bin 均来自已验证公开 catalog；未知文件不能因通用路径而暴露。后续发布
仍先验签落盘再做 HTTPS 正文回读，无需为每次内容摘要修改网站配置。

只有以上全部通过且 daemon 的相关授权投影仍相同时，才在独立节点并行推进 current；同节点保持 YAML 顺序，每次仍在
目标端锁内比较计划固定的旧值，已是同一 catalog 时幂等回读。推进后再验签读取完整 catalog 与包。中途
失败明确输出已推进及未确认目标，退出非零；不倒退已推进的指针，不把 SSH 断线解释为远端未写入。
重试从全部真实 current 重建条件输入，低代与同代异值继续拒绝。上传使用仅本次命令拥有的临时目录，
不传私钥、provider token、设备配置或运行 floor；退出清理临时目录，异常遗留不能成为发布权威。

反例：目标一已推进而目标二被另一发布者改变时，本次不能覆盖目标二，也不能把目标一倒退；重新执行
相同 catalog 可验证目标一并按目标二的新事实决定接受或拒绝。缺少任意 HTTPS 正文、授权变动、错误密钥、
同摘要异字节或任一身份不匹配均不能产生整体成功。没有已认证 HTTPS 根时也不能称全目标分发完成。
本入口仅发布下载内容，不签发期望组件、不安装客户端、不推进任何既有运行 floor。
域、签名 wire 和持久值仍是原 Catalog、manifest、制品与 current；相对文件清单和复用集合是可删除的
传输投影。CLI 仅增加本次实际发送/复用的文件数与发送正文长度，不能用复用命中代替目录验证。
反例是同目录重试时文件已被截断：清单核对必须拒绝，不能因上次成功就省略后续验证。最小测试覆盖空目标、
部分复用、全复用、复用后发生变化、异常路径/条目拒绝，以及原指针保留和正式入口的实际少传结果。
旧 SSOT 发布构建、常驻循环、镜像写入、旧 release/pin/history 写入和无签名 current fallback 同项删除。
旧 signed-current 与 snapshot 仅保留离线验签、原始备份完整性检查；运行入口不能调用历史签发或分发器。

最小测试覆盖：prepare 不改 current 与重启回读；混合本机/SSH 的独立节点重叠执行、同节点顺序、失败等待及全局前提；目标身份与
认证 URL 的来源、配置/权限变化、条件推进冲突及同 catalog 重试；真实正式 CLI、全部 YAML 目标落盘、
公开 HTTPS 与私有 Releases 下载回读。测试不把“current 可读”解释为运行制品已应用。

`loom control serve` 可成对传入 `-release-root <绝对路径>` 和 `-release-pubkey <带外公钥文件>`，作为该
control 的受保护只读安装输入；它们不进入 `.env` 或网络权威。私有 Releases 页面从验证结果投影 Linux
archive、Windows 数据面 ZIP 和 Android 正式 APK，下载走既有管理员认证服务，原有页面与交互保留。
Windows 数据面不是完整 Windows 应用安装器；其应用安装包尚未定义的 manifest 不进入目录。通用 bootstrap 供邀请交付
入口使用，不作为另一款客户端卡片。sh 交付从当前设备授权中的 HTTPS distribution_urls 读回同一脚本，
成功才在私有页面显示一次粘贴块。块中携带交付时仍获授权且读回通过的地址集合，目标机器按规范顺序
分别尝试脚本和程序包，每次下载均核对固定摘要；全部失败时停止，不能重新创建加入事务。缺少有效入口时
显示不可用，复制与刷新复用原邀请。页面中的整包摘要与真实运行文件摘要分开，下载成功不制造部署成功。
现有公开 HTTPS 分发及正式私有下载已部署验收，见[实施状态](../progress.md)；生产自动更新仍未启用。

私有 Releases 的整包下载必须允许低速但持续前进的传输。实际浏览器已取得正确响应和部分 APK，
但整响应的固定写入期限会在正文尚未完成时截断连接；端口可达和公开分发成功不能抵扣此失败。
文件下载因此在每次写入前重新设置原两分钟写入等待期限，停止接收的连接仍有界退出；不按包大小
假定最低带宽，不增加配置项，也不改变其他 API 的总超时。正常入口仍为原下载链接。
domain、签名 manifest/catalog、原文件与持久目录保持；这里只改变 runtime 写入期限，UI 及下载
坐标不变。额外成本仅为每块正文更新连接期限。最小验证为真实 HTTP 持续传输跨过原总期限后
逐字节一致、停止接收时写入失败退出，以及已发布 APK 的实际私有浏览器下载和摘要回读。

私有页面和设备期望投影仍须校验本次实际读取的制品字节。已有内容地址缓存只复用签名包的解析，
不能凭文件大小、mtime 或 inode 省略摘要。原实现命中缓存后仍为每个整包反复分配和复制正文，
真实控制服务的 CPU 采样已显示这些读取及内存回收争用报告处理；最小修正是在缓存命中时用固定
大小缓冲流式校验同一文件的完整长度和摘要，首次解析仍读取完整包。manifest、签名和包坐标
继续逐项核对，文件变化或短读仍失败；没有新的缓存权威、运行配置或完成判定。验证覆盖同长度
篡改、截断、追加和删除缓存后的相同结果，并沿实际页面及成员报告重新验收。

#### 生产发布与实际消费

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
   重新读取、重新计划。单目标 import 已实现并验收此条件更新；统一全目标 executor 使用上面的正式 publish 入口。
   推进后再次读回指针、签名 catalog 和实际制品；消费方仍须依经批准的单调发布规则验收，
   不能因指针可读而跳过验签、摘要或反重放检查。部分指针推进失败时逐目标记录结果，
   不把整体写成已激活，也不把已推进的指针倒退到较旧 generation。
4. 全部目标的发布读回成立后，管理员再经私有认证控制写入入口，为需更新的节点签发“期望组件”
   普通事实，只引用已核验 catalog 所绑定原 manifest 中对应运行组件/平台的精确程序摘要，不能使用 ZIP、
   archive 或 MSI 的整包摘要代替。control 本地接受、持久化和同步后，
   `Projection` 才改变期望；发布者、`.env` 或 `current` 都不能自动写入该事实。
   正式 Web 入口为节点详情的 Expected components；CLI 继续使用 `loom control write` 提交
   [expected_component.put/delete](../core/current-contract.md#节点期望组件的精确发布引用)，
   `loom control inspect` 可回读原引用，程序坐标和报告比较由私有节点详情回读。
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

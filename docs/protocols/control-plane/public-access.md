# 公网 profile、DNS 与证书

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 域名、公开服务与证书管理

### 当前交付范围与独立 DNS 工作

入口部署（Issue #8）使用现有可验证的域名／地址、有效证书链和节点本地私钥引用，完成
静态分发、HY2／Trojan Bootstrap、Data listener、认证 catalog 和真实可达验证。
现有绑定须从原网络受验证迁移或经管理操作认证；公开解析结果不产生控制权限。

域名命名／存量迁移、provider/PAT、A/AAAA/TXT、DNS-01 challenge、ACME order、自动签发／
续期及其恢复与联合验收统一由 Issue #17 承担，目前暂缓。#8 的完成条件不包含这些任务，
也不等待 #17 完成。后续自动签发产生的证书复用相同安装接口；安装侧继续验证 SAN、完整链、
有效期、私钥匹配和认证 SPKI。有效证书缺失时报告具体输入错误，不使用测试证书抵扣生产验收。

这里暂缓的是域名管理与证书自动化。[业务由最终出口解析、入口使用独立 underlay 解析](../../clients/routing.md#业务域名由最终网络出口解析)
是既有数据面要求，继续实现和验收，不转入 #17 等待。

### 统一的 forward server 公网基线

本章所称 forward server，是 active Device 的 responsibilities 包含 forward；internet_egress
蕴含 forward。use_loom 是可叠加职责，不影响该判定。每个 active forward server 必须有：

1. 一个稳定 FQDN，解析到其公网地址或 NAT 前端；
2. 公网 Nginx HTTPS：TCP 443 可用时使用 443，否则使用 public profile 中的替代 TCP 端口；
3. 匹配认证域名/SPKI 的有效证书、完整链及节点本地 TLS private key；自动 DNS-01 签发与续期由 #17 跟踪；
4. Hysteria2 UDP listener/可轮换端口池；
5. WireGuard UDP listener，用于永久 L3/data 或 overlay link；
6. 正式版的独立 Trojan/TLS TCP bootstrap fallback。

FQDN 不携带端口。客户端拨号端口只能来自签名 EndpointSet/catalog，不能根据“有域名”推断为
443。域名必须在 listener advertise 前已解析到正确公网前端并通过外部 transport probe。

公开 Nginx 的允许面只有：

~~~text
GET/HEAD /                              → 静态 fake website
GET/HEAD /distribution/sha256/<digest>  → 精确 immutable object
~~~

可选静态索引也必须自身内容寻址并由 descriptor/hash 引用。禁止动态 latest 选择、上传、cookie、
按 token 变体、目录遍历、claim/control/config/report handler 和这些服务的 reverse proxy。
响应应设置 immutable cache policy、固定 Content-Type 与长度。`<digest>` 对二进制 blob 是 raw
SHA-256，对 canonical wire object 是协议 domain-separated typed hash；无上下文的 Nginx/镜像不能
自行把后者当 raw SHA-256 复算。publisher 必须按对应 domain 生成路径，客户端仍以 certified ref
中的 domain、size、typed hash 和 Loom signature/QC 为最终 authority。

### PublicAccessProfile 与三类部署

公开期望与 provider/NAT 私有细节分离：

~~~text
ServerPublicAccessProfileV1
  schema = 1, cluster_id, server_id, generation
  fqdn
  dns_zone_ref
  address_family_policy
  https_public_port                 # 443 或显式替代端口
  deployment_kind                   # direct_standard | direct_alternate | nat_mapped
  public_frontend_addresses[]
  certificate_profile_ref
  forward_listener_resources_hash

ForwardServerListenerResourcesV1    # control-private aggregate；不是旧 ListenerResourceIntentV1
  schema = 1, cluster_id, server_id, generation
  nginx_local_tcp_port
  hy2_local_udp_port_pool[]
  wireguard_local_udp_ports[]
  trojan_local_tcp_port_pool[]
  mappings[]                        # 仅 nat_mapped

PortMappingIntentV1
  schema = 1, mapping_id
  transport                         # tcp | udp
  public_address, public_port_start, public_port_end
  local_address, local_port_start, local_port_end
  mapping_generation

ServerPublicAccessStateV1            # reducer/reconciler projection；不由 intent sender 填写
  schema = 1, cluster_id, server_id, generation
  public_access_profile_hash
  status                             # preparing | active | draining | disabled
  last_verified_observation_hash?
  last_changed_head_hash
~~~

profile、private resources、mapping 和派生 state 分别使用独立
`loom-server-public-access-profile-v1`、`loom-forward-server-listener-resources-v1`、
`loom-port-mapping-intent-v1`、`loom-server-public-access-state-v1` domain 计算 hash。公网 profile
不得嵌入本地运行时 status；只有 certified intent 加验证 observation 后才能派生 active state。

三种合法部署：

| kind | DNS | Nginx | 数据 listener |
|---|---|---|---|
| direct_standard | FQDN → 公网服务器地址 | public TCP 443 → local Nginx | HY2/WG 独立 UDP tuple；Trojan 独立 TCP tuple或 L4 SNI |
| direct_alternate | FQDN → 公网服务器地址 | public 替代 TCP 端口 → local Nginx | 各 transport 显式端口 |
| nat_mapped | FQDN → NAT 公网前端 | public TCP 端口映射到 local Nginx | public UDP/TCP 池按 transport 映射到 local listener |

示例只能使用文档地址和符号端口：

~~~text
k7v2m9q.example.com → 192.0.2.40
HTTPS: <public-https-alt>/tcp → <nginx-local>/tcp
HY2 pool: <public-udp-a..b>/udp → <local-udp-a..b>/udp
WG: <public-wg>/udp → <local-wg>/udp
~~~

direct 部署不得伪造 NAT mapping；nat_mapped 部署必须声明公网/本地 tuple 和映射代次。外部与
本地范围长度必须相等，协议必须一致，且验证器要拒绝重叠、反向范围、端口越界和同一 UDP
tuple 同时分配给 HY2/WG。Nginx TCP 与 HY2 UDP 可以使用同一个数值端口，因为 L4 协议不同；
Nginx 与 Trojan 同为 TCP，若共用 tuple 必须有显式 L4 SNI dispatcher，不得由 HTTP location
分流。

active forward profile 要求 Nginx local port、至少一个 HY2 UDP 资源和至少一个 WG UDP 资源；
正式发布 profile 还要求至少一个 Trojan/TLS TCP fallback。preparing 阶段可暂缺尚未部署的资源，
但 UI 必须列出缺口且 validator 不允许把它标 active。internet_egress responsibility 缺 forward
responsibility、FQDN 或上述资源时同样失败关闭。

不能使用 80/443 的服务器仍然必须有 FQDN，并通过 DNS-01 签证书；替代端口不是备案或供应商
政策的绕过机制。executor 在激活前必须确认该公开方式在适用法律、供应商条款和本地网络中可用，
否则保持 preparing。位于光猫/NAT 后的 server 除 DNS 指向外，还必须由 operator/provider 完成
相应 TCP 与 UDP 映射。该映射是 Loom 之外由操作者提供的外部事实；Loom 不取得网关权限，
不经 UPnP、NAT-PMP 或供应商接口创建、修改、删除映射，只记录 certified private intent 并从
外部逐 transport 验证 exact public/local tuple。

### 托管域名的受理与执行

托管 DNS 的目标和验收由本节定义，交付跟踪见 [DNS 生命周期 Issue](https://github.com/Scisaga/loom/issues/17)。
DNS 管理输出 certified 名称/地址绑定、DNS 读回状态及受认证 DNS-01 接口；
[公网入口与证书交付](https://github.com/Scisaga/loom/issues/8)消费这些输入，负责节点本地 CSR、
ACME order、证书安装与 listener 验证，不自行分配名称、维护记录或持有 provider PAT。

一次生命周期请求由一个 control 受理：准备名称、提交绑定/任务/删除状态并指定 executor；
副作用只能在 Raft commit、apply 和提交后 QC 后执行。其他 control 复制认证事务，普通 SSOT/CRDT
同步、配置发布或重启不重新派发任务。“一个 control 受理”不赋予其绕过 quorum 的权限。

实际 DNS API 请求只由在役、具备 DNS 执行授权、可达 provider 的**非 control Device**在现有节点
进程中执行。正式入网后满足资格的新节点可以维护自身记录，否则委派其他合格节点。
兼任 control + forward 的物理节点可以需要公网域名，但不执行 Gandi API。缺少 executor 时显示
具体待执行原因，不回退到 control/开发机，不新增固定全网 DNS 管理机或常驻抢占选主/轮询系统。

### 名称分配与隐私

自动主机标签严格为七字符小写 Base36：`^[a-z0-9]{7}$`，在 proposal preparation 使用密码学安全
随机源均匀生成。根域从操作者已授权、无项目语义的 zone 池中选择；不使用 Device ID、显示名、
地址、地区、职责、时间、顺序号及这些属性的可推导哈希，也不添加项目、网络或职责前缀。
例如 `k7v2m9q.example.com`。不使用区分大小写的 Base62，不因冲突改变长度。

- 以规范化完整 FQDN 为唯一性边界，准备阶段核对私有绑定、预留、退役记录和 provider 已有占用；
  未知归属记录不覆盖。冲突有界重试，结果随 proposal 固化；reducer/renderer 不查询 DNS、不读时钟、不随机选号。
- 重试和接管复用同一已提交绑定。提交后才发现外部冲突时，显式修订尚未启用的分配事务，不能直接换名重试副作用。
- 重启、改显示名/职责、IP 变化、端口轮换和例行续证不改变 FQDN。修改域名池不自动改写既有绑定；
  换域名通过显式迁移和新旧入口 overlap 完成。已提交名称退役后不复用给其他身份。
- 完整 `Device → FQDN → 公网前端` 映射只进私有认证状态；普通 Device 只取得其授权连接需要的部分。
  不把内部 Device/cluster ID、职责或全网映射写进公开 DNS 辅助 TXT、镜像或报告。
- 随机标签不是认证秘密。共享根域、IP 与证书透明日志仍可能关联入口；可在已授权根域池分散分配，
  不能声称网络不可枚举。证书不为方便而汇总多个节点名称或复用节点私钥。

### 存量迁移、预留与删除

首次迁移由管理员经现有私有 control UI/API 显式提交，复用 admin 鉴权、expected head 与 request ID。
受理者读取已提交节点清单，生成可逐节点回读和恢复的计划；升级二进制不自动注册域名。

| 原状态 | 迁移规则 |
|---|---|
| 只有公网 IP 或无可用域名 | 按同一规则分配七字符随机名称 |
| 既有名称符合字符/长度、独立随机性、隐私与授权 zone 要求 | 验证真实归属后接管；外观或同 IP 不足以证明归属 |
| 暴露身份/地区/职责或不符合规则的名称 | 分配新名并显式迁移入口，不能默认沿用 |
| 旧名称不在托管 provider/范围 | 建立受管新名，迁移完成前保留旧入口，不越权修改旧 provider |
| 离线、地址未知、缺执行者或凭据 | 记录对应待处理原因，保留原身份和可用配置，不阻塞其他节点任务 |

迁移按“绑定/任务提交 → 授权 executor 写 DNS 并读回 → 证书/listener 准备与外部验证 → 新旧入口
视图 → reader、DNS TTL/缓存、Invite 与退役 guard 满足 → 删除被替换入口和有权管理的旧记录”执行。
复用原 Device/Enrollment 身份；不重装全网、清空 registry 或提前关闭旧入口。

| 生命周期事件 | DNS 行为 |
|---|---|
| 创建需要公网服务的 Device/Invite | 预留名称并提交私有绑定；尚未入网或无服务地址时不创建 A/AAAA，不公开邀请映射 |
| 正式入网且取得公网服务地址 | 沿同一事务派发 DNS 创建，身份安装与公网入口就绪分别显示 |
| 公网 IP、NAT 前端或地址族变化 | 提交下一代地址绑定，保留名称；旧地址按 overlap/退役 guard 移除 |
| 证书签发/续期 | 提交绑定 certified 域名与 exact ACME order 的 DNS-01 任务 |
| 端口轮换、普通配置同步或短暂离线 | 无地址/challenge 变化时不写 DNS、不重新分配名称 |
| 删除节点或撤销公网服务 | 提交撤下和删除状态，guard 满足后由仍在役的其他授权非 control executor 清理 |
| 未使用 Invite 取消或预留作废 | 结束预留，已提交名称留下退役记忆，不回收给新身份，不删除其他事务记录 |

公网服务地址来自目标节点自己的实际网络发现；不得取执行者、开发机、control、管理 SSH 或
HTTP 代理的地址。已提供 NAT mapping 不可达只阻止 listener advertise，不阻止名称预留和正确 DNS
配置；Loom 不登录或改动网关。被删除节点已销毁也须能由其他 executor 清理。旧节点恢复只能服从
最新认证状态，不能靠本地旧配置、DNS 成功或旧回执重注册；恢复原身份也需新的显式授权。

### DNS 任务、并发与凭据

私有持久任务绑定 lifecycle/request ID、owner Device、FQDN、binding generation/desired hash、
exact RRSet/order TXT value、action、指定 executor、授权代次/期限、执行阶段、读回结果与错误分类。
最终 wire 仍须严格 schema/hash 设计，不能用本地 JSON 或 generation 文件充当 authority。
同一绑定/RRSet 的冲突操作经现有事务机制串行；不同节点任务可以并行。重试、control/executor
故障和回执丢失时恢复原事务并 read-after-write，不因其他副本新收到配置就重复派发。

必须先核实真实 provider 的条件创建、更新、删除和逐值原子能力；支持 CAS/version 时必须使用。
单 control、本地 generation、先读后写、ownership tag 或短租约都不能取消已发出的迟到 HTTP 请求，
不能替代 provider 条件写/删。执行语义是可恢复的 at-least-once，不宣称 exactly-once。

DNS-01 只增加/移除当前 order 拥有的精确 TXT 值，保留并行 order 和其他用途值。先 GET 再整集合
Replace/Delete 不构成逐值原子保护。若 provider 不支持所需条件删除或等效防护，保留资源并显示
“待清理”，提供受审计的清理路径；未解决迟到写/删与并行 TXT 防护前，不能宣称自动清理已完成。
旧授权停止新请求，旧代/迟到回执不推进新状态；executor 自报成功不改变名称归属或产生另一份 SSOT。

首个真实 adapter 使用 Gandi LiveDNS，保留 provider-neutral 接口和 fake provider。按 exact name/type
操作，不重写整区。Gandi HTTPS 验证原站证书与主机名，PAT 不进入 redirect 或 CONNECT 握手；provider
HTTP client 与节点公网地址发现 client 分离。实际能力、产品/zone scope、错误分类与撤权须分别验收：
本地 record scope 校验不是 provider 隔离，能修改整个授权 zone 的 PAT 不能称为“仅能改本节点”。

PAT 来源为忽略的 `.env` 中 `GANDI_PAT_TOKEN`。受保护交付端将其封装给获授权的非 control executor；
运行时不依赖开发机 `.env`。control 只持 secret ref/密文和分发状态，不持有或解封 PAT 明文。
forward/internet_egress 不自动授予 DNS 权限；候选可有多个，首次交付、executor 撤权或转为 control
后的凭据收回与必要轮换必须可操作。PAT 不进日志、命令参数、Issue、文档或公开 artifacts。
配置 PAT 不授权购买/续费/转移域名或修改注册信息。

UI 分别显示名称预留、DNS 待执行/已核对、证书/入口准备、就绪、退役待清理和失败原因；
迁移计划显示保留/新分配/替换/冲突/等待及逐节点结果。DNS API 成功不是公网入口就绪，
只读状态不使用 Apply；失败重试继续原任务。authoritative DNS 与至少两个外部 resolver 一致后，
才把 DNS 结果交给 listener verify；入口失败仍保持 preparing。

### DNS 与证书 reconcile

证书流程只消费上面的认证绑定、DNS 状态及 DNS-01 接口；不在证书组件中直接调用 provider、
维护 DNS 记录或持有 PAT。接口必须核对域名/order/任务授权，DNS 失败不推进证书或入口就绪。

证书统一使用 DNS-01，不依赖公网 80。每个 forward server 在本地生成 private key/CSR；private
key 不进入 SSOT、CRDT、distribution 或 control backup。ACME account 可由受约束 executor 管理，
证书 artifact 只封装给目标 server。续签过程：

~~~text
cert prepare
  → DNS-01 challenge
  → issue
  → local install without advertise
  → external hostname/SNI/SPKI verification
  → EndpointSet old+new pin overlap
  → prefer new
  → drain old
  → remove old pin/key after floor
~~~

节点本地执行器把 `CertificateIdentityProjectionV1` 与 `CertificateIntentV1` 分开：前者绑定
logical intent、endpoint/DNS names、issuer profile、key owner、key artifact 和 SPKI；后者只增加
CSR、renew/overlap policy 与 issuance generation。listener 只引用 projection hash，因此同一 key
的例行续签不会无故制造 EndpointSet identity 变化，换 key 则必须先形成下一 identity generation。

ACME adapter 使用节点本地 P-256 account key，并固定 HTTPS directory origin、禁用环境代理和
redirect。order 返回后，authorization/finalize URL、已拥有的 DNS-01 TXT value 与本地 key/CSR
路径会在 DNS 或 finalize 副作用前写入 0600 状态；重启只能续跑同一 pending order。CA 返回的 leaf 必须与
exact CSR/SPKI 和完整 DNS SAN set 相同、用途仅为 server auth，并通过配置的 WebPKI roots 验链，
随后才原子写入本地 certificate artifact。签发失败不替换 active LKG。换 key 成功后状态同时保留
old/new certificate 与严格排序 pin；仅带 certified head、rotation guard 和 reader floor 的退役授权，
且最短 overlap 已结束时才能收缩旧 pin，旧 key/cert 仍留待 backup retention 回收。

公开 WebPKI 只证明 transport identity，不能替代 catalog/head/QC。若 cert 自动续签但 SPKI 未被
当前 certified endpoint generation 接受，listener 不得 advertise。紧急证书撤销也必须先发布
可达替代入口，除非继续运行旧入口的风险高于失联风险。

### 私有 control 服务没有公网域名依赖

control_api、private Enrollment、device_config/report 按 private `ControlServiceDirectoryV1` 中的
overlay IP 拨号；ControlSet membership 与 Raft/replication peer RPC 只按 private
`ControlPeerDirectoryV1` 拨号。两者都使用 internal CA 的用途隔离证书，并且：

- 不要求公网 FQDN、公开 WebPKI 或 NAT mapping；
- 不写入 PublicAccessProfile、公开 EndpointSet 或 Nginx；
- 不允许通过公网 IP 直连后关闭证书验证；
- 可使用证书 IP SAN，或 directory 绑定的 service ID + SPKI pin；
- 只有已入网 admin/Device/control，或持有效受限 bootstrap tunnel 的未入网客户端可达。

一台物理 Device 同时具有 forward 与 control 职责时，公网和私网 listener 必须绑定不同地址或
受防火墙严格隔离；公网 compromise 不得直接获得 control socket。

---

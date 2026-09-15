# 公网 profile、DNS 与证书

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 12. 域名、公开服务与证书管理

### 12.1 统一的 forward server 公网基线

本章所称 forward server，是 active Device 的 responsibilities 包含 forward；internet_egress
蕴含 forward。use_loom 是可叠加职责，不影响该判定。每个 active forward server 必须有：

1. 一个稳定 FQDN，解析到其公网地址或 NAT 前端；
2. 公网 Nginx HTTPS：TCP 443 可用时使用 443，否则使用 public profile 中的替代 TCP 端口；
3. DNS-01 证书管理和节点本地 TLS private key；
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

### 12.2 PublicAccessProfile 与三类部署

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
demo-edge.example → 192.0.2.40
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

### 12.3 DNS 与证书 reconcile

DNS/证书 provider adapter 接收的只是 certified desired state。推荐 DNS API 使用最小权限：

- 仅能修改受管 zone 下指定 record 前缀和 ACME TXT；
- 不能转移域名、修改注册联系人或扣款续费；
- 凭据作为 secret artifact 只封装给当前 executor；
- 所有写入带 provider CAS/version，并以 operation ID 幂等；
- authoritative DNS 与至少两个外部 resolver 一致后才进入 listener verify。

FQDN 分配必须先形成 certified `server_id → fqdn → public frontend` binding，再由 executor 写 DNS。
label、冲突重试结果和 generation 都由 proposal preparation 注入；reducer/renderer 不查询 DNS、
不读时钟也不随机选名字。同一 active server 的 FQDN 跨 listener/端口轮换保持稳定；换域名必须先
让新旧 binding、证书和 EndpointSet 重叠，再按 reader floor 回收旧名。域名购买、续费支付、跨
注册商转移继续要求显式 operator 批准，不因配置了 DNS API 自动授权。

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

### 12.4 私有 control 服务没有公网域名依赖

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

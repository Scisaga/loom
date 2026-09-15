# 凭据与概念数据模型

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**职责：概念模型与 v1 配置边界。** 本文的字段清单是设计映射，不是可直接编码的 wire schema；v1 由严格模型定义，v2 对象由控制面专题定义。

---

## 18. 凭据与分发

**绝不通过邮件/IM 发明文配置。**

| 机制 | 说明 |
|---|---|
| **加入码** | 短 TTL；certified record 固定 Device-intent commitment、token commitment、issuance policy、catalog 与 private-service-ref hash；compact descriptor 携 2～3 个 distribution mirror、catalog/proof hash、有界 private ref 和 exact-bound 短期 tunnel capability，token 只在私有内层 TLS 中提交并由 Raft CAS 一次性消费 |
| **设备绑定** | 客户端先无 bearer 实测 HY2 outer transport/SNI（正式版含 TCP fallback），选中后才以 capability 建临时隧道访问 private Enrollment；本地生成 P-256 identity/CSR key 与独立不可导出 wrapping key，以 stable request-body hash + fresh server-nonce detached PoP 绑定，completion QC 后才激活 |
| **二维码** | 加入码的 compact 封装；完整 catalog 与不含 intent opening 的 public proof 按各自 hash 从静态 Nginx 镜像取得，intent/opening 只在 inner-TLS preflight 返回；客户端扫码、导入图片或 `.loom-invite` 不创建第二个 Device；未 commit 只在 Invite/capability 有效期内重试，已 reservation 只接受管理员签发的 exact-bound resume |
| **可吊销** | 控制面拒绝读取/上报与数据面撤除凭据必须分别收敛；各平台源码接线见[实现对照](../../implementation.md)，实际覆盖须核对验收回执 |
| **有效期** | 自带过期时间 |

**配置模板化**：Android 是 TUN；v1 Windows 是 TUN + `127.0.0.1:1080`；Linux
Server 是 `127.0.0.1:1080`，另可带显式的兼容/高级覆盖端口。所有 matcher、Service
与 AccessDeclaration 定义都由 certified 控制平面 view 下发；客户端本地只可切换 Direct / Auto /
指定出口三模式。平台应提供**下发前预览**，但预览不能变成客户端侧规则或路径
编辑器。

---

## 19. 数据模型

下列清单同时标出当前模型和目标态扩展；标为“目标态”的 control/DNS/EndpointSet 类型尚未
进入 v1 Go `model.Node` 严格 schema，不能据此向部署 SSOT 提前写字段。目标对象这里只做
概念索引，不是可编码 wire schema；字段、tagged union、排序和签名的规范定义以
[分布式控制平面专题](../../distributed-control-plane.md)及其黄金向量为准。

```
Node                           # §1 —— Loom 管的机器。目标地址不在这里
  id, name, country, city, provider
  public_endpoint?, ssh_port?, nat_type, arch, os
  components?                  # 组件版本,缺省取全局默认(§15.4)
  agent_last_seen, agent_version, status

  server?                      # 这个块存在 = 持有 server 能力(§1.3)
    direction                  # 仅 v1 兼容/迁移输入；目标态由每条 LinkIntent 表达(§2)
    public_data_ingress?       # 仅 v1 compatibility 客户端直拨开关；v2 单独无 authority(§2.3)
    inbound_port               # 接受上游连接的端口(§8.1)
    inbound_protocol?          # hysteria2 | trojan(§6.2.1)
    egress_capable             # 能否作为出口出公网
    wg_public_key              # 节点上报,平台不持有私钥
    secret_generation          # 秘密层代次,只记代次不记私钥(§12.1)

  responsibilities[]           # 目标态：use_loom | forward | internet_egress；后者蕴含 forward
  server_public_access_profile_ref? # 目标态：所有 forward Device 必有；不进入 v1 strict schema

  access?                      # 这个块存在 = 持有 access 能力(§1.3)
    platform                   # android | windows-desktop | linux-server(§7.2)
    credentials[]              # §8.2
    mixed_ports[]              # managed 1080；固定声明端口仅限 Linux 兼容/高级覆盖
    default_declaration?       # Auto 的中控 catch-all；客户端本地三态偏好不进入 SSOT

  control?                     # 目标态：certified FinalControlSet + matching private directory 的只读投影
    member_id                  # 公开 set 中的 opaque ID；不从 Device ID 导出
    signing_public_keys        # config / membership / enrollment 的独立公钥（公开 authority）
    peer_rpc_endpoints[]       # private directory；overlay IP only
    private_service_endpoints[] # control_api/enrollment/config/report；overlay IP + internal cert
    peer_identity_spki_hash    # private directory；同时绑定 exact control_peer_identity artifact hash
    fault_domain?              # private directory；部署提示，不改变 quorum 公式

  # 没有 capabilities 字段 —— 由哪个块存在推导；多个块并存合法(§1.3)。
  # 没有 target 能力 —— 出口是位置不是类型(§1.1)。
  # 没有 mesh_eligible —— 是否存在 overlay/data link 由 certified LinkIntent 决定(§2)。

ServiceAddress                 # §9 —— 目标地址。不是节点,不参与渲染
  address                      # 如 https://llm-b.internal/v1
  service                      # 服务类型标签(§1.4)
  access_contract              # §4.4 转发前提:域名、证书 CA、凭据来源、
                               #      请求路径前缀、协议版本
  egress_credential_ref?       # 出口服务器向它鉴权用的凭据引用(§9.3)
  region?, provider?           # 仅用于策略过滤与排障标注

EquivalenceClass               # §4.3 —— 可互换性的定义
  id                           # 如 llm:qwen3-32b-int8@openai-v1
  output_contract              # §4.3 输出等价:参数、上下文长度、流式行为
  carrier                      # l4_direct | l7_gateway | sdk(§4.4)
                               # l4_direct 要求所有成员 access_contract 同构
  observation_point            # 决定能产出哪些指标(§16.2)
  price_source?                # 无则 objective: cost 不成立(§5.2)
  verification_suite           # 定期校验用的测试请求集(两个契约都要校验)
  members[]                    # ServiceAddress 列表 —— 是地址,不是节点
  last_verified_at, failures[]

ReachEdge                      # 仅 bootstrap 阶段(§14.1)
  from_node, to_node, ssh_port, ssh_user

Tunnel                         # v1 compatibility；迁移后投影成 LinkIntent
  id, from_node, to_node, protocol(wg|awg|hy2)
  initiator                    # 由两端 direction 推导,不可手工指定
  listen_port, from_addr, to_addr
  obfuscation_param_set?
                               # 一条隧道一个网卡:多个出口都要 0.0.0.0/0,
                               # 同一网卡上无法共存(§6.3)

LinkIntent                     # 目标态：每条边的唯一传输契约(§2、§6.3)
  id, from_device_id, to_device_or_service
  purpose                      # control_overlay | data_forward | bootstrap
  allowed_transports[]         # wireguard | hysteria2 | trojan_tls；稳定排序
  initiator                    # from | to；经可达性验证后由 certified intent 固化
  listener_resource_refs[], credential_refs[], route_scope
                               # purpose/ACL 不因 transport 可用而自动扩大

ObfuscationSet                 # §17
  id, version, created_at
  Jc, Jmin, Jmax, S1..S4, H1..H4, I1..I5
  validated: bool

RouteCandidate                 # §5.6 —— 排序、选择与归因的唯一单位
  id                           # 下发 ranked list 与上报 Measurement 时引用它
  declaration_id
  server_chain[]               # 有序;最后一台就是这次的出口(§1.1)
  address?                     # 地址轴若"由请求决定"则为空
  eligible                     # 策略过滤结果(§5.1),false 则不进排序
  score, rank                  # 排序产物 —— 运行时状态,不进 SSOT(§12.1)
  sample_count, last_sample_at # 冷启动与过期判定(§5.8)

AccessDeclaration              # §4 —— 访问声明,选路的单位
  id, name

  # 两个轴分别声明,不合成一个 mode(§4)
  address_axis                 # from_request | class:<equivalence_class_id>
  egress_axis                  # any | pinned:<node_id>

  matcher                      # 当前占位字段；v1 matcher 属于中控规则，不由客户端编辑
  objective                    # latency | ttft | throughput | stability | cost
  constraints[]                # 合规、地域、SLA —— 过滤而非评分(§5.1)
  allowed_servers[], max_hops  # 渲染成服务器侧"允许的下一跳集合"(§8.2)
  ranking_period?              # 控制平面重算 ranked list 的周期(§5.5)
                               # address_axis = from_request 时无意义
  tuning_period                # 接入节点 top-N 内微调的周期(§5.5)
  switch_threshold             # §5.5
  top_n                        # 下发给接入节点的候选数(§5.6)
  window, min_samples, stale_after            # §5.8
  fallback                     # fail_closed | direct | last_known_good(§5.8)

PriceRecord                    # 声明值,与度量值分开(§5.2)
  address, equivalence_class
  unit_price, tiers[], currency
  effective_from, effective_to, source

Measurement                    # 运行时状态,不进 SSOT(§12.1)
  candidate_id, declaration_id, ts   # 按完整路径归因(§5.6)
  rtt_p50, rtt_p95, loss, jitter                    # 网络层
  first_byte_ms, bytes_in, bytes_out, conn_ms       # L4 可得(§16.2)
  ttft, tokens_per_sec, error_rate                  # 应用层,需 L7 观测点(§16.2)
  observation_point            # l4_tunnel | l7_gateway | sdk | endpoint
                               # 不同观测点的数据不可直接比较(§16.2)
  observation_kind             # passive | active(active 计入探测预算)
  score

Credential                     # §8.2 —— 接入凭据
  id, secret_ref, owner
  declaration_id
  issued_at, expires_at, revoked_at
                               # 出口凭据是另一类东西,见 ServiceAddress(§9.3)

Snapshot                       # 不可变版本
  id, created_at, author, ssot_hash
  rendered_bundles{owner: bundle_hash}          # 只含渲染层,不含秘密层
                               # owner 是节点 id 或客户端档案 id
  component_versions{node_id: {sing-box, wireguard, tailscale, agent}}
                               # 与配置同快照,绑定回滚(§15.4)
  secret_generations{node_id: gen}
                               # 只记代次与公钥,不含私钥;
                               # 回滚不回滚秘密层(§12.1)

ControlHead                    # 目标态；versioned wire profile 详见分布式控制专题
  recovery_epoch, recovery_statement_hash, recovery_policy_hash
  control_epoch, control_set_hash, control_revision
  raft_term, raft_index, parent_head_hash, head_hash
  operation_root, effective_ssot_hash, device_views_root
  replication_qc               # Raft commit/apply 后的 quorum attestation，不属于 Snapshot

FinalControlSet / Transition   # 目标态；成员 authority，不由普通 SSOT 字段自我授权
  JointControlSet(old,new) -> FinalControlSet(new)
  recovery/old/new set hash, Raft coordinates, old+new quorum proof

DeviceViewEnvelope             # 目标态；绑定 ControlHead/QC、leaf/proof、payload 与 EndpointSet

DeviceViewLeaf / Proof         # 目标态；本机最小授权 view；leaf 不含 head/root/control 坐标
  cluster_id, view_schema_version, device_id, device_generation, state
  payload_hash, previous_view_hash, public_endpoint_set_hashes[], private_service_directory_hash
  min_reader_version
  RFC 6962 inclusion path -> ControlHead.device_views_root

ControlSet / ControlPeerDirectory # 目标态；公开 authority 与私有拓扑严格分离
  public set: opaque member_id + membership/config/enrollment public keys
  private directory: hiding nonce + member→Device/SPKI/peer URL/fault-domain；head 只公开其 hash

PublicEndpointSet              # 目标态公开 transport bundle；authority 坐标由 DeviceViewEnvelope/head 绑定
  schema, cluster_id, endpoint_set_id, generation, source, digest
                               # source 是 genesis epoch 或 parent-head + 预生成 operation ID + revision
                               # 不引用当前 head/object hash，避免 EndpointSet 自引用
  kind                         # distribution | bootstrap_ingress | data_ingress
                               # 前两者可由 Invite/catalog 引用，data_ingress 按 Device 授权
  endpoints[]

DistributionEndpointSet / BootstrapIngressEndpointSet / DataIngressEndpointSet
                               # 上述 kind 的独立 wire profile，不能跨 kind 搬用 endpoint/credential

LogicalPublicEndpoint          # PublicEndpointSet 内的稳定逻辑身份
  id, role(distribution|bootstrap_ingress|data_ingress), owner_device_id
  protocol, public_endpoint_intent_hash, public_endpoint_intent_generation
  address_or_domain_intent_hash
  transport_identity           # TLS server_name/WebPKI/SPKI pins 或 WireGuard peer public key 的 tagged union
  listeners[]                  # 唯一键=(id,generation)，允许同一 id 的新旧代 overlap
                               # advertised|preferred|draining + certified FQDN/public port/transport identity
                               # rotation-operation hash + validity/retire-not-before；不含 local mapping
  frozen_dependency_hashes[]   # intent/DNS/cert/credential/policy/pool/mapping/firewall/render/evidence

ControlServiceDirectoryV1      # 不公开；由 matching certified view/directory hash 约束
  services[]                   # role=control_api|enroll|device_config|device_report
                               # overlay IP + 分用途 internal cert、pin 与 subject policy

ControlPeerDirectoryV1         # 与上项独立；只下发给 ControlSet voter
  peers[]                      # member→Device/SPKI/overlay peer tuple + control-peer mTLS policy
                               # 不进入普通 Device view 或公开 distribution

ServerPublicAccessProfileV1    # 每个 forward Device 的公网基线
  server_id, generation, fqdn, dns_zone_ref, public_frontend_addresses[]
  address_family_policy, https_public_port, certificate_profile_ref
  deployment_kind              # direct_standard | direct_alternate | nat_mapped
  forward_listener_resources_hash

ForwardServerListenerResourcesV1 # server-private desired/resource facts
  nginx_local_tcp_port, hy2_local_udp_port_pool[], wireguard_local_udp_ports[]
  trojan_local_tcp_port_pool[], mappings[]
                               # public EndpointSet 只投影 FQDN/public port，不泄露本地/CPE 细节

PortMappingIntentV1            # 只用于 nat_mapped
  transport, public_address/port_range, local_address/port_range, mapping_generation

BootstrapTunnelCapability      # Invite/QC 授权、BootstrapIssuer 签发的短期能力
  body
    certified_invite_record_hash, invite_issuance_policy_hash
    issuer_authorization_hash, ingress_set_hash, private_service_ref_hash, mode
    not_before, expires_at, resume_transaction_binding?
    allowed_private_destination, session_limit, byte_limit, attempt_limit
  capability_id                 # exact body 的 domain-separated hash；不回填 body
  signature
                               # 与 enrollment token 分离；只准 Enrollment TCP /32(/128)+port

BootstrapIssuerAuthorization   # certified registry leaf + inclusion proof + matching head/QC
  id, generation, previous_hash, active|revoked, key/purpose, validity
  max_ttl/session/bytes/attempts/concurrency, permitted ingress/service scope

InviteProofBundleV2            # public mirror；只含 hiding commitment，不含 intent/opening
  certified invite record/policy/commitment + operation inclusion + issuer/authority/head/QC proofs

DeviceEnrollmentIntentOpening # control-private；仅 capability tunnel + inner-TLS preflight 返回
  exact intent + per-Invite 32-byte hiding nonce；客户端重算 intent/opening/commitment hash

StableEnrollmentAdmissionQCV1  # control-private；不含 token 明文
  token-commitment + exact request-body/PoP facts + invite/base-head/state
  stable enrollment-key quorum signatures；reservation operation 只引用其 exact hash

PublicEndpointIntent           # 目标态；显式决定公网 listener，不从 control role 自动推导
  id, generation, owner_device_id, role, exposure, protocol
  address_or_domain_intent, listener_policy_ref, credential_artifact_hashes[]
  certificate_identity_projection_hashes[]? # TLS 排序 1..2（old/new overlap）；WireGuard 缺失

ManagedZoneV1                  # 目标态；id+generation+hash 固定已委派 DNS 边界
  suffix, provider profile, exact credential artifact hash, record/TTL/naming policy

DomainBindingIntentV1 / DNSAddressLifecycleStateV1 # 目标态；DNS desired 与新旧地址 overlap
  exact zone ref, endpoint/owner/fqdn/families/policy hash
  claim generation, preparing/overlapping/preferred/draining/retired, actual TTL/remove-not-before

AddressChallengeIntentV1 / AddressClaimV1 # 目标态；地址 ownership、可达性和代次
  one-time challenge、binding/endpoint/owner/family/address、前代与有效期
  Device signature、连续稳定窗口、多视角验证 receipts

CertificateIdentityProjection # public role-bounded 稳定绑定；不是 internal control/Device authority
  certificate_intent_id, identity_generation, role, endpoint_ids[], dns_names[], issuer_profile_ref
  key_owner_device_id, exact key_artifact_hash, spki, identity_projection_hash

CertificateIntent              # 可按 issuance 变化的签发对象
  exact identity_projection + hash, csr_hash, renew_before, issuance_generation
  # 同 projection 下例行续签不迫使 PublicEndpointIntent/EndpointSet 换代

SecretArtifactRef              # 目标态；权威 secret 必须在引用它的 proposal 提交前固定
  cluster/proposal/secret/purpose/owner/generation, public_identity_or_spki, immutable_ref
  ciphertext_digest + sealing_policy/recipient key versions + availability receipts
  # 当前使用 sealed 软件后端；禁止 latest/alias/可覆盖路径；托管硬件后端见独立后续计划

ResourceLease                 # 目标态；协调外部副作用，不产生 desired-state authority
  resource_id, holder_control_id, recovery_epoch, control_epoch, raft_term
  acquired_index, desired_hash, fencing_token, expires_at
```

**十一处关键关系:**

- **`Node` 与 `ServiceAddress` 是两张表,不是一张。** 前者是 Loom 管的机器,后者只是地址 —— 这条区分是全模型的地基([§1](model.md#1-两类节点加一类不是节点的东西)、[§9](servers.md#9-目标地址));
- **没有 `target` 角色** —— 出口是路径上的位置,由 `RouteCandidate.server_chain` 的最后一项决定([§1.1](model.md#11-出口不是一种节点是路径上的一个位置));
- v1 `Tunnel.initiator` 由两端 `direction` 确定性迁移；目标态由每条 certified
  `LinkIntent` 独立固定 initiator/transport/purpose，节点级方向不再授权新边([§2](model.md#2-发起方向可达性与-transport-是每条边的契约)、[§6.3](transports.md#63-只渲染被显式授权的-linkintent));
- `EquivalenceClass.carrier` 由成员 `access_contract` 是否同构决定 —— **`l4_direct` 是有前提的,不是默认可行**([§4.4](model.md#44-访问契约换地址能不能只靠-l4-完成));
- `RouteCandidate` 是排序、下发与归因的**唯一单位** —— 地址与服务器链不分开排序([§5.6](scheduling.md#56-决策位置由信息可得性决定));
- `PriceRecord` 与 `Measurement` 分表 —— **声明值与度量值性质不同**([§5.2](scheduling.md#52-评分输入分两类))；
- `control` 与 access/server 正交；正式 authority 由 certified `FinalControlSet` 确定，映射到 Device
  的只读投影还必须取得同 head 绑定的 matching private `ControlPeerDirectory`，不由普通字段
  自我授权或在线探测推导；
- 每个 `forward` Device 必有稳定 FQDN 与 `ServerPublicAccessProfile`；DNS 没有端口，实际
  TCP/UDP public tuple 来自 signed public EndpointSet；NAT mapping 只在 private resource intent；
- `DistributionEndpointSet`、`BootstrapIngressEndpointSet` 与 `DataIngressEndpointSet` 是公开
  transport 集；control/Enrollment/Raft/config/report 只在 private service directory；
- bootstrap capability 与 enrollment token 分离：前者只开限时限路由 tunnel，后者只在内层
  TLS 中由 ControlSet CAS 消费；issuer authorization、Invite policy 与 admission QC 都必须由
  exact hash/proof 连到 certified head，不能拿独立合法的 QC 拼接；
- public EndpointSet 的逻辑 ID 稳定，DNS/地址/端口/certificate generation 可重叠轮换；HY2/WG
  端口池分离，NAT 预映射范围仍逐 generation 验证；同一逻辑 ID 的 listener 以 generation 复合
  唯一键并显式携带 advertised/preferred/draining 状态。

**校验器必须拒绝的矛盾配置:**

| 矛盾 | 出处 |
|---|---|
| 两端 `direction` 组合非法(rev↔rev、dir↔dir) | [§2.2](model.md#22-v1-direction-只是迁移输入) |
| 手工指定 `mesh_eligible` / `Tunnel.initiator` / `uses_tun` / `capabilities` | [§2.2](model.md#22-v1-direction-只是迁移输入)、[§7.2](client-platforms.md#72-平台差异)、[§1.3](model.md#13-数据平面职责分块control-是正交只读投影) |
| 把角色字段写进错误的块(如 `access: {direction: …}`) | [§1.3](model.md#13-数据平面职责分块control-是正交只读投影),严格解码在加载阶段即拒绝 |
| 方向组合与显式 `Tunnel` 矛盾 | [§2.2](model.md#22-v1-direction-只是迁移输入)、[§6.3](transports.md#63-只渲染被显式授权的-linkintent)；当前不能假设 Headscale 已接管 |
| **把目标地址写成 `Node`** | [§1](model.md#1-两类节点加一类不是节点的东西),目标不是节点 |
| `carrier: l4_direct` 但成员 `access_contract` 不同构 | [§4.4](model.md#44-访问契约换地址能不能只靠-l4-完成) |
| `objective: ttft` 但等价类缺少 L7 观测点 | [§16.2](measurement.md#162-被动观测优先但被动能看到什么由观测点决定) |
| 有合规 `constraints` 但 `fallback ≠ fail_closed` | [§5.8](scheduling.md#58-数据不足与候选集为空) |
| `address_axis = from_request` 却配置了 `ranking_period` | [§5.5](scheduling.md#55-调整周期与阻尼) |
| `egress_axis = pinned:<x>` 但 `x` 不在 `allowed_servers` 里 | [§5.1](scheduling.md#51-策略裁剪候选集度量在候选集内选优) |
| `ControlSet` 为空、按在线数缩 quorum，或成员变化缺 old/new joint proof | [§11.1](control-rendering.md#111-control-是动态节点能力不是固定三台机器) |
| 未完成普通 Device Enrollment/overlay 身份就加入 ControlSet | [§11.1](control-rendering.md#111-control-是动态节点能力不是固定三台机器) |
| 相同 control epoch/revision 或 endpoint generation 对应不同 hash | [§12](control-rendering.md#12-逻辑-ssot-与纯函数渲染)、[§14.3.2](public-endpoints.md#1432-公网-listener-与端口无中断轮换) |
| 公网 Nginx 接收/代理 claim 或公开 control/config/report/Raft listener | [§8.1](servers.md#81-职责)、[§13.5](identity.md#135-客户端加入网络复用-certified-ssot-与发布链)、[§14.3.1](public-endpoints.md#1431-托管域名与证书) |
| bootstrap capability 可访问 Enrollment 之外的地址/协议，或与 enrollment token 共用 | [§13.5](identity.md#135-客户端加入网络复用-certified-ssot-与发布链) |
| capability 未绑定 certified record/policy/issuer authorization，或 admission QC 未绑定 exact claim body | [§13.5](identity.md#135-客户端加入网络复用-certified-ssot-与发布链) |
| 公开 proof 正文含 intent/opening 或可离线枚举的 Device ID/Responsibilities/grants commitment | [§13.5](identity.md#135-客户端加入网络复用-certified-ssot-与发布链)、[§14.2.2](distribution.md#1422-分发面公开证明与私有-device-view-分离) |
| forward Device 无 FQDN/PublicAccessProfile，NAT public/local tuple 未分离，或 HY2/WG 共用 UDP tuple | [§8.1](servers.md#81-职责)、[§14.3.2](public-endpoints.md#1432-公网-listener-与端口无中断轮换) |
| DNS/ACME/端口副作用没有 certified intent 就执行，或对象缺席触发删除 | [§14.2.3](distribution.md#1423-publisherreconciler提交与外部副作用分开) |
| 新 listener 未验证就 advertise/prefer，或 retire 时兼容/排空门槛不足 | [§14.3.2](public-endpoints.md#1432-公网-listener-与端口无中断轮换) |
| 同一 logical endpoint 的新旧 generation 无法共存、没有唯一 preferred，或轮换阶段读取 mutable latest 依赖 | [§14.3.2](public-endpoints.md#1432-公网-listener-与端口无中断轮换) |

---

<a id="第四部分--构建顺序"></a>

---

# Loom · v2 控制面规范入口

[文档地图](README.md) · [架构与七条不变量](design.md) · [实现对照](implementation.md) · [本机部署信息](operations/local-deployment.md)

**规范状态：已批准的迁移目标。** 本目录定义 v2 对象、认证、状态机与验收要求；
`§` 编号沿用原控制面文档。它不描述源码已支持到哪里，也不证明生产已经迁移。

**引用关系：** 架构入口定义系统不变量，本专题定义控制协议细节；
[决策记录](decisions.md)只解释理由。已接受的结论合入对应正文，发现矛盾时修正规范，
不以某个 D 编号或文件时间作为覆盖规则。v1 是明确的迁移输入，不能把 v2 字段塞入严格 v1 schema。

<a id="loom--分布式控制平面域名与入口生命周期"></a>

## 按任务阅读

| 任务 | 规范正文 |
|---|---|
| Device 控制能力、quorum 与故障模型 | [4. Device 能力与控制角色](specs/control-plane/membership-model.md) |
| 信任域、管理员与 CA | [6. 信任域与密钥](specs/control-plane/identity.md) |
| 权威 secret artifact | [6.2 权威 secret artifact](specs/control-plane/secret-artifacts.md) |
| CRDT、Raft、QC 与读写 | [7. 复制模型：CRDT 保存材料，共识决定生效](specs/control-plane/consensus.md) |
| ControlSet 加入与移除 | [9. ControlSet 成员变化](specs/control-plane/membership-transition.md) |
| 丢失 quorum 的显式恢复 | [9.3 丢失 quorum](specs/control-plane/recovery.md) |
| Recovery policy 计划轮换 | [9.4 recovery policy 的计划轮换](specs/control-plane/recovery-policy.md) |
| 签名发布、Device view 与 anti-rollback | [10. 发布、签名与客户端 anti-rollback](specs/control-plane/publication.md) |
| Enrollment 流程、Invite 与二维码 | [11. Enrollment、邀请与报告](specs/control-plane/enrollment-invite.md) |
| Bootstrap tunnel capability | [11.3 Bootstrap tunnel capability](specs/control-plane/bootstrap-capability.md) |
| Enrollment TLS、claim 与事务完成 | [11.4 内层 TLS、token、Keystore PoP 与一次性提交](specs/control-plane/enrollment-transaction.md) |
| 私有 Device 配置与报告 | [11.5 稳态配置与报告](specs/control-plane/device-services.md) |
| 公网 profile、DNS 与证书 | [12. 域名、公开服务与证书管理](specs/control-plane/public-access.md) |
| EndpointSet、catalog 与端口模型 | [13. EndpointSet、catalog 与公网端口模型](specs/control-plane/endpoints.md) |
| Listener 与端口轮换 | [14. Listener 与端口无中断轮换](specs/control-plane/listener-rotation.md) |
| 外部副作用、租约与 UI/API | [15. 外部副作用与租约](specs/control-plane/reconciliation-ui.md) |
| 故障、备份与垃圾回收 | [17. 故障语义](specs/control-plane/failure-backup.md) |
| 迁移与旧路径删除 | [19. 从当前实现迁移](specs/control-plane/migration.md) |
| v2 验收矩阵 | [20. 验收矩阵](specs/control-plane/acceptance.md) |

涉及功能替换时，必须同时阅读[迁移完成条件](specs/control-plane/migration.md)与
[对应验收条款](specs/control-plane/acceptance.md)，不能只读兼容安排。

## 1. 结论

Loom 不再有一台永久的“中控机器”。一台合格 Device 可以同时承担 `access`、`server` 和
control 能力，但 control 的权威来源不是普通 SSOT 编辑：Raft config ledger 中最新 durable
committed 的 `JointControlSet` 或 `FinalControlSet(epoch)` 是内部选举/提交必须立即遵守的唯一
成员事实；Joint 要求 old/new 双多数，Final 表示稳定态。相应 transition apply/recompute 后
取得所需 joint replication QC，才成为可对客户端发布的 certified authority。
授权 operator 的 private materialized view 中，`control` 职责块只是 certified FinalControlSet
authority 与同 head 绑定的 private ControlPeerDirectory 联合得到的只读 capability projection；公开发布只含 opaque
ControlSet member/key，不含 Device 映射或 peer 拓扑。ControlSet 至少一个，最多可以是全部合格 Device；协议和数据模型不得
写死 3，也不得让节点靠添加本地 `control` 块自我授权。

3 只是最小的高可用部署建议：在崩溃故障模型下，3 个投票成员的多数派为 2，可以容忍
1 个成员离线。它不是节点类型、许可证限制或协议常量。

控制状态采用混合模型：

```text
管理员签名请求 / 节点签名事实
              │
              ▼
  内容寻址操作与对象集合 ── CRDT anti-entropy ── 所有 control 副本
              │
              ▼ 确定性校验、候选归约/渲染
       针对精确 parent/hash 的 Raft entry
              │
              ▼ durable commit → apply/recompute → quorum attest
       唯一 certified head + quorum certificate
              │
              ├──► 公开 head/QC/transition ──► 不可信静态镜像
              ├──► 每 Device Merkle-proofed view ──► 身份认证的 device_config API
              └──► DNS、ACME、端口、防火墙等幂等 reconciler
```

CRDT 负责复制事实、草稿和不可变对象；quorum 负责决定什么已经生效。control Device
只能通过 Loom overlay 上的私有地址承载管理、Enrollment、报告、配置读取和 peer RPC；
这些服务不得写入公网 DNS、公开 EndpointSet 或 Nginx route。公网 forward server 只承载静态
distribution/fake website 和被签名目录授权的数据/临时 bootstrap listener；它可以不是
ControlSet 成员，也不能因此转发应用层 claim。当 `q > 1` 时，单个控制节点不能独立改变成员、权限、配置、邀请、
证书批准、域名绑定或入口端口；`N=1,q=1` 是明确的迁移/最小部署模式，不具备这项抗单节点
失陷性质。

管理客户端只能在已验证的私有 ControlServiceDirectory 中选择 overlay IP，校验 internal CA、
IP SAN/固定 SPKI 和 admin mTLS 后提交。尚无 Device 身份的客户端先从二维码列出的 2–3 个
公网 distribution mirror 下载并验证不可变 bootstrap catalog，再实测 catalog 中的 HY2
bootstrap ingress；正式版在 UDP 全阻断时使用独立 Trojan/TLS TCP fallback。外层临时隧道
只允许到私有 Enrollment `/32` 或 `/128` 和精确 TCP 端口，token 与 CSR 只在内层 TLS 中发送。
公开 Nginx 永远不接收、终止或代理 Enrollment。

---

## 2. 目标与非目标

### 2.1 目标

1. 控制节点数量可以从 1 在线扩展到任意数量，也可以安全缩容。
2. 任一已入网且合格的 Device 都可晋升为 control；ControlSet 为 1..N，管理与 peer RPC 只在
   Loom overlay 内可达，control Device 不需要任何公网入口。
3. 网络分区时至多有一个控制状态继续提交，少数派不得自封为新集群。
4. 控制面失去 quorum 不影响已安装的数据面；节点继续使用最后一个已认证 view。
5. 配置来源、传输镜像、DNS 和 TLS 终止点均可替换，但不能扩大签名 authority。
6. 每个 active forward server 都有稳定 FQDN 与 public access profile；自动申请和续签证书，
   并显式支持直连 443、替代 TCP 端口和 NAT 映射三种部署。
7. Hysteria2、Trojan/TLS 等可并行 listener 的公网入口使用同一代次模型无中断轮换；
   WireGuard 只有采用双接口/双 peer 专用状态机后才能宣称同等级别的无中断轮换。
8. Android、Windows 和 Linux 使用同一信任、anti-rollback、端点集合与轮换语义。
9. 从当前单签、单控制节点部署可以分阶段迁移，不重建既有 Device 私钥。

### 2.2 非目标

- 不让控制平面进入用户数据路径，也不把控制服务暴露到公网。
- 不声称普通多数共识能够容忍 Byzantine 控制节点；首版只承诺 crash/partition safety。
- 不用 DNS、HTTPS 证书、在线节点数或 Web 测量结果决定控制成员资格或客户端实际入口。
- 不把域名购买、续费扣款或注册商迁移默认做成无人批准的自动操作。
- 不承诺 QUIC/TCP 会话跨端口迁移；“无中断轮换”靠新旧 listener 重叠和旧会话排空。
- 不为控制复制重新引入客户端整路径探测；客户端仍遵守入口单次有界测量约束。

---

## 3. 不变量

| # | 不变量 |
|---:|---|
| 1 | **一个逻辑 SSOT，多份副本。** 副本数量不产生第二套期望态。 |
| 2 | **生效状态必须有唯一 certified head。** CRDT 对象或尚无 QC 的 Raft commit 不能直接授权安全关键动作。 |
| 3 | **quorum 按已提交成员数计算。** 不能按当前在线数自动缩小。 |
| 4 | **成员变化也是被共识保护的状态。** `control` 不能靠本地开关即时获得投票权。 |
| 5 | **签名高于传输信任。** DNS、TLS、反代、镜像和临时 leader 都不是配置 authority。 |
| 6 | **密钥按用途分离。** Device、control peer、配置签名、Enrollment、admin、CA 与公开 TLS 不复用。 |
| 7 | **外部副作用只追随 certified state。** 无 QC 的 Raft commit 不得驱动 DNS/ACME/防火墙；执行失败也不能倒写另一个 SSOT。 |
| 8 | **端点身份稳定，物理地址可轮换。** 客户端选择逻辑 endpoint，不把端口代次当新出口。 |
| 9 | **数据面离线自治。** 无 quorum、所有控制端不可达或新 view 无效时保留 last-known-good。 |
| 10 | **恢复必须显式留下新 epoch。** 丢失 quorum 后不得静默删成员、降门槛或重置 revision。 |
| 11 | **公开面与控制面隔离。** Nginx 只给 fake website 和不可变 distribution；Enrollment/control/config/report 只走 Loom 私网。 |
| 12 | **首次入网双层认证。** 外层 capability 只开受限隧道，内层 TLS 才承载 token、CSR 与 Keystore PoP。 |

---

## 21. 实现约束摘要

实现者必须同时遵守：

1. ControlSet 是已入网 Device 的 1..N 动态集合；control 服务只在 overlay IP + internal cert 上。
2. CRDT 复制材料，Raft commit + apply + QC 才产生唯一 effective head。
3. 每个 active forward server 有 FQDN/PublicAccessProfile、Nginx、证书管理、HY2 和 WG；
   正式 bootstrap 另有独立 Trojan/TLS TCP fallback。
4. Nginx 只给 fake website 与 immutable content-addressed distribution，绝不处理
   Enrollment/control/config/report。
5. QR 保持紧凑：token/capability、catalog/proof hash、2–3 mirror 和有界 private Enrollment ref；
   完整无秘密 catalog 静态下载。
6. bootstrap capability 只开短期、限地址/端口/流量/次数的 tunnel；token 只在内层 TLS 使用。
7. 首次身份是 server-authenticated TLS + token + Keystore PoP；正式 Device cert 完成后销毁
   bootstrap 状态。
8. HY2 是首选 bootstrap，Trojan/TLS 是 UDP 全阻断 fallback；WG 是入网后的永久 L3/control
   overlay，三者不混成一个隐式 tunnel。
9. 公网 EndpointSet 按 distribution/bootstrap/data 拆分；私有 ControlServiceDirectory 与
   ControlPeerDirectory 再按调用方分离，公网/local/NAT 资源分层。
10. HY2/Trojan 用 overlap generation 轮换；WG 必须有独立双 peer/interface 设计才可称无中断。
11. DNS、WebPKI、镜像和 executor 只提供可达性/副作用，不扩大 quorum、签名或 Device 权限。
12. 任何尚未实现的 transport、证书 profile、轮换步骤或私有 API 必须显式失败，不得静默降级。

<details>
<summary>旧章节链接（按需展开）</summary>

<a id="4-device-能力与控制角色"></a>[4. Device 能力与控制角色](specs/control-plane/membership-model.md#4-device-能力与控制角色)
<a id="5-controlsetquorum-与故障模型"></a>[5. ControlSet、quorum 与故障模型](specs/control-plane/membership-model.md#5-controlsetquorum-与故障模型)
<a id="6-信任域与密钥"></a>[6. 信任域与密钥](specs/control-plane/identity.md#6-信任域与密钥)
<a id="61-初始-adminca-与轮换"></a>[6.1 初始 admin/CA 与轮换](specs/control-plane/identity.md#61-初始-adminca-与轮换)
<a id="62-权威-secret-artifact"></a>[6.2 权威 secret artifact](specs/control-plane/secret-artifacts.md#62-权威-secret-artifact)
<a id="7-复制模型crdt-保存材料共识决定生效"></a>[7. 复制模型：CRDT 保存材料，共识决定生效](specs/control-plane/consensus.md#7-复制模型crdt-保存材料共识决定生效)
<a id="71-内容寻址操作"></a>[7.1 内容寻址操作](specs/control-plane/consensus.md#71-内容寻址操作)
<a id="72-哪些数据可以直接-crdt-合并"></a>[7.2 哪些数据可以直接 CRDT 合并](specs/control-plane/consensus.md#72-哪些数据可以直接-crdt-合并)
<a id="73-哪些状态必须串行提交"></a>[7.3 哪些状态必须串行提交](specs/control-plane/consensus.md#73-哪些状态必须串行提交)
<a id="74-raft-committed-log-与提交后-certified-qc"></a>[7.4 Raft committed log 与提交后 certified QC](specs/control-plane/consensus.md#74-raft-committed-log-与提交后-certified-qc)
<a id="75-时间语义"></a>[7.5 时间语义](specs/control-plane/consensus.md#75-时间语义)
<a id="8-写入读取与分区行为"></a>[8. 写入、读取与分区行为](specs/control-plane/consensus.md#8-写入读取与分区行为)
<a id="81-写路径"></a>[8.1 写路径](specs/control-plane/consensus.md#81-写路径)
<a id="82-读路径"></a>[8.2 读路径](specs/control-plane/consensus.md#82-读路径)
<a id="83-分区"></a>[8.3 分区](specs/control-plane/consensus.md#83-分区)
<a id="9-controlset-成员变化"></a>[9. ControlSet 成员变化](specs/control-plane/membership-transition.md#9-controlset-成员变化)
<a id="91-加入"></a>[9.1 加入](specs/control-plane/membership-transition.md#91-加入)
<a id="92-移除"></a>[9.2 移除](specs/control-plane/membership-transition.md#92-移除)
<a id="93-丢失-quorum"></a>[9.3 丢失 quorum](specs/control-plane/recovery.md#93-丢失-quorum)
<a id="94-recovery-policy-的计划轮换"></a>[9.4 recovery policy 的计划轮换](specs/control-plane/recovery-policy.md#94-recovery-policy-的计划轮换)
<a id="10-发布签名与客户端-anti-rollback"></a>[10. 发布、签名与客户端 anti-rollback](specs/control-plane/publication.md#10-发布签名与客户端-anti-rollback)
<a id="101-signed-current-v2"></a>[10.1 signed current v2](specs/control-plane/publication.md#101-signed-current-v2)
<a id="102-floor-与-recovery-lineage"></a>[10.2 floor 与 recovery lineage](specs/control-plane/publication.md#102-floor-与-recovery-lineage)
<a id="103-v1--v2-不可逆-latch"></a>[10.3 v1 → v2 不可逆 latch](specs/control-plane/publication.md#103-v1--v2-不可逆-latch)
<a id="104-镜像"></a>[10.4 镜像](specs/control-plane/publication.md#104-镜像)
<a id="11-enrollment邀请与报告"></a>[11. Enrollment、邀请与报告](specs/control-plane/enrollment-invite.md#11-enrollment邀请与报告)
<a id="111-边界与端到端流程"></a>[11.1 边界与端到端流程](specs/control-plane/enrollment-invite.md#111-边界与端到端流程)
<a id="112-invitecatalog-与紧凑二维码"></a>[11.2 Invite、catalog 与紧凑二维码](specs/control-plane/enrollment-invite.md#112-invitecatalog-与紧凑二维码)
<a id="113-bootstrap-tunnel-capability"></a>[11.3 Bootstrap tunnel capability](specs/control-plane/bootstrap-capability.md#113-bootstrap-tunnel-capability)
<a id="114-内层-tlstokenkeystore-pop-与一次性提交"></a>[11.4 内层 TLS、token、Keystore PoP 与一次性提交](specs/control-plane/enrollment-transaction.md#114-内层-tlstokenkeystore-pop-与一次性提交)
<a id="115-稳态配置与报告"></a>[11.5 稳态配置与报告](specs/control-plane/device-services.md#115-稳态配置与报告)
<a id="12-域名公开服务与证书管理"></a>[12. 域名、公开服务与证书管理](specs/control-plane/public-access.md#12-域名公开服务与证书管理)
<a id="121-统一的-forward-server-公网基线"></a>[12.1 统一的 forward server 公网基线](specs/control-plane/public-access.md#121-统一的-forward-server-公网基线)
<a id="122-publicaccessprofile-与三类部署"></a>[12.2 PublicAccessProfile 与三类部署](specs/control-plane/public-access.md#122-publicaccessprofile-与三类部署)
<a id="123-dns-与证书-reconcile"></a>[12.3 DNS 与证书 reconcile](specs/control-plane/public-access.md#123-dns-与证书-reconcile)
<a id="124-私有-control-服务没有公网域名依赖"></a>[12.4 私有 control 服务没有公网域名依赖](specs/control-plane/public-access.md#124-私有-control-服务没有公网域名依赖)
<a id="13-endpointsetcatalog-与公网端口模型"></a>[13. EndpointSet、catalog 与公网端口模型](specs/control-plane/endpoints.md#13-endpointsetcatalog-与公网端口模型)
<a id="131-按用途拆分不再使用公开-roleenrollcontrol"></a>[13.1 按用途拆分，不再使用公开 role=enroll/control](specs/control-plane/endpoints.md#131-按用途拆分不再使用公开-roleenrollcontrol)
<a id="132-公网与本地资源的分离"></a>[13.2 公网与本地资源的分离](specs/control-plane/endpoints.md#132-公网与本地资源的分离)
<a id="133-transport-与端口约束"></a>[13.3 transport 与端口约束](specs/control-plane/endpoints.md#133-transport-与端口约束)
<a id="134-客户端选择与测量边界"></a>[13.4 客户端选择与测量边界](specs/control-plane/endpoints.md#134-客户端选择与测量边界)
<a id="14-listener-与端口无中断轮换"></a>[14. Listener 与端口无中断轮换](specs/control-plane/listener-rotation.md#14-listener-与端口无中断轮换)
<a id="141-通用重叠状态机"></a>[14.1 通用重叠状态机](specs/control-plane/listener-rotation.md#141-通用重叠状态机)
<a id="142-nat-预映射池"></a>[14.2 NAT 预映射池](specs/control-plane/listener-rotation.md#142-nat-预映射池)
<a id="143-客户端行为"></a>[14.3 客户端行为](specs/control-plane/listener-rotation.md#143-客户端行为)
<a id="144-wireguard-独立状态机"></a>[14.4 WireGuard 独立状态机](specs/control-plane/listener-rotation.md#144-wireguard-独立状态机)
<a id="15-外部副作用与租约"></a>[15. 外部副作用与租约](specs/control-plane/reconciliation-ui.md#15-外部副作用与租约)
<a id="16-ui-与-api"></a>[16. UI 与 API](specs/control-plane/reconciliation-ui.md#16-ui-与-api)
<a id="17-故障语义"></a>[17. 故障语义](specs/control-plane/failure-backup.md#17-故障语义)
<a id="18-备份恢复与垃圾回收"></a>[18. 备份、恢复与垃圾回收](specs/control-plane/failure-backup.md#18-备份恢复与垃圾回收)
<a id="19-从当前实现迁移"></a>[19. 从当前实现迁移](specs/control-plane/migration.md#19-从当前实现迁移)
<a id="m0--协议不变量与-golden"></a>[M0 · 协议、不变量与 golden](specs/control-plane/migration.md#m0--协议不变量与-golden)
<a id="m1--单成员私有-controlset"></a>[M1 · 单成员私有 ControlSet](specs/control-plane/migration.md#m1--单成员私有-controlset)
<a id="m2--reader静态-distribution-与-bootstrap-tunnel"></a>[M2 · Reader、静态 distribution 与 bootstrap tunnel](specs/control-plane/migration.md#m2--reader静态-distribution-与-bootstrap-tunnel)
<a id="m3--多-voter-与动态成员"></a>[M3 · 多 voter 与动态成员](specs/control-plane/migration.md#m3--多-voter-与动态成员)
<a id="m4--分布式-enrollmentdevice-api-与发布"></a>[M4 · 分布式 Enrollment、Device API 与发布](specs/control-plane/migration.md#m4--分布式-enrollmentdevice-api-与发布)
<a id="m5--域名dns-01证书与三类公网部署"></a>[M5 · 域名、DNS-01、证书与三类公网部署](specs/control-plane/migration.md#m5--域名dns-01证书与三类公网部署)
<a id="m6--hy2trojan-重叠轮换与-wg-独立轮换"></a>[M6 · HY2/Trojan 重叠轮换与 WG 独立轮换](specs/control-plane/migration.md#m6--hy2trojan-重叠轮换与-wg-独立轮换)
<a id="m7--收口与废弃旧路径"></a>[M7 · 收口与废弃旧路径](specs/control-plane/migration.md#m7--收口与废弃旧路径)
<a id="20-验收矩阵"></a>[20. 验收矩阵](specs/control-plane/acceptance.md#20-验收矩阵)
<a id="201-共识与成员"></a>[20.1 共识与成员](specs/control-plane/acceptance.md#201-共识与成员)
<a id="202-crdtssot-与-secret"></a>[20.2 CRDT、SSOT 与 secret](specs/control-plane/acceptance.md#202-crdtssot-与-secret)
<a id="203-qrdistribution-与-catalog"></a>[20.3 QR、distribution 与 catalog](specs/control-plane/acceptance.md#203-qrdistribution-与-catalog)
<a id="204-bootstrap-transport-与-capability"></a>[20.4 Bootstrap transport 与 capability](specs/control-plane/acceptance.md#204-bootstrap-transport-与-capability)
<a id="205-enrollment-transaction"></a>[20.5 Enrollment transaction](specs/control-plane/acceptance.md#205-enrollment-transaction)
<a id="206-dns证书与公开-profile"></a>[20.6 DNS、证书与公开 profile](specs/control-plane/acceptance.md#206-dns证书与公开-profile)
<a id="207-轮换"></a>[20.7 轮换](specs/control-plane/acceptance.md#207-轮换)
<a id="208-客户端与移动可靠性"></a>[20.8 客户端与移动可靠性](specs/control-plane/acceptance.md#208-客户端与移动可靠性)
<a id="209-运维ui-与负面暴露"></a>[20.9 运维、UI 与负面暴露](specs/control-plane/acceptance.md#209-运维ui-与负面暴露)

</details>

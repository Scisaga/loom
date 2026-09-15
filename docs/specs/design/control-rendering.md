# 控制边界与纯函数渲染

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**职责：控制面架构映射。** 本文解释全系统关系和标明的 v1 契约；v2 对象、认证、状态机与验收规则统一定义在控制面专题，本文不另设 wire schema。

---

## 10. 职责

拓扑与服务定义、配置渲染、候选集裁剪与排序、探测调度、价格与配额管理、密钥签发、部署编排、可视化。

**它不在数据路径上,不转发任何用户流量。**

---

## 11. 铁律:控制平面与数据平面分离

> **控制平面停机,数据平面必须继续正常运行。**

推论:

- 节点配置必须**落地为本地文件** + systemd 管理,不得在运行时向控制平面查询;
- 节点必须能**自治运行**;
- **排序结果也必须落地。** 控制平面离线时,节点沿用最后一次下发的 ranked list 继续本地选服务器链(见 [§5.6](scheduling.md#56-决策位置由信息可得性决定))。

### 11.1 `control` 是动态节点能力，不是固定三台机器

Loom 没有永久中控。除由离线 recovery/bootstrap authority 明确签定的初始 genesis member 外，
**control member 必须先作为普通 Device 完成 Enrollment、取得 permanent overlay 地址与 Device
identity，之后才能由既有 ControlSet 的 Joint→Final membership transition 晋升。** 邀请中的
Responsibilities 或本机配置都不能直接创建 voter；genesis 例外也只能建立首个已认证 lineage，
不能作为以后绕过 Enrollment 的通道。

Raft config ledger 中最新 durable committed 的 `JointControlSet` 或
`FinalControlSet(epoch)` 是内部 membership 状态；Joint 立即要求 old/new 双多数，Final 表示
稳定态。只有相应 transition 完成 apply/recompute 并取得所需 joint replication QC 后，
才成为对外 effective 的成员 authority。materialized SSOT 再把该 certified 集合中的 Device
投影为 `control` 块。集合
至少一个，最多可以包含全部合格 Device。普通 SSOT operation 不能靠先增加 `control` 字段
来自我授权。协议、客户端和
校验器不得写死 3，也不得出现 `primary_controller`。3 只是 CFT 模型下能容忍一个
成员离线的最小推荐部署：

```text
N = |ControlSet(epoch)|
q = floor(N / 2) + 1
```

| N | quorum | 可容忍离线 |
|---:|---:|---:|
| 1 | 1 | 0 |
| 2 | 2 | 0 |
| 3 | 2 | 1 |
| 4 | 3 | 1 |
| 5 | 3 | 2 |

Raft 选举、AppendEntries 和 commit quorum 只能按日志中最新 durable committed 的稳定
`FinalControlSet` 或 JointControlSet 计算，绝不能按在线数自动缩小；Final commit 后即使其
post-commit QC 尚未齐，新集合也已经约束内部 Raft，但不能对客户端发布为新 authority。
外部 reader/executor 只接受 joint-QC-certified Final。任一 control Device 都可在私有 overlay 内
接收管理请求、转发给 leader 并复制对象；`control_api` 使用 overlay IP、internal service
certificate 与 admin mTLS，不进入公网 DNS、PublicEndpointIntent 或 public EndpointSet。Raft 临时 leader 只负责串行化日志，外部
副作用由另行持有资源租约的合格 executor 执行，二者都不是额外信任根。失去 quorum 时停止成员、权限、邀请、配置和端口等安全关键
写入，但继续收集观测和草稿；数据平面继续使用最后一份已认证配置。

首版故障模型是 crash/partition tolerant，不宣称普通多数能抵御恶意 voter。成员加入、
移除和控制密钥更换必须由旧、新集合 joint quorum 确认；旧 quorum 永久丢失时只能用
离线 recovery root 产生显式更高 epoch，不能用 CRDT 或 DNS 静默接管。recovery transition
只授权新的 bootstrap lineage；新 ControlSet 仍须对精确 genesis durable install/commit、
apply/recompute 并形成 `q(new)` replication QC，缺少该 QC 时客户端继续旧 LKG。完整协议见
[分布式控制平面专题](../control-plane/membership-model.md#5-controlsetquorum-与故障模型)。

---

## 12. 逻辑 SSOT 与纯函数渲染

> **拓扑与服务定义是唯一事实来源。所有节点上的配置文件,都是它的渲染输出。**

```
签名不可变操作/完整候选 SSOT ── CRDT anti-entropy ── control 副本
                         │ 每个 voter 严格 validate + candidate Reduce/render
                         ▼
                   Raft durable commit
                         │ state-machine apply/recompute roots
                         ▼
                 quorum replication attest/QC
                         │ certified 后才成为 effective SSOT/发布同一确定性字节
                         └──► 每节点配置包(sing-box.json / wg*.conf / systemd unit / 候选集 / ...)
```

“唯一”指一个已取得提交后 replication QC 的 certified 逻辑提交头，不是磁盘上只能存在一个 YAML 文件。
Git/YAML 继续适合导入、导出、评审、diff 和归档；在线 authority 是不可变 operation DAG、
commit ledger 与 deterministic reducer。未提交草稿即使已经复制到所有 control Device，也不
能进入 **effective/published** 渲染或改变权限；voter 仍必须对它执行无副作用的 candidate
reduce/render，才能在 append 前验证确定性结果。

**手工登录任何机器改配置,都是错误操作。** 正确做法是由已经入网的管理员 Device 通过
permanent overlay 选择 private ControlServiceDirectory 中的 `control_api` IP，验证 internal
service certificate/IP SAN 或 pinned SPKI，并使用 admin mTLS 提交带 base head 的变更；候选经各 voter校验、Raft durable commit、状态机 apply/recompute 并取得
提交后 replication QC 后，才把相同的确定性结果提升为 effective SSOT 并发布。控制副本间只能交换 canonical 操作和
内容寻址对象；字段级 LWW 合并不得直接产生一份从未被操作者批准的 SSOT。

理由是一致性约束:[§6.3](transports.md#63-只渲染被显式授权的-linkintent) 的 N×M 矩阵两端必须严格对应;凭据到访问声明的映射必须在所有服务器上一致;候选集必须与实际存活的节点集合一致;混淆参数双端必须逐位相同。**这些人工维护必然出错。**

### 12.1 纯函数的三个产物

1. **dry-run diff** —— 部署前看到会改哪些文件的哪些行;
2. **漂移检测** —— Agent 比对本地文件哈希与期望值,不一致即纠正;
3. **回滚** —— 用旧快照重新渲染,不需保存旧配置文件。

渲染函数里**不能有**随机数、当前时间戳、外部查询。**控制平面生成的随机性**（混淆
参数、端口等公开随机选择）必须在 proposal 前生成并成为 canonical 输入，因此可以参与
无副作用的 candidate render；只有经 Raft commit、apply/recompute 与提交后 QC 后，同一结果
才可进入 effective/published render。秘密随机值只提交 commitment/hash、公钥、加密制品引用或 secret ref；invite token
明文、Device 数据面凭据和私钥不得进入 operation、CRDT、SSOT 或镜像。

**节点私钥是显式例外。** [§13.1](identity.md#131-私钥不集中生成) 要求 WG 私钥只在节点本地生成、永不离开节点 —— 平台既然没有它,就渲染不出含 `PrivateKey = ...` 的完整文件。两条规则用**渲染配置 + 本地秘密覆盖层**调和:

| 层 | 内容 | 谁产生 | 进快照吗 |
|---|---|---|---|
| **渲染层** | 配置文件全文;私钥位置写成对本地文件的引用(wg-quick `PostUp` 读 `/etc/loom/secrets/node.key`) | 平台渲染 | ✅ 全文哈希 |
| **秘密层** | 私钥文件本身,**一台机器一把**(SSOT 里每节点只有一个公钥) | 节点本地生成 | ❌ 只记 `secret_generation` 与**公钥** |

纯函数性质因此保住:同一份 SSOT 在任何时候渲染出的字节完全相同,私钥不参与渲染,[§15.3](deployment.md#153-幂等收敛) 的哈希比对也只比对渲染层。

> **回滚不回滚秘密层。** 节点保留当前 generation 的私钥。私钥轮换必须是**独立的一次操作**,不能搭在配置回滚上 —— 否则回滚会把对端 SSOT 里已更新的公钥变成过期值,两边对不上,隧道反而起不来。

> **运行时状态不进 SSOT。** 当前选中哪条路径、各候选的实时评分,是度量的产物,变化频繁,不应污染配置版本历史。价格属于**声明值**,有版本和生效时间,进 SSOT。

---

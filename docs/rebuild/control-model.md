# 最小控制模型

本文独立定义重建后的控制面核心。读者不需要阅读实现代码，就能回答以下问题：

- 哪些事实具有权威性；
- 一次写入何时生效、何时可以对外宣称完成；
- CRDT、Raft 和 quorum certificate（QC）各自解决什么问题；
- 节点重启、分区和成员变更后如何恢复同一结果；
- 领域对象如何无歧义地映射到 wire、持久层、运行时和 Web UI。

这里遵循“如无必要，勿增实体”。领域模型只有五个概念：
`Material`、`ControlConfig`、`ConsensusLog`、`Projection`、`CertifiedHead`。
签名、哈希、Raft 任期、运行时请求和 UI 表格都只是这五个概念的字段、协议机制或展示，
不是新的领域实体。

## 1. 原始需求与边界

### 1.1 必须实现

1. 一个或多个 control 节点使用同一模型；单节点只是 quorum 为 1 的自然情况，
   不得存在单独的 N=1 业务分支或以后再移除的门禁。
2. 已认证的管理写入必须形成唯一、确定、可恢复的顺序。任意健康 control 可以接收请求，
   但只有 quorum 可以确认新状态。
3. CRDT 必须用于不可变内容的增量同步；重复、乱序和断线重传不能改变结果。
4. 失去 quorum 时拒绝产生新权限和新权威状态，同时继续读取最后一个已认证结果。
5. 成员增加、删除和密钥变更进入同一权威写入链，不依赖旁路 registry 或人工修改多份状态。
6. 每个对外可消费状态都能从持久事实确定性重建，并有 quorum 签名的头部证明。
7. Web UI 保留，但只能展示 `Projection`，管理动作必须提交正常的认证写入，不能直接修改投影。
8. 私有管理服务承载写入。公网静态分发或网站不得成为管理写入入口。

### 1.2 明确排除

- 不把“每个节点都可以独立写，稍后按时间戳合并”用于权限、成员或配置决策。
- 不用 CRDT 的“已同步”代替 quorum 同意，也不用 QC 再建立第二套排序或投票规则。
- 不保留 v1 双写、旧 registry 回调或其他兼容路径作为最终架构。
- 不在这个模型中定义 Enrollment、Endpoint 轮换、客户端选路或平台交付；它们只消费这里认证的状态。
- 不为尚未出现的规模问题预建快照协议、分层 journal、工作流 phase、gate 或后台修复状态机。
- 不通过测试矩阵发明领域分支。新场景应首先表示为五个概念中的数据。

## 2. 五个领域概念

### 2.1 `Material`

`Material` 是一项不可变、规范编码、内容寻址的控制输入。它表达“希望控制状态发生什么变化”，
例如设置一项策略、撤销一项声明，或携带一个新的 `ControlConfig`。

其恒等式为：

```text
material_id = Hash(domain_separator || CanonicalEncode(material))
```

相同规范字节必得相同 ID。不同字节不得占用同一 ID；发现哈希键与内容不一致时必须拒绝，
不能覆盖。业务上的删除也是一份新的 `Material`，不是从内容集合中抹掉旧事实。

`Material` 出现在本地只表示“内容已知”，不表示它已获授权或已生效。只有被
`ConsensusLog` 的已提交前缀引用时，它才参与控制状态。

### 2.2 `ControlConfig`

`ControlConfig` 定义当前 control 成员、成员验证键和 quorum 规则。它是唯一的成员与
quorum 事实来源。它通过一种 `Material` 内容进入 `ConsensusLog`；不得另设 membership
registry、成员 ledger 或密钥目录与它并行决定成员资格。

`ControlConfig` 有稳定和联合两种取值形态：

- 稳定配置包含一个成员集合及其 quorum 规则；
- 联合配置同时包含旧集合和新集合，写入与认证都必须分别满足两侧 quorum。

“联合”是 `ControlConfig` 的一个值，不是新的领域实体或工作流对象。
初始安装提供规范的首个 `ControlConfig`；首条已提交记录引用它。单成员配置按同一规则运行。

### 2.3 `ConsensusLog`

`ConsensusLog` 是按索引增长的、唯一的已提交 `Material` ID 序列。它回答两个问题：

1. 哪些内容已被 control quorum 接受；
2. 这些内容以什么顺序生效。

Raft 负责形成并复制这个序列。日志记录至少绑定索引、Raft 所需的顺序信息、被引用的
`Material` ID 和前缀摘要；具体传输字段不是新的领域对象。

已提交前缀只能追加，不能改写或回退。在 follower 确认一条日志记录前，它必须已经持久化并
校验该记录引用的 `Material`。因此，不会出现 quorum 已提交但 quorum 上没有对应内容的合法状态。

### 2.4 `Projection`

`Projection` 是从 `ConsensusLog` 已提交前缀及其引用的 `Material` 确定性折叠出来的当前业务视图。
设备可见配置、管理列表、拓扑输入以及当前生效的 `ControlConfig` 都从该视图读取。

`Projection` 不是另一份权威数据库。它可以在内存中保存，也可以作为经过摘要校验的加速缓存保存，
但必须随时可以删除并重建。任何 UI 编辑、后台任务或迁移脚本都不得直接写它。

### 2.5 `CertifiedHead`

`CertifiedHead` 绑定一个已提交索引、该索引处的日志前缀摘要、对应 `Projection` 摘要、
适用的 `ControlConfig` 引用以及满足该配置的 control 签名集合。QC 就是它内部的签名集合，
不是第六个领域实体。

`CertifiedHead` 是对外消费和离线恢复的认证边界。它证明“这个日志前缀及其确定性投影已经由
规定的 quorum 共同确认”，但不重新决定日志顺序。节点可以内部拥有更新的 Raft commit，
在相应 `CertifiedHead` 形成前不得把更新后的状态作为已完成结果分发给外部消费者。

## 3. 关系与权威边界

```text
ControlConfig --作为一种内容--> Material
Material --由 ID 引用----------> ConsensusLog
ConsensusLog + Material --折叠--> Projection
ConsensusLog + Projection + ControlConfig --quorum 签名--> CertifiedHead
CertifiedHead --认证------------> 对外可消费的 Projection
```

| 概念 | 权威内容 | 不是它的职责 |
|---|---|---|
| `Material` | 某个内容 ID 对应的规范字节 | 不决定该内容是否生效 |
| `ControlConfig` | 成员、验证键与 quorum 规则 | 不另行保存运行时健康或领导者 |
| `ConsensusLog` | 已接受内容的唯一顺序 | 不复制大对象状态，也不承担 UI 查询模型 |
| `Projection` | 无独立权威性；只是确定性结果 | 不接受直接写入，不反推日志 |
| `CertifiedHead` | 某个可消费头部的 quorum 认证 | 不形成第二个日志，不改变已提交顺序 |

系统的业务权威不是任意一张表，而是：

```text
Canonical Material bytes
+ committed ConsensusLog order
+ active ControlConfig rules
+ matching CertifiedHead
```

其中 `Projection` 是上述事实的可验证计算结果。

## 4. 三份逻辑持久存储

实现只需要三份逻辑存储。它们可以位于同一数据库或不同文件中，但契约不能混淆。

| 逻辑存储 | 保存内容 | 写入规则 | 恢复用途 |
|---|---|---|---|
| Material store | `material_id →` 规范 `Material` 字节 | put-if-absent；同 ID 不同字节硬失败 | 解析日志引用；CRDT 增量补齐 |
| Consensus store | `ConsensusLog` 与 Raft 恢复所需的最少元数据 | 仅由 Raft 协议追加/截断未提交尾部；已提交前缀不改写 | 恢复接受顺序和当前 `ControlConfig` |
| Certified store | 单调推进的 `CertifiedHead`，以及可选的同摘要 `Projection` 缓存 | 新 head 索引不得倒退；替换前必须验签和验摘要 | 提供最后已认证读结果和重启校验点 |

Raft 任期、投票记录和传输重试是 Consensus store 的协议元数据，没有独立业务语义。
可选 `Projection` 缓存仍是 `Projection` 的编码，不构成第四份权威存储；摘要不匹配时直接丢弃并重建。

初始实现不增加独立 snapshot、checkpoint、journal 或 GC ledger。确有测量证据表明完整重建成本不可接受时，
再为现有 `Projection` 增加可验证缓存策略，而不是增加新的领域真相。

当前文件绑定保持这三个逻辑边界：`materials/<digest>.json` 是 Material store；
`consensus.json` 与同目录的 `consensus-raft.db` 共同组成 Consensus store，前者保存领域日志，后者只保存
Raft 任期、投票、复制日志和成员协议元数据；`certified.json` 是 Certified store，并可携带同摘要的
Projection 缓存。`node.json` 只保存本节点监听、TLS、签名私钥内容和恢复 floor，是
[本机部署配置模型](configuration-model.md)所述运行输入，不是第四份控制权威。初始实现关闭 Raft snapshot；
重启从完整日志重放。

## 5. 同构映射

“同构”要求同一概念跨层只换表示，不改变语义，也不在中间层复制一套影子状态。

| Domain | Wire | Persistent | Runtime | Web UI |
|---|---|---|---|---|
| `Material` | 带领域分隔、种类和规范内容的不可变消息；ID 由规范字节计算 | Material store 中以 ID 为键的原始规范字节 | 校验、去重、按 ID 解析；未提交内容保持惰性 | 管理动作形成待提交内容；UI 不显示“已同步”等同“已生效” |
| `ControlConfig` | `Material` 中的规范成员、验证键与 quorum 表示 | 不单设 store；保存在对应 `Material`，生效位置由日志给出 | 从已提交前缀得到当前稳定或联合配置，并驱动 Raft/QC 阈值 | 展示当前认证成员、quorum 和是否处于联合配置；不直接编辑表格行 |
| `ConsensusLog` | Raft 复制消息中的有序记录及前缀摘要 | Consensus store 的已提交前缀和必要 Raft 元数据 | leader/follower 只是在维护同一日志；接收节点可转交当前 leader | 展示认证索引和是否具备写 quorum；不暴露手工改索引/任期操作 |
| `Projection` | 读取 API 返回其确定性编码；不是写入协议 | 默认不持久化；可选缓存必须由 head 摘要验证 | 逐条 fold 或重启全量重建，供业务读取 | 所有 Devices、Topology、Services 和状态页都是同一投影的不同查询 |
| `CertifiedHead` | 头部摘要、配置引用和 quorum 签名的规范消息 | Certified store 中最新有效值 | 验签、单调推进，并限定可对外导出的投影边界 | 展示已认证索引/摘要和降级只读状态；成功提示只对应已覆盖请求的 head |

约束如下：

- wire 与持久层复用同一份规范编码，禁止为数据库再发明语义不同的 DTO。
- runtime wrapper 可以持有缓存和连接，但不得拥有领域层没有的持久状态机。
- UI 的写操作表达用户意图，由服务端生成、鉴权并提交 `Material`；UI 返回对象不得成为新权威。
- UI 读取必须带所依据的 `CertifiedHead`，避免把不同头部的卡片拼成一个不存在的状态。

## 6. 编码、解码与重建等式

### 6.1 权威表示必须可逆

对 `Material`、`ControlConfig`、`ConsensusLog` 的记录和 `CertifiedHead`，规范 codec 必须满足：

```text
Decode(CanonicalEncode(x)) = x
CanonicalEncode(Decode(b)) = b      // b 是被接受的规范字节时
Load(Store(CanonicalEncode(x))) = x
```

第二条排除“多种字节表示同一个签名对象”。未知字段、重复字段、非规范排序、错误领域分隔和非规范数值
必须拒绝，不能静默归一化后继续验签。哈希和签名只针对规范字节。

`ControlConfig` 的 wire/domain 映射同样可逆。不得在 wire 中省略一个权威字段，再由本机默认值补出；
也不得把可推导字段写回权威结构。

### 6.2 `Projection` 只能单向生成

设 `M[id]` 为 Material store 中的规范内容，`L[1..n]` 为 `ConsensusLog` 的已提交前缀：

```text
P0 = EmptyProjection()
Pn = Fold(P0, Decode(M[L[1].material_id]), ..., Decode(M[L[n].material_id]))
Cn = ActiveControlConfig(Pn)

LogDigest(n)        = Hash(CanonicalEncode(L[1..n]))
ProjectionDigest(n) = Hash(CanonicalEncode(Pn))
```

有效的 `CertifiedHead Hn` 必须满足：

```text
Hn.index             = n
Hn.log_digest        = LogDigest(n)
Hn.projection_digest = ProjectionDigest(n)
VerifyQuorum(Cn, Hn.signed_bytes, Hn.signatures) = true
```

联合配置期间，`VerifyQuorum` 必须分别满足旧集合和新集合的阈值。

不存在 `Projection → Material`、`Projection → ConsensusLog` 的逆映射。备份、迁移或 UI 导入若只有投影，
不能伪造历史；它必须通过明确的一次性导入过程生成新的规范 `Material` 并走正常共识。

### 6.3 重启算法

1. 读取并校验三份逻辑存储；任何 ID/内容或规范编码不一致均硬失败。
2. 按已提交日志顺序解析每份 `Material`，从空投影重建 `Projection` 和当前 `ControlConfig`。
3. 验证最新 `CertifiedHead` 的日志摘要、投影摘要、索引单调性和 quorum 签名。
4. 可选投影缓存仅在摘要完全相符时使用；不符则丢弃，不能修补权威数据来适配缓存。
5. 日志已提交引用缺少本地 `Material` 时，保持最后可完整验证的 `CertifiedHead` 只读，
   从其他 control 增量补齐内容后再继续重建。

## 7. CRDT、Raft 与 QC 的唯一分工

### 7.1 CRDT：回答“内容是否已知”

Material store 在逻辑上是内容寻址的 grow-only set：

```text
Merge(A, B) = A ∪ B
Merge(A, A) = A
Merge(A, B) = Merge(B, A)
Merge(Merge(A, B), C) = Merge(A, Merge(B, C))
```

节点交换摘要并只传缺失 ID 对应的规范字节。重复和乱序 delta 无副作用；断线恢复只补差集。
收到内容后先校验 ID，再放入 store。CRDT 同步不改变 `ConsensusLog`、`Projection` 或权限。

不另建 `CRDTState`、同步 session、完成 receipt 或 per-peer 进度作为领域实体。连接游标可以是可丢弃的
运行时优化；丢失后重新比较集合即可。

### 7.2 Raft：回答“什么以何种顺序被接受”

Raft 只复制 `ConsensusLog`，并根据当前 `ControlConfig` 获得提交 quorum。接受请求的 control
可以把请求转交当前 leader；这不改变“任意健康 control 可作为正常入口”的产品语义。

Material CRDT 与 Raft 的结合点只有一个：节点在确认引用该 ID 的日志记录前，必须持久拥有对应内容。
因此 CRDT 提供高效增量内容同步，Raft 提供安全的授权顺序，两者不能互相替代。

### 7.3 QC：回答“哪个结果可以脱离 Raft 会话被验证”

Raft commit 后，各 control 对同一索引重建投影。摘要一致且索引单调时，按当前
`ControlConfig` 签署同一 `CertifiedHead`。收集到 quorum 后，该 head 才能成为新的对外读取边界。

QC 不携带第二套业务决定，不允许对日志重新排序，也不维护独立 QC 日志。签名者只验证：

- 该索引已经在本地提交；
- 所有引用内容存在且有效；
- 日志与投影摘要匹配；
- head 使用正确的 `ControlConfig` 和 quorum 规则；
- 本地尚未为冲突的同索引头部签名。

## 8. 状态转换

| 概念 | 允许的转换 | 不允许的转换 |
|---|---|---|
| `Material` | 不存在 → 规范内容按 ID 持久化 | 原地修改、同 ID 覆盖、因业务删除而物理删除历史 |
| `ControlConfig` | 稳定旧配置 → 联合配置 → 稳定新配置 | 绕过日志直接改成员；旧/新两侧各自独立生效 |
| `ConsensusLog` | 已提交前缀 `1..n` → `1..n+1` | 改写已提交位置、两个不同内容占用同一已提交索引 |
| `Projection` | `Pn` + 下一份已提交 `Material` → `Pn+1` | 直接 patch、从 UI 或缓存反写权威状态 |
| `CertifiedHead` | `Hk` → `Hn`，其中 `n > k` 且全部验证通过 | 索引倒退、摘要不匹配、签名不足或冲突头部替换 |

未提交的 Raft 尾部可以按 Raft 安全规则被覆盖，它不是 `ConsensusLog` 的已提交领域事实。
同理，已同步但未被日志引用的 `Material` 没有“半生效”状态。

## 9. 正常流程

### 9.1 写入

1. 私有管理入口认证调用者，并针对最新已提交投影检查权限和业务前置条件。
2. 服务端形成规范 `Material`，计算 ID，执行幂等 put。相同请求重试复用同一内容 ID，
   不新建 transaction 或 receipt 实体。
3. 当前 leader 提议把该 ID 追加到 `ConsensusLog`。每个确认者先确保持久拥有并校验内容。
4. Raft quorum 提交记录；所有已提交节点按相同顺序更新 `Projection`。
5. control 为对应摘要签名并形成 `CertifiedHead`。
6. 只有覆盖该记录的 head 持久化后，入口才返回业务完成，并让 UI/客户端读取新投影。

若步骤 4 已完成而步骤 5 暂时失败，提交不可回滚，但外部仍读取旧 head。调用者重试同一请求时，
系统继续完成认证并在 head 覆盖该 ID 后返回；不为这种情况另建持久工作流。

### 9.2 读取

1. 任意 control 读取最新有效 `CertifiedHead`。
2. 使用已校验缓存，或从该 head 覆盖的日志前缀重建 `Projection`。
3. 响应同时携带 head 标识，使消费者知道所有字段来自同一个认证边界。
4. UI 可显示本地 Raft 已提交索引高于认证索引，但不得把尚未认证的投影显示为已完成配置。

无需线性一致性的设备和 UI 普通读取以最新 head 为准。需要“写后立即读”的管理请求，等待覆盖该写入的
head，而不是轮询多个影子 store。

### 9.3 网络分区

- 能满足当前（或联合）配置 quorum 的分区可以继续追加日志并形成新 head。
- 不能满足 quorum 的分区不得确认写入、产生权限或签署冲突 head，只提供最后有效 head 的只读结果。
- 两侧仍可交换或暂存 `Material`；这不会让少数派的内容生效。
- 网络恢复后先按 ID 补齐 Material 差集，再由 Raft 补齐权威顺序，重建投影并验证最新 head。
- 不存在“最后写入者胜出”的状态合并，也不需要人工选择两份业务数据库。

### 9.4 成员增加或删除

1. 变更前先让拟加入成员通过普通 Material 与 Raft catch-up 达到当前认证头部；这只是准备条件，
   不建立 learner 领域实体。
2. 提交一份携带联合 `ControlConfig` 的 `Material`，按旧稳定配置完成 Raft 提交；该联合 head
   的认证必须同时满足旧、新两侧 quorum。
3. 联合配置生效后，所有后续写入、包括最终配置写入，都分别要求旧、新两侧 quorum。
4. 在联合规则下提交携带新稳定 `ControlConfig` 的 `Material`；应用该记录后，认证 head 使用
   新稳定配置的 quorum。Raft 的联合提交已经证明旧、新两侧都接受了这次收敛。
5. 从下一项写入起只使用新稳定配置。被移除成员可以保留历史只读材料，但其签名不再计入新 head。

任一步骤失去所需 quorum 就停在最后已认证配置，不通过超时自动越过，也不使用旁路成员表“修正”。
密钥轮换同样表示为旧键和新键均可验证的联合配置，再收敛到只含新键的稳定配置。

## 10. 失败语义

| 失败 | 对外行为 | 恢复 |
|---|---|---|
| `Material` 非规范、ID 不匹配或语义无效 | 在进入日志前拒绝；不产生状态变化 | 修正输入后形成新的规范内容 |
| 内容已同步但未提交 | 对读取不可见；不声称部分成功 | 后续被日志引用，或作为无害未引用内容保留 |
| 日志引用内容在本机缺失 | 不应用该位置；提供最后完整认证 head 的只读结果 | 通过 CRDT 差量补齐并重放 |
| 无 Raft quorum | 明确拒绝/不可用，不排队制造未来权限 | quorum 恢复后由调用者幂等重试 |
| 已提交但暂缺 QC | 不回滚；不把新投影作为外部完成结果 | control 恢复后为同一摘要补签，重试得到完成结果 |
| 投影重建失败或摘要不符 | 视为数据/实现错误并停止推进 head | 从规范存储重建；不能修改摘要或跳过记录 |
| `CertifiedHead` 签名不足、配置错误或索引倒退 | 拒绝该 head，继续使用最后有效 head | 取得正确 quorum 签名或修复受损副本 |
| 同索引出现冲突 head | 拒绝并报警；签名者不得再次签冲突值 | 依据 Raft 已提交前缀定位故障，不以时间戳择胜 |
| 少数派或被移除节点继续提交 | 不可能获得有效 commit/QC；消费者拒绝 | 按当前配置重新加入或保持历史只读 |

所有未知、缺失和未认证状态保持未知或只读；不得用默认健康、固定成功或本地缓存填充。

## 11. 最小必要测试集

测试验证模型，不穷举节点数、传输方式和故障的笛卡尔积。以下六组覆盖独立语义边界：

1. **规范同构与确定性**：五个概念的权威编码往返无损；乱序 map、未知字段和非规范字节被拒绝；
   同一日志从空状态重建得到相同投影与摘要。
2. **正常 quorum 写读**：三成员配置中，从任意健康入口提交一份普通 `Material`，确认日志只追加一次、
   投影只应用一次、head 获得 quorum，随后所有健康节点读取同一结果。单成员配置复用同一用例参数，
   证明不存在特殊业务分支。
3. **CRDT 与共识解耦**：重复、乱序传输相同 delta 结果不变；仅同步内容不会改变投影；
   follower 未持久化引用内容时不能确认相应日志记录。
4. **分区与恢复**：多数派继续完成一项写入，少数派只能读旧 head；恢复后只补缺失内容和日志，
   两侧收敛到同一投影，不出现 LWW 合并。
5. **联合成员变更**：完成一次加入和一次删除；联合阶段必须同时满足两侧 quorum，
   删除完成后旧成员签名不再计数，任一步 quorum 不足时停在最后有效 head。
6. **损坏与重启**：分别破坏 Material 字节、日志引用、投影缓存和 head 签名，确认系统硬拒绝对应层、
   保留最后有效只读结果；用三份逻辑存储重启后重建出相同认证状态。

扩展测试只有在最小集合通过并且实际实现出现新的风险类别时添加。增加节点数量、重复同类网络故障或
复制平台组合，不算新的模型风险。

## 12. 明确禁止或应删除的实体

以下对象若承担持久业务语义，必须删除或折回五个概念；不能因为已有代码或测试而保留：

- 独立的 operation journal、application journal、mutation ledger；顺序只能来自 `ConsensusLog`。
- 独立的 membership registry、membership ledger、member phase store；成员只能来自已提交的
  `ControlConfig`。
- 独立的 control-state、application-state、authority-state 真相；当前状态只能是 `Projection`。
- 独立的 QC log、approval ledger、proof store；QC 只存在于 `CertifiedHead`，持久位置只有
  Certified store。
- proposal/approval/completion、prepare/activate、Gate A/Gate B 等通用工作流实体；正常写入只有
  Material 持久化、Raft 提交、投影计算和 head 认证。
- CRDT session、sync receipt、per-peer completion 作为领域状态；CRDT 只合并内容集合。
- 可直接写入的 projection/cache/store，以及以缓存版本替代 `CertifiedHead` 的“快速路径”。
- N=1 mode、N>1 mode 或迁移 latch；成员数量只是 `ControlConfig` 数据。
- 为 UI 单独维护的设备、拓扑、服务权威表；UI 只能查询同一个 `Projection`。

运行时队列、连接、重试计时器和 Raft 内部状态可以存在，但必须可丢弃或由三份逻辑存储恢复，
不得借这些名字重新引入第六个领域真相。

## 13. 完成判定

核心控制模型只有在下列条件同时满足时才算接通：

- 正式私有管理入口使用上述写流程，正式 daemon 启动同一套运行时；
- 三份逻辑存储可在重启后重建完全相同的 `Projection` 和 `CertifiedHead`；
- N=1 与 N>1 使用同一实现，三成员分区和联合成员变更通过最小测试；
- CRDT 只传差量内容，Raft 只决定接受顺序，QC 只认证对外头部；
- Web UI 从认证投影读取，写动作等待覆盖该写入的 head，不依赖旧 registry 或影子状态；
- 上述禁止实体和双写路径已经从正常调用链、持久层和 UI 中消失。

任何一项缺失，都只能称为局部组件存在，不能称为控制模型完成。

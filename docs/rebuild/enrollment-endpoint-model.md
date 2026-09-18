# Enrollment 与 Endpoint 核心模型

本文定义设备从获得一次受限引导权限，到取得私有配置并开始使用服务入口的最小模型。
它是领域、线格式、持久化、运行时和 UI 的共同语义来源，不以任何既有实现为前提。

目标不是把每一步都变成一个对象，而是让同一个事实只有一个名字、一个权威来源和一条
状态变化路径。控制输入直接使用 `CertifiedHead` 所认证的 `Projection`，不再包装成另一种权威对象；
本模型只有五个自有核心概念，并复用客户端模型定义的 `Observation`。

## 边界与不变量

1. 公网 Nginx 只提供伪装网站和明确标记为通用公开的不可变 `Artifact`。它不反代
   Invite、claim、resume、Enrollment、设备配置、设备报告或管理请求。
2. 设备专属身份、秘密、配置和报告只经过受限 bootstrap tunnel 或已认证私有设备通道。
   它们永远不是公开 `Artifact`。
3. Invite 是 `BootstrapCapability` 的交付形式；claim 和 resume 是对同一个
   `EnrollmentTransaction` 的操作。重试不得创建第二笔事务、第二个身份或第二份权限。
4. `EndpointGeneration` 与 `DeviceView` 决定“允许使用什么”；`Observation` 只回答
   “在这个网络代上最近实际发生了什么”。授权声明不等于当前可达，临时不可达也不修改授权。
5. 轮换不是独立领域对象，而是新旧 `EndpointGeneration` 的受认证状态转换。
6. 本阶段只使用已经存在且通过校验的证书。DNS 修改、ACME 签发、续期和挑战均不属于本模型。
7. 控制多数派不可用时不授予新权限；已经完成 Enrollment 的设备可以继续使用已验证的
   last-known-good `DeviceView` 和数据面。

## 控制输入、五个核心概念与共享观测

### 控制输入：`CertifiedHead` + `Projection`

`CertifiedHead` 及其摘要匹配的 `Projection` 是[控制核心模型](control-model.md)输出的认证状态。
这是一对已有控制概念，不是本文新增的领域实体。本文只消费它们，不复制其共识、CRDT、证书或持久化实现。

与本模型有关的内容只有：获准的 Endpoint generation、通用 Artifact 清单、签发者与设备权限、
事务审批结果，以及这些内容所对应的 certified head。私有服务只接受能追溯到当前或仍受允许的
certified head 的写入；客户端可以继续读取自己已经验证的旧 view，但不能借旧 view 获得新权限。

### EndpointGeneration

`EndpointGeneration` 是一个逻辑入口在某一代上的完整、不可变配置及其受认证生命周期状态。
它以“逻辑入口 + 单调 generation”标识，引用既有证书和监听材料，并声明哪些接入方式可被授权。
地址或 `public_data_ingress` 声明只表示该候选可以被尝试，不表示此刻网络可达。

生命周期只有：

```text
prepared -> serving -> draining -> retired
```

- `prepared`：材料已验证，但客户端不得使用。
- `serving`：可授权给新连接；同一逻辑入口可以短期有多个 serving generation，其中偏好顺序由
  认证 `Projection` 给出，而不是另建 preferred 状态机。
- `draining`：不再分配给新连接，已有会话可在明确期限内结束。
- `retired`：运行时不得再启动或使用，材料只按审计/备份策略保留。

轮换由以下转换完成：准备新代，使新旧两代短暂同时 serving，确认最小成功路径后提升新代偏好，
再将旧代置为 draining，最后 retired。任何一步失败都停在可恢复的已认证状态；不得根据一次探测
失败自动退休 generation，也不得在旧代退出后恢复到更低的安全 floor。

### Artifact

`Artifact` 是按内容摘要寻址的不可变通用制品，例如客户端安装包或通用静态清单。它最少具有
规范摘要、长度、媒体类型、签名引用和受众分类。相同摘要的字节必须完全相同；内容变化必须产生
新摘要，而不是覆盖旧地址。

只有受众被认证 `Projection` 明确标为“通用公开”的 Artifact 才能由公网 Nginx 以只读方式提供。
设备专属配置、token、身份材料和含设备秘密的归档不允许通过改变名称伪装成 Artifact。

### BootstrapCapability

`BootstrapCapability` 是一个自包含、带签名、有限时限和有限作用域的引导权限。它绑定一笔
EnrollmentTransaction、允许的动作和必要的防重放约束。Invite（二维码、文本或离线交付）只是
这一 capability 的编码，不是新的持久实体。

Capability 的签名和作用域属于静态授权；承载它的某个 bootstrap endpoint 是否可达属于
Observation。失败的网络尝试不能扩大 capability 的权限，也不能把公开 Nginx 变成 claim 入口。
首次有效 claim 会把事务绑定到设备生成的密钥；此后相同设备可幂等 resume，不同密钥不得接管。

### EnrollmentTransaction

`EnrollmentTransaction` 是 Enrollment 全流程唯一的可变持久事实。它保存事务标识、capability
约束摘要、设备密钥绑定、审批结果、当前状态和最终结果引用。其状态机为：

```text
open -> bound -> approved -> completed
  |       |          |
  +-------+----------+-> rejected | expired | cancelled
```

- `open`：capability 已签发，尚未绑定设备密钥。
- `bound`：第一次有效 claim 已绑定设备密钥，重复的同请求返回同一状态。
- `approved`：新权限已进入认证 `Projection`，可以生成私有 DeviceView。
- `completed`：最终 DeviceView 的规范摘要已固定；重复 claim 或 resume 返回同一结果。
- `rejected`、`expired`、`cancelled`：终态，不生成设备权限。

网络中断、服务重启或暂时失去 quorum 不是新的事务状态。它们保留最近一次持久状态，resume 继续
同一事务。输入相同的重复请求必须得到相同结果；已绑定后换密钥、换意图或扩大 scope 必须冲突失败。

### DeviceView

`DeviceView` 是面向一个已认证设备的私有、可验证投影。它包含该设备身份、安全 floor、可使用的
Endpoint generation、允许的直连/转发约束、所需的通用 Artifact 引用以及 certified head。
它不包含其他设备的信息，也不是新的治理权威。

服务端可从认证 `Projection`、已完成事务和设备身份确定性生成 DeviceView；缓存不具有权威性。
客户端验证后将完整 view 保存为 last-known-good。新 view 验证失败时继续使用旧 view，不拼接
新旧字段；提升过的安全 floor 不允许通过回滚 view 降低。

### Observation

`Observation` 的完整语义由[客户端运行时模型](client-runtime-model.md#observation-与可用性)定义；本文只定义其
私有报告和服务端展示边界，不建立第二种观测。它是限定在“设备、底层网络代、授权候选、有效期”内的运行时事实，状态只有
`available`、`unavailable`、`unknown`，并保留产生结论的实际动作类型和时间边界。

可达结论来自真实入口传输握手或正常业务结果，不由声明、ICMP 成功或 UI 绿灯推断。首轮只对
去重后的授权入口各并行探测一次；入口之后复用已有、已验证的服务器观测，不扫描每条完整业务路径，
不为填样本重复测量。缺失、过期或无效记录一律回到 unknown。

直连 `[demo-overseas]` 和经境内入口转发 `[demo-domestic, demo-overseas]` 可以同时由同一 DeviceView
授权。前者 unavailable 时，选择器可以使用后者；前者日后恢复时只更新 Observation，不修改
认证 `Projection`、DeviceView 或拓扑。最终出口固定时，fallback 仍必须保持相同最终出口。

## 跨层同构

每个概念在各层名称相同、标识相同、状态集合相同。线格式和数据库不得创造领域层不存在的阶段，
运行时对象和 UI 也不得反过来成为权威。

| 领域概念 | 线格式 | 持久化 | 运行时 | UI 投影 |
|---|---|---|---|---|
| 控制输入 | `CertifiedHead` 与摘要匹配的 `Projection` | 由控制模型唯一持有 | 只读、已验证快照 | head、版本与是否可验证 |
| EndpointGeneration | 规范 generation 声明及生命周期 | 与领域字段无损对应的一份记录 | listener 与候选入口的投影 | generation、阶段；可达性另列 |
| Artifact | manifest 与摘要寻址字节 | 不可变内容存储及同一 manifest | 下载、校验后使用的字节 | 版本、摘要、签名和发布位置 |
| BootstrapCapability | 自包含的规范签名编码 | 不建可变 capability store；事务仅保存约束摘要 | 对请求做一次验证的值 | 仅显示摘要、作用域和失效状态，不显示秘密 |
| EnrollmentTransaction | claim/resume 请求和同一事务响应 | 唯一事务记录，原子更新状态 | 当前请求处理上下文 | 一行事务及其领域状态 |
| DeviceView | 私有认证的完整 view | 服务端为可重建缓存；客户端保存完整 LKG | 候选、配置和 selector 输入 | 设备实际获得的版本与授权摘要 |
| Observation | 私有认证报告或本地规范记录 | 可过期的观测记录，不进入治理状态 | 可用性与选择输入 | available/unavailable/unknown 和证据时间 |

首个实现投影中，`EndpointGeneration` 的 wire/persistent 字段是 `endpoint_id`、单调
`generation`、承载 listener 的 `node`、`tls_tunnel` transport、本地 `listen`、客户端
`address`、`server_name`、已有 TLS 证书/私钥文件引用、证书 SPKI SHA-256、领域状态和
`preference`。除状态与 serving 期间的偏好外，同一 generation 的其他字段不可变。listener
只从已认证 Projection 投影；进入 serving 前必须在所声明节点实际读取证书，核对
SPKI 和有效期，并成功绑定 listener。

`tls_tunnel` 仅提供 TLS 1.3 且使用独立 ALPN。bootstrap 模式在握手中校验完整
`BootstrapCapability`；device 模式对随机挑战做设备 Ed25519 签名。claim、resume、DeviceView
与 report 的 HTTP 路由认证后的连接内部承载，不注册到公网或控制 listener。客户端把
设备私钥、稳定 claim request ID、capability 信任边界、防回退 floor 和完整 DeviceView LKG
作为一个 owner-only 文件原子替换；服务端 Observation 与签名 report 保存在独立可过期
运行时记录中，不进入 Raft/QC Projection。

线格式必须规范化并可逆：

```text
Decode(Encode(x)) = x
```

需要持久化的领域对象也必须无损往返：

```text
Load(Save(x)) = x
```

实现可以拆表或合表，但不得因此产生第二套标识、第二个状态机或无法回到领域对象的中间事实。
BootstrapCapability 不需要可变持久状态；其规范字节本身满足编码往返，使用结果由唯一事务记录。

运行时和 UI 是单向投影：

```text
DeviceView = Project(CertifiedHead, Projection, CompletedTransaction, DeviceIdentity)
AuthorizedCandidates = Project(DeviceView)
SelectedCandidate = Select(AuthorizedCandidates, FreshObservations, Preference)
UI = Present(CertifiedHead, Projection, Transactions, DeviceViews, Observations)
```

这些等式不可反向使用：UI 颜色不能生成 Observation，Observation 不能授权候选，runtime listener
不能证明 generation 已认证，缓存的 DeviceView 不能改变 `CertifiedHead` 或 `Projection`。服务器收到的 Observation
可以作为私有观测记录展示，但仍不是治理写入。

## 正常业务链

1. 操作者通过私有管理入口提交 generation、通用 Artifact 及授权策略；控制面形成并认证新的 `Projection`。
2. 发布器按摘要发布被认证为通用公开的 Artifact。公网 Nginx 只允许伪装站点以及这些 Artifact 的
   `GET`/`HEAD`，不会出现设备专属路径或 Enrollment 反代。
3. 私有服务创建一笔 open EnrollmentTransaction，并签出指向它的 BootstrapCapability；Invite 只
   负责把该编码交给设备。
4. 设备生成自己的密钥，选择一个被允许且实际可达的 bootstrap 入口，通过受限 tunnel 提交 claim。
5. 服务验证 capability 后原子地把同一事务绑定到设备密钥。需要审批时等待认证 `Projection`；得到
   认证批准后转为 approved。
6. 服务确定性生成 DeviceView，固定其规范摘要并把事务置为 completed；结果只经认证私有通道交付。
7. 设备校验 view 与 certified head，完整替换本地 LKG，投影授权候选，并以最小 Observation 集选择
   可用路径。报告也只经私有认证通道提交。
8. 任何响应丢失都通过 resume 读取或继续同一事务，不重新签发身份、不创建补偿事务。

## 失败与恢复

- **公开分发失败**：按同一摘要从另一个已认证分发位置重试或使用已校验缓存；不得转而公开设备配置。
- **入口不可达**：为该网络代记录 unavailable 或 unknown，并尝试另一个已授权候选；授权状态不变。
- **capability 无效**：签名、scope、时限或事务不匹配时失败关闭，不创建事务分支。
- **请求或响应丢失**：相同设备密钥 resume 同一事务；服务重启后从唯一持久记录继续。
- **不同密钥重放**：已绑定事务拒绝接管；不得靠另建 receipt 或 reservation 修补冲突。
- **控制多数派不可用**：open/bound 可保持原状，但不批准新权限；已完成设备继续使用验证过的 LKG。
- **轮换失败**：新代保持 prepared 或 serving，旧代保持原可用阶段；未满足退出条件不得退休旧代。
- **证书不匹配或失效**：阻止 generation 进入 serving；只报告需要替换既有材料，不启动 DNS/ACME。
- **观测过期**：回到 unknown；不得伪造健康样本，也不得阻塞客户端读取 LKG 后启动。

## 最小必要测试

以下是等价类测试，不展开平台、入口、协议和故障的笛卡尔积：

1. 所有自有领域对象完成规范 encode/decode；所有需持久对象完成 save/load，逐字段相等且标识不变。
2. 公网只可读取伪装站点和认证的通用 Artifact；claim、resume、DeviceView、report 和设备专属字节均
   不存在公开路由，发布器也拒绝将其归类为公开 Artifact。
3. 一笔事务完成 invite → claim → approve → complete；丢失响应、重启和重复 resume 均返回同一事务、
   同一设备身份与同一 DeviceView 摘要，换密钥重放失败。
4. 一个已授权直连候选实测失败时，同最终出口的已授权转发候选可以被选择；直连恢复只改变
   Observation。unknown 保持 unknown，未授权候选始终不能因观测良好而入选。
5. 新旧 generation 依次经历 prepared、并行 serving、偏好切换、draining、retired；重启不改变阶段，
   无成功路径或仍有受保护旧会话时不能提前退休。
6. 既有证书匹配时 generation 可进入 serving；不匹配或失效时失败关闭，并确认没有 DNS/ACME 行为。
7. 控制多数派中断时新审批失败关闭，已完成设备仍能从 LKG 启动；恢复后 bound 事务从原状态继续。
8. UI 的状态、标识和转换与领域对象一致；Observation 以运行事实展示，不提供伪装成期望态修改的操作。

扩展测试只能在最小集合通过后增加，并且必须对应新的风险等价类，不能为每个服务器、每种协议或
每个中间阶段复制同一测试。

## 禁止的重复实体与待删除逻辑

- 不建立独立的 Invite、Claim、Resume、EnrollmentReceipt、EnrollmentProof、Reservation、
  ProvisionalIssuance 或 CompletionRecord；它们都是同一 EnrollmentTransaction 的命令、状态或投影。
- 不建立 enrollment plan、rotation plan、Gate A/Gate B、phase、milestone 等运行时权威。计划和验收条件
  属于工作管理或测试，不进入产品状态机。
- 不为 capability、claim、resume、receipt、proof、approval、completion、DeviceView 分别建立语义
  store。允许一个物理数据库和必要索引，但唯一可变事实仍是 EnrollmentTransaction。
- 不建立独立 ResumeIssuer、receipt signer、proof collector、rotation coordinator 或后台补证循环。
  签名响应从当前权威对象确定性生成，resume 读取同一事务，轮换提交 generation 状态转换。
- 不建立第二份 endpoint catalog、public access profile 或 listener registry 作为权威。目录、listener、
  下载清单和 UI 列表都从认证 `Projection` 与 EndpointGeneration 投影。
- 不把 Artifact manifest、签名、catalog proof 各自升级成业务实体；摘要与签名是 Artifact 的完整性属性。
- 不为“可能可达”建立健康事实，不从静态声明填充 available，不用 ICMP 结果冒充实际传输成功。
- 不保留公网 per-device 配置、公开 claim/report handler、对应反代、客户端 fallback 或兼容状态机。
- 不把 DNS、ACME、证书续期、全路径扫描、重复采样或全组合验收以可靠性名义重新带入本模型。

删除上述重复逻辑后，如果某个响应、表或后台任务无法映射回五个自有概念或共享的 Observation，它不属于核心模型；只有
能指出新的明确需求和无法由现有概念表达的事实时，才可以讨论增加实体。

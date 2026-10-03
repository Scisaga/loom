# 唯一现行契约与修订规则

[设计入口](../README.md) · [控制模型](control-model.md) · [实施状态](../progress.md)

本文只索引**一套目标语义**。每种权威对象只有一份规范编码、一个正式写入入口和一个权威来源；
对象各自已有的格式数字不构成可并行选择的业务版本，也不授权同一数字对应两套不同签名语义。
下表描述应实现的契约，不表示现有源码或生产状态已经符合；差距见[实施状态](../progress.md)。

| 对象 | 唯一权威与规范边界 | 对外投影 |
|---|---|---|
| 控制事实 `Material` | 一份规范签名的不可变事实；绑定网络、签发 control 及验证键、引用的成员表、该键连续序列与前哈希、因果依赖、稳定目标和操作。操作限于设备（含组合申请 control 时的条件授权事实）、网络意图、管理员证书、私有入口、Invite 生命周期与冲突解决。接收只判定事实自身及其声明依赖；设备授权携带的 `RuntimeKey` 使 Material 含秘密，只在 control 间加密同步。 | 当前 `Projection` 从有效事实与成员表确定性重建，不另存可写副本；依赖之外的并发事实只影响是否生效，不影响接收。 |
| control 成员 `ControlConfig` | 首个受保护信任锚及引用前驱摘要的成员表链；后继表按全序轮次由旧成员在同一轮次多数签名，只封存失去资格的验证键；逐轮计算可能选定项后，仅在最高轮提案唯一时继承，同轮多个不同提案仍可能已选定则补取证据，封存点及 tip 摘要由首次合法提案所引多数签名前缀报告和完整原始事实链证明，后轮安全继承时不重算。增员证书绑定 Invite/事务 ID、目标设备 ID、首次 claim 的公钥，以及非 control 职责所需的条件授权事实 ID，并直接完成该事务；成员不变的作废证书绑定事务 ID 与取消/到期原因，阻止迟到增员。整体删除 control 节点时同一多数载荷带不可复活墓碑。只有成员表赋予 `control` 职责。 | 多数派从成员集合计算，不保存冗余阈值、连接或健康状态；整体删除原子收口其他职责和依赖。诚实成员遵守持久投票规则时防止分叉，不防御单个被攻破的 control。 |
| 网络意图 `NetworkIntent` | 节点、稳定且不随每台设备参与而改写的 `TransportResource`、显式中继 `NetworkLink`、Service、Policy、共享 HTTPS 探测目标、精确 `.loom` DNS、局域网映射、公开信任材料和期望组件均随各自稳定 ID 的规范事实更新；不以全量 `network.update` 或全局 `base_head` 覆盖并发变化。 | 普通 access 首跳由授权及共享资源投影；中继候选引用 LinkID；观测按 Service、底层网络代与实际依赖摘要记录，不因无关事实变化全网失效。 |
| 私有入口与 Invite | `EndpointGeneration` 定义入口身份和生命周期，只由承载它的 control 签发，承载者失去 control 资格时一并退出；Invite 是 control 签名的一次性受限能力，固定发行者、首次信任锚、目标设备、职责与授权。首次 claim 只由发行者处理；纯 `access` 使用二维码，含其他职责使用 SSH/sh 脚本，三处入口均校验职责与媒介匹配。 | 已加入设备以设备身份使用认证管理通道；入口可达不授予成员或业务权限；`control.loom` 解析为 web 模式入口。 |
| 设备授权与视图 | `DeviceAuthorization` 是签名事实的有效结果，`PolicyIDs` 保存设备选择的策略集合，每条 Policy 固定属于一个 Service，且同设备同服务最多选择一条；Service 不绑定全局 Policy，业务授权来自所分配的 allow Policy；普通职责由有效 control 单签，`control` 只由成员表投影。`DeviceView` 由有效 control 对设备相关配置、成员证明和事实前沿签名；设备原子保存信任绑定、完整 LKG、不可回退 latch 与单调的已见高水位。连续多数证书仅可对明确封存的键把新 View 验收前沿降至封存序列，原高水位与 latch 保留，旧 LKG 只在验收失败时保留，成功时原子替换唯一 LKG；留任 control 在证书验收前已持久接受且可验证的超限撤权自动重签，原始证据全失时可能复权，必须标记可见差异和剩余未知风险。其他键、成员链和既有全局认证 floor 不回退。 | 运行时、报告和 UI 仅从获授权的视图与真实观测生成；不能由视图、报告或颜色倒写权威。 |
| 发布记录 | 发布签名密钥签署的不可变 release catalog 与制品 manifest；规范签名负载包含 schema 3、单调发布 generation，以及每项的组件 ID、目标平台、制品摘要、长度、媒体类型、受众、版本和可选最低兼容版本，签名覆盖所有这些字段及规范排序。发布私钥引用来自 `LocalDeploymentConfig.signing_key`（`LOOM_SIGNING_KEY`）；验签公钥由验证方受保护的安装信任输入固定，发布前须与签发密钥的公钥核对，不从待验 catalog 或 Web 响应取得。签名 release store 独立于控制事实；可变 `current` 指针只定位待验 catalog。 | `Projection` 只按摘要引用期望组件；Web 仅展示验签且逐文件核验通过的 catalog。公网 Nginx 只分发受众为通用公开的制品；设备与节点报告实际运行坐标，只有报告与期望摘要相符才能显示已应用。 |
| 客户端本机值 | `DeviceIdentity` 私钥与信任绑定、已见 floor、完整 LKG、唯一 `Preference`，以及 Android/Windows 保存用户命名、稳定本机 ID 与恢复意图的 profile catalog；各自严格 schema、原子持久往返。 | 候选、Selection 与 UI 每次从这些值和宿主回读重建；这些值不作为网络权威上传。 |
| 本机部署输入 | [配置模型](../operations/configuration-model.md)规定的六键白名单规范 `.env`；可选键缺席时不写该行，密钥和证书正文留在受保护本机输入。 | 只生成本次部署计划与脱敏结果，不保存 control 或 DNS overlay 的第二份事实。 |

成员证书及所引事实一经某验收方验证，control 资格与组合职责即在该方投影中生效；交付丢失只影响设备
获知证明，不改变这份权威结果。取消整次 control 加入若因安全继承被迫先完成，后续按既有节点整体删除
规则撤去全部职责，不能用仅卸任 control 代替；原加入历史仍为 completed。

正式入网的控制面 Web 使用网站服务端证书和 admin 客户端证书。网站根证书必须有 critical `.loom` DNS 约束和全 IPv4/IPv6 IP 排除，且目标浏览器已实测执行这些约束才可导入，根私钥不得进入 control；control 的正式 Web 入口仅持有 `control.loom` 网站叶私钥，网站根与成员/传输 CA 分离。普通已加入 access 可打开私有
`control.loom` 入口页；管理数据和操作要求 admin 证书，受信 admin 名单由普通事实维护、所有 control
一致。reader 证书、read capability 和对应的第二套页面权限不是本契约的一部分。
目标 Web 对 admin 客户端证书还要求验链并与受信叶精确匹配。受信叶事实的加入/撤销只决定**授权**，
不能代替 X.509 叶证书的签发、签发者信任锚或私钥保管。现有 `admin.p12` 及密码文件的 control 生成、
手动取回和浏览器登录是用户已验证的入口；目标模型尚未定 admin 叶的签发者、验链锚和多 control
场景中哪台机器持有签发能力，这些须基于现有实际材料只读核对后补入，不把补发说成已实现。
开发调试的已验证入口是笔记本经 SSH 将指定 control 的 Web 端口映射到本机，再由浏览器访问
`https://127.0.0.1:<本地端口>/`，使用已交付的 `admin.p12` 登录；SSH 不解析 `control.loom`，也不改变浏览器的
TLS 校验名。入网设备则由 Loom DNS 解析 `control.loom` 访问 serving Web 入口。这两条路径不互相替代。
受 `.loom` 限定且排除 IP 的正式网站根不能签出可供 `127.0.0.1` 验证的叶证书。切换前须只读核验现有
回环入口实际使用的证书、信任锚和浏览器行为，再确定独立于正式网站根的回环调试证书及信任处理并完成实测；
不能以 SSH 转发成功或 admin 客户端证书存在代替该 TLS 验收。此项未完成时，不宣称切换后的回环调试入口可用。
根私钥由操作者隔离离线保管，区别于 `LOOM_SIGNING_KEY` 的发布私钥；各 control 本机生成叶私钥与 CSR，
操作者在叶证书到期前手工续签，经受保护渠道交回证书链，并用新的 `EndpointGeneration` 验证和切换。

## 现行编号

用户已明确决定：本轮目标的规范对象——`Material`、`ControlConfig` 成员证书、`DeviceView` 及其交付
envelope、Invite 与 claim/resume、设备 report——统一使用 schema **3**，签名使用新的领域分隔符，不复用
现有 `loom-material-v1`；本轮其他改变字节或语义的规范对象（包括上述签名发布记录）同样使用 3。
1、2 号及旧 `runtime_contract` 值不进入任何解码、写入、重放或迁移运行路径，新路径接管时删除相应
代码和测试；现网已有的 1、2 号原始字节只作为受保护证据保全，不删除、不重解释。

这一编号只约束本轮定义为 schema 3 的规范对象及其 decoder；没有 schema 字段的根 `.env`、证书和制品
原始字节仍按各自的严格格式校验，不因这里的“非 3 号”规则被重新编号。独立发布 store 不成为控制事实；
其旧 catalog 字节也不能冒充本轮签名发布记录进入新路径。

签名输入均为固定领域分隔符的原始字节后接完整规范负载字节，`\0` 表示单个 NUL 字节：

| 签名目的 | 领域分隔符 |
|---|---|
| `Material`（含签发 Invite 的事实） | `loom-material-v3\0` |
| 成员承诺回复 / 成员投票 | `loom-control-promise-v3\0` / `loom-control-vote-v3\0` |
| `DeviceView` 交付 envelope | `loom-device-view-v3\0` |
| claim / resume / report | `loom-claim-v3\0` / `loom-resume-v3\0` / `loom-report-v3\0` |
| 发布 catalog / manifest | `loom-release-catalog-v3\0` / `loom-release-manifest-v3\0` |

### 已确定的签名边界与字段级阻塞

`CanonicalEncode` 目前只是所需规范编码函数的名字，尚未选定字节格式、各类值的完整字段表、
排序、长度和可选字段规则；不能把当前源码的 JSON 结构、旧 schema 字节或某种通用 JSON 规范
默认为 schema 3。签名领域分隔符已由上表确定，签名输入严格为该分隔符的原始字节后接**无自身签名的业务载荷**
的规范字节；对象自身的签名与自身 ID 不在该载荷中，被引用对象的 ID 可以是业务字段。对 `Material`，完整签名事实由该载荷及签名组成，
`material_id` 根据完整事实的规范字节计算且不再写入事实本身，避免签名和 ID 循环；完整公式见
[Material](control-model.md#21-material规范签名事实)。

现有模型已决定下列字段**语义**，但以下清单不等于可编码规格：

| 对象或既有值 | 已确定的字段语义 | 尚缺的字段级决定 | 受影响的业务行为 |
|---|---|---|---|
| `Material` | 网络、签发 control 与验证键、所引成员表、该键序列和前事实 ID、因果依赖、稳定目标、操作及对应内容、签名；genesis 固定初始成员、网络意图和管理员信任。 | genesis 与普通事实的精确字段；每种操作的唯一内容形状（含按 PolicyID 排序、拒绝同服务重复策略的 PolicyIDs；Policy 固定 ServiceID、allow/deny 及范围模式；不能沿用 DestinationGrants）；签名字段所在的完整事实形状；ID 哈希领域、哈希函数与输出文本格式；编码、排序、长度及拒绝向量。 | 管理 operation 的签名写入、事实同步、重启重建、授权与冲突解决不能仅凭领域描述实现互通。 |
| 成员承诺、投票、证书 | 基础表、轮次、发起者、成员、完整投票史、按键已验证前缀、后继提案、封存点和同轮多数签名。 | 每种消息的精确字段、提案摘要输入、历史／前缀／签名集合的字节排序、空值及长度。 | control 加入、移除、换键及离线设备验证连续成员证明需要相同的签名字节。 |
| `NetworkIntent` 内的 `TransportResource` | 稳定资源 ID、种类、承载节点、interface/listener 身份、拨号坐标和公开认证参数；共享首跳与中继复用同一资源，私钥留在本机。 | 按资源种类固定认证材料的具体形状、信任身份表达、字段及规范字节；不能由适配器临时选择证书链、SPKI 或其他身份表示。 | WG、Hy2、私有 TLS 的真实身份校验、资源复用和参数变化后的观测失效；无公网域名不能成为关闭 Hy2 验签的理由。 |
| 设备授权内的 `RuntimeKey` 与凭据派生 | 只在 control 间保管根密钥；派生绑定设备、Service、Policy、用途、资源和接收节点，不向设备交付根密钥。 | 密钥长度、KDF、用途域、精确输入顺序、输出编码，以及更新失败时的原子替换规则。 | 同一授权在客户端与服务节点产生匹配且用途隔离的凭据；撤权、策略替换或换钥后旧凭据的拒绝不能依赖旧派生规则。 |
| `DeviceView` 与 envelope | 单设备配置、签发者资格、连续成员证明、签发者事实前沿、View 摘要、设备绑定与签名。 | View 每种内层值、摘要输入、证明和签名封装的精确字段及规范字节。 | 配置领取、认证 LKG 原子保存、离线恢复与运行消费须验证同一完整 View，不能拼接或补造缺项。 |
| Invite、claim、resume | Invite 的签发者/锚/设备/职责/PolicyIDs/入口/一次性约束；首次 claim 的设备公钥、目标端识别的平台与 request ID；Invite 不预锁平台，平台随绑定事实及设备授权签名；resume 同事务同密钥同平台。 | 请求与响应逐字段表、签名覆盖范围、排序和严格 decoder。 | SSH、脚本与二维码共用加入协议；目标平台绑定、同事务恢复和重复提交拒绝需要统一字节。 |
| 设备 report 与逐条 Observation | 当前 View 摘要、按设备递增序列、真实观测与运行回读；观测绑定设备、网络代、层级、Service/候选或 LinkID、实际目标及规范摘要，缺失或失效为 unknown。 | 请求与响应逐字段表、签名覆盖范围、观测键、时间和有效期编码、最大可接受寿命、设备时钟偏差处理，以及相同序列不同签名内容的拒绝规则。 | 当前路径、业务状态、链路测量和部署回读的新鲜性及重放拒绝；不能由签名有效或单项成功推定其他范围仍可用。 |
| release catalog 与 manifest | generation、组件/平台、不可变文件摘要、长度、媒体类型、受众、版本和最低兼容约束，发布密钥签名。 | catalog 与 manifest 的分层字段、路径规则、排序、签名和摘要字节；旧 floor 与新发布坐标的迁移证明。 | 精确制品验签、下载、期望摘要与实际应用对照，以及维持既有反重放边界的生产切换。 |

资源身份与 KDF 的未决问题对应[控制模型的凭据派生](control-model.md#21-material规范签名事实)和
[传输资源边界](control-model.md#7-networkintent传输资源和显式中继)；report 寿命与拒绝规则对应
[Enrollment 的 Observation](enrollment-endpoint-model.md#observation)。表中的缺项是这些既有值的规范边界，
不新增权威对象，不撤销已确定语义，也不构成另一份实施计划。选路中的多目标结果归约、指标优先级及
稳定平局另由[Preference 与 Selection](../clients/client-runtime-model.md#preference-与-selection)列出；
完成编码格式本身不能替代这些算法决定。

任何对象的内层值、可选性或签名输入仍不明确时，生产 writer/decoder 不得自行发明格式。
Policy 必须签名覆盖固定的 ServiceID、allow/deny、独立的入口与中间转发范围，以及互联网服务适用的
出口范围、Direct 与设备限定本地出口许可。范围模式 any / only / none 不可混淆：any、none 的 ID
集合为空，only 的集合非空并规范排序；模式缺失、未知模式、重复 ID 或矛盾组合拒绝。UI 的未设限制
提交为显式 any，不能在 decoder 中把遗漏字段或旧空数组当不限。LAN Policy 不接受互联网出口、
Direct 或本地互联网出网字段，终点从固定所属 Service 读取；Policy 创建后不得改属其他 Service。
节点和 Invite 只保存规范 PolicyIDs，不再双写 ServicePolicies；重复 PolicyID、同一设备选择同 Service
的两条策略、悬空/冲突引用、非 access 携带访问策略均拒绝。合法空 PolicyIDs 表示没有业务授权；
deny 保留分配但无业务权限。解析到的 Service/Policy 对只是可重建投影，不成为另一份签名分配值。
设备限定本地出网的逻辑最终出口为本机稳定 NodeID，空跳链仅表达本机执行；普通 Direct 的最终出口为
`direct`。本机出口仍须满足设备限定许可、职责及出口范围；本地出网没有网络入口，不受入口范围限制，也不要求自拨或入站资源。
两者不能靠空跳链混同，指定本机出口能匹配已获本地出口许可的候选，Direct 偏好不取得该许可。
策略创建后再分配的部分失败与原请求重试见
[策略创建、分配与复用](control-model.md#策略创建分配与复用)。这些同属 schema 3 的现行目标；
旧 AllowedServers、Service.policy、DestinationGrants 和先前 ServicePolicies 目标不能通过改名继续运行。
完成字段表时须给出接受和拒绝字节向量，验证 `decode(encode(D))=D`、`encode(decode(B))=B`；
拒绝未知字段、重复字段、歧义空值、错误排序、错误签名目的、签名未覆盖字段及不规范输入。

成员证书由同一提案的规范投票签名组成，不能把另一目的签名当成员票。发布 catalog 固定
generation 与规范排序的 manifest 摘要集合；每份 manifest 固定组件、平台及逐文件字段。解码后重编码
必须得到原字节，缺项、重复组件/平台映射、未知受众或签名不符均拒绝。当前代码及现网尚未实现这些字节，
不能把旧发布记录解释为此格式。

不复用 1 号，因为 1 号是真实存在过的旧 `Material` 格式，现网不可回退 latch 要求 reader 版本不低于 2，
`loom-material-v1` 领域也已被 2 号使用。3 号此后冻结。

## 往返与拒绝

对权威领域值 `D`、被接受的规范字节 `B` 与耐久值，必须满足：

```text
decode(encode(D)) = D
encode(decode(B)) = B
load(save(D))      = D
decode(X)          = error，若 X 对该对象为非现行 schema、未知、歧义或非规范输入
```

本轮 schema 3 对象的非现行 schema 即非 3 号。旧 `runtime_contract` 语义同样直接拒绝；不建立历史材料
解码、重放或兼容写入运行路径。缺少因果依赖的现行事实可以等待补齐，但不得提前生效。Projection、
DeviceView、客户端运行时和 Web 都是从已验证事实的单向投影，不能反写权威。

发布 `current` 指针和签名 catalog 的“当前可下载”只说明该 release store 此刻选中的制品；不能改写
`Projection` 的期望摘要，也不能证明设备已安装。最低版本只按签名发布记录中对同一组件和目标平台给出的
可核验约束判断；未声明最低版本则此项不适用，已声明而实际版本不可比较时为 `unknown`，不能由
文件名、版本字符串排序或 UI 猜测。

现网节点已有持久的 signed-current 反重放 floor，记录已接受的 generation、签名载荷摘要和所选快照。
它不是可删除缓存。schema 3 的可变 `current` 指针没有与该 floor 自然可比的摘要；原 floor 字节须作为
受保护证据保全，不进入新 decoder，也不得重置。经批准的一次性前向切换证明新发布接受规则维持同等或更强
的反重放约束之前，schema 3 catalog 不得作为生产激活依据；不以旧 current 的长期双读填补此缺口。

切换证明必须逐节点覆盖下列事实及失败边界，不能只展示一份新 catalog 验签成功：

1. 只读取得各节点已持久接受的旧 floor 原始字节及其 `generation`、`payload_sha256`、
   `selected_snapshot`，按旧**验证工具**及固定发布公钥核对相应 signed-current 原始载荷和所选不可变制品；
   核对生产实际运行坐标、备份和 latch，证据只放受保护部署证据目录，旧字节不喂给 schema 3 decoder。
2. 冻结会改变旧 signed-current 的写入。定义并由操作者批准旧 `(generation,payload_sha256,selected_snapshot)`
   到新 `(catalog_generation,catalog_digest,manifest/artifact_digest)` 的逐节点对应，说明发布验签公钥是否延续；
   换钥须有独立受保护的认证证明。新旧摘要不是同一对象的哈希，不能直接比较或以同号相等替代证明。
3. 证明每节点存在从旧 floor 到新发布坐标的严格单调接受关系：旧 floor 已拒绝的重放在切换后仍被
   拒绝，同一新 generation 的不同 catalog 内容不得择一覆盖，`current` 可变指针不能降低已保存的
   接受前沿。若新旧 generation 不共用含义，必须给出可验证的顺序映射和持久切换证据，不能把数字
   大小直接当作证明，也不能删除旧 floor 从零起算。
4. 对每节点先验证 schema 3 reader、catalog、全部 manifest 和逐文件摘要，再证明切换前沿的落盘与
   精确制品激活具有崩溃可恢复的顺序；重启、断电、重复执行和部分节点成功时均不能接受旧格式或
   更低发布坐标。失败节点继续保持其最后可验证的运行状态并停止切换写入。
5. 通过正式发布入口、节点拉取、实际进程／文件摘要及正常状态入口回读每节点结果，确认
   `Projection` 期望摘要、从 catalog 选定的 manifest 和真实运行坐标一致。完整证明与受保护证据
   交由用户明确决定切换；未经决定不启用生产路径。

上述是证明义务，**尚不是一份已批准的迁移算法**：现网逐节点 floor、签名材料、公钥连续性、
快照到 manifest 的对应和真实运行制品尚未在本轮只读核对，因此不能填写切换记录或声称生产可用。

### 设备服务授权修订的切换边界

用户已确认：Service 定义目标；每条 Policy 固定属于一个 Service、可复用；节点只选择 PolicyIDs。
同一设备同服务最多一条策略，路径未设置限制规范表达为 any，没有分配策略不获得服务业务权限。
这取代先前设备单独保存 ServicePolicies 配对的目标，也不恢复旧 Service 的全局唯一 Policy 绑定。
此修订只改变尚待实现的 schema 3 目标契约，不重解释任何现网 `Service.policy`、DestinationGrants、
已签 Invite、既存空数组或已部署持久字节。即使名字相近，旧 Policy ID 也不能直接视为具有固定
ServiceID 与新范围语义的策略；每个旧目标范围及限制须单独证明保全。
平台仍由目标识别、首次 claim 绑定；旧 Invite 固定平台的字节不视为跨平台邀请，设备身份、密钥、
认证 floor 和 latch 均保持。实施前只读列出受保护现网材料中的逐设备实际服务范围、路径与 Direct
权限，供操作者核对。旧空集合不得扩大为 any；一个旧通用策略涉及多个 Service 时，迁移必须为每个
Service 明确构造所属策略及节点引用，保留同等范围，不能把一个 ID 自动授权到未来新增服务。
未知、无法证明或可能扩权的映射停止写入并报告，原型样例不用于生成迁移值。沿用既定前向切换与
现网保全门禁，获准并验证前不激活生产，不增加协议号、双读或第二份授权 store。

## 遇错时只修订这一份契约

3 号确定后，除非用户再次明确要求**新协议或新版本**，错误、字段遗漏、测试失败和实现偏差都通过修订
同一 3 号模型、实现与测试解决。不得追加 4 号、新的 `runtime_contract` 值、第二份 DTO/store、双写、
双读或长期旧格式 fallback；`EndpointGeneration`、源码提交号和制品版本也不是协议版本逃生口。

## 现网字节与生产切换

3 号对象改变了现有签名 Material、成员证明及设备视图的字节和投影语义。已认证 head、已部署持久字节、
现网身份与密钥、数据、认证 floor 和不可回退 latch 必须保全，编号变化不授权重解释这些字节。现网状态
与 3 号目标不相容，冲突写入和生产切换保持失败关闭，不自动生成替代 genesis、清空信任或让旧路径继续
充当权威。由用户明确决定并验证前向切换办法后，才能启用相应生产写入；文档完成不视作业务完成。

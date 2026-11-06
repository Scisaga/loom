# 唯一现行契约与修订规则

[设计入口](../README.md) · [控制模型](control-model.md) · [实施状态](../progress.md)

本文只索引**一套目标语义**。每种权威对象只有一份规范编码、一个正式写入入口和一个权威来源；
对象各自已有的格式数字不构成可并行选择的业务版本，也不授权同一数字对应两套不同签名语义。
下表描述应实现的契约，不表示现有源码或生产状态已经符合；差距见[实施状态](../progress.md)。

| 对象 | 唯一权威与规范边界 | 对外投影 |
|---|---|---|
| 控制事实 `Material` | 一份规范签名的不可变事实；绑定网络、签发 control 及验证键、引用的成员表、该键连续序列与前哈希、因果依赖、稳定目标和操作。操作限于设备（含组合申请 control 时的条件授权事实）、网络意图、管理员证书、私有入口、Invite 生命周期与冲突解决。接收只判定事实自身及其声明依赖；设备授权携带的 `RuntimeKey` 使 Material 含秘密，只在 control 间加密同步。 | 当前 `Projection` 从有效事实与成员表确定性重建，不另存可写副本；依赖之外的并发事实只影响是否生效，不影响接收。 |
| control 成员 `ControlConfig` | 首个受保护信任锚及引用前驱摘要的成员表链；后继表按全序轮次由旧成员在同一轮次多数签名，只封存失去资格的验证键；逐轮计算可能选定项后，仅在最高轮提案唯一时继承，同轮多个不同提案仍可能已选定则补取证据，封存点及 tip 摘要由首次合法提案所引多数签名前缀报告和完整原始事实链证明，后轮安全继承时不重算。增员证书绑定 Invite/事务 ID、目标设备 ID、首次 claim 的公钥，以及非 control 职责所需的条件授权事实 ID，并直接完成该事务；成员不变的作废证书绑定事务 ID 与取消/到期原因，阻止迟到增员。整体删除 control 节点时同一多数载荷带不可复活墓碑。只有成员表赋予 `control` 职责。 | 多数派从成员集合计算，不保存冗余阈值、连接或健康状态；整体删除原子收口其他职责和依赖。诚实成员遵守持久投票规则时防止分叉，不防御单个被攻破的 control。 |
| 网络意图 `NetworkIntent` | 节点、稳定且不随每台设备参与而改写的 `TransportResource`、Service（含网址与限制开关）、Policy、精确 `.loom` DNS、局域网映射、公开信任材料和期望组件均随各自稳定 ID 的规范事实更新；不以全量 `network.update` 或全局 `base_head` 覆盖并发变化。 | 普通 access 首跳由授权及共享资源投影；中继候选引用 LinkID；观测按 Service、底层网络代与实际依赖摘要记录，不因无关事实变化全网失效。 |
| 私有入口与 Invite | `EndpointGeneration` 定义入口身份和生命周期，只由承载它的 control 签发，承载者失去 control 资格时一并退出；Invite 是 control 签名的一次性受限能力，固定发行者、首次信任锚、目标设备、职责与授权。首次 claim 只由发行者处理；纯 `access` 使用二维码，含其他职责使用 SSH/sh 脚本，三处入口均校验职责与媒介匹配。 | 已加入设备以设备身份使用认证管理通道；入口可达不授予成员或业务权限；`control.loom` 解析为 web 模式入口。 |
| 设备授权与视图 | `DeviceAuthorization` 是签名事实的有效结果，`PolicyIDs` 保存设备获准选择的策略集合，每条 Policy 固定属于一个 Service，同服务可授权多条；客户端当前选择一条互联网 Policy，并由其唯一确定 Service；Service 不绑定全局 Policy，业务授权来自所分配的 allow Policy；普通职责由有效 control 单签，`control` 只由成员表投影。`DeviceView` 由有效 control 对设备相关配置、成员证明和事实前沿签名；设备原子保存信任绑定、完整 LKG、不可回退 latch 与单调的已见高水位。连续多数证书仅可对明确封存的键把新 View 验收前沿降至封存序列，原高水位与 latch 保留，旧 LKG 只在验收失败时保留，成功时原子替换唯一 LKG；留任 control 在证书验收前已持久接受且可验证的超限撤权自动重签，原始证据全失时可能复权，必须标记可见差异和剩余未知风险。其他键、成员链和既有全局认证 floor 不回退。 | 运行时、报告和 UI 仅从获授权的视图与真实观测生成；不能由视图、报告或颜色倒写权威。 |
| 发布记录 | 发布签名密钥签署的不可变 release catalog 与制品 manifest；规范签名负载包含 schema 3、单调发布 generation，以及每项的组件 ID、目标平台、制品摘要、长度、媒体类型、受众、版本和可选最低兼容版本，签名覆盖所有这些字段及规范排序。发布私钥引用来自 `LocalDeploymentConfig.signing_key`（部署 YAML 的 `signing_key`）；验签公钥由验证方受保护的安装信任输入固定，发布前须与签发密钥的公钥核对，不从待验 catalog 或 Web 响应取得。签名 release store 独立于控制事实；可变 `current` 指针只定位待验 catalog。 | `Projection` 只按摘要引用期望组件；Web 仅展示验签且逐文件核验通过的 catalog。公网 Nginx 只分发受众为通用公开的制品；设备与节点报告实际运行坐标，只有报告与期望摘要相符才能显示已应用。 |
| 客户端本机值 | `DeviceIdentity` 私钥与信任绑定、已见 floor、完整 LKG、唯一 `Preference`，以及 Android/Windows 保存用户命名、稳定本机 ID 与恢复意图的 profile catalog；各自严格 schema、原子持久往返。 | 候选、Selection 与 UI 每次从这些值和宿主回读重建；这些值不作为网络权威上传。 |
| 本机部署输入 | [配置模型](../operations/configuration-model.md)规定的 `.env` 文件引用与唯一部署 YAML；可选键缺席时不写该行，密钥和证书正文留在受保护本机输入。 | 只生成本次部署计划与脱敏结果，不保存 control 或 DNS overlay 的第二份事实。 |

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
CSR 的公开签发请求使用同一 schema 3，精确字段、成员签名和独立可信输入见
[网站 CSR 的受保护交付](enrollment-endpoint-model.md#网站-csr-的受保护交付)。它不是控制事实或网站信任根；
规范解码和再编码必须还原原字节，操作者须独立核对当前成员配置及目标入口，不能接受请求自选的网络锚。

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

普通设备服务授权与撤权链使用下方[字段级规范](#普通设备服务授权链的字段级规范)定义的唯一规范 JSON、
字段、排序和拒绝规则；这是 schema 3 的细化，不是现有源码 JSON 的自动继承，也不表示实现已经接通。
不在该链中的发布载荷等剩余边界继续在下表列明，不能由 writer 自行补造。
签名领域分隔符已由上表确定，签名输入严格为该分隔符的原始字节后接**无自身签名的业务载荷**
的规范字节；对象自身的签名与从完整对象计算的内容 ID 不在该载荷中，稳定目标 ID、事务 ID 及被引用对象的 ID
仍是受签名覆盖的业务字段。对 `Material`，完整签名事实由该载荷及签名组成，
`material_id` 根据完整事实的规范字节计算且不再写入事实本身，避免签名和 ID 循环；完整公式见
[Material](control-model.md#21-material规范签名事实)。

下表区分本次固定的编码边界与仍需完成的工作；详细字段表才是编码依据：

| 对象或既有值 | 已确定的字段语义 | 字段规范及剩余边界 | 受影响的业务行为 |
|---|---|---|---|
| `Material` | 网络、签发 control 与验证键、所引成员表、该键序列和前事实 ID、因果依赖、稳定目标、操作及对应内容、签名；genesis 固定初始成员、网络意图和管理员信任。 | 下方固定普通授权链的操作、ID、签名及规范字节，以及 genesis、初始成员表和 NetworkIntent 外层；DNS/LAN 分配、发布期望与其他普通对象采用本文对应章节的唯一规范值，不用全量 network.update 代替。 | 管理 operation、事实同步、持久重建与运行消费的已验范围见实施状态；字段表不抵扣正式验收。 |
| 成员承诺、投票、证书 | 基础表、轮次、发起者、成员、完整投票史、按键已验证前缀、后继提案、封存点和同轮多数签名。 | 初始表、内容 ID、完整后继载荷及历史／前缀／签名集合的字段与排序见下文；非空后继与初始表共用连续证明验证，持久原件和正式入口见控制模型。 | control 加入、移除、换键及离线设备验证连续成员证明需要相同的签名字节；不能用初始表代替后继证明。 |
| `NetworkIntent` 内的 `TransportResource` | 稳定资源 ID、种类、承载节点、interface/listener 身份、拨号坐标和公开认证参数；共享首跳与中继复用同一资源，私钥留在本机。 | 下方固定资源公共字段及 Hy2 的 CA/校验名、凭据和接收端 ACL 投影；WG 的普通设备参与身份和地址投影、各 Link 真实探测动作仍须与 adapter 入口核对。真实执行以实施状态为准。 | WG、Hy2、私有 TLS 的真实身份校验、资源复用和参数变化后的观测失效；无公网域名不能成为关闭 Hy2 验签的理由。 |
| 设备授权内的 `RuntimeKey` 与凭据派生 | 只在 control 间保管根密钥；派生绑定实际发送节点、网络、传输用途、资源认证材料及接收节点，不向设备交付根密钥。 | 下方固定 32 字节根密钥、HKDF-SHA256、最小 info、输出及执行失败收口，不用整份授权/Policy 摘要引入无关换钥。资源认证值及实际凭据/ACL 替换仍须完成；现网旧凭据不能直接解释为新凭据。 | 同一授权在客户端与服务节点产生匹配且用途隔离的凭据；撤权、策略替换或换钥后旧凭据的拒绝不能依赖旧派生规则。 |
| `DeviceView` 与 envelope | 单设备配置、签发者资格、连续成员证明、签发者事实前沿、View 摘要、设备绑定与签名。 | 下方固定普通互联网授权的外层字段、摘要和设备绑定；连续成员证明及服务节点执行回读仍是完整 writer 的前置。 | 配置领取、认证 LKG 原子保存、离线恢复与运行消费须验证同一完整 View，不能拼接或补造缺项。 |
| Invite、claim、resume | Invite 的签发者/锚/设备/职责/PolicyIDs/入口/一次性约束；首次 claim 的设备公钥、目标端识别的平台与 request ID；Invite 不预锁平台，平台随绑定事实及设备授权签名；resume 同事务同密钥同平台。 | 下方固定普通加入的交付、请求、绑定与响应；申请 control 的条件授权及多数后继使用本文固定的成员消息与原绑定引用。 | SSH、脚本与二维码共用加入协议；目标平台绑定、同事务恢复和重复提交拒绝需要统一字节。 |
| 设备 report 与逐条 Observation | 当前 View 摘要、按设备递增序列、真实观测与运行回读；观测绑定设备、网络代、层级、Service/候选或 LinkID、实际目标及规范摘要，缺失或失效为 unknown。 | 下方固定普通 access 报告字段、签名、时间编码、重放拒绝及接收端时效投影；服务节点 listener/ACL/返回路径的逐项回读仍须分别验证。 | 当前路径、业务状态、链路测量和部署回读的新鲜性及重放拒绝；不能由签名有效或单项成功推定其他范围仍可用。 |
| release catalog 与 manifest | generation、组件/平台、不可变文件摘要、长度、媒体类型、受众、版本和最低兼容约束，发布密钥签名。 | catalog 与 manifest 的分层字段、路径规则、排序、签名和摘要字节；旧 floor 与新发布坐标的迁移证明。 | 精确制品验签、下载、期望摘要与实际应用对照，以及维持既有反重放边界的生产切换。 |

资源身份与 KDF 的语义依据是[控制模型的凭据派生](control-model.md#21-material规范签名事实)和
[传输资源边界](control-model.md#7-networkintent传输资源和自动中继)；report 寿命与拒绝规则对应
[Enrollment 的 Observation](enrollment-endpoint-model.md#observation)。表中的缺项是这些既有值的规范边界，
不新增权威对象，不撤销已确定语义，也不构成另一份实施计划。多目标结果按客户端模型的
[同一服务的多个测试目标](../clients/client-runtime-model.md#同一服务的多个测试目标)处理；指标优先级及
稳定选择由[Preference 与 Selection](../clients/client-runtime-model.md#preference-与-selection)列出；
完成编码格式本身不能替代这些算法决定。

任何对象的内层值、可选性或签名输入仍不明确时，生产 writer/decoder 不得自行发明格式。
Policy 必须签名覆盖固定的 ServiceID、action（新写入固定 allow）、独立的入口与中间转发范围，以及互联网服务适用的
出口范围、Direct 与设备限定本地出口许可。范围模式 any / only / none 不可混淆：any、none 的 ID
集合为空，only 的集合非空并规范排序；模式缺失、未知模式、重复 ID 或矛盾组合拒绝。UI 的未设限制
提交为显式 any，不能在 decoder 中把遗漏字段或旧空数组当不限。LAN Policy 不接受互联网出口、
Direct 或本地互联网出网字段，终点从固定所属 Service 读取；Policy 创建后不得改属其他 Service。
节点和 Invite 只保存规范 PolicyIDs，不再双写 ServicePolicies；重复 PolicyID、不同服务的歧义目标组合、悬空/冲突引用、非 access 携带访问策略均拒绝。合法空 PolicyIDs 表示没有业务授权；
历史 deny 原件保留原义但不产生业务权限，新分配不接受 deny。解析到的 Service/Policy 对只是可重建投影，不成为另一份签名分配值。
设备限定本地出网的逻辑最终出口为本机稳定 NodeID，空跳链仅表达本机执行；普通 Direct 的最终出口为
`direct`。本机出口仍须满足设备限定许可、职责及出口范围；本地出网没有网络入口，不受入口范围限制，也不要求自拨或入站资源。
两者不能靠空跳链混同；只有所选 Policy 允许的候选可执行，普通 Direct 许可不授予本地出网。
策略创建后再分配的部分失败与原请求重试见
[策略创建、分配与复用](control-model.md#策略创建分配与复用)。这些同属 schema 3 的现行目标；
旧 AllowedServers、Service.policy、DestinationGrants 和先前 ServicePolicies 目标不能通过改名继续运行。
完成字段表时须给出接受和拒绝字节向量，验证 `decode(encode(D))=D`、`encode(decode(B))=B`；
拒绝未知字段、重复字段、歧义空值、错误排序、错误签名目的、签名未覆盖字段及不规范输入。

成员证书由同一提案的规范投票签名组成，不能把另一目的签名当成员票。发布 catalog 固定
generation 与规范排序的 manifest 摘要集合；每份 manifest 固定组件、平台及逐文件字段。解码后重编码
必须得到原字节，缺项、重复组件/平台映射、未知受众或签名不符均拒绝。Windows 数据面与 Linux 客户端 manifest 已按下方
字段接入签名包；catalog 与通用 Linux 脚本的签名、下载和单目标 import 已接通，其余应用制品 manifest
及现网发布 floor 的自动消费仍未完成。分发目录 current 不等于运行安装代，不能把旧发布记录解释为此格式。

不复用 1 号，因为 1 号是真实存在过的旧 `Material` 格式，现网不可回退 latch 要求 reader 版本不低于 2，
`loom-material-v1` 领域也已被 2 号使用。3 号此后冻结。

## 普通设备服务授权链的字段级规范

本节细化同一个 schema 3，服务于“普通 access 加入、取得服务策略、实际执行、改权与撤权”的一条业务链。
工程实现直接替换现有 Material、Service、Policy、设备协议与持久入口，不建立 `v3` 旁路包、第二 DTO/store
或 schema 1/2 fallback。成员治理、DNS/LAN 分配和发布仍分别遵守其现行模型；本节不以普通操作替代这些门禁。
以下规则可先在独立测试数据中实现；现网切换仍须满足本文末尾的前向映射与用户决定。
当前源码中的认证 LKG 先保存、执行失败不回退与精确清理修改，只是旧协议中的安全检查点；
本节没有使它们成为 schema 3 实现，也没有完成普通授权、撤权或任何生产切换。

### 规范编码、标量与内容摘要

`C(x)` 即 `CanonicalEncode(x)`，唯一编码为紧凑 UTF-8 JSON，无 BOM、缩进或末尾换行。
对象键限本节规定的 ASCII 键，并按键的 ASCII 字节升序输出；字段表的书写次序不决定编码。
字符串须为合法 UTF-8，不做 Unicode 归一化；双引号和反斜杠分别写为 `\"`、`\\`，U+0000～U+001F 仅写为
小写十六进制 `\u00xx`，其他字符直接输出 UTF-8，不转义 `/`、`<`、`>`、`&` 或非 ASCII 字符。
decoder 必须在丢失重复键信息前拒绝重复键，再按精确类型和字段集验证，最后验证 `C(decode(B))=B`；
不能通过 Go struct 顺序、普通 map 序列化或浏览器的 `JSON.stringify` 猜测规范字节。
运行回读中明确规定的目标映射使用精确 string 键和值类型；空映射为 `{}`，键仍按 ASCII 排序，
逐项验证规范域名/IP＋端口和当前 Policy。严格解码不接受 interface 值、任意字段对象、null、重复键
或自定义 codec；映射按同一输入大小、项数和深度限制处理，失败不改变调用者。

| 记号 | 唯一 wire 值与限制 |
|---|---|
| `ID` | 1～128 个 UTF-8 字节，首尾无空白、不含 Unicode 控制字符；身份按原始字节比较，不按显示名称合并 |
| `Text` | 1～256 个 UTF-8 字节，首尾无空白、不含控制字符；仅作显示名称，不授予身份或权限 |
| `U64` | JSON 字符串中的无符号十进制整数，范围 0～18446744073709551615；除 `"0"` 外无前导零，无正号；按数值比较，不能按字符串排序或转为 JS 浮点数 |
| `Time` | UTC Unix 毫秒的 JSON 非负整数，最大 253402300799999；无指数、分数或前导零；UI 的本地时区不进入签名 |
| `Digest` | `sha256:` 加 64 个小写十六进制字符；空字符串只用于字段表明确规定的初始引用 |
| `PublicKey` / `Signature` | Ed25519 原始 32 / 64 字节的无填充 base64url；解码后重编码必须相等 |
| `Secret32` | 32 个字节的无填充 base64url；不得进入公开投影、日志或报告 |
| `IP` / `Prefix` | RFC 5952 形式的 IPv6 或无前导零点分 IPv4；前缀必须网络地址规范化，地址字段不能借前缀扩大范围 |
| `InterfaceAddress` | 规范 IP 加 `/` 与规范十进制前缀长度；保留主机位，不能与表示网络范围的 Prefix 互换 |
| `Port` | 1～65535 的 JSON 整数；没有“0 表示默认端口”的 wire 规则 |
| `HTTPS_URL` | ASCII HTTPS URL，无用户名、口令或 fragment；主机使用规范 DNS/IP，省略默认 443 端口，非默认端口为 Port；空路径写 `/`，百分号转义使用大写十六进制，不改写路径或 query 的业务字节 |
| 集合 | 无重复、按本表规定的键升序；字符串按 UTF-8 字节，对象按其稳定 ID；空集合只能为 `[]`，不能缺席或为 null |

有顺序的值——成员证书链、候选节点链、LinkID 链和证书链——保持业务顺序，不能当集合重排。
布尔值只能为 JSON `true/false`。未标为可选的字段必须出现；可选字段未使用时省略，不能用空值或 null 代替。
decoder 需要输入大小、集合和嵌套的资源保护，但不能未经完整成员证明与运行配置的边界核对，就把统一
大小限额冻结为所有权威值的业务上限。具体入口限额及必要的分批取得须随该入口实现验证；超限明确失败，
不截断事实、投票史或成员证明，在完整认证值通过验收前不写入或提升 LKG。

摘要均为 `"sha256:" + lowerhex(SHA256(domain || C(value)))`，domain 后的 `\0` 为单个 NUL：

| 用途 | domain 与被摘要值 |
|---|---|
| Material ID | `loom-material-id-v3\0`；含签名的完整 Material，不含自身 ID |
| 验证键 ID | `loom-control-key-id-v3\0`；`{"public_key":PublicKey}` |
| 成员表内容 ID | `loom-control-config-id-v3\0`；完整成员表业务载荷，不含外部证书的轮次、凑票签名集合或自身 ID；初始载荷的精确形状见下节 |
| Service/Policy/资源当前值摘要 | `loom-network-value-v3\0`；`{"kind":"service"或"policy"或"resource","value":完整值}` |
| 资源认证摘要 | `loom-resource-auth-v3\0`；资源的完整 authentication 值 |
| 接收端传输用户名 | `loom-inbound-user-v3\0`；`{"network_id":ID,"resource_id":ID,"sender_id":ID}`；只作当前进程的 auth_user 投影，不新增身份 |
| 接收端 ACL 摘要 | `loom-inbound-acl-v3\0`；当前资源、相关节点授权、Service 访问边界、Policy 与本资源传输凭据的单向投影；不包含测量和候选展开 |
| Link 规范摘要 | `loom-directed-link-spec-v3\0`；网络、派生有向 Link、接收资源、实际来源节点的公开 WG 身份及来源解析参数 |
| 候选身份 | `loom-candidate-id-v3\0`；下述候选身份字段，不含其 ID 和规范摘要 |
| 候选规范摘要 | `loom-candidate-spec-v3\0`；`{"identity":候选身份,"service":完整Service,"policy":完整Policy,"resources":按首跳及链路顺序列出的完整资源,"links":按路径顺序列出的完整Link}`；资源按路径保留重复引用 |
| View 摘要 | `loom-device-view-digest-v3\0`；完整 DeviceView，不含 envelope |

签名算法固定为 Ed25519；签名输入为上方签名域表指定的 domain 加 `C(unsigned)`。
`unsigned` 是同一个值删除其自身 `signature` 键后的完整业务载荷，**不保留空 signature 字段**。
引用的事实 ID、其他对象的签名及证明仍属于业务载荷，不能被一起删除。持久原始字节和网络字节相同；
加密保存可以包裹它们，但解密后必须逐字节恢复原值，不能借重编码改变签名对象。

### 普通 Material、依赖与操作

普通 Material 的字段集固定为：

```text
schema: 3
network_id: ID
issuer_control_id: ID
issuer_key_id: Digest
control_config_id: Digest
sequence: U64，至少 1
previous_material_id: Digest；序列 1 使用固定空链值
dependencies: []Digest
request_id: ID
target_kind: service | policy | device | invite | endpoint | resource | link | probe_target | expected_component | admin_certificate
target_id: ID
operation: 下表中的精确操作名
payload: 对应的唯一类型
signature: Signature
```

`probe_target` 仅保留旧签名事实的验签、因果依赖及一次性删除所需标识；当前写入不允许
`probe_target.put`，不产生独立探测对象、引用或管理页。新探测网址只写在 Service 中；删除旧
对象不删除其原始签名事实，也不将历史可解码形状恢复为当前运行模型。

空链值固定为 `SHA256("loom-empty-material-chain-v3\0")` 的 Digest 表达。
sequence 按签发验证键连续递增，前项 ID 必须属于同网络、同签发键的紧前序列，不能按成员表换代归零。
`issuer_key_id` 必须等于该成员验证键的规范摘要；`control_config_id` 必须指向已验证成员表，
签发者在该表内有权且未违反当前成员链的封存约束。初始表按下节完整 genesis 验证；后继表及其证书的
精确字节按下文成员字段规范；运行未实现时明确拒绝，不能用旧 GovernanceHead、QC 或一个无证明的成员数组填充这个引用。

dependencies 保存本操作所读取的对象事实、同目标前值及必要授权事实的 ID，按字节升序；
前序签发链本身隐含为因果历史，不必将整条历史再复制进数组。新建对象没有同目标前值；
修改必须引用操作者审阅的前值，撤权后再次授予必须引用撤权；冲突解决必须覆盖全部冲突事实。
正式管理请求使用 `schema,request_id,operation,target_kind,target_id,dependencies,payload`，不接受
签发键、序列、签名、任意 RuntimeProfile、RuntimeKey 或全局 BaseHead。device.put 的管理 payload
仅为 `id,name,responsibilities,policy_ids,distribution_urls`；daemon 从因果前值保留身份、原加入绑定与 RuntimeKey，
生成下表完整 DeviceAuthorization。device.join、invite.bind 与 invite.expire 由既有加入/到期入口产生，
不能从通用管理表单自造；首次 RuntimeKey 由 control 生成并随事实一次持久化。
其他本链管理 payload 使用下表对应规范值；表中是 Material 字段，设备冲突解决的管理命令不得以完整值
回传秘密，其与受保护前值的精确组合仍须在同一操作补齐，不能复用通用任意 JSON 写入。
daemon 校验依赖后生成签名事实并持久化，
返回 `material_id` 与“本地接受”；重复 request ID 和相同规范请求返回原结果，不重复产生随机密钥；
同一签发者下相同 request ID 携带不同内容拒绝。索引由原始事实重建，不另存请求完成权威。

| operation / target_kind | payload 及约束 |
|---|---|
| `service.put` / service | 完整 Service；payload.id 与 target_id 相等 |
| `policy.put` / policy | 完整 Policy；所属 Service 已有效，更新不能改变 service_id |
| `service.delete`、`policy.delete` / 对应种类 | `{"id":ID}`；删除只留下事实，不清空依赖者的 ID 或扩大范围 |
| `invite.issue` / invite | 下述 Invite 值；只由其 issuer 签发 |
| `invite.bind` / invite | `transaction_id,invite_material_id,claim_request_id,device_public_key,platform`；发行者签发，直接依赖原 Invite |
| `invite.cancel`、`invite.expire` / invite | `transaction_id,invite_material_id`；expire 另含 `expired_at:Time`；普通事务终结依赖已知绑定，不能覆盖 completed；申请新 control 资格的终结仍走成员规则，已有初始成员首次设备绑定不改变成员资格 |
| `device.join` / device | 完整 DeviceAuthorization；只由 Invite issuer 签发，直接依赖绑定事实；事务完成从此事实投影，不再签 complete |
| `device.put` / device | 完整 DeviceAuthorization；任一有效 control 可改普通职责/PolicyIDs，身份、公钥、平台和原加入绑定不变 |
| `device.revoke`、`device.delete` / device | `{"id":ID}`；revoke 后须显式后继重新授予，delete 留永久墓碑；涉及 control 的整体删除不能走此入口 |
| `resource.put` / resource | 下述完整资源值；任一有效 control 可签发，依赖已审阅的资源前值与承载节点授权；本机私钥路径不进入 payload |
| `endpoint.put` / endpoint | 下述完整入口值；只由承载 control 签发；本机私钥路径不进入 payload |
| `resource.delete`、历史 `link.delete` / 对应种类 | `{"id":ID}`；共享资源删除收口全部引用，link.delete 只前向撤销历史人工配置，不删除当前派生边 |
| 历史 `probe_target.put` / probe_target | 已签原件只用于历史验签与因果引用；当前不新增或修改，探测网址直接属于 Service |
| `probe_target.delete` / probe_target | `{"id":ID}`；不改变设备权限 |
| `expected_component.put` / expected_component | 下述 ExpectedComponent；依赖有效设备授权及已审阅的同目标前值，签发前独立验证精确发布引用 |
| `expected_component.delete` / expected_component | `{"id":ID}`；只撤销该期望，不删除程序、不降低安装 floor 或改变设备权限 |
| `admin_certificate.put` / admin_certificate | 下述 AdminCertificate；本机先按配置的 admin 验链锚验证新叶，普通事实只授予该精确叶 |
| `admin_certificate.delete` / admin_certificate | `{"id":ID}`；撤销精确叶，新请求及既有管理 WebSocket 重新检查当前授权 |
| `conflict.resolve` / 被解决目标种类 | `conflicts:[]Digest,action:put或delete`；put 另含对应完整 `value`，delete 不含 value；引用须覆盖全部冲突，不能通过此操作绕过成员资格/已绑定 control 事务或设备墓碑 |

普通对象解决的精确映射见[显式冲突解决](control-model.md#普通对象的显式冲突解决)。conflicts 恰为
本次审阅的全部同对象当前并发引用，至少两项，严格升序、无重复，且每项都显式出现在 dependencies。
put 的 value 由 target_kind 选择原对象完整规范类型；device 的公开管理 value 只允许 DevicePut 字段
（包括当前可选 dns_servers），签名 Material 的 value 由 daemon 保留原身份、密钥及加入绑定后组成
完整 DeviceAuthorization。delete 不含 value，采用原目标删除语义。Invite、Endpoint 的有限生命周期
和成员治理不扩展为通用可编辑值；跨目标碰撞仍须沿真实事务、名称或前缀消除，不冒充一次任选合并。

以上为本链所需操作，不新增成员治理或发布操作的编码。那些入口仍须遵循各自模型，
待其精确字段确定后修订同一 schema 3；不得把未定义 payload 当任意 JSON 接受。

#### 成员之间的稀疏双签证据

有效成员的私有 TLS 入口 `GET /internal/material-conflicts?after=<摘要>` 返回规范对象
`{material_ids:[摘要],more:布尔}`；after 必须出现一次，首次为空，后续为上一页最后一个 ID。
未知/重复参数、非法摘要和非规范响应拒绝。列表恰由已保存原 Material 中同 IssuerKeyID、同
Sequence 的不同内容 ID 构成，按 ID 严格递增去重，仅返回大于 after 的最多 256 项；more 表示
本次读取还有后续项。它不包括正常连续事实，不是第二份持久集合或认证前沿。

消费方每轮从空 after 开始，仅沿原 `GET /internal/materials/<摘要>` 获取本地缺失正文，继续执行
原件摘要、规范签名和接收校验，再补声明依赖。空页带 more、逆序/重复/越界 ID、缺字段或未知字段
均拒绝；网络取消、中途失败或分页期间新增原件不删除已保存事实，下一轮重新按实际集合补齐。
原件接收返回同键同序列双签时，只有已耐久保存才可继续接收其他证据；该键的签发禁用和投影收口
保持。无关键的普通前沿仍独立同步，正文已存在且相同的原件不重复下载。

本响应只是现行 Material 的 runtime/wire 投影；原签名、原持久文件、设备高水位、schema 3
及 UI 的授权/冲突回读均不改变。它不产生新签发权、完成状态或旧协议 fallback。

### 管理员精确叶授权与交付

既有 `AdminCertificate` 仍恰为 `{id,certificate_der}`，证书为单个完整 DER 的规范 base64url；不增加
管理员 store、签发任务或轮换状态。新证书 ID 为 `admin-` 加 DER 的完整 SHA-256 小写十六进制。
现有 genesis 的原 ID、证书和签名字节保持；对这些 ID 重新授予时只能引用同一原叶，不能更换证书。
新值必须是 P-256、非 CA、仅 clientAuth、digitalSignature 的叶。证书 ID 永久绑定原叶，同一叶不能另换 ID
逃避撤权；普通 put/delete 引用已审阅前值，撤权后的重新授权须显式引用撤权。并发撤权优先，并发不兼容
修改使该目标失败关闭；多个 control 不是特殊模式。撤销全部浏览器管理员仍保留既有 root-only Unix 管理入口。

| 层 | 表达与方向 |
|---|---|
| domain / wire | AdminCertificate 与 put/delete 普通 Material，使用既有 schema 3 规范签名 |
| persistent | 原 genesis 与普通事实原字节；管理员私钥和 P12 是受保护交付物，不写入事实 |
| runtime | 从事实重建精确叶名单；TLS 独立按本机已有 admin 信任锚验链，请求与 WebSocket 再查当前名单及证书有效期 |
| UI / CLI | Settings 展示证书 ID、公开指纹与有效期；导入公开 admin.json 后授予，撤销写同一普通操作；生成包本身不授权 |

control 的普通签名权与 X.509 签发能力分别验证。`control admin issue` 只消费本机显式指定、受保护的
P-256 admin 根证书及匹配签发私钥，在新 owner-only 目录产生同一新叶、私钥、完整 P12、独立密码文件和
公开 `admin.json`；不依赖旧管理员私钥，不签授权事实。该能力只在持有操作者所提供签发密钥的 control
上可用，其他 control 可按相同规则授权已验链叶，缺少签发引用明确失败，不从成员键或网站键补值。
首证可把同一公开值纳入首次 genesis；已有网络走普通 put，不重写 genesis。当前现网签发根、公钥与
服务端原信任输入延续，秘密只提取为独立受保护文件引用，不恢复旧权威解码或轮换状态机。

签发时间和随机数是调用方输入，不进入纯投影。交付目录先完整生成并验证，再耐久原子安装；同目录重试
验证并复用原叶、私钥和密码，不覆盖异值或部分损坏。删除交付文件不撤权；已授予的丢失包先正式撤权，
再生成另一个证书。包与密码由操作者手动取回，网站信任与客户端身份分开，不以 admin 根代替网站根。
新 put 在接收 daemon 验链并检查当时有效期后签发；同步/重放不依赖本机时钟或另一个 control 的文件。
每个服务端在实际 TLS 连接时独立验链；信任输入不一致导致该端明确拒绝，不能把本地授权说成全网成功。
已接受请求的重试返回原事实，证书过期不重签事实、不删除历史，运行入口拒绝过期证书。

正常链：本机签发交付包 → 手动安装 P12 → 原管理员通过 Settings 导入公开值并授予 → 普通事实持久/同步 →
新证书实际浏览器登录、正常写入和回读 → 撤销后新请求与原 WebSocket 拒绝 → 重启仍拒绝。
最小测试覆盖原 genesis 字节不变、规范往返、ID/证书替换与重复叶拒绝、撤销优先、错误 CA/用途/有效期、
同请求重试、交付目录损坏与原值保留、真实 TLS/浏览器操作、同步及重启；旧 N=1 和旧私钥证明轮换入口不恢复。

### Genesis 与初始成员表

genesis 是 Material 的初始形状，字段集**恰为**下表；使用同一规范编码、Material 签名域和完整事实 ID
算法，不另设 bootstrap 协议。没有普通事实的 sequence、previous_material_id、dependencies、
request_id、target_kind、target_id 或 control_config_id，出现这些字段即拒绝。

| 字段 | 类型与约束 |
|---|---|
| schema | JSON 整数 `3` |
| network_id | ID；本网络稳定身份 |
| issuer_control_id | ID；必须唯一命中内嵌初始表的一个成员 |
| issuer_key_id | Digest；必须等于该成员 public_key 的验证键 ID |
| operation | 精确字符串 `genesis` |
| control_config | 下述完整初始成员表业务载荷 |
| network_intent | 下述初始 NetworkIntent 值，全部集合显式出现 |
| admin_certificates | 首批受信 admin 叶授权集合，每项恰为 `id:ID,certificate_der:CertDER`，按 id 排序；叶 DER 也不得重复 |
| signature | Signature；由上述成员的本机受保护私钥签署全部其余字段 |

`CertDER` 是一张完整 X.509 证书的 DER 字节，以无填充 base64url 编码；必须严格解码为恰好一张证书，
不得有剩余字节、PEM 包装或私钥。admin 项只表达对该叶的授权，不替代验链、clientAuth 用途及既有
管理员认证要求。admin_certificates 可以为 `[]`，此时没有任何远端管理者因空集合而自动获授；
显式本机受保护管理入口仍按其已有认证边界工作。admin 证书签发者和验链信任锚的未决问题见本文开头，
不能从这份叶名单反推出一套新 CA 或远端管理豁免。

初始 ControlConfig 载荷字段恰为：

```text
schema: 3
network_id: ID；与 genesis.network_id 相等
previous_config_id: ""
operation: "genesis"
members: 非空集合，每项恰为 control_id:ID,node_id:ID,public_key:PublicKey
sealed_keys: []
```

members 按 control_id 的 UTF-8 字节严格升序；control_id、node_id 与 public_key 分别唯一，NodeID
不得为保留终点 `direct`。成员表不写地址、传输、健康、普通职责、quorum、mode、签名轮次或自身 ID。
previous_config_id 的唯一初始值为空字符串；sealed_keys 在 genesis 必须为空，不得伪造对未知前键的封存。
成员数量没有其他分支；初始表只赋予 control 职责，不能据此授予 access、forward、internet_egress
或任何 Service 权限。初始成员取得同一 NodeID 的设备身份和组合职责，使用既有的
`invite.issue → claim → invite.bind → device.join`，不在 genesis 夹带 RuntimeKey 或默认生成授权。
允许该初始成员**自己**为其 NodeID 签发首次设备绑定 Invite：签发者必须仍有该节点的 control 资格，
目标尚无 DeviceAuthorization、已绑定设备身份、其他未终结事务或节点墓碑；同事务重试恢复原绑定。
Invite 职责包含已经成立的 control，以及本次请求的普通职责，因此媒介仍为 SSH/sh，不能转为二维码。
设备在目标本机生成独立的 Ed25519 身份并签 claim；成员自签 Invite、绑定事实和设备授权共同证明
这份身份与已有 NodeID 的关系，不复制或复用 control 签发私钥，也不增加另一份身份权威。
已有 control 资格无需重新申请，完成这次绑定不产生 ControlConfig 后继；普通职责只随 device.join 生效。
即使没有普通职责，也可形成职责数组为空的 DeviceAuthorization，节点 control 职责仍只来自成员表。
新 NodeID 申请 control 继续走原多数增员规则；已绑定身份只能沿原事务恢复或 device.put 改普通权限，
不能借再次邀请更换身份，删除 control 节点仍须同一多数门禁。首次绑定取消/到期只终结这次设备事务，
不撤销既有成员资格，也不抹掉已接受的绑定证据。

正式入口是目标成员的私有管理 API 或本机管理 socket；首次绑定需选中这个成员，之后普通改权可由任一
有效 control 提交。当前 `createExistingNodeRejoin` 依赖旧 NetworkIntent 节点，
`validateNewEnrollmentIdentity` 又一概拒绝成员 NodeID；替换时改为上述身份和事务谓词，不能恢复旧导入
或 rejoin fallback。这是同一成员/Invite/设备模型内的合法转换，不是新的加入模式或 N=1 特例。

ConfigID 是上表**完整载荷**的成员表内容 ID，包含 network_id、空前驱和空封存集合；不得将 genesis
的签名或 Material ID 再放回载荷。genesis 签名覆盖内嵌成员表，受保护初始锚固定完整 genesis 的
Material ID；仅有一个自签正确的 genesis 不能替换已固定锚。普通事实引用 ConfigID，不引用某组票
组成的证书摘要。同一后继提案在不同合法轮次或由不同多数子集证明，成员表内容 ID 必须相同；改变提案
业务载荷才改变内容 ID。外部证书仍须证明同轮同提案多数，不能因此合并跨轮票。

引用与计算顺序为 `成员公钥 → KeyID`、`初始成员表 → ConfigID`、`完整无签名 genesis → signature`
及 `完整 genesis → Material ID / 受保护锚`，没有反向引用环。genesis 不占用任何成员键的普通 sequence；
每把键的第一条普通事实均从 sequence `"1"` 和固定空链摘要开始。初始 Service 等值的创建证据是 genesis
Material ID；后续首次修改/删除这些目标，或读取其中已有值的普通操作，须把该 ID 放入 dependencies。
普通事实的 control_config_id 仍须验证；它不是可以省略相关对象因果依赖的全局 base_head。

建立初始锚只允许显式、本机、经授权的新空权威初始化：事先选定网络、全部初始成员公钥与本机签发身份，
校验完整 genesis 后保全同一原始规范字节和锚，才接受普通写入。启动时缺文件、损坏、读失败、出现另一
genesis、已有旧格式材料或已存在认证 floor/latch，都不能触发自动初始化或重设。重启从同一锚和原始
事实恢复；不能从缓存或当前设备状态重造 genesis。现有网络仍须经过本文规定的受保护前向映射，
空初始化不是现网迁移或身份恢复办法。

成员证明唯一形状为 `control_proof={genesis:完整genesis Material,successors:[]ControlCertificate}`。
successors 按前驱顺序排列，空链唯一值为 `[]`，不是省略或 null。空链须验完整 genesis 的规范字节、
签名及固定锚，终表为其初始 ControlConfig；任意成员数使用同一规则。不能用无证明成员数组、旧 QC、
测试表或 Runtime 状态代替 genesis。已见更高成员链不得回退为空链，锚也不得替换。

后继成员消息沿用[现有轮次、完整票史及安全继承算法](control-model.md#后继表投票)，字段固定为：

| 值 | 精确字段与排序 |
|---|---|
| ControlRound | `counter:U64,proposer_control_id:ID`；counter 至少 1，按 counter、再按 proposer_control_id 字节比较 |
| ControlSealedKey | `key_id:Digest,sequence:U64,tip_material_id:Digest`；sequence 0 的 tip 为固定空链摘要 |
| 后继 ControlConfig | 初始表的六字段仍必含；operation 仅 `add/resign/revoke/delete/rotate/invalidate_join`，previous_config_id 为基础表内容 ID；另必含 `target_node_id:ID,origin_promises:[]ControlPromise`。members、sealed_keys 分别按 control_id、key_id 排序；只封存失去签发资格的键 |
| ControlJoinBinding | `transaction_id:ID,invite_material_id:Digest,binding_material_id:Digest,device_public_key:PublicKey,authorization_material_id`；最后字段为所引普通职责事实 Digest，纯 control 为固定空字符串；仅 add 的 `join` 字段携带 |
| ControlJoinInvalidation | `transaction_id:ID,invite_material_id:Digest,binding_material_id:Digest,reason`；reason 仅 `cancelled/expired`；仅 invalidate_join 的 `invalidation` 字段携带 |
| ControlVote | `schema=3,network_id:ID,base_config_id:Digest,round:ControlRound,proposal_id:Digest,voter_control_id:ID,signature:Signature`；proposal_id 为所投完整 ControlConfig 的内容 ID |
| ControlVoteHistoryItem | `proposal:完整ControlConfig,vote:完整ControlVote`；提案 ID 与 vote.proposal_id 相等 |
| ControlPromise | `schema=3,network_id:ID,base_config_id:Digest,round:ControlRound,responder_control_id:ID,votes:[]ControlVoteHistoryItem,prefixes:[]ControlSealedKey,signature:Signature`；votes 按轮次排序，包含该成员对此基础表的完整已投历史；prefixes 按 key_id 排序，覆盖基础表的每把验证键 |
| ControlCertificate | `config:完整后继ControlConfig,round:ControlRound,promises:[]ControlPromise,votes:[]ControlVote`；promises 按 responder_control_id、votes 按 voter_control_id 排序，分别为同轮旧表多数；每票绑定同一基础表、轮次和 config 内容 ID |

管理成员操作请求为 `schema=3,base_config_id,operation,target_node_id`，operation 使用成员表的六种
后继操作；add 另含 `transaction_id`，invalidate_join 另含 `transaction_id,reason`，rotate 另含
`public_key`，其他字段拒绝。它是本次请求参数，不是持久权威。base 指向管理员已读回的完整成员表，
超时后重试同一 base；已形成后继时返回实际原证书及请求是否已满足，不把安全继承选出的其他操作
报告为请求完成。新 control 的 control_id 确定为其新 node_id，既有身份不改名。

管理请求沿 `POST /api/control/members` 使用与普通写入相同的私有管理员认证和同源规则；CLI
`loom control member` 使用同一路径。成功响应为原 `certificate` 与布尔
`requested_change_applied`，后者为 false 时必须展示实际决定并重新读取成员表，不能显示请求完成。
多数不足返回失败且保留已持久承诺、票和 claim；重试不会清空它们。成员页面直接读取当前 members
及 ControlConfig ID，不建立成员操作状态库。已绑定 control 事务不能降级成普通 invite.cancel/expire。

私有成员 prepare 请求恰为 `schema=3,base_config_id,round`，vote 请求恰为
`schema=3,config,round,promises`，成功分别返回原 `ControlPromise` 和 `ControlVote`。
证书发送使用原 `ControlCertificate`，成员链读取返回原 `ControlProof`。请求沿当前成员的既有
端到端 TLS 通道发送，prepare 的 proposer 必须是该认证成员；vote 的当前轮 proposer 同样核对。
这些是操作参数与原证据的交付，不持久化请求包装或新状态。

`GET /internal/control-proof` 可用强 ETag 比较完整规范 `ControlProof` 字节：
`ETag` 恰为双引号包围的 `sha256:<规范原件摘要>`。请求的单个 `If-None-Match` 与服务端当前
原件完全一致时返回无正文的 304 并回传同一 ETag；其余读取返回原 200 正文。客户端只从本机
Authority 已验证的完整证明生成条件值，并在本次请求内保留对应原字节；只有当前成员 TLS
检查通过、304 无正文且回传的单个强 ETag 完全相等，才能把本次已知原件交给原证明验证链。
没有确认、确认不匹配及其他入口的 304 均拒绝。证明变化、成员失格和通知丢失仍走原完整证明
验收与停止链，不降低检查频率，不增加远端证明缓存、持久游标或第二份成员权威。

成员每轮读取普通事实前沿时，可在同一 `GET /internal/frontier` 响应确认上述完整证明，避免无变化
时分别请求证明、前沿及空分叉目录。规范正文仍为原 `[]FactFrontier`；强 ETag 只绑定完整前沿
规范字节。`Loom-Control-Proof` 为完整规范 ControlProof 的同一强 ETag，
`Loom-Material-Conflicts` 为原事实分叉目录的 `none/present` 提示。服务端在同一个 Authority
读锁内派生三个值；权威被阻断时拒绝。提示不进入签名对象、持久值、缓存或 UI，不成为同步完成
状态，也不增减任何原件。前沿相同可以隐藏旧位置双签，故分叉提示不绑定前沿 ETag：即使返回
304 也必须重新投影，只有明确的单个 `none` 才省去空目录读取。

请求只使用本次已捕获的本机规范前沿生成条件值；304 须无正文并回传同一单个强 ETag。
只有当前成员 TLS 再检查通过，且响应的单个完整证明摘要与本机 Authority 已验证原件完全相等，
才可直接消费本轮前沿。缺少确认、证明变化或前沿读取失败时，仍经独立的证明专用通道执行原
完整证明认证、成员变化和停止链，丢弃首次前沿并重新读取普通前沿与分叉目录；不从 provisional
响应获得权限。普通读取不接受未经条件确认的 304。分叉提示缺失、未知或为 present 时仍读取原
分叉目录并逐件验签、保全原件。下一轮重算全部提示；重启无需恢复额外状态。

domain、规范 wire、persistent 与 UI 不变；runtime 仅在当前认证请求内复用已知原件与派生前沿。
最小验证覆盖真实 TLS 无变化轮询的请求与字节减少、普通事实持久收敛、错误确认、完整证明变化、
通知丢失后的撤权/换键、等前沿的旧分叉传播和连接隔离/关闭。成员轮询与设备十五秒刷新保持原频率。

上述消息没有省略的空集合；ControlConfig 的 join/invalidation 只在对应操作出现，其余操作出现即拒绝。
genesis 拒绝 target_node_id、origin_promises、join 和 invalidation。delete 与 target_node_id 一起构成该
节点的不可复活删除事实；不再增加第二份墓碑实体。add 的事务、公钥、目标及所引条件授权必须一致，新增 Member.public_key 等于 join.device_public_key；
其他操作的成员差量、封存集合和节点资格按控制模型验证，字段存在本身不授予资格。

Vote、Promise 分别使用既定 `loom-control-vote-v3\0`、`loom-control-promise-v3\0` 域，签名覆盖删除自身
signature 字段后的全部规范载荷。origin_promises 为首次合法提案引用的同轮多数原始签名回复，固定
其封存依据；安全继承不修改它。Certificate.promises 是当前证书轮次的回复，不进入 ConfigID。
origin_promises 的 prefixes 给出各被封存键的序列最大值及对应 tip；控制签署者另验完整原始事实链，
设备证明只携带这些签名回复与多数票，不携带含 RuntimeKey 的事实链。

每份 Promise 内的历史 vote.round 必须严格小于该 Promise.round，且必须由同一 responder 签发；
同轮同提案只保留一票，同轮异提案双签拒绝。同一提案引用的 origin_promises 不得晚于该提案的投票轮。
因此递归历史只指向更早轮次，不会把当前提案摘要放回自己的签名依赖。首次提高承诺时，成员原子保存
当时完整已投历史、前缀和原始签名回复；同轮重试返回完全相同字节，不能在投票后重生成同轮回复，
否则会把当前票放回自己的起源证明或破坏历史约束。这些是已有成员承诺持久值，不另增 store。

某提案可以在后轮得到多数票，而其 origin_promises 保留首次轮次。完整投票历史不包含每个投票轮次的
全部承诺，不能单凭这些历史票拼造该轮 Certificate.promises。已知同轮多数票时，该完整提案值已经
选定：优先取得原始证书；原证书无法取得时，以当前轮的有效 promises 和同轮多数 votes 为同一 config
形成证书。提案字节及 ConfigID 保持，新增成本仅为补取证书失败后的同值收票；未取得完整证书前不推进
成员链。这不增加消息字段、权威对象或成员状态，旧轮多数决定不能因响应丢失被撤销。

成员 writer 必须完整执行后继验证、持久承诺与票史、安全继承及原事实验收；不得把 successors
元素声明成空类型、任意 JSON 或跳过验签。真实 genesis 加空链与后续完整链属于同一证明结构，
不存在 N=1 或测试专用 decoder。正式入口、持久和重启映射见[控制模型](control-model.md#成员消息的持久与重启映射)，
实际部署与业务验收结果单独记录在[实施状态](../progress.md)。

### 初始 NetworkIntent 的字段与引用边界

genesis.network_intent 的字段集固定为下表；schema 为整数 `3`，其余字段均为集合，空值恰为 `[]`。
这只是现有网络意图的初始值，不增加可独立写入的 store 或全量更新操作。非空集合必须逐元素使用对应
唯一规范类型、检查排序与全部引用；不能用 `[]any`、原始 JSON 或“当前没用到”跳过校验。

| 字段 | 元素及排序、引用 |
|---|---|
| services | 本节 Service；按 id 排序；互联网 matcher 非空，局域网值不能伪装成互联网 Service |
| policies | 本节 Policy；按 id 排序；service_id 须引用同一初值中有效 Service；节点范围不得引用不存在或不具对应职责的节点 |
| resources | 本节 TransportResource；按 id 排序；owner_node_id 须具有该资源所需资格；公开认证值按资源种类严格校验 |
| links | 历史 NetworkLink 原件的规范值；仅历史验证，当前执行图由有效节点和资源派生；新 genesis 保持显式空集合 |
| 历史 business_probe_targets | 已签 Genesis 中的原值保全；新 Genesis 只能为空，不新增独立目标权威 |
| dns_records | `DNSRecord` 集合，按稳定 id 排序；每项为 `id,name,addresses`，LAN 记录另含 `service_id`，规范及并发同名拒绝见下文 |
| public_trust | `PublicTrust{id,purpose,certificate_der}`，按 id 排序；当前 purpose 恰为 website，证书为受约束网站根 DER 的无填充 base64url，id 为 website- 加 DER 的 SHA-256 小写十六进制；规范与撤销规则见[公开网站信任根](control-model.md#公开网站信任根)。数据面认证仍由 TransportResource 的原公开值确定，不继承网站根 |
| expected_components | 下述 ExpectedComponent；按 node_id、component_id、platform 排序；初始值没有普通设备授权，非空初始期望拒绝，后续通过普通事实逐项修改 |

所有元素稳定 ID 在本类集合内唯一；Service 与 Policy 即使使用相同文本 ID 也分别按目标种类寻址。
引用只在同一完整初值及初始成员表内解析，不能查询现场网络、未签 registry、旧 Projection 或部署输入
补全。初始值没有设备授权；初始成员只有 control 职责，因此指向尚不存在的普通节点/网关、或要求其
forward/出网职责的 Policy、资源及链路都拒绝。合法空 Policy 分配与 any/only/none 的区分仍遵守本节，
空网络不因没有资源或探测目标而自动获得 Direct、互联网或局域网权限。

节点身份与职责由成员表和设备事实投影，不在 genesis 另存可改权的 nodes 数组；LAN mapping 已属于
local_network Service，不再列 lan_mappings。配置模型要求的认证 distribution_urls 是下述
DeviceAuthorization 的公开节点属性，经同一个 device.put 管理；NetworkIntent.nodes[].distribution_urls
与 PublisherInput 只从该有效值投影。初次 device.join 保存 `[]`，有合法绑定后可设置或清空；纯 control
初始成员也先走上文的首次设备绑定，不必伪授 forward 等职责。genesis 不另复制此列表，初始无分发地址
不阻止 Service/Policy 和普通 access 的加入。当前 publisherInput 已消费节点的 DistributionURLs，
替换其来源为设备事实并删除旧 network.import 来源，不从 .env、旧 registry 或报告补值。
DNS resolver 运行地址与 overlay DNS 记录不同，
不把旧 dns 字符串数组解释为 dns_records。设备授权、Invite 事务与 EndpointGeneration 属于 Projection
的其他既有值，不混入这张初值表或从成员地址自动生成。

字段完整性到此分为两层：本节规定已列出的 genesis、初始成员表及 NetworkIntent 初始字段的编码规则，
初始节点的首次设备绑定与认证分发地址也使用上文的同一事实链。互联网 Service/Policy 和共享 HTTPS 目标已有完整
非空值规范；Hy2 authentication 的字段固定于下文，公开网站根使用上述完整 PublicTrust。
Link 探测动作使用下述原生 WG 回显契约，LAN 使用 Service 的局域网映射契约。
任何未定义的非空值仍须指明缺项并拒绝，不能先落盘后补规范。
空集合是合法新网络的无配置初态，不是允许忽略其非空内容的测试协议；正式入口与测试使用同一个 decoder，
对已规定元素执行同一检查，对未规定元素同样拒绝。补齐元素时修订同一 schema 3；既有 genesis 原始
字节和锚不变，新增普通事实逐对象生效，不把空集合事后解释为隐含默认对象。

### 精确 overlay DNS 记录

`DNSRecord` 包含 `id:ID,name:DNS_NAME,addresses:list<IP>`；可选 `service_id:ID` 将名称绑定到一个 LAN Service，缺席保持原普通记录字节；空字符串和 null 均拒绝。绑定记录的每个地址必须属于该 Service 当前启用的虚拟 IPv4 前缀，写入引用该 Service 的当前事实。只有获得该 Service allow 权限的设备及实际执行其 ACL 的接收节点得到该记录；禁用、删除、撤权或前缀重分配后不再适用的记录退出运行投影，但原记录继续供管理员检查和更新。运行时可由记录派生精确名称匹配，最终网关仍对解析后的每个地址检查虚拟前缀。没有绑定的旧记录保持原含义，不自动变成 LAN 记录。名称以 `.loom` 结尾且不等于
`control.loom`，地址非空、唯一、按规范字符串字节序排列，拒绝 unspecified、multicast、zone 和
IPv4-mapped IPv6。`dns_record.put` 的 target_kind 固定 `dns_record`，target_id 等于 payload.id；
`dns_record.delete` 使用既有 `DeleteTarget`。初始记录按 ID 排序且名称唯一；并发普通事实同名时
按[普通记录的写入与执行](control-model.md#普通记录的写入与执行)保留管理读回并停止该名称的设备投影。
DeviceView 的可选 `dns_records` 使用同一值与 ID 排序，名称唯一；没有记录时字段缺席，显式空数组或
null 均拒绝。这保全旧的空 NetworkIntent 及缺席字段的 View 原字节，不增加版本或旧格式 fallback。
域值、wire 和持久值可逆，UI/DNS 答案及数据面配置只是单向投影。
候选 spec 的既有输入仅在存在与所属 Service 名称 matcher 匹配的记录时增加 `dns_records`，
集合仍按 ID 排序；没有相关记录时该键缺席，保持旧摘要。候选身份、KDF 和 Service 授权不变。
删除、改名、地址变化及名称冲突导致相关记录集合改变，从而使对应业务观测失效；不相关名称不参与摘要。

空初值的签名与摘要可按以下确定性构造演算；`Sign`、`C`、摘要域均用本文定义，成员数只体现数据。
演算使用公开的测试种子 `SHA256(UTF8("demo-genesis-control-a"))` 和
`SHA256(UTF8("demo-genesis-control-b"))` 生成两把 Ed25519 演算键；这些公开种子不得用于部署。

```text
network_id = "demo-network"
members = [
  {control_id:"demo-control-a",node_id:"demo-node-a",public_key:PublicKey(demo_a)},
  {control_id:"demo-control-b",node_id:"demo-node-b",public_key:PublicKey(demo_b)}
]
control_config = {schema:3,network_id,previous_config_id:"",operation:"genesis",members,sealed_keys:[]}
network_intent = {schema:3,services:[],policies:[],resources:[],links:[],
                  business_probe_targets:[],dns_records:[],public_trust:[],expected_components:[]}
unsigned = {schema:3,network_id,issuer_control_id:"demo-control-a",
            issuer_key_id:KeyID(PublicKey(demo_a)),operation:"genesis",
            control_config,network_intent,admin_certificates:[]}
genesis = unsigned + {signature:Sign(demo_a,"loom-material-v3\0" || C(unsigned))}
initial_config_id = ConfigID(control_config)
protected_anchor = MaterialID(genesis)
wire = C(genesis)
```

这里是构造式，不是可原样提交的 JSON；writer 必须产生完整公钥、签名与规范 wire，不接受表达式或
占位字符串。最小反例是：交换 members、两个成员复用节点或键、改变内嵌 network_id、给初始表添加票
或非空封存、增入未授权普通职责、添加未知 NetworkIntent 字段，以及改动任意已签初值，全部拒绝。
实现须验证同一 genesis 重复打开得到相同 ConfigID、锚和投影；空目录显式初始化与带旧材料/锚目录的
重启不能混用。签名演算本身不能证明节点绑定、公开信息投影或运行消费已实现；已有设备改 PolicyIDs
还要求合法的 Invite/绑定/设备授权事实，不能由该 demo 或初始化补造一台设备。正式管理写入、运行、
动态成员和生产切换的实际实施与验收范围分别见[实施状态](../progress.md)。

### Service、Policy 与设备授权

互联网 Service 的当前目标是保存预期访问服务的探测网址及“是否只能访问这些目标”开关，
不再分别编辑访问范围、Destinations 和探测对象。客户端当前选择一条互联网 Policy，所属
Service 从 Policy.ServiceID 唯一确定；多个已授权 Policy 是可选集合，不同时成为互联网当前策略。
完整业务语义见[当前业务基线](control-model.md#服务与策略的当前业务基线)。

限制关闭时允许普通互联网，不以探测网址构成白名单；限制开启时从这些目标派生访问边界。
普通互联网不授予 LAN、overlay、本机或管理 underlay 访问，最终解析与实际拨号须检查边界。
没有探测网址且未开启限制时，仍可依靠传输及真实业务观测联网；空目标不能产生受限访问许可。
网址仍使用规范 HTTPS URL，排序、去重及未知/非规范输入拒绝规则保持。

当前 Service 字段为 `id,name,kind,restrict_to_probe_targets,probe_urls?,local_network?`。
限制开关必须显式出现；未配置网址时省略 probe_urls，不能用 null 或空数组替代省略。
限制开启时网址必须非空；权限按每个 URL 的规范 host 与有效端口生成并去重，默认 HTTPS 端口为
443。路径、query 和探测响应不改变权限。互联网仍逐次拒绝非公网解析及拨号；LAN 仍与其完整
LocalNetwork 映射取交集，不能借一个网址扩大范围。kind 与 local_network 的对应保持。

派生接收端 Matcher 可带 `port`（1～65535）；省略表示该原有范围内不限端口，仅用于普通互联网
及完整 LAN 映射。限制网址生成的 Matcher 必须带精确端口，域名只生成 dns_exact，字面 IP 只生成
精确 /32 或 /128。它们不是新的可编辑目标列表。只改 URL 的路径或 query 不改变执行凭据及 ACL；
限制关闭时任何纯探测网址编辑都不改变授权。限制开启时改变 host/端口须重新应用相应授权。

固定出口时不按探测网址分别优选入口或中继，所有目标共用到该出口的传输路径选择；网址结果
只作相应业务诊断。非固定出口时，多网址分别参与所选 Policy 内的目标相关优选，未测目标使用
该 Policy 的默认优选；没有 Service 平均分或跨 Policy 回落。实际目标按原始域名/IP＋端口匹配，
不以 HTTPS 路径区分连接。一个连接或 UDP 会话的最终出口保持，复用该连接的请求不另选出口。

用户已确认非固定出口的默认规则：未测目标先比较当前 Service 探测目标的已测可达覆盖，同等
覆盖再比分段代价。按规范域名/IP＋有效端口去重；同一连接目标的多个 URL 分别保留测量，任一
新鲜成功可证明该目标有成功证据，全部 URL 均有新鲜失败才记目标失败，其余为 unknown。
成功目标数是已证明的覆盖，不把 unknown 记失败，不取 HTTPS 耗时平均分。覆盖较少或无样本
不删除候选；未知入口及出口继续得到探索机会。该规则不改变固定出口的传输排序。

每个 internet_egress 自行持续检测其适用 Service 的探测项；同出口、URL 与实际测量规格去重，
结果进入既有签名报告、成员差量同步及相关观测批量交付。节点预算约束覆盖频率，不能因暂无
消费者取消检测。access 消费共享出口原样本，保留本机到入口的测量及真实业务观测，不重复执行
整套出口网址扫描。Policy 可见性随运行观测更新，是 UI 投影。

原 matchers、access_scope、按服务 services Preference 是待迁移的已存在字节形状；保全原件
不等于继续把它们作为目标写入口。新字段修订及前向迁移验证完成前，停止相关配置写入；不在
同一认证前沿重解释旧 View，不增加协议版本、双读、双写或旧执行 fallback。

当前 Preference 是同一个身份内的规范值：`schema:3,policy_id?:ID,lan_policy_ids?:{ServiceID:PolicyID}`。
省略 policy_id 表示互联网策略待选；LAN 按 Service 独立保存当前选择，不能向该 map 写入互联网
Service 或不属于该 Service 的 Policy。空 LAN map 必须省略，未知字段、非法 ID 和非规范编码拒绝。
它保存在唯一 DeviceIdentity 记录中；不再单独保存 Android 的第二份路由偏好，也不在 runtime
缓存中寻找偏好 fallback。PolicyID 唯一确定 Service；若选择 LAN Policy，其映射仍单独授权，
不会合并其他 Service 的权限。首次接受 LKG 时，互联网可选 Policy 恰好一条才初始化该选择，
LAN 分别在该 Service 恰好一条可选 Policy 时初始化；其他情况保存待选。此后撤权或引用失效
只清空受影响的选择，新增／恢复授权不自动挑选另一 Policy，也不重新初始化已有身份。

运行投影只有一个本机互联网 access selector，默认拒绝，共享传输由稳定授权和资源派生。
选择快照只引用当前 Policy 的本机候选；非固定出口时可附带按网络类型、host/IP＋端口的目标优选，
固定出口不生成该目标覆盖表。接收端仍独立校验同一权限。
目标覆盖使用相同 Policy，未测目标使用该默认，不查询另一个 Service。普通性能优化保留已有
合法连接；主动“重建该服务连接”只作用于本机该服务业务，无需重启 VPN 或共享传输。
用户已明确：手动更换 Policy 后，新连接立即采用新选择；仍获当前授权的旧连接保留原 Policy
和路径，至自然结束或用户明确重建该服务连接。切换不受性能冷却限制，也不自动关闭该服务旧流。
应用未完成时新连接可暂时拒绝，不能继续使用旧选择并声称新选择已应用；这种运行拒绝不撤销
旧连接的授权。真正撤权仍由完整当前权限逐条关闭失权连接。此前“必关旧连接”的实现是迁移
差距，不能再由偏好变化推出授权撤回；显式服务重建继续是独立的用户操作。

连接建立时从已验证 Policy 固定派生所属 ServiceID，作为本机实际连接元数据保存；后续选择
不能改写它。原生 transport 仍只携带和校验原 Policy 上下文，不再传第二份 Service 权威。
私有连接回读的 `metadata.serviceID` 投影这一既有 ID。显式重建按实际 source scope 及该 ID
筛选连接，再沿原逐 UUID 关闭入口执行；不能只按共享 `access` 链标签关闭其他 Service 的
合法旧流，也不能从目标网站或当前选择猜测旧连接归属。此项随按需回收的原生修订接线，
较早仅按 scope 关闭的制品不算已满足该边界。

当前签名报告使用可选 `policy_id:ID` 采样唯一互联网选择，省略时不宣称已选择；独立 LAN
意图使用可选 `lan_policy_ids:{ServiceID:PolicyID}`，空 map 必须省略。两者只采样本机意图，
不授予权限；LAN 项仍须对应当前获授的局域网 Service／Policy。历史 policy_choices/preference
仅按原字节验证，新报告不能携带它们。Selection 可带可选
target（规范 `tcp://host:port` 或 `udp://host:port`）；省略表示默认优选，存在时表示该网络及连接目标
的优选，按 ServiceID、
target 排序且唯一。它们描述新连接选择，存量连接的实际路径须从数据面连接回读，不从偏好推断。
新签发的每条 Selection 必须有非空 PolicyID，并匹配该 Service 的当前互联网选择或独立 LAN
选择；未选择互联网 Policy 不阻止报告已确认的 LAN 结果。没有实际选择时仍可报告 unknown，
不能借无关 LAN 意图签发未绑定 Policy 的选择。

国内/国外样本不产生 traffic_class、地域域名/IP 库或实际请求的地域 Service 归属。Policy 的
固定出口限制只约束最终出口，不能因样本较快改选别的 Policy 或 Direct。探测没有独立 ID、
事实目标、全局池或管理页；已签 probe_target 原件仅保全历史验签及因果关系，删除只用于显式退休。

运行投影中的 Matcher 继续用于接收端目标校验，不构成另一份可编辑 Destinations。精确域名
按原 FQDN 比较，后缀不得匹配相似字符串，IP 按规范前缀比较；TLS SNI 不能替代实际目标扩权。
每段都必须从同一 Service/Policy 派生权限，不以传输嵌套复用另一协议的授权。

局域网 Service 恰为 `id,name,kind="local_network",local_network`；不能带 `matchers`。
`local_network` 是同一 Service 的值，恰含 `gateway_node_id,local_prefix,virtual_prefix,allocation_attempt,enabled`。
网关为非 `direct` 的 NodeID；两个前缀均为规范、已掩码的 IPv4 CIDR，长度相同且至少 /8，
本地前缀须为单播网络，虚拟前缀完整位于 RFC 1918 空间；两者须不相交，或精确相等且位于 `10.0.0.0/8`。
新的分配只产生 10 段地址，首次优先保留源前缀除第一段外的网络位；历史其他 RFC 1918 映射的规范值与签名字节保持原义。
`allocation_attempt` 是 0 至 3 的整数，0 表示首次分配，1 至 3 表示本轮重分配；`enabled` 是显式布尔值。
禁用保留地址与授权引用供审阅，但不产生运行权限。服务种类不能在原 ID 上改变；互联网原件的四个字段
及其签名字节不变。LAN 的地址、启用与尝试数在同一普通事实中原子改变，不增加映射实体或恢复日志。

Policy 字段为 `id,name,service_id,action,entry_scope,relay_scope`；互联网 Policy 还必含
`exit_scope,allow_direct,local_egress_devices`。action 的历史 wire 值为 `allow/deny`，当前新写入只接受 `allow`；Scope 唯一形状为
`{"mode":"any|only|none","node_ids":[]ID}`。any/none 必须为空，only 必须非空，ID 排序去重；
LAN Policy 出现三个互联网字段即拒绝。历史 deny 完整保留原规则，运行投影不给业务权限；撤回引用后删除，禁止改写为 allow。
id/service_id 为 ID、name 为 Text、allow_direct 为布尔值、local_egress_devices 为 ID 集合；
每个节点引用须满足现有位置及职责规则。NodeID 不可为终点保留值 `direct`。
这些资格检查用于新写入；已持久策略的节点后来失效时保留原 ID，相关候选退出，不能把 only 改为 any。
三个互联网字段在类型中以“全部存在”或“全部省略”表达；显式 null、部分存在及与所属 Service 种类
不符均拒绝。已有互联网 Policy 的 false 和空集合仍显式编码，不能因新增 LAN 分支改变旧签名字节。
LAN Policy 不增加另一个网关字段；固定终点只来自 Service。`max_hops` 对两种 Policy 保持原有可选语义。

LAN 首次分配由 Web 选择网关与源网段后自动请求，人工重试复用同一只读分配入口，返回完整 Service 和所审阅的依赖，随后沿原
`service.put` 提交。预览不是预留，不能赋权；提交重新核对网关、最新且与当前 View 匹配的认证前缀报告、排除集合和精确
分配结果，陈旧预览拒绝，操作者重新审阅。其事实的历史验证只依赖规范值及签名的设备依赖，
不依赖可过期的报告或后来变化的地址池。普通 Service 改名、禁用保留原映射；改变映射或明确重新启用
须再次走分配审阅。其他成员不从自己的报告集合重新计算已签虚拟地址。

DeviceAuthorization 字段为 `id,name,platform,device_public_key,responsibilities,policy_ids,distribution_urls,runtime_key,`
`transaction_id,invite_material_id,binding_material_id`。platform 固定为 `android/linux/windows`，
职责是规范排序的 `access/forward/internet_egress` 子集；control 由成员链额外投影，不能被这个数组授予。
普通加入职责非空；上文已有初始 control 的首次设备绑定允许普通职责为空，由已验证成员资格提供 control。
PolicyIDs 可为空，没有 access 则必须为空。同 Service 可有多条可选 Policy；新分配时
未知/冲突/悬空引用和歧义目标组合均拒绝。已分配引用后来失效，原分配仍可回读但不再产生相应权限。
RuntimeKey 是 control 生成的 Secret32，不是设备身份私钥。

DeviceAuthorization 还可保存 `wireguard_public_key:PublicKey`，为本节点现用 WG 身份的规范
无填充 base64url。省略表示未登记 WG 身份，不从资源是否存在、报告或缓存补造；显式空值和
null 拒绝。它与设备签名公钥不同，知道公钥不授予 access、forward 或出口职责。
现有 `device.put` 可显式登记；省略该字段保留当前已认证登记值，普通改名、改权或探测编辑
不能抹掉或替换它。显式登记必须与仍存在的本节点 WG 资源公钥一致，实际执行还须验证本机
私钥。当前新加入沿原 RuntimeKey 派生原有发送键并登记其公钥；使用既有固定键的节点在建立
WG 接收资源前显式登记实际公钥，不写入或移动私钥。该操作不新增管理对象或密钥 store。
历史缺席字段的原件仍按原义验签和往返；现存固定键从已核实的原资源及本机私钥引用取得公钥，
现存派生键按原算法取得公钥，均经新的普通事实前向登记，不能在同一认证前沿补写 View。
读取者先升级；生产登记与部署仍须获得该任务授权。

设备还可带 `dns_servers:[]Resolver`，由同一 `device.put` 公开命令管理，表示该设备已认证的
underlay 与本机最终出网解析器集合。Resolver 是现有字段中的规范字符串值，不是新权威实体：
裸规范单播 IP 保持原 UDP/53、截断后 TCP/53 的含义；`https://IP[:port]/path` 表示 DoH，
IP 必须是规范单播字面地址，IPv6 使用方括号，省略默认 443 端口，其他端口为规范十进制。
路径必须是非空的规范绝对路径；拒绝域名主机、用户信息、查询、fragment、转义别名、点路径与尾部空包装。
集合按完整字符串排序、去重，不混用裸 IP 与 HTTPS；DoH 失败绝不降级到明文或系统解析。
未配置唯一表示为字段省略，显式空数组、null、带 zone 的地址和非规范值均拒绝。
这个扩展保持所有已签 IP、缺席字段与对应历史运行投影的原义和字节；
Invite 可带相同约束的可选 `dns_servers`；首次 device.join 原样继承，省略时保持未配置。
这让具名入口设备在一次正常加入中取得解析器，避免先加入失败再补配置；管理员按设备原有部署输入配置，
不从 `.env`、宿主 resolver 或旧事实自动导入。
公开命令替换完整设备值，省略该字段表示取消配置，重命名或改权的 UI 必须保留操作者未改动的解析器。
`DeviceView.dns_servers` 继续使用既有必填数组：未配置投影为 `[]`，已配置逐项复制。
它只决定解析位置，不改变 Service/Policy 权限或认证 TLS 名称、SPKI；它与 `.loom` 权威记录分开。
正式入口为设备管理表单或 `loom control write`，普通事实持久化、同步、重启重建和冲突处理复用设备目标。
客户端纯渲染只消费认证地址；网络查询在连接 adapter 中执行，结果不可倒写 DeviceView 或身份。

最小测试覆盖设备配置的值/字节往返及未配置历史字节不变、普通管理写入与重启投影、解析失败不借
系统 DNS/hosts 回退、真实域名设备认证及错误 TLS 身份拒绝、Android underlay socket 的 protect 回调。
DNS 修改后新 View 使旧运行与相关观测失效；认证接受必须先持久化，执行失败仍保留新授权。
首次 bootstrap 未持有 View，只用客户端随签名制品交付的默认 DoH 查询短引用中的唯一 Host，
再核对该引用的完整 TLS 身份；该预设不授予网络权限，不进入二维码，也不是 View 缺配置时的 fallback。
字面入口不查询 DNS。已绑定但未取得 View 的 claim/resume 仍使用同一事务与身份，
不得因失败重建身份或换入口。加入后的域名入口只使用当前 View 的解析器；两者复用同一 underlay 拨号适配，
保留平台 socket 保护。地址是瞬时拨号参数，不能改写 EndpointGeneration 的主机名、TLS 名称、SPKI 或签名字节。
普通改权保持原 transaction、Invite、绑定、公钥和平台；这些引用沿事实依赖可验证，不由 UI 重建。
id/transaction_id 为 ID，name 为 Text，公钥为 PublicKey；两个 material_id 为 Digest，policy_ids 为 ID 集合。

distribution_urls 是必填的规范排序、无重复 `[]HTTPS_URL`，仅定位该节点的公开制品分发回读地址；
不授予 Service 访问权限，不含口令、不定位设备专属制品，也不替代发布验签。device.join 初值必须为 `[]`，
管理员通过 device.put 与其他公开设备字段一起审阅和提交；清空只移除这份分发定位，不能撤销其他职责。
同一事实的签名与因果依赖覆盖完整列表，公开投影可显示，DeviceView 无须复制。它不进入凭据 KDF；
仅改地址不能换 RuntimeKey、服务凭据或 PolicyIDs。节点删除、撤权或设备目标冲突后，该节点的地址不再进入
有效发布投影，旧字节仍存证，不能从旧 registry 恢复。原始成员或设备事实、规范持久值和这份列表可逆；
PublisherInput、部署计划与 UI 是单向投影，不新增节点属性 store 或 node.put。

### 资源与用途隔离凭据

修订边界：用户已明确禁止 Hy2 套在 WG 内及 WG 对 Hy2 的执行依赖。
`access_hy2_resource_id`、普通 WG 到 Hy2 的投影和 WG 上逐跳 Hy2 均不是现行执行契约。
已有签名资源、Link 与 LKG 的原字节不得静默重解释；限定历史验签与同一 schema 3 的
前向替换见下文，实际部署结果见[传输实现纠偏](../progress.md#传输实现纠偏)。

TransportResource 字段为 `id,kind,owner_node_id,listener_id,dial_host,dial_port,authentication`，
Hy2 可另外保存 `link_only:true`，表示不开放普通公开首跳；forward 仍可用其建立后续 Hy2 段；false 的唯一编码是省略该字段。
WG 以可选 `access_enabled:true` 明确开放普通首跳；省略表示不开放，规范输入拒绝显式 false。
承载者可为 forward 或 internet_egress，后者可直接作为最终出口。已签历史字段
`access_hy2_resource_id` 仅在历史验签中识别，现行写入和运行 View 一律拒绝。
listener_id 是稳定本机资源身份，不是私钥文件路径。dial_host 是规范 IP 或上述规范 DNS 名，
dial_port 是 Port。kind 仅 `wireguard/hysteria2/tls_tunnel`，authentication 按种类精确匹配：

- wireguard：`public_key` 为 32 字节 WG 公钥的无填充 base64url，`local_addresses:[]InterfaceAddress` 是资源自身地址；
  不放逐设备 peer 或参与者表。地址的主机位有意义，按 IP 字节和 prefix length 排序，不能当目标 Prefix 清零主机位。
- hysteria2：恰好为 `server_name,ca_certificates`。server_name 为规范 DNS/IP 校验名；ca_certificates
  为非空、无重复、按编码字节排序的 CA 证书 DER 无填充 base64url 集合，每张必须有有效 CA 约束及
  certSign 用途。没有 PEM 空白或主机系统根的隐式补集。客户端验证该集合、名称、serverAuth 与有效期；
  保持 TLS 验证和 SNI，不以拨号 IP、无公网域名或 Gandi token 缺席关闭验证。不另加叶 SPKI 固定。
  这是现有公开 CA 与校验名方案的唯一规范字段；此前非空 Hy2 值未有合法现行解码路径，不改写旧材料。
- tls_tunnel：`spki_sha256,alpn`，可选 `server_name`；SPKI 固定值与专用 ALPN 必须匹配，
  有 server_name 时还须匹配该名称。内部请求继续验证成员/设备身份，TLS 成功不产生业务授权。

#### 普通 WG 首跳的私有执行投影

##### 分段传输的替代执行模型

当前目标由用户确定：access 选入口，forward 在相同 Policy/最终出口约束内继续选路。
下文现存完整 Candidate 绑定、逐路径地址和凭据计算是需要前向替换的具体执行形状；其原始
字节必须保全，但不能因已部署就要求保留源端指定完整路径。新接收端一致校验与规范 wire
尚须完成，不能继续按旧形状签发新执行配置，也不通过嵌套传输或新增协议版本绕过。

WG 公钥的规范检查与授权检查分开：相同规范公钥是否能执行 X25519 是不随设备、策略、
时间或网络变化的数学属性。重复渲染、身份回读和报告序列预留会反复验证同一公钥，
不能让这些重复运算耗尽私有报告的请求时限。执行器可在内存中复用至多 256 个精确规范
公钥的成功数学检查；满额即丢弃并重算，不保存拒绝结果，不持久化，也不新增输入。
domain、wire、persistent、runtime 配置与 UI 表达均不变；缓存只属于可删除的计算投影。
缓存命中仍不能代替资源归属、签名、权限、来源地址、认证 floor 或严格规范解码。
反例是同一合法公钥被放入未授权资源或非规范编码：前者仍须按当前授权拒绝，后者不得
借用缓存命中。最小验证覆盖这些拒绝、并发读取、淘汰后的等价重算，以及运行配置字节不变。

Linux 同时承担 access 与服务端职责并使用隔离 TUN 时，已有两个进程不能分别持有同一发送端 WG 会话，否则会发生 peer endpoint 漫游竞争。最小变化是只让服务端进程持有实际传输；隔离 capture 通过固定回环、临时密码保护的 SOCKS 入口提交原始目标和独立的互联网／LAN selector 范围。实际传输所在进程从当前选择绑定 Policy、入口及出口，并按 Service 边界校验后发送下一段，拒绝其他用户、目标与入口流量。此本机连接不进入 WG，也不新增远端代理层、持久身份或第二份授权；增加的运行成本仅为本机一次转发及两个可删除 DNS 缓存。Mixed 与纯 access 仍只需一个进程。

本段定义唯一现行执行；旧耦合字段仅在下文的历史字节识别边界内验证，不能生成新的接入。
正常业务是 access 选择同一 Service 的 RouteCandidate，经首跳到入口，再逐段经 Link 到最终
出口。每段独立终止 WG 或 Hy2，forward 可选择后续独立 WG 或 Hy2 段。原始域名／IP 与端口随执行请求传递，最终出口解析公网域名；WG 接收器将解密后的
TCP/UDP 交给公共路由器，权限来自同一 Service/Policy，不从传输类型推测。

共享 WG 接收器的不同 peer 可以并发交付报文。每次调用交给宿主 TUN 的筛选批次必须独立拥有
其切片描述符，直到该次写入返回；TUN 的批次合并会原地延长、交换这些描述符。不能用接收器上
共用的临时数组承载各 peer 的批次，否则另一调用可能在合并中覆盖长度并造成崩溃或串包。
最小修正为调用内的临时宿主批次，仅有宿主报文时分配，不新增锁、持久值或配置；额外成本是
该次报文数对应的切片描述符。domain、签名 wire、身份、固定键、管理路由和 UI 均不变。
验证须让两个 peer 的不同长度批次同时处于交付中，确认互不覆盖，再验证显式隔离的共享 WG 收包能力与业务连接；这项底层能力不触发普通业务资源的宿主管理投影。

本次修订的规范值明确如下，仍使用 schema 3：WG 资源以 `access_enabled:true` 显式开放
普通接入，false 只编码为省略。没有该字段的旧资源仍不自动开放普通接入；
`access_hy2_resource_id` 只在已签历史材料中识别，当前写入及 DeviceView 拒绝。
新派生 Link 的 `probe_target` 引用接收资源。WG action 为 `wireguard_echo`，host 为该资源
确定性执行地址、port 为 53；Hy2 action 为 `hysteria2_echo`，host/port 为该资源认证的拨号坐标。该地址与端口承载 WG 内部的原生执行帧，不提供普通 DNS fallback。
回显只证明该段传输；access 准入回显另检查本段实际认证来源的当前 Policy 入口资格。
旧 `wireguard_dns`、`hysteria2_tls` 原件仅按历史原义验签，不进入当前测量身份。

DeviceView 显式绑定 network_id。传输凭据的唯一交付行是
`{resource_id,sender_id,credential}`；只交付本机发送或本机接收所需的 Hy2 行。
WG 从同一节点公开身份和资源派生 peer 与精确来源地址，不签发逐 Policy 或逐出口的 peer 表。
相关节点的职责、PolicyIDs 和公开身份只投影原授权；来源解析参数仅用于当前测量规格匹配。
`access_grants`、`policy_exits`、`wireguard_peers` 都是可删除的本机计算结果，不能进入签名 View。

Hy2 用原 32 字节 RuntimeKey 和 HKDF-SHA256，salt 为 `loom-runtime-key-v3\0`；规范 info 为
`{network_id,sender_id,resource_id,resource_auth_digest,receiver_node_id,purpose:"transport-auth"}`，
输出 32 字节、无填充 base64url。不得把 Policy、Service、入口／中继用途、网址或完整路径放回凭据。
普通业务和准入回显在原生请求中显式传 PolicyID；仅传输回显不携带 Policy。

一个节点使用一个共享 WG 实例。精确 /128 来源复用原基础地址算法：
`SHA256("loom-wg-access-address-v3\0" || C({resource_id,receiver_node_id,receiver_public_key,peer_public_key}))`
取前 16 字节并将首字节置 fd。它标识实际发送节点，不授予 Policy 或业务目标权限；每条连接
仍须校验显式上下文。peer 公钥与 AllowedIPs 共同认证来源，跨 peer 地址冲突必须拒绝。
原设备身份、RuntimeKey、固定密钥和认证进度必须保留。WG 公钥由上述节点授权登记，资源公钥
必须与 owner 的登记值相等；删除接收资源不删除发送身份。DeviceView 自身的可选
`wireguard_public_key` 与相关 ViewNode 的同名字段都只复制该登记值。自身派生私钥仅在其公钥
确实等于登记值且执行需要时交付；否则由 Linux 消费原受保护私钥文件，不能改用另一把派生键。
一个进程内的共享 WG endpoint 固定为 `wg-shared`，不随接收资源增删改名。固定私钥的加载
与接收 listener 分开；缺失、错误私钥或资源／owner 公钥不一致均拒绝。没有登记值的节点
不具备 WG 发送资格，但不因此撤销独立 Hy2 或 Direct 权限。

接收端 /64 合成池仍绑定 `{network_id,resource_id,receiver_public_key}`，采用
`loom-wg-target-prefix-v3\0`；池用于 UDP 目标注册。TCP 在 WG 自身可靠流的执行前缀后直接
传递上下文及原目标，接收后转发该流，不先做一次 DNS 注册往返。UDP 通过同一 WG 会话的可靠
执行流注册原目标和上下文，再发送到返回的池地址；缓存使用时重新校验当前来源与权限。
名称不从 SNI 或共享 IP 的历史答案猜测，中间节点不解析业务公网名称，最终出口才解析并检查
实际公网地址。WG 没有 Hy2 依赖，Hy2 使用自身请求与可靠会话注册，不套入 WG。

新增设备及撤权更新原生接收投影、WG 准入 peers 或 Hy2 用户，保持监听器、固定密钥和未变化
会话。授权替换与新连接登记共用短时 fence；发布新权限后只关闭最新权限已拒绝的存量连接。
传输更新失败不得重新装回旧权限。性能推荐只改变新连接选择，既有连接保持固定路径。
本机 API 的不可预测 CAS revision 与投影摘要仅属于可删除运行实例，不形成认证进度或持久权威。

Policy 的可选正整数 `max_hops` 限制受管节点数量；省略无额外限制，始终拒绝重复节点。
公开首跳和本机 hybrid Link 起点使用同一候选模型。每一跳检查当前 Service 目标边界，
forward 在同一 Policy 和最终出口约束内选择下一跳；只有获准 internet_egress 才执行最终互联网出站。
原完整 Candidate 指定下一跳的形状退出目标，相关历史字段按下文说明保全。

###### Linux WG 的宿主接口名

现行普通 WG 接入与中继只在共享用户态 endpoint 内执行。`TransportResource`、自动派生的
relay Link、节点职责和本机监听输入均不隐式创建宿主 WG 接口、地址、返回路由或任意宿主
管理权限。新增远端资源只改变完整权限、发送资源描述及 forward 遍历图，由本机资源池消费；
不输出 `system/name/host_sources/stack_address`，也不由业务边生成宿主接口名。

正式 bootstrap、配置、报告与 `control.loom` 使用认证 Endpoint、认证 DNS 和精确的
website underlay；既有 underlay SSH、WG、LAN、DNS 与代理不因业务资源增减被改写。
某个 Endpoint 的显式地址恰与资源地址相同，也不能推导出额外宿主权限或自动创建一条路径。
这保留其真实可达性要求，不能用 Direct、系统 DNS 或扩大 Policy 掩盖缺失路径。

先前执行器曾从网络与资源 ID 派生宿主接口名，创建临时 TUN、改名并添加精确返回路由。
这属于历史执行；相关事故与已记录的原件保留原义，不是现行业务资源的运行前提。
旧 generation 的精确所有权记录只供原对象的 compare-and-delete 清理，不能从原资源或公钥
重新猜测所有权、恢复旧执行或接管未知对象。清理失败保持 failed/inactive，不清空身份、
认证进度或发布 floor，也不修改既有 underlay 管理配置。

| 层 | 对应关系 |
|---|---|
| domain / wire / persistent | 原 `TransportResource.id/listener_id`、身份、密钥、原签名与唯一 LKG 保持；不新增管理邻接对象 |
| runtime | 接收 listener 使用显式本机端口；发送 principal 与 pool 保持原算法；业务资源不生成宿主接口与路由 |
| 历史所有权记录 | 只定位原 generation 明确拥有且仍可严格核对的旧对象，用于精确清理；不授予新执行权限 |
| UI / report | 按原资源、节点及 `listener_id` 显示和回读真实 listener，不从历史接口名推断 peer、授权或健康 |

最小验证覆盖本机端口与公网拨号端口独立、两族对端地址、原密钥引用不变、新增资源不产生
宿主接口或路由，以及正常配置更新后同实例与合法旧业务连接保持。显式隔离的底层接口能力
与严格所有权测试继续成立，但不能据此要求普通业务图触发宿主管理接口。

撤权先接受并持久化新授权，再移除相应来源地址、用户及目标规则，并关闭旧业务连接；其他
服务的共享 WG 身份不因此换钥。最后一项发送权限消失时移除 peer。应用失败保持新授权并
停止不符合它的执行，不恢复旧权限。重启从唯一 LKG 重建权限；缓存只恢复名称，不能复权。
已经签名的旧 View/Link 不按这份新语义重解释，生产迁移另须验证新事实前沿、新 View 接受、
原身份与 floor 保全和旧运行退出；当前基础实验不抵扣这项迁移。

最小反例与业务验证：同一设备同一目标的不同出口必须可区分；另一设备或另一 peer 冒用
来源地址必须拒绝；同一共享 IP 的不允许名称及任意 IP 携带允许 SNI 均不得扩权；一个服务
撤销后另一服务仍能建立新连接。正式链须覆盖 Hy2/WG 两种首跳、WG 中继、TCP/UDP 返回、
域名与两族 IP、指定出口、同出口直达/中继、撤权及重启，并回读原候选身份和报告。

##### 前向替换的认证材料冲突

操作者已在本轮明确确认以下限定历史验证与前向替换。确认不等于迁移已实现或生产验收通过；
实际执行仍须遵守原身份、认证进度、精确所有权和宿主管理连接保全边界。

现存 schema 3 `link.put` 原件把 `probe_target` 绑定到 Hy2；控制事实按原签名和因果依赖
持久化并在重启时重新验证。设备 LKG 同时包含这些 Link、接收凭据和嵌套运行配置。
`Material` 解码会验证原 payload；`DeviceView` 验证会按当前渲染器重建候选与运行配置并比较。
直接删除旧字段或改变含义，会使既有签名材料无法按原义验证；保留原签名而改正文会验签失败。
清空 LKG 也不是前向迁移：设备状态明确拒绝“已有 high_water / report_sequence 却无 LKG”，
清空这两个值则违反不可回退边界。

已确认的最小处理范围：

1. 当前 schema 3 的已签原事实继续保留原字节，只为历史验签、原身份与因果依赖验证读取；
   它们不能生成新业务配置。现行写入与运行只有分段传输这一种语义，不保留旧 transport fallback。
   这是对“旧格式材料不进入解码、重放或迁移运行路径”的限定澄清，不能由实现自行扩大。
2. 通过现有 `resource.put` 和历史人工 Link 的 `link.delete` 等正式写入产生新事实前沿，保留设备、资源的
   稳定身份及密钥；当前中继 LinkID 从有效资源自动派生。新 View 交付稳定节点授权与传输身份，候选及 ACL 仅在本机派生；新的 `DeviceView` 由同一有效 control 签发；
   不改 genesis、不另建网络、不增加全局 checkpoint、协议号或第二份事实权威。
3. 设备进行显式、一次性的 LKG 前向替换：先校验原认证进度及新 envelope 的身份绑定、成员
   证明与前沿，再原子保存新状态。私钥、公钥、Invite、latch、报告序列和 high_water 均保留
   或单调前进。旧 LKG 原字节只进受保护证据；失败不能删除身份、降 floor 或运行旧嵌套配置。
   本次自动邻接纠正还包含已经运行的共享原生 WG 配置：历史识别必须正向同时核对规范的单个
   `resource:<ResourceID>`（普通 access 为 `wg-shared`）共享 endpoint、受保护资源对应、公钥、
   精确私有地址与资源绑定的 fd DNS /64，以及原人工非摘要 LinkID 的两端资源与 DNS 探测形状。
   原配置和原签名仍为 opaque 证据，不以新渲染器重新生成或执行它；新目标必须通过当前稳定授权、独立传输与本机运行投影校验。已经自动派生的当前 LKG 不属于历史识别范围，不能重复调用迁移
   形成第二普通 writer。同前沿、降低已见任一键的进度、变更固定身份或原件篡改继续拒绝。
4. 切换验证须覆盖 control / device 重启、旧消息重放拒绝、撤权不复活、管理通道与实际业务。
   成功后删除旧生成器、RelayTarget 的 Hy2 端口授权、AccessHY2ResourceID 耦合、探测执行器
   和相应旧运行入口。历史签名材料的验证不调用这些执行代码。

不得改现网认证原字节、清空 LKG，或先部署会使现有状态无法加载的控制/设备程序。
显式 `loom client migrate-transport` 实现历史验证、原件保全及 LKG 原子替换，启动和普通同步不调用历史 reader。
生产切换结果须独立读回，源码及隔离测试不作为生产回执。

共享 WG 修订同样走这个显式入口：旧独立发送实例的签名配置仅作原件验证，不能用新渲染器
假装它本来就是共享实例。原接收 DNS 缓存的地址池与新资源 /64 不同；停旧执行后先保全旧缓存
精确字节，再生成新的派生缓存，不能让旧地址在新池内解释为另一个目标。旧缓存不进入当前
运行，已建立会话在切换时终止，调用方重新解析和连接；身份、RuntimeKey、固定节点键与 floor
不受影响。迁移失败不回退到旧运行，也不删除原件。

具体交付使用原控制机的 owner-only 管理 socket：
`loom control export-device-view -device demo-device -out /var/lib/loom/demo-view.json`。
文件是已签名的私有执行投影，包含该设备的运行凭据；只交付给对应设备，不进入公开制品目录。
停止该设备旧运行后，Linux 使用
`loom client migrate-transport -state /var/lib/loom/demo-state.json -view /var/lib/loom/demo-view.json -evidence /var/lib/loom/demo-original.json`。
Windows 对应制品使用 `migrate-transport -state … -view … -evidence …`，保留原 DPAPI 保护范围。
Android 从既有配置页文件导入入口选择同一签名文件，在运行互斥下保全原 Keystore 密文并替换该配置。
各端先验证新签名、原身份与认证进度，再保存原始文件的精确字节，最后原子替换唯一状态；
证据保存或验证失败时不写新状态。重启只能消费当前配置；重新导入旧 View 不能降低认证进度。

##### 已否决实现的字节识别

历史材料仅保留原 `access_hy2_resource_id`、Link 的 `hysteria2_tls` 探测描述与完整原签名。
旧 View 中的 `link_probe_credentials` 和嵌套运行配置只作为原签名字节验证，不解码成可执行配置。
当前生成器、接收权限和探测执行器没有这些入口；不得恢复 Hy2 detour 或旧凭据作为 fallback。


现存 Hy2 首跳 `service-auth` 的完整路径绑定如下，仅用于界定旧字节及前向替换：RFC 5869 HKDF-SHA256 的 IKM 为原始 32 字节 RuntimeKey，
salt 为 `loom-runtime-key-v3\0`，info 恰为 C 编码的
`{network_id,device_id,service_id,policy_id,resource_id,resource_auth_digest,receiver_node_id,purpose,candidate_id,sender_id}`，
其中 sender_id 等于来源 device_id，输出 32 字节后无填充 base64url。candidate_id 固定完整授权路径；
resource_auth_digest 仅绑定资源 authentication，显示名称及无关 Service 不导致凭据轮换。
撤权、deny、收窄范围或路径后，新 View 不再投影原权限；先保存认证进度，再替换执行，失败不能恢复已撤销权限。
不存在 `relay-auth`、`relay_target` 或 `link-probe-auth` 的当前执行用途。

无自有 WG 资源的普通设备使用上述 HKDF/salt，IKM 取本设备 RuntimeKey，info 为
`{network_id,device_id,purpose}`，purpose 固定 `wireguard-access`。输出按 X25519 clamp，
私钥只交付本设备，全部接收资源使用同一公钥。拥有 WG 资源的节点直接使用该资源固定密钥，
不得再派生逐接收端密钥。RuntimeKey、设备身份键及固定节点键不变；旧派生传输凭据的替换属于
明确的 LKG 前向迁移，不是原签名字节的静默重解释。Service/Candidate 只投影精确源地址与权限。
`wireguard_peers` 按 resource_id、device_id 排序；来源设备、转发节点和原生回显使用同一共享传输。
基础源地址只允许原生传输回显；每项业务源地址由本节已定义的绑定导出，每跳都按原始目标执行权限。

ACL 摘要使用 `loom-inbound-acl-v3\0`，绑定本资源的规范接收权限、WG peers、相关 Policy、
Service 目标边界、来源授权与最终出口资格；探测网址在未限制访问时不参与摘要。无需独立
探测口令或另一个授权 store。
新 View 必须保持身份、成员证明、latch 和 floor，且认证事实前沿实际前移；同一前沿不同 View 仍拒绝。
未知现存宿主对象不因它曾出现在 View 中而取得所有权，清理失败保持 failed/inactive。

#### 稳定 View 与本机运行派生

用户已确认本轮采用以下唯一 schema 3 契约。删除旧执行字段不改变已签原件；历史仅由显式前向
替换验证器读取，普通解码、加入、同步及重启均只接受本节形状。没有第二份 View、授权 store 或版本。

| 层 | 唯一值与转换 |
|---|---|
| domain | 现有设备及四种职责、设备的 PolicyIDs、Service、Policy、资源和入口；其他节点的职责及授权只作这些事实的最小投影，不新增节点种类、管理实体或登记流程 |
| signed wire / persistent | DeviceView 保存自身身份、职责、可选 Policy、相关节点的职责／PolicyIDs／公开 WG 身份、Service、Policy、资源、必要 Hy2 凭据及自身派生 WG 私钥、DNS／入口／发布引用。删除 routes、runtime_profile、inbound_credentials、wireguard_peers、access_grants、policy_exits、links、business_probe_targets 的预展开交付 |
| runtime | 从同一 LKG 和身份内 Preference，派生当前互联网 Policy 与独立 LAN 选择的候选、图和 selector；转发／出口按自身职责派生相关权限。资源 transport 按资源复用，不能再创建 Policy×入口×出口的 outbound 或凭据。候选、运行 JSON、测量与推荐均可删除重建 |
| UI / report | 保留策略选择和现有交互；授权来自 LKG，当前偏好来自身份，实际选择来自原生回读，路径链区分估计与实际观测。报告只采样，不设置或重签 Policy |

相关节点投影是 DeviceAuthorization／成员事实的只读子集，无独立 ID、写入、生命周期或持久库。
删除它会使消费端无法校验其他位置的职责、来源授权和最终出口资格，因此不能只按资源名称猜资格。
接收与发送凭据只认证实际发送节点和资源：WG 使用原固定／原设备派生身份及资源内精确来源；
Hy2 使用同一 RuntimeKey 派生的节点／资源凭据，不绑定 Service、Policy、原始来源或完整路径。
有凭据不等于有业务权限。Policy／来源撤权更新授权投影并关闭相关连接，不靠轮换全网传输身份。

每条原生请求显式携带 PolicyID、原始来源、最终出口和已走节点。Service 由 Policy 唯一推导。
接收端先认证实际发送者，再查当前 Policy 与原始来源授权，核对本资源接入开关、实际前驱、入口／
中继范围、最终职责、受管跳数、无重复节点和目标边界；只有全部满足才转发。传入的上下文不能
自带权限。起点访问要求原始来源等于认证发送者；中继要求已走链尾等于发送者且该段具有合格
转发关系。受管 forward 负责保全原始上下文，不声称逐段终止后仍有端到端的来源传输认证。
WG 与 Hy2 各自承载同一语义，无嵌套及旧请求 fallback。

##### 逐跳上下文的信任边界

当前采用可信中继模型：获授 forward 职责的节点是可信执行参与者，负责保全连接的 Policy、
OriginID、FinalExitID 和 Visited。传输认证只证明直接发送者；PathContext 没有完整历史的端到端
签名，不保证抵抗恶意授权中继修改仍符合当前授权的来源、Policy、出口或路径历史。
这不增加签名字段、密钥、持久对象或协议版本，仍为 schema 3。

| 场景 | 当前保证与边界 |
|---|---|
| access 首跳冒充另一来源 | 空历史时 OriginID 必须等于传输认证发送者，即使另一来源也获授同一 Policy 仍拒绝冒充 |
| forward 改来源、Policy 或最终出口 | 正常 PrepareContext 拒绝改写原连接绑定；每个接收端仍核验当前授权。恶意 forward 换成另一组仍合法的值不具备端到端防伪保证 |
| 删除历史节点 | 缺失或不匹配的实际前驱拒绝；保留实际前驱且删减后仍合法的早期历史无法证明是否被删 |
| 增加伪造历史 | 重复节点、未知节点、缺少有向边、越范围或超跳数拒绝；形状合法不证明该节点真实参与过 |
| 重复旧上下文 | 每次按当前授权重新校验；当前授权仍成立时可建立另一连接，Nonce 只关联响应，不承诺逻辑请求防重放 |
| 撤权后恢复旧连接 | Restore 和连接登记按当前快照重验；权限更新的 receiver fence 清理已失权连接，不能以原上下文恢复权限 |
| WG／Hy2 与声明身份不一致 | 两者独立认证实际发送者，消费同一接收校验及恢复语义；声明的链尾必须等于实际发送者 |

负面测试与真实回环加密传输测试分别证明协议拒绝规则、正常上下文保全及两种接收入口行为，
不代替真机、多中继或生产验收；本轮验证范围见[定向审查记录](../progress.md#当前版本定向审查与修复)。

运行选择包含当前 Policy、默认入口／出口及按目标的覆盖；固定出口不建立目标专属入口优选。
资源 transport 独立于选择复用；每连接建立时固定上下文和 transport。原生 CAS 更新推荐仅影响
新连接，旧连接保留；撤权及用户操作按受影响的 Policy／Service 处理，不能断开整个 VPN 替代。

forward 候选的 FirstResourceID 必须保持到首段 LinkSampleRef 的对应：按同一 Policy、来源与
实际接收资源定位有向 Link，不能仅按下一跳节点合并 WG／Hy2。后续路径继续引用实际 LinkID；
观测仍按来源、资源、LinkID、SpecDigest、目标与动作匹配。同一节点的不同资源独立比较，
这些引用仅是可删除运行投影，不改签名授权、持久身份、最终出口或 UI 的确认语义。

常驻数据面的更新边界见[常驻数据面与增量应用](../clients/client-runtime-model.md#常驻数据面与增量应用)。
本地认证运行 API 可增量更新 WG peer 坐标、keepalive、AllowedIPs 与接收准入，不替换 WG 设备，
不重写未变化的 endpoint，不更改既有 underlay 管理所有权。纯发送 WG endpoint 同样消费 peer 差量，
不要求伪造接收权限或增加监听资源。此 API 是已接受配置的单向运行投影，没有新的签名对象、
持久状态或协议版本；CAS 与完整应用回读仍为必要条件，失败不恢复旧授权。

本机 `PolicyIDs` 只授予本机 access 消费，不是节点 forward 职责的前提。撤掉本机未选中的
Policy，不删除仍为其他来源执行的共享 Policy、转发或出口设施。access selector 的成员引用表
由同一 access 投影中的 entries、egress_outbounds、forward_outbounds 和 reject 确定性派生，
引用表本身不授予权限；增减引用而实际组件未变时沿现有权限 CAS 更新。每次使用仍检查当前
Policy、目标、入口和最终出口，再取既有组件；撤权只关闭受影响连接。Mixed 的 capture 校验
与原生 forward 入口分别核对，不能要求所有 forward Policy 同时授予本机 access。

### 发送资源的按需增量应用

节点已认证的当前 View、传输资格、凭据交付集合及认证前沿保持原义；本节只修订它们的本机运行消费。
不得为预备未来入口扩大签名材料池，也不在同一认证前沿重签不同 View。按需资源池是同一数据面实例
内已创建对象及当前请求工作集的可删除投影，不是新管理对象、权限 store、注册表或发布权威。

先耐久接受完整新权限，再沿既有 source／receiver API 提交并回读；当前合法资源尚未物化不能阻止
撤销旧权限。完整权限无法确认时仍须执行安全收口，不能当作普通资源未齐继续旧权限。已确认新权限
而本机资源准备失败时保留合法旧连接，返回既有 `unknown`，清除完整应用／资源证明，并沿原配置跟随
及检查重试；不得因此关闭整个 VPN、恢复旧权限或用空字符串／布尔值混淆这两类失败。

接收端在登记连接所用的同一短 fence 内接受权限并立即清理失权连接，随后才在锁外进行物理
配置。接收回读的 `config_hash` 证明本次操作所包含的投影：WG 仅提交 `execution` 时可立即
确认纯权限摘要，不能因较早的物理操作未完成而把已确认权限改成未知；它也不证明 peer、
监听或发送工作集已就绪。包含物理更新的操作忙时返回现有本机未完成结果，不排队积累任务，
沿原入口重试。旧物理回调无论成功或失败均不得覆盖较新的权限、修订或确认摘要；完整资源
与实际选择继续分别回读，不从纯权限摘要推导业务成功。

| 层 | 对应值与边界 |
|---|---|
| domain／signed wire | 原职责、资源、Service、Policy、身份与凭据行不变；每条连接仍由 source 和各 receiver 校验当前完整路径及目标 |
| persistent | 原唯一身份／LKG、密钥、原始签名、high_water／floor、latch、报告序列不改；不保存另一份池期望或权限 |
| runtime | 既有 manager 管理实际 sender 对象；新增、精确撤下及合法旧流租用由本实例处理；资源未申请不是配置失败，已申请组件未创建／未确认才是本次请求未完成 |
| UI／report | 分别消费权限已确认与资源工作集已确认；部分应用用既有 unknown，不从 active profile 的新 ViewDigest 自动制造 applied_view_digest 或 running 资源证明；页面与选择交互不增加对象 |

本机资源操作只走既有 Bearer 认证的回环 HTTP 服务。`GET /loom/resources` 回读本实例的执行修订、
当前请求摘要及已完成摘要；`PUT /loom/resources` 使用下列唯一字段，不交付或接受签名权限：

| 请求字段 | 含义 |
|---|---|
| `expected_revision` | GET 得到的本实例池执行 CAS 修订；不等于 View、认证 high_water 或网络代 |
| `authorization_revisions` | 此请求依赖的现 source／receiver scope 到已回读权限 revision 的映射；发布前逐项重核，权限提交本身即使旧准备失效 |
| `outbounds` | 当前合法运行投影中可构造 sender 的完整 typed 描述，复用原生 outbound 值；出现只安装说明，不触发构建，不扩大 View 材料范围，也不是候选扫描命令 |
| `forwarding` | 必填的当前 selector tag 到既有 `ExecutionHopOptions` 的完整派生遍历描述；无 forward 时显式空表。由现 manager 创建、更新或退休容器，不是另一份权限；图中引用资源不要求提前全部物化 |
| `wireguard`（可选） | `tag`、`source_routes`、`peers` 的当前可构造发送说明；来源仍为原 `{source,destination,execution}`。`initializer` 只提供首次需要共享 WG 时的构造定义，重复相同定义不重初始化；身份差异仍拒绝，已有接收监听及宿主管理几何不能由此改写 |

回读至少含 `revision,authorization_revisions,desired_config_hash,config_hash`；摘要按本次规范请求
（排除 CAS 前置）计算。`config_hash` 只证明本次构造说明、遍历图及权限前置已完整应用，其他
情况为空；不以尚未创建的备选制造 pending，也不据描述应用宣称实际 sender 或业务已可用。
实际选择仍须完成 selector 的原子引用交接和完整回读，报告的完整运行证明同时需要它们。
GET 必须足以识别 PUT 回应丢失和同 View 重试；同一请求重试不重复换权限 revision。
池执行 CAS 及当前期望摘要只属于实例内执行，不能持久化或倒写认证前沿。

GET 另回读 `described_outbounds` 的构造摘要、实际 `outbounds`／`forwarding` 摘要和共享 WG
设施是否存在，不再保留累计历史需求的 `requested_outbounds`。forwarding 摘要
只绑定遍历描述，不含持续变化的性能排序；响应总摘要不能抵扣逐项实际摘要。遍历图与排序在
一个不可变快照中发布，图改变产生新 selector revision，使旧优化 CAS 失效；发布保留最新仍合法
的性能顺序，再追加新候选，不从构造时的初值覆盖刚完成的优化。已建立连接继续使用固定后继和
实际身份，由完整当前接收权限重核，不能借新图或新优选重标记既有连接。

没有新需求的同 View 重试只修复当前仍需要的有限工作集；显式探索 C 不把尚未创建成功的 B
变成其他入口的前置条件，也不因 A 曾经物化就永久保留 A。B 的授权、原样本截止和公平复测保留；
本机构造失败不冒充实测全网失败。forward 容器的纯退休同样不关闭合法 leaf 连接，真正撤销 Policy
或后继资格仍由当前 source／receiver 精确收口，不增加容器管理对象。

用户已确定闲置发送传输按需回收。实际保留依据仅为当前 source 选择所需的默认／目标路径、
合法旧连接和正在执行的拨号、测量或转发任务；同一对象的需求合并，最后一个需求退出后精确
释放。候选、观测缓存、已认证资源材料及 forward 的完整遍历图均不构成保温需求。闲置备选
再次使用时重新建连，接受由此产生的首次建连成本；不增加闲置等待时钟、保温模式或管理页。
WG 接收身份、ACL 及接收所需 peer 与发送需求分开：保留接收资格不要求持续发送保活；不能
仅因节点合格或图中存在边就保活所有 peer。Hy2 闲置发送会话同样随实际需求释放；回收不得
关闭仍被合法业务或在途任务持有的共享会话。已确认选择仍须有实际可用对象，释放与并发申请
沿原实例／对象身份校验，迟到释放不能删除新对象。此处是当前目标，旧工作集累积及静态保活
仍须修改和实测，不能把已有增量创建验收扩大为闲置回收已经完成。

用户已选定完全回收闲置纯发送 WG peer：当前选择、合法旧流及在途任务的最后引用退出后，
若该 peer 也不属于当前接收准入或宿主管理所需集合，删除其实际协议对象，停止并等待自有
协程退出，释放队列与会话状态；不能只把保活设为零后保留闲置执行对象。仍保留当前合法
构造说明、原身份及密钥，下一次需要时按当前授权重新构造和握手。接收准入所需 peer 继续
存在，独立于发送闲置决定；不增加按需接收机制、闲置时钟或保温模式。

逻辑撤下与并发申请必须按具体对象及当前引用判定；物理停止在资源发布锁和权限 fence 外
完成。同公钥的新对象不能被旧清理删除，新引用也不能被旧保活更新覆盖。失败只清理本次
未发布对象，并按最新合法说明与仍有效引用收敛；不能恢复旧授权或用旧快照覆盖较新的坐标。
这些均为现实例内的运行派生，不新增签名字段、持久状态、管理对象或用户操作。

资源准备在权限 fence 和 manager 全局锁外进行；请求可取消并在返回前 join 所有自有 I/O。
发布只在短临界区再次核对当前期望、实例及权限 revision，迟到对象不得复活已撤资源。失败只能
关闭本次未发布对象，不能关闭原同 tag 对象或覆盖后来的对象；同 tag 规格改变须按实际引用与
撤权处理，不能直接调用关闭旧对象的通用 Create 代替增量。

工作集缺项与撤权分开：仅不再请求某资源时，仍被当前选择或合法旧连接租用的对象、WG peer 和
来源绑定保留到不再使用；真正撤权先收紧权限并关闭精确受影响连接，再回收。租用包含待拨号阶段、
TCP 及 UDP，旧对象迟到释放不能删除后来的同 tag 对象。新选择只引用已物化资源，缺项拒绝或未知，
不回退 Direct、系统 DNS 或更宽 Policy。

source 完整选择 CAS 仅从默认路径及 Targets 实际引用取得需要的现有 Lease，不因完整 Choices
保温资源。在锁外按当前说明冷准备并持有新引用，再于短临界区重核原选择、权限、描述修订和
实际身份，一次发布选择并接管引用；发布后释放旧选择引用，失败只释放本次准备。旧业务继续
自己的 Lease，同值 CAS 仍推进 revision。构造说明只保存在既有池内，可由当前运行投影重建。

测量及后台 TCP 校准在原生正式入口同次冷准备和借用，引用贯穿准备、拨号及任务结束；取消
并 join 后才释放，不经一次独立准备请求永久增加工作集。共享测量由真正执行的 flight 持有
引用，单个等待者取消不影响其他等待者。forward 图及完整 exit_choices 不预建发送对象；新流
按原 Policy、出口及 visited 约束排序，冷准备后固定下一跳。构造失败可试下一合格项，不为
回收增加已固定连接或已交付数据后的透明重拨。实际连接继续持有它已取得的 Lease。

WG 实际发送绑定与所需保活从所有有效引用合并，接收 base 继续保留公钥、PSK、接收 ACL
及协议已学坐标，单凭静态资格生成的 persistent keepalive 为零；新增与释放沿原同快照 CAS
增量执行，不重建共享设备。Hy2 最后一个实际引用释放时关闭闲置发送 QUIC，会话再用时从
当前说明重建。上述本机执行字段只维护这一份当前语义，原实现及旧制品仅作证据保全，不能
增加旧运行 fallback，也不能以描述摘要代替实际选择、监听或业务回读。

WG 旧流租用保留精确来源／AllowedIPs 绑定，不保留一份能覆盖当前值的历史拨号坐标。同一公钥
仅改公开地址或端口时，当前请求规格优先；该资源随后退出工作集但旧流仍在时，取原生实际快照
中的当前 peer 规格补足绑定，不从 entry 首次创建值恢复旧地址。读取、合并及发布依赖同一原生
快照并沿原 CAS 拒绝迟到操作；身份差异、已撤绑定、重叠及歧义仍拒绝，不借旧流增加权限。
域名坐标的主机或端口已改变时，也不继承旧目的地的已解析 endpoint 来掩盖新解析失败；
同一目的地的解析刷新失败与协议已学习地址保持原义，不能据此关闭仍合法的旧连接。

WG 的内部用户态栈使用稳定双族初始化地址，与候选和资源集合无关；它们不标识或授权远端来源。
真正发送仍使用原 resource／receiver 公钥／sender 公钥算法的精确 IPv6 principal。source routes
与 peers 验证来源唯一、同 peer 的 pool／execution 归属及不重叠，以一致快照供一次拨号／UDP 注册
读取。资源增减不增删栈地址、不重建 Device／Bind；普通业务图不生成 Linux 宿主 Address／HostSources、接口或返回路由。
本机诊断使用一个固定身份及一条动态分派，只允许当前请求资源的精确执行 DNS 目标；不增加逐资源
SOCKS 用户／静态路由，也不改变远端回显请求、测量规格或授予业务权限。

最小验证须覆盖：撤 A 同时新增 B 而 B 准备失败，A 的撤权仍生效且合法旧流保留；新增 B、退役 B
及空池重入均不重建共享实例；取消／旧 CAS／旧实例迟到不发布；TCP／UDP 的旧绑定保持；首业务无需
等待所有候选；部分完成不报告全应用；同 View 重试修复缺项；Android、Linux、Windows 沿正式入口
消费同一结果；WG 同公钥改址、改址后重试及退出工作集仍有旧流时不得冲突或恢复旧坐标。
另须覆盖闲置备选释放且再用可恢复、测量结束不遗留保活、当前路径与 TCP／UDP 旧流继续租用、
并发重用与迟到释放、接收准入不因发送回收丢失，以及资源数量不随已探测历史单调累积。
域名改址解析失败与同目的地刷新失败分别覆盖。真正监听／宿主管理、后续图／出口及其他设施变化的边界须分别验证，不能借本节假称
所有资源生命周期都已完成。

WG 的公开 `dial_host/dial_port` 与本机监听端口分开。接收节点从受保护的现有
`ResourceInputs.listeners` 读取 WG 项 `{resource_id,listen_port}`，按资源及 owner 资格投影
原生 `listen_port`。端口须为显式非零值，不从公开拨号端口补默认值；NAT 可以将公网端口 P
映射到本机端口 Q。既有映射的 `host_address` 定位落点，不成为 WG 绑定 IP 或地址族的限制。
WG 项省略 `listen` 和 TLS 引用；Hy2 项仍使用原 `listen` 与成对的证书、私钥文件引用，原字节
不改写。未引用输入不启动接收资源，也不授予权限。

同一 WG Device 使用原生 Std 双栈共享 UDP 端口，每个支持的地址族共用一个 socket 收发，
不按 peer 增加 socket。没有接收资源的发送端由同一 Bind 分配临时共享端口；端口存在不表示
该节点取得接收资源或接入授权。每条业务连接仍须核对 peer 公钥、AllowedIPs 与原连接上下文。
cookie 回复沿原共享 socket 返回。同一 peer 改址或无关 peer 加入不重建 WG Device、密钥或
既有业务连接；停止、切网与撤权仍按真实传输及授权边界执行。

预检须核对本机共享端口 Q 与所有支持地址族的实际占用。同机其他 IP 上的 Hy2 或其他 UDP
服务使用相同端口也会与 WG 通配 socket 冲突，不能只比较地址是否相同。端口冲突必须明确失败，
不能自动改用公网 P、随机端口或退成单栈；原生对真实不支持地址族的处理保持原义。

本机换端口沿原认证运行 API 的 `wireguard_listener:{port}`、`wireguard_peers` 和接收
`execution` 执行两次 CAS：先提交新权限与当前已确认端口，再提交相同权限与新端口。两次
均使用各自提交前实际读回的 `expected_revision`，并在成功后核对新 revision 及完整
`config_hash`；第一次成功不能代替第二次的执行确认。换端口只重绑 WG UDP，保留 Device、
业务栈与独立 Hy2。来源 selector 的完整选择 CAS 继续独立成立，不把接收更新当成新选择。
权限先发布、传输尚未完成或失败时，接收状态的 `config_hash` 为空，执行保持 unknown；成功
并完整回读后才确认摘要。已经确认新权限后，仅 WG 换端口失败不得恢复旧权限、宣称旧端口
仍在运行或停止无关 Hy2。权限本身无法确认时仍须按授权安全边界失败关闭，不能吞错。
重试核对实际绑定端口，不能凭上次请求值跳过执行；底层网络刷新和唤醒仍使用明确请求的
接收端口，绑定失败不改用随机端口。完整摘要与实际 socket 所有权都成立才确认接收执行；
只有摘要吻合而 socket 缺失时，按相同当前权限重新应用期望端口，再核对两项回读。
执行 TCP 包装显式透传半关闭，保留另一方向；复制优化不得绕过原生响应确认。

本机输入变化由现有运行检查及明确重载入口消费，不增加 watcher、持久回执或第二份权威。
实际迁移只前向登记已核实的本机端口，不修改 NAT、原资源身份、固定密钥、签名原件及认证进度。
共享 socket 仅消除按 peer 建 socket 的成本；现有 peers、keepalive 与探测在节点增长时的
内存、流量、计算及耗电成本仍须收敛并实测，不能据此宣称全邻接或规模问题已经解决。

首次加入链为认证绑定、唯一身份／LKG 原子保存、接收准入生效、本机派生、原生应用回读、首个
真实业务、持续优化与独立报告。删除缓存和离线重启可由相同 LKG＋Preference 重建；新选择不改
签名 View。同一认证前沿的 View 内容仍不得改写。显式迁移保全原身份、固定及派生密钥、原签名、
high_water/floor、latch 和报告序列，只接受前沿真正前进的替换，不双读或双写运行配置。

最小反例测试：大 Policy 集合不生成签名候选／运行 JSON；加策略、网址或设备不轮换其他节点
传输身份；单凭据不能使用未授 Policy、伪造来源／出口／已走链或绕过目标限制；WG-only、Hy2-only
及混合逐段传输；切换互联网不改变 LAN；性能更新保留旧流；撤权与登记竞态不漏关；迁移字节
保全与删除缓存后的恢复。通过单元检查不抵扣真实代理业务、真机、长连接和加入干扰验收。

#### 逐跳 TCP 建连确认

原生 WG／Hy2 的业务 `Dial` 只有在下游确认目标建连后才成功返回。forward 因而先等待下一段
的确认，再向上一段确认；最终出口先完成实际目标 TCP 建连。确认不等待 TLS、HTTP 或其他应用
首包，也不代表应用请求成功。业务域名仍由最终出口解析，入口不为获得确认而抢先解析。

捕获入口的 HTTP CONNECT 响应、SOCKS 预读确认及 TUN 内部 TCP 状态不能代替这一结果。
HTTP 入口可能先确认隧道接管，裸 IP 的名称嗅探也可能先读取并确认 SOCKS；真实业务反馈必须
从固定到该连接的原生拨号结果取得，再分别保留应用响应及其成功范围。

WG 沿既有响应帧校验 nonce、操作及 Accepted／Denied／Unavailable；Hy2 沿既有 TCPResponse
编码读取状态和消息，不增加帧、字段或版本。原生 Hy2 的明确拒绝／不可用消息仅为精确的
`loom:execution:denied`／`loom:execution:unavailable`；普通 Hy2 和任意其他错误消息不据此推导
明确的原生结果。Denied 表示本次执行被拒绝，Unavailable 仅说明本次获准路径不能完成建连，
不能仅凭它断言最终网站或某一段故障。后续业务观测必须保留该范围，不能据此隐藏全部 Policy。

当前 Loom 单拨号端口的原生入口中，建流／认证、发送请求和读取确认共用八秒上限，并取调用方
更短期限；取消只终止本次连接或 QUIC stream，
不关闭共享 WG／QUIC 传输。取消回调与成功返回须同步结束，不能迟到关闭已返回的连接。收到
下游 Denied 不得改报 Accepted；取消、普通 EOF 或关闭不能伪造成功，也不生成目标故障事实。
确认头后的首个业务字节及 TCP 半关闭语义保持，通用非原生 Hy2 的懒读行为不因此改变。
失败的 `Dial` 返回错误及真正的空连接；具体指针转为 `net.Conn` 接口前须先处理错误，
不能让含空指针的非空接口进入上层清理，也不能靠空 `Close` 或吞错掩盖这项返回契约。
发送端停止等待不等于远端 forward 的在途 Dial 立即取消；远端仍受自身有界期限约束。
不能把 TCP 读 EOF 或 QUIC 发送半关闭当成整个双向连接取消。

这只是既有运行与传输入口的确认修正，不改变领域授权、签名对象、持久身份或 UI 完成判定。
最小验证覆盖：下游延迟确认时 Dial 不提前成功；明确拒绝与不可用逐跳保留；取消后共享传输仍可
建立另一连接；确认与首字节同包不丢字节；半关闭保留返回方向；无探测网址的普通业务仍可执行。
正式 WG／Hy2 Endpoint 的拒绝和失败同时检查错误语义与空连接，不只在具体指针 helper 上验收。

#### 普通 TCP 结果的本机消费

access 的普通本机 TCP 连接在实际下游 Dial 完成处采集一次结果，不从代理握手、字节计数或关闭
事件推断。记录保留连接固定的 Policy、候选、原始 host/IP＋端口、已有选择 revision、尝试开始与
完成时间。成功只证明 TCP 建连，明确不可用只证明该候选无法完成这一目标；拒绝、取消、未知
确认及正常 EOF 不产生失败。诊断探测、forward 入站、LAN 和管理流量不混入普通互联网结果。
本机等待确认的期限到达仍为 unknown；不能只因裸 deadline 或通用 timeout 就声称下游明确失败。
未取消的真实尝试即使结果未知，也可按原开始时间保留 `unknown`，仅证明近期确有使用；按最新
尝试规则消费，不制造不可用或性能确认，不借新未知结果延长旧成功／失败的截止。拒绝、取消和
正常关闭不提供这种活动证据，后台校准也不能更新普通活动缓存。

原生实例通过既有带认证的本机 API 提供有界快照，不新增公网入口。缓存最多 128 条、64 KiB，
按真实尝试开始时间保留最新结果；同刻冲突为 unknown，迟到旧尝试不能覆盖更新尝试。保留上限
为既有成功样本寿命，读取不续期；实际成功／失败寿命仍沿用节点采样参数。它不执行额外探测，
限额不是 Service 网址数量或探索并发限制。

复用已有不可预测 revision，不增加观测上下文字段。客户端在完整选择回读后，仅在 RAM 绑定
revision、本机网络代及当前 Policy 的实际执行规格。切网、重启或执行条件变化时，同路径也通过
原完整 CAS 重新确认；授权差量改变 revision 后也重新绑定。迟到且不匹配的事件丢弃，不套用当前
路径或规格。性能更新保持已消费、同网络同规格的原样本至原截止；新事件只按其原归属消费。
绑定和普通 TCP 样本不进入身份、Preference、Probe 持久缓存或共享 Observation 原件。
本机循环只领取现存结果，与远端报告和测量请求独立；没有新事实且无待确认改善时不重算路径图。
其读取周期不等于主动测量周期、样本有效期或性能最小换路间隔，也不产生额外网络探测。

本机 `tcp_connect` 样本复用 Observation 值，Target 是规范 host/IP＋端口，MetricMillis 是完整
建连耗时而非 RTT；HTTPS 仍保留完整 URL。两类证据分开，TCP 成功不能清除 HTTPS 失败或增加
Service 网址覆盖，也不能抹去分段故障。固定出口仍只按分段观测选入口和中继。非固定出口中，
某 TCP 目标的当前候选明确失败可立即尝试同 Policy 的未证实失败候选；全部失败时不反复切换。
恢复优化仍遵守改善确认和最小间隔，已有连接保持。

运行目标 key 统一为 `tcp://host:port` 或 `udp://host:port`，仅前缀区分传输，host/IP 与十进制
端口仍严格规范，不含路径、query 或用户信息。原生选择按实际网络取 key，未知目标用默认；TCP
或 HTTPS 证据只产生 TCP 覆盖，不连带更换 UDP。Service 访问边界仍为 host/IP＋端口，不因此新增
访问分类。选择报告沿现有 Target 字段发送同一 key，不增加字段或报告对象；只上送实际覆盖，
不把每次普通连接变成全网共享测量项。已签 schema 3 中的裸 host:port 保留原泛协议语义和原始
字节，可历史验签；新的运行覆盖与报告 writer 不生成裸 key，不增加运行 fallback。

domain 没有新权威概念；签名 wire 只细化选择 Target 的网络范围，旧原件不改写；persistent 的
身份、进度、原签名不变；runtime 的绑定、结果与覆盖均可删除重建；UI 分别说明 TCP 建连、HTTPS
请求及实际选择，不能将 TCP 成功显示成网站或整网成功。

最小验证覆盖：真实拨号点采集及取消／拒绝排除；旧慢结果、同刻冲突和缓存限额；同路径切网
CAS、执行条件变更与旧实例迟到；无网址的 TCP 故障选合法备选、恢复稳定及固定出口不按目标分路；
TCP 覆盖不影响 UDP；报告 key 严格拒绝与历史签名字节不变；普通业务与长连接经正式入口回读。

#### 后台 TCP 恢复校准

用户已确认：先在后台试连，再让新连接采用优选路径，已有连接保持。本节只处理非固定出口
Policy 内近期实际目标缺少恢复证据的情形；固定出口继续按分段规则选入口与中继，不产生目标
校准任务。它不是 Service 网址扫描、权限扩张或新的 Probe 对象。

运行端先从可比的当前分段样本形成显著且持续的改善推荐，再检查目标证据。不能因当前候选
持续产生 TCP 成功，就永远不提出更好的备选；旧目标证据到期也不能清空仍成立的分段推荐。
只有近期真实 `tcp_connect` 证明该目标仍值得校准。原健康截止与近期使用保留界限分开：过期
结果不再证明可用，仍可在原保留窗口内证明曾实际使用；读取和校准都不延长这个窗口。

每个活跃目标只保留必要备选，任务由既有待确认改善和节点调度单向派生，不建立完整路径与
网址乘积。已有当前相关出口 HTTPS 成功时优先复用原共享与分段证据；不伪造本机端到端 TCP
样本，不清除尚有效的本机失败。相关 HTTPS 明确失败时，不以一次 TCP 成功洗白，也不重复做
这种不能解决问题的校准。缺少足够相关共享结果时，才为持续改善的合法备选做少量 TCP 试连。

校准复用现有节点请求率、并发、预留字节及截止预算，与其他测量公平轮转。重测周期、原样本
寿命与性能最小间隔仍分别处理；性能冷却期间可以继续测量，不能用冷却代替采样周期。预算
不足只延后，不续期旧证据。实际计数须注明范围，本机 API 的字节不能冒充共享 WG／QUIC 的
全部线上开销。校准不发送 HTTP、TLS 或应用内容，只等待原生逐跳 TCP 建连结果。

本机认证 API 为 `POST /loom/access/{name}/tcp-connect`，只在带非空认证的字面 loopback
listener 可用，请求正文最多四 KiB，恰含 `expected_revision,policy_id,choice,target`；choice
使用已有 `entry_node_id,first_resource_id,final_exit`，target 为规范 `tcp://host:port`。拒绝
未知字段、尾随正文、query 与非规范目标。当前 selector 必须为互联网 access，Policy 及
revision 必须与实际选择一致；候选 ID 由当前 Service、Policy 与 choice 重新计算，摘要不是
权限。复用当前源权限、目标边界、资源职责、运行组件和完整路径约束校验，不能给未选 Policy
执行，不能靠临时切换生产 selector 探路。近期目标还须存在于原生普通 TCP 缓存，校准不写该缓存。

短授权 fence 内完成校验及现有连接 tracker 登记，释放后才能 DNS／Dial；撤权和停止只取消
这次试连，迟到连接立即关闭，不关闭共享 WG／QUIC 或其他流。结束前再次核对当前选择及授权，
过时结果丢弃。响应复用本机 TCP 结果的 revision、Policy、候选、原目标、开始／完成时间和
结果；调用方只在原网络代、执行规格与运行所有者仍有效时接受。明确不可用只描述该候选与
该目标；普通确认超时、未知、取消与拒绝不制造故障，不能据此隐藏整个 Policy。

校准结果仅在同一 RAM 工作集使用既有 Observation 的本机动作 `tcp_calibration`。它与真实
`tcp_connect` 按原尝试时间比较 TCP 证据，但不能续真实活动、不进入签名 Observation、身份、
Preference 或 Probe 持久缓存，也不增加 Service 网址覆盖。TCP 可用性是恢复准入条件；持续
改善仍由新分段样本确认，不能把 TCP 更新时间当 RTT 或要求旧连接反复重建来增加确认。
取得所需证据、改善仍成立且最小间隔满足后，只改变新连接。真实故障、撤权与用户操作继续
沿其原规则及时处理，不等待性能校准。

domain 与持久身份无新权威实体；签名 wire 与传输上下文保持 schema 3 原义；新增请求只是
既有本机执行 API 的派生操作；运行记录可删除重建。UI 区分真实业务建连与后台校准来源，不
把试连成功说成网站成功，不新增管理对象或页面。

最小验证包括：无网址的真实目标故障绕行后，由实际校准生产恢复结果而非注入成功；当前
持续成功与旧证据到期均不锁住备选；共享结果复用与 HTTPS 失败保留；固定出口、UDP、LAN 不
参与；预算、公平、取消、撤权和旧结果归属；校准不切 selector、不发应用内容，性能更新后旧
TCP 仍收发，新连接才采用新路径。


### Invite、claim、resume 与配置交付

Invite payload 的字段为 `id,genesis_digest,issuer_control_id,device_id,name,responsibilities,policy_ids,`
`medium,endpoint,expires_at`；id 即事务 ID，medium 仅 `qr/ssh/sh`。endpoint 使用下方 EndpointGeneration
的同一完整公共值，其中包含稳定入口 ID、generation、host、port、校验名和 SPKI；全部随 Invite Material
签名覆盖，并与因果依赖中的入口事实精确对应。不能只给新设备一个无法解析的 ID/generation，或让它在
认证前从另一来源补拨号坐标。这里是既有入口的冻结交付值，不提供第二份入口写入权威。
纯 access 必须 qr，含其他职责必须 ssh/sh；签发、扫码解码和 claim 使用同一拒绝规则。
对上文初始成员的首次设备绑定，职责包含其已有 control；签发与 claim 均核对目标就是签发者的初始
NodeID、资格仍有效且没有既有绑定/授权冲突。它不是申请新的 control 资格，不能据 control 字样再增员。
策略 ID 固定而规则内容可随有效后继变化；不在 Invite 中复制第二份策略。端点必须归 issuer 所有并 serving，
证书有效期覆盖邀请到期。平台不属于 Invite。
可选 `ssh_target` 是 [SSH 自动交付](enrollment-endpoint-model.md#ssh-目标只读检查与同事务执行)的操作者
别名，只有 medium=ssh 可携带，语法为 `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`。未指定时省略，不能编码空值；
它不改变 claim 的授权范围、平台和密钥绑定。已有缺席该字段的认证字节保持缺席，不补写或重新签名。

BootstrapInvite 唯一形状为 `schema=3,network_id,genesis_digest,control_proof,material`；material 必须是
上述 `invite.issue` 的完整规范签名事实，两个网络锚与 payload 精确一致。control_proof 是从固定锚到
发行者所引表的完整成员证明，不能用自称的当前表替代。此值只在控制面私有存储、
绑定后的私有响应及设备受保护身份中使用；既有签名原件不重签、不改写。

唯一公共加入交付是 `InvitationReference`，字段为 `schema=3,genesis_digest,transaction_id,medium,endpoint,capability`。
endpoint 仅含 `host,port,server_name,spki_sha256,certificate_digest`，精确投影原 Invite 的冻结入口，
不含入口 ID、owner、成员、模式或状态。capability 是 32 字节无填充 base64url：
`SHA256("loom-invite-capability-v3\0" || DecodeBase64url(Material.signature) || UTF8(MaterialID))`。
原签名必须受保护；公开内容摘要不足以导出能力。它是原 Invite 的可删除重建投影，不另存 token 权威。
链接/QR/文件唯一为 `loom://enroll#` + 无填充 base64url(C(InvitationReference))，规范 JSON 正文最多
1536 字节；拒绝未知/重复字段、非规范字节、压缩流、完整 BootstrapInvite URI、空白及其他包装。
加入文件的文本适配器可移除一个末尾行尾（LF、CRLF 或 CR）；二维码/URI 解码不接受空白，
文件适配不修改规范 URI 本身。不携带策略/规则、名字、设备身份、因果依赖或成员证明，大小不随这些内部资料增长。
首次连接仅用客户端内置 DoH 预设解析唯一 host，必须核对交付的全部 TLS 身份；后续只使用认证 View 的解析器。
媒介 qr 的引用只用于 access；服务端以原签名 Invite 再检查职责与媒介，篡改引用不能改变授权。

客户端先持久化同一设备身份的密钥、request ID 与引用，再连接 claim；服务端以原事务和常量时间短凭据
认证，在同一 TLS 中返回 `EnrollmentStart`：`schema=3,network_id,genesis_digest,transaction_id,invite_material_id,`
`medium`。它不包含策略、原件或成员证明。客户端核对 genesis、事务和媒介，
随后签名现有 claim。签发者、原件 ID、原冻结入口、当前资格和生命周期都由控制面原事实验证。

claim 和 resume 的字段均为 `schema=3,network_id,genesis_digest,transaction_id,invite_material_id,`
`request_id,device_public_key,platform,signature`。使用各自既定签名域，身份私钥在设备生成。
首次 claim 仅交 issuer；服务端核验端点 bootstrap 模式、原存储 Invite、短凭据、当前签发资格、职责/媒介、期限、
平台能力和一次性绑定，再签 bind 事实。平台只表达目标端识别结果，不是硬件证明；不能因此扩权。
resume 必须与已持久绑定的 request ID、公钥和平台完全一致；响应丢失不能重新生成 RuntimeKey 或身份。

普通加入响应字段为 `schema=3,transaction_id,state`，state 为 `open/bound/completed/cancelled/expired`；
completed 必须另有完整 `device_view` envelope，其余状态不带 View。bootstrap 响应在 bound/completed 时
另有 `enrollment_proof:BootstrapInvite`，仅在请求签名、公钥与持久绑定一致后交付；其他状态及 device 模式
省略该字段。客户端逐层验证证明、原件及其派生短引用，再在同一身份值中以 `invite` 替换
`invitation_reference`；已持久完整原件保持原字节。响应经认证私有 tunnel 取得，
响应状态只投影事实；成功授权须由下面的 View 验证，状态字符串本身不能推进 LKG 或 floor。
绑定、完成、终结由事实恢复，没有 approval/complete writer、pending-device 或安装回执权威。

EndpointGeneration 的普通值字段为 `id,generation:U64,owner_control_id,host,port,server_name,spki_sha256,`
`certificate_digest,modes,state,drain_until:Time,preference`；generation 至少 1，modes 为 `bootstrap/device/web` 排序集合，
另有可选 `website_trust_id`：仅 `server_name=control.loom` 且包含 web 模式时必须出现，
引用唯一已授权的 PublicTrust 根 ID，并与本代坐标一同不可变；其他入口省略，原认证字节不变。
这类入口的 host 不得是 `.loom` overlay 名称，根授权与原 CSR 的执行检查见
[网站 CSR 的受保护交付](enrollment-endpoint-model.md#网站-csr-的受保护交付)。
state 仅 `prepared/serving/draining/retired`，preference 为 0～65535 整数。certificate_digest 只定位公开
证书字节，本机秘密文件引用不在 wire。draining 的 drain_until 必须大于 0，其他状态固定为 0；
正式状态变更入口核对 draining 截止期晚于请求时刻，纯值校验不读时钟。到期关闭本代已有会话，
retired 的写入还须回读本代 Active 为 0。合法阶段转换、承载者退出和正式/回环 Web 证书边界仍按既有模型执行。

### DeviceView、成员证明与唯一 LKG

私有 tunnel 使用 TLS 1.3 和 ALPN `loom-tunnel/3`。每帧为四字节网络序长度及一个完整 C(JSON) 值；
接收者超出资源边界时拒绝，不截断值。bootstrap hello 仅为
`schema=3,mode="bootstrap",transaction_id,capability`；device hello 保留
`schema=3,mode="device",endpoint_id,generation:U64,device_id` 的现有字节，两种字段不得混用。
device challenge 为 `schema=3,nonce`，nonce 为 32 随机字节的无填充 base64url；proof 为
`schema=3,signature`，设备以 `loom-device-tunnel-proof-v3\0` 加 `C({hello,challenge})` 签名。
认证成功回应 `schema=3,status="ready"`，bootstrap 另含 `enrollment_start`；device 不含该字段。
之后同一连接承载私有 HTTP。bootstrap 只能访问同一邀请的
claim/resume；device 每次请求仍检查当前设备授权。SPKI 摘要为 `sha256:` 加 X.509
RawSubjectPublicKeyInfo 的 SHA-256 小写 hex，证书摘要同格式但哈希完整叶证书 DER，均不加 JSON 或签名域。
客户端同时验证这两个摘要、名称、serverAuth 用途和有效期；仅握手成功不能制造运行健康。
多个已认证入口沿[私有入口与运行时](enrollment-endpoint-model.md#私有入口与运行时)作独立有界的
完整业务尝试。HTTP、规范值、签名、设备绑定与已见前沿均通过后才取得一个结果；失败候选不写
LKG，不因先握手成功取消尚可完成业务的入口。报告只预留一次序列并重用同一已签原件；配置及
加入后 resume 的持久接受仍沿原唯一 SaveLKG。新 control 原件收集也须在同一候选收齐完整证明、
事实和冲突后验证重放，不能拼接多个失败候选的半套内容。首次 claim 仍固定 Invite 签发者。
这些调度与诊断修订不改变任何已签帧、事实、View、Report 字段或现网原件。

DeviceView envelope 字段为 `schema=3,network_id,genesis_digest,issuer_control_id,issuer_key_id,control_proof,`
`fact_frontier,view,view_digest,signature`；以 `loom-device-view-v3\0` 对除自身签名外的全部字段签名。
fact_frontier 按验证键 ID 排序，每项为 `key_id,sequence,tip_material_id`；0 使用固定空链值，
其他项须为签发者已经验证的连续前缀，不能以报告自称的进度生成。已见非零键不能从新前沿省略。

control_proof 使用上文完整 genesis 与连续后继证书的唯一结构。其验证终表确定 envelope 签发者资格；
Invite Material 的 control_config_id 必须等于其证明终表内容 ID。隔离测试的初始表也须由显式 genesis
按同一规范校验并固定锚，成员数只是数据；不能引入 N=1 模式、无证明成员表或测试/生产特殊 decoder。
设备所见封存证明是签名前缀报告与成员多数签名；完整原始事实链由签署 control 核验，不放进设备证明。
control_proof、Invite 和 View 均不得因此泄漏设备授权的 RuntimeKey 或其他设备的派生凭据。
后继验证实现后沿同一 envelope 交付，不加 runtime_contract 或第二份 View。

本链 DeviceView 的必需字段为 `schema=3,network_id,device_id,name,platform,device_public_key,`
`responsibilities,policy_ids,nodes,services,policies,resources,transport_credentials,endpoints,dns_servers,expected_components`。
集合必须显式出现。`nodes` 不重复自身；每项为 `id,responsibilities,policy_ids`，可带公开 WG
身份及非空来源解析参数。Hy2 传输凭据按资源／实际发送节点排序；不得出现重复或越过本机
发送／接收边界的秘密。可选自身派生 WG 私钥只为自身执行；固定私钥仍用原本机文件。
可选非空 `dns_records`、`public_trust`、`web_endpoints` 保留各自规范字段和当前有效引用；
显式空可选集合、null、未知或非规范输入拒绝。

签名 wire／持久 LKG 不含候选、运行 JSON、逐路径或逐 Policy 的凭据／peer 展开；具体删去的
旧字段和一次性替换见[稳定 View 与本机运行派生](#稳定-view-与本机运行派生)。旧原件保全并按
原义验签，不得在同一认证前沿改写成薄 View。职责包含普通设备授权与成员表的有效投影；
control 只能来自已验证成员表。

access 依据唯一当前互联网 Policy 与独立 LAN 选择派生候选。共享 transport 和稳定授权谓词
在本机编译，实际选择由完整 CAS 快照提交：`policy_id,now,targets,choices,revision`；
`choices` 的键为候选摘要，值为 `entry_node_id,first_resource_id,final_exit`。原生 selector 重新
计算候选身份、校验当前 Policy、入口资源、出口资格及目标边界；性能更新只影响新连接。
无业务权限或待选是可接受的认证状态，运行 selector 保持 reject。运行 JSON、测量、推荐及
本机 API revision 只能单向派生，不能签发、倒写或形成第二份持久权限。

policy_ids 保留设备原分配，policies 只包含相关当前有效值；缺失的 Policy 或所属 Service 收口
相应权限，不得因此拒绝整个认证 View。源解析参数改变使对应测量规格失效，不改变其他节点
的执行或 ACL。探测网址仅从 Service 投影，未配置也能依据传输和真实业务观测正常联网。
expected_components 的项为
`component_id,platform,version,artifact_digest`，按组件和平台排序；发布记录的验签仍需其独立契约。
Service 的 HTTPS 网址不隐含仅 443 的业务约束；非默认端口仍须精确授权和按原 URL 校验证书。
TLS 校验名始终是原 URL 的主机名，HTTP authority 保留非默认端口；地址尝试或代理不能将二者换成
拨号 IP，也不能跟随重定向后把另一目标的结果记给原 URL。各端实际端口消费的证据见[实施状态](../progress.md)。

#### 待替换的完整路径执行字节

以下描述现存完整候选、入站凭据及排除目标的旧字段，用于界定原件保全和前向替换范围；
它们不能约束 access 选入口、forward 在同一 Policy/最终出口内继续选路的目标。新规范字段和
接收端一致校验尚须完成，不继续签发该旧执行形状，也不将其保留为运行 fallback。

历史候选身份字段为 `service_id,policy_id,first_resource_id,node_chain,link_ids,final_exit`；Direct 与本机出口的
first_resource_id 为空且两条链为空，final_exit 分别为 `direct` 和设备 NodeID。一跳有首跳资源而无 LinkID。
RouteCandidate 在这些字段外还有 `id,spec_digest,scope`；id 和 spec_digest 按本节摘要规则计算，
scope 固定为 `service:` 加 Service ID。入站权限项为
`device_id,service_id,policy_id,candidate,resource_id,receiver_node_id,sender_id,allowed_targets,excluded_targets`；
Hy2 另含前述 KDF 输出 `credential`，WG 省略该字段。互联网 allowed_targets 是规范排序 Matcher 集合，只能来自该 Service 及当前策略的
获授权投影，不能由 credential 持有者扩张。历史 excluded_targets 为旧多服务选择模型派生的 matcher 并集（包括 deny）。该规则只描述旧
原件，不再生成“其他当前所选互联网 Service”的排除权限。先拒绝 excluded，再允许 allowed，默认拒绝；
这保持 Service 后继修改造成交集时的拒绝语义，不把凭据本身当成目标授权。每项按
`device_id,service_id,policy_id,candidate.id,resource_id,receiver_node_id,sender_id` 排序且唯一；Hy2
凭据用户名由这些绑定字段的规范摘要派生，不通过有歧义的字符串拼接。权限绑定完整候选、
实际前驱和本段接收器，下一段或最终出网从接收器在该候选中的位置推导。

一跳 Hy2 的第一资源 owner 必须同时符合 Policy 入口和出口范围并有 internet_egress；节点链恰好
为 `[owner]`，LinkIDs 为空。签发端按完整 Projection 检查 owner 资格，只向 access 交付实际可消费的
远端资源；接收端另取得自身承载资源及其入站凭据。接收端 services/policies 可包含这些入站引用，
其自身 PolicyIDs 仍只表示自身 access 分配，不能填入来源设备的 PolicyIDs。access 的派生密码留在
同一认证 runtime_profile 对应 Hy2 outbound 中；检查该配置时只将密码当私有投影输入，其他拨号、
信任、候选和授权规则均须由 View 重建并比较，不从配置反写领域事实或增加 fallback。

接收端按 Hy2 请求实际携带的 FQDN/IP 或 WG 执行 DNS 恢复的原名称/字面 IP 执行目标规则；
不得用 sniff SNI 为任意 IP 请求扩大权限。
本机 TLS 引用及监听坐标仅定位执行输入。撤权先耐久接受新 View，再终止受影响的旧会话，
不能只改 user 表却让越权已认证会话继续。失败保持新 LKG，重启不复权；无法精确更新是实现
缺口，不应规定增员或性能优化必须重启共享 listener。不得为连续性保留旧 ACL 或第二状态源。
完整中继与 WG 参与地址使用上文的逐段权限、peer 和来源投影；实际业务结果仍须分别验收，
不能从一跳成功推定其他路径可用。

#### 认证接受与执行分离

验收顺序固定为：严格规范解码 → 固定网络锚 → 连续成员证明与签发资格 → 完整 envelope 签名 →
View 摘要 → 设备 ID/公钥/平台 → 内部引用及授权/运行映射 → 已见前沿。任何一步失败都不覆盖原 LKG。
只在合法连续多数证书明确封存的键上适用前沿例外；原高水位和不可回退 latch 不删除，其他键不回退。
前沿验收通过后，成员证明、完整 envelope 和逐键高水位在同一次原子持久替换中保存，成功后只有一个 LKG。
平台 preflight、进程启动、业务探测和 report 成功均不参与认证验收；它们失败也不能撤销已经接受的新授权边界。

Envelope 的公开校验只需严格编码一次本值的 unsigned：它包含除 signature 外的全部字段，
同时完成 View 及嵌套值的领域和结构校验。从本调用生成的这份规范 unsigned 中取顶层 view
原片段，按原 View domain 求摘要，再用同一 unsigned 原字节和原 envelope domain 验签；
成员证明、签发者、前沿、control 职责与 endpoint owner 的原约束全部保留。signature 本身
仍须满足规范 base64url、精确长度与密码学验签。固定 Envelope 类型的编码器在检查其静态
schema 并完成上述校验后，不再次递归校验同一子树；不能推广为任意值跳过校验的开关。
domain、wire 与 persistent 均保持原值和原字节，runtime 只有本调用临时编码与片段复用，UI
不变，不增加第二份可写对象、缓存或生命周期。反例是 View 内出现嵌套同名字段，或 View 改变后沿用旧
签名：只能取这份 typed unsigned 的顶层 view，仍须拒绝错摘要或错签名。最小检查覆盖片段与
独立规范 View 编码相等、原域与完整 envelope 字节往返、unsigned 字段覆盖、非法 UTF-8、
空集合、成员与签名拒绝，以及正常设备领取、LKG/floor 原子保存和重启消费。

### 私有设备的中继观测交付

`POST /device/link-observations` 复用加入后的设备认证通道，唯一当前请求、响应、cursor 与
工作集语义见[设备相关测量的批量差量交付](#设备相关测量的批量差量交付)，不另维护无 cursor
的响应格式。摘要必须等于该设备当前可签发 View；未知、非规范、错设备、bootstrap 或陈旧
配置请求拒绝。每条引用保留真实来源、原 U64 序列、完整规范报告的内容摘要与原 Observation。

交付核对当前身份、公钥与原件签名、来源当前职责与规格、最新已知的唯一 head 所声明的运行
应用状态和来源网络代。最高位置分叉、明确停止、应用失败、换代、撤权或规格变化清除对应
证据；没有新报告不等于停止、数据面故障或新网络代。选路按原样本 valid_until、合法原寿命与
时钟边界使用，current_until 保留该原截止；不因领取、重复报告或分页续期。Web 报告的三分钟
陈旧标记仅属于展示，不裁剪选路样本，不成为第四个测量时钟。

只交付接收设备当前 View 中允许的 Link 与出口目标，Link 来源必须等于 From；调用端重算
Link/spec 和目标/动作对应，复核自己的 View 摘要仍相同。来源网络代不得改成接收设备的网络代。
设备只使用仍匹配当前已接受 View、来源、目标、规格且未到原截止的样本。取件失败保留精确
base/cursor，不产生新样本；跨页有效事实由同一有界工作集合并。客户端原子替换通过验证的
完整工作集，不在该工作集之外自行补回旧行。缺项只令无其他证据的段为 unknown，不制造故障。
接受撤权或资源/spec 变化、View 改变或样本到期后，旧样本立即不再使用；
不持久化第二报告/健康 store，不把远端样本签成自己的报告，不把观测放进授权 DeviceView。
TLS 认证控制交付，来源签名由 control 核验；它不提升来源或接收者的 Service 权限。

同一次交付请求从同一事实与发布输入投影每个设备的 View，完整校验并计算摘要成功后，临时绑定
保存这一对值；接收者请求核对、来源报告核对及最终范围检查复用这对值，不重复编码同一 View。
该绑定复用下述完整认证输入绑定的配置投影；失败不保存，下一请求仍核对当前输入；逐报告的当前授权、公钥、
签名、实际应用范围与原有效期仍逐一检查。先由接收者当前 Links 确定来源集合，再只读取这些来源的最高位置；
空范围返回规范空集合，最高位置分叉不得回选旧值。公开的 View 范围校验入口仍独立校验 View 并重算摘要，
调用者不能用任意摘要跳过该边界。domain、wire、persistent 和 UI 均不变，只有 runtime 的本次
计算结果复用；没有新权威或操作步骤。反例是两次请求间撤权：前次成功的 View/摘要
不能供后次使用。最小检查覆盖同请求复用、失败重算、跨请求事实变化、错设备与旧摘要拒绝。

#### 未变认证输入的配置投影复用

设备周期读取配置的目标是及时接受认证前沿及执行输入变化，而非反复重建相同 View。同一 Authority
已接受输入、设备、签发身份及独立验真的发布引用确定同一 View、摘要、证明、前沿和规范签名响应。
配置请求与响应仍使用原 schema 3；缓存不按 ViewDigest 单独绑定，因为执行 View 未变时证明和前沿仍可前进。
Authority 替换输入即使原复用失效；阻断、撤权或发布引用验证失败不得命中旧成功结果。

同一输入快照内捕获投影、证明与前沿，锁外执行重计算，返回前复核绑定仍为当前值；相同绑定的并发
构建合并，等待可取消，失败不保存，不以取消启动重复构建。配置复用最多 64 MiB，原件校验缓存最多
14 MiB，按保守字节计量及 LRU 淘汰，超大结果不保存；不保存完整报告正文。删除缓存或重启后从原权威重建。
计量只计算一次结构内联存储与切片 backing，另计算外置引用及保留容量中的引用；共享引用仍可重复保守计费，
不能因重复计算内联字段导致同一批合法配置持续淘汰。管理快照可复用同一绑定下的 View 和已计算摘要，
本次独立验证的发布集合仍是输入；只读或阻断状态的既有脱敏快照不因此获得签发配置的权限或新的签名要求。
domain/wire/persistent 均不新增值；runtime 仅持有这些输入的单向输出，客户端仍消费完整签名响应，
UI 与 Link 范围检查只消费内部的 View 和摘要，不为只读投影签发配置。
正常链为已认证输入变化、配置重建、设备验证并持久保存唯一 LKG/floor、运行应用与报告回读。
最小检查包括并发单次构建、同 View 的证明推进、撤权/阻断/发布材料损坏、取消及冷热规范字节等价。

配置跟随使用同一 `/device/config`、原认证摘要及可选的规范 `Loom-Config-Wait` 传输头，
详细边界见[私有配置交付](enrollment-endpoint-model.md#配置领取与认证持久化)。本机认证输入变化通知及
成员前沿请求中的 `Loom-Facts-Changed: 1` 只调度原领取/取缺，不构成授权、同步前沿或执行回执；
该提示按[普通事实同步](control-model.md#4-普通写入与大规模增量同步)丢弃重建。签名对象与持久
schema 3 字节均不变，已认证原件不重签或重解释。配置变化后先持久保存认证进度，再局部应用；
同 View 的前沿前进也须保留，不能因未重建数据面而丢弃。

合法的服务节点配置可包含数百条分段权限与完整运行配置；例如 4 MiB 的规范输出及其 typed View
无法进入原 2 MiB 预算，连续配置读取与管理快照即使输入未变也持续重算。预算提高到上述固定上限，
仍使用同一认证绑定、保守计量、构建并发限制和 LRU；不延长认证或发布校验的有效期，不缓存超大结果。
新增成本只是在已有 control 进程内最多增加 62 MiB 的派生内存，无操作者输入、持久字段或新生命周期。
最小回归还覆盖多个数 MiB 配置的连续读取复用、总预算淘汰及超过总预算的结果不留存。

冷构建也不得为求摘要、签发及生成完整响应而反复运行同一 View 的领域校验与运行投影。
控制端在一次私有构建内严格检查实际 View 及其余全部字段，复用本次检查后的值与规范编码，
仍完整核对成员证明、签发者、前沿、View 摘要和最终签名；响应须与公开规范编码逐字相同。
这种复用只接受本绑定内生成的私有片段，不能接受外部片段、向公开编码器增加跳过检查的选项，
或沿用修改前的值。公开投影、解码、校验及签发入口的接受与拒绝边界不变。

只读页面的目标是检查当前授权与报告，完整配置交付才需要新的控制签名。原办法在配置缓存
未命中时为页面也构造整份证明、unsigned 和签名响应，随后只取 View 与摘要，形成无用计算。
最小变化是在同一个输入键、LRU 和字节预算内分别复用两个纯计算结果：严格 View、摘要及其
规范片段；由它们按需生成的完整签名响应。前者只有完整校验成功才可使用，后者仍必须完成
全部证明、前沿、摘要与签名检查后才能交付。它们没有持久状态、业务完成位或独立权限；
不增加第二缓存、后台预热、页面对象或操作者步骤。配置与只读并发复用同一次严格 View 计算，
只读消费者不等待无关的签发；取消不重启共享计算。签发失败不保存失败或不完整响应，已独立
成功的 View 仍只能在原绑定当前有效时使用。配置与 Link 交付返回前的当前输入及发布引用复核
不能被复用替代。管理快照继续使用本次独立验证的发布集合，返回前检查当前 Authority 输入；
不为只读查看追加配置交付的发布重读，也不把发布读取失败变成已核实状态。
反例是 View 成功后撤权或证明推进：旧 View 不能使新请求返回旧响应，配置消费者也不能把只有
View 的结果当作可验证配置。删除或淘汰后均从认证输入重建，超大结果依旧不缓存。
最小检查还须比较按需交付与公开签发的原字节，覆盖并发单次严格编码、只读不签发、签发失败与
重试、预算淘汰、嵌套非法值、规范集合、错误签发键及同 View 的认证前沿变化。

domain 和 persistent 仍只有原签 DeviceReport、DeviceView 及其依赖事实；wire 是同 schema 3 的
只读范围投影，runtime 是可删除缓存与选择输入，UI 继续分别显示 Link、Service 和实际 Selection。
交付字段规范往返，原报告字节可逆保留；投影只单向生成，不能倒写报告或授权。Link 有效失败仅
排除引用该方向/spec 的路径；同路径、同 Service 全部目标更新且仍有效的真实业务成功可以覆盖
旧失败，Link 成功不能生成 Service 成功。原有认证回环诊断入口按完整 candidate 身份、同
Service 的允许/排除目标执行每轮至多一个未选 candidate/目标的 HTTPS 请求，生产 selector
不为采样而切换；真正改善仍经原选择函数、应用及回读。无新的 listener、协议版本或权威对象。

最小验证覆盖正式设备认证、当前 View 范围、来源分叉/撤权/错规格/错代/runtime 未应用/过期，
原样本与截止往返、相关路径失败隔离、新完整业务覆盖旧失败、稳定公平轮转、诊断入口目标拒绝、
不关闭生产业务连接，以及正常入口取件和重启原件保全。禁止恢复 Link 只供 Web 而不参与选择、
以当前路径成功阻止其余路径恢复观测，或通过切换生产 selector 进行全量探测。

### 本机出口测量的物理 I/O

出口测量由既有节点 worker 从当前已认证 View 派生 `EgressProbes`，按原规格去重、预算调度并
在原 owner fence 内提交。它不使用来源路径校准的 candidate 诊断权限，也不建立逐 Service 的
原生探测用户、路由 ACL 或另一份可更新授权。互联网业务共用一个固定的公网物理出站；
Service／Policy 的原始目标、来源、最终出口和路径约束仍由 access／receiver 当前权限快照校验。
LAN 保留独立映射及权限；捕获匹配完整获授权映射，实际访问再与当前限制目标取交集，拒绝后
不能落入其他 Scope。存在物理出站不等于节点取得互联网出口职责或业务许可。

可信本机消费者沿既有回环认证 HTTP 服务使用 `CONNECT /loom/egress`，以 `X-Loom-Target`
携带规范 `tcp://host:port`。只接受 HTTP/1、强认证、回环监听和无 query 的请求；固定出站必须
保持认证 DNS、原生平台 underlay 绑定及每次实际拨号的公网地址守卫，不使用系统 DNS fallback。
持有同一临时本机口令的消费者本来已可应用整个运行权限投影；此入口是其物理 socket 能力，
不是远端 Service 授权。普通 Mixed／TUN、`source:access`、WG／Hy2 用户及设备资源凭据不能
借它绕过 Policy，也不能取得该本机口令。

建连继承本次 HTTP 请求的取消与原八秒总期限，成功后才交接数据通道；交接后的通道保持原
绝对截止及运行实例所有权，不能因 HTTP handler 返回误关闭，也不能在停止后遗留。停止、取消、
失败仅关闭本次持有的 socket 并等待本次 I/O 退出，不将普通 TCP 半关闭解释为取消。
Go 继续执行原 GET、TLS／主机校验、不跟随重定向、状态判断和前 4 KiB 读取；实际网络位置及
请求／解析规格不变，不改 `egressProbeSpec` 或重解释历史签名报告。

domain、签名 wire、persistent 与 UI 均无新对象或字段：Service／Policy、身份、原签名、认证
进度和报告序列保持；本机 CONNECT 与共享出站只是单向运行投影，不写回 View 或偏好。
最小验证覆盖未授权／错入口／非公网拒绝、建连前后取消与通道退出、普通半关闭、受限目标撤回
后仅关闭失权连接、仍允许连接保持、共享请求与原规格保持，以及 Hy2-only 出口的认证业务 DNS。

### Report 与逐条观测

DeviceReport 字段为 `schema=3,network_id,device_id,report_sequence:U64,view_digest,network_generation,reported_at,`
`selections,observations,runtime,components,signature`，report_sequence 至少 1，签名域固定 `loom-report-v3\0`。
设备在发送前将下一序列与本机身份状态持久保存，重试只重发同一原始报告；崩溃允许序列跳号，不允许复用。
可选 `local_networks:[{prefix:IPv4Prefix,lan:bool}]` 保存本轮只读获得的 underlay 连接前缀，
规范掩码、至少 /8，按 prefix 文本排序去重。`lan` 必填；只有物理接口与直接连接路由均读回
才为 true，其他 TUN/WG 前缀为 false，仍参与地址冲突检测。Loom 自有执行地址不报告。
空数组表示已读回但没有合格前缀，省略表示没有此读回，null 拒绝。
签名覆盖该集合，省略时旧报告原字节不变。它不授予共享权限；只有当前 forward 的报告可用于
创建 LAN Service，且只能选择其中 lan=true 的项；access 的集合仅用于地址冲突检测。
读回失败不能用空集合冒充成功，不能由接口名称或设备职责推断 lan=true。
同一原件、序列和数据库持久化/同步规则适用，不新增 LAN 报告文件或冲突 store。
实际选择与保存意图必须分别报告，不能从其中一个制造另一个。互联网当前意图只包含一条
Policy，由其确定 Service，实际新连接仍须保持该 Policy 和最终出口约束。现存报告的
`selections:[{service_id,policy_id,candidate_id}]` 及 `policy_choices:[{service_id,policy_id?}]`
按原义验签和保全，不能用它们要求新的客户端按服务分别选择。当前意图使用上文规定的
`policy_id` 与独立 `lan_policy_ids`，实际已确认选择仍由 selections 采样，不能从保存意图
制造执行结果。历史 policy_choices／preference 不再用于新报告签发，不重解释或重签旧原件；
报告不授予权限，不增加报告 store。

runtime 为 `state,applied_view_digest,error_code`，另可有 `permission_view_digest`；state 仅 `running/error/stopped/unknown`，
无故障时 error_code 为空字符串，不能承载含秘密的错误正文。运行摘要必须来自实际加载结果，失败时不能将
当前获认证 View 摘要冒充已应用摘要；尚未加载任何 View 时 applied_view_digest 为空字符串。
`permission_view_digest` 只在本实例完整 source／receiver 权限已提交并回读成功时填写，必须等于
本报告 View；不从 LKG 已保存推断，不证明组件、路径或业务已就绪。完整 running 与 applied
一致；资源未齐时仍为 unknown，applied 留空，只有权限确认可继续报告。停止、权限未确认或
失败时不填。缺席字段保持历史 schema 3 原字节与原义，不新增持久权限或重签旧报告。

可选字段保留历史缺席字节，不表示旧严格消费者能够解析新字段。未来经授权发布时，须先更新
承接报告及报告同步／读取的 control 消费者，再激活发送该字段的新 producer；不能反向发布后
自动删掉权限证明绕过拒绝，也不增加兼容解码路径、协议版本或第二份报告。本轮源码和独立验收
不构成生产发布。

独立链路／出口观测可由上述当前权限证明交付，仍逐样本核对职责、资源／请求规格、网络代、
原时间及截止；业务路径、选择、监听／ACL 和整实例应用证明继续要求完整 running 回读。
资源未齐不能令无关有效样本全失效，重复报告也不能为样本续期；原报告的其他 View 字段不进入
测量身份。control 的验签缓存及批量读取必须保留该标量，不能以 UI 状态代替这项确认。
承载 Hy2/WG 的运行报告另有非空可选 `resources`，按 resource_id 排序；纯 access 不写空的替代集合。
每项为 `resource_id,listener_id,listen,certificate_digest,acl_digest`，WG 另含 `public_key`，其中 Hy2 certificate_digest 为证书摘要，WG 固定为空且 public_key 必须匹配资源认证公钥。
旧 Hy2 回读缺席 public_key，保持原签名字节；两种身份不可同时提供。
WG 回读核对已启动精确进程及所有支持地址族的共享端口 socket，只证明执行，不能代替 WG DNS 或业务探测。
listen 仍为实际 socket 的规范 IP:Port；WG 的通配地址是运行回读，不成为精确绑定 IP 的输入。
certificate_digest 是对 Hy2 listener 完成真实 QUIC/TLS 验证所见叶证书 DER 的摘要；
有获授权用户时还须用实际派生凭据完成 Hy2 认证。acl_digest 覆盖本 generation 已交给精确执行制品的
该资源完整规范入站凭据集合，接收 control 重算比较；不把它当单个业务请求成功或全网撤权证据。
只有完整执行已就绪且 applied_view_digest 等于该 View 才可携带这些回读；一般启动失败不填期望值。
旧 generation 已停止且新 generation 尚未完整运行时也为空，不能把上次成功加载的摘要当当前运行回读。
components 使用上述组件坐标，表示实际运行坐标，不复制期望值充数。是否已经设置期望组件不影响
实际回读；未安装、未运行或无法测量的组件不填猜测值。Linux 的 agent 摘要来自当前进程的
`/proc/self/exe`，版本来自该镜像的源码提交（无可追溯提交或 dirty 构建明确为 devel）；sing-box
来自本 generation 已就绪子进程的 `/proc/<pid>/exe`，版本与摘要须从同一个已打开的镜像取得。
平台来自实际执行平台，不从期望复制。切换磁盘路径或软链接而未重启进程，不能使报告变成新文件的摘要。
每个 generation 的测量可缓存在本进程内，进程退出即失效；重启重新测量，不建立组件状态 store。
单个组件无法测量只缺少该项，不抹去其他实际回读，也不把运行故障改成成功。

Windows 同样从实际进程回读 agent 和 sing-box，不按期望列表筛选。此前按期望筛选会在
未配置期望时漏报，且从已验签包直接复制 Wintun 会把 Portable Mixed 未加载的 DLL 算成运行组件。
最小修正只改变 HostAdapter 的测量：启动前以禁止写入/删除共享的只读句柄固定已验签程序文件，
本 generation 结束后释放；就绪后核对受 Job 监督子进程的镜像及已加载 Wintun 模块与同一文件身份。
只有实际文件摘要与原 manifest 相等时才从该 manifest 取版本；agent 版本取实际镜像的源码提交。
Mixed 未加载 Wintun 时不报告它。domain、wire 与报告持久值仍为原 ComponentReadback，UI 按现有
坐标比较；没有新增安装状态或操作者配置。停止释放句柄后可正常升级/卸载，重启重新测量。
最小验证覆盖无期望时仍回读、未加载 DLL 不充数、运行文件替换被拒绝、错误 manifest/退出进程
不伪造组件，以及同机 VM 正常业务、签名报告、重启与停止后的文件释放。
原数据面通过内存 loader 使用内嵌 Wintun，不能用旁边未加载的 DLL 代替其运行证据。源码修订将
Windows Wintun 的唯一加载入口改为 sing-box 镜像目录内已验签的同一个 DLL；显式绝对路径及系统
依赖搜索范围固定，缺失或加载失败即失败，不回到内嵌副本。Mixed 不触发此加载。此变化只修复
交付文件与执行文件的对应，不增加 capture、路由、权限或操作者配置。

Android 的正式入口仍为具名配置的运行报告。此前 HostAdapter 固定提交空 components，不能满足
实际版本回读。最小变化复用 ComponentReadback：agent 的可执行包边界是系统加载的主 APK，
sing-box 的边界是其中实际加载的当前 ABI `libbox.so`；APK 不是某个内部 ELF 的摘要替身。
Android 以当前进程内测量函数的代码地址定位 `/proc/self/maps` 中的执行映射，核对已打开主 APK 的
设备号/inode，并将映射文件偏移对应到未压缩 ZIP 条目内 ELF 的执行段；只知道安装路径或库文件存在不算加载。
主 APK 来自正常 Context 的 packageCodePath，平台来自运行 ABI，agent 版本取该应用内嵌源码提交
（未提供规范提交为 devel），数据面版本取实际 Libbox.version；测量不读期望值。
APK 与库的摘要从同一已打开文件取得，文件身份、大小、修改时间及代码映射在测量前后均须一致。
不接受旧路径、新 APK 文件或另一 ABI 冒充当前执行代码；无法测量只缺少相应组件，不阻断既有报告。
libbox 与共享 Go 核心同处一个已加载模块，其坐标不表示 VPN 正在运行，runtime.state 仍单独报告实际状态。
正常断开在资源清理后通过现有应用作用域提交一次实际停止/错误报告，不随 VPN service 的周期任务一起取消；
读取仍受原运行锁约束，不能预写 stopped 或把清理失败写成成功。报告失败不阻止断开，也不恢复已停止的 VPN；
没有新报告时控制面只保留带原时间的历史回读，不推断仍在运行或已经停止。

对应关系为实际 APK/执行映射 → 原 ComponentReadback → 原 schema 3 签名报告/观察持久值 → 设备版本页面；
没有新的安装权威、配置字段或组件状态 store。当前完整 APK 的直接库映射是唯一已实现交付形态，
未知 split/提取形态不能猜测文件；应用 manifest 未定义前不能从这些运行报告倒写发布期望。
最小验证覆盖无期望时 APK/库摘要回读、另一文件或 ABI/偏移拒绝、文件变化、报告平台约束，以及
原签名 APK 在同机模拟器的真实业务、受保护身份重启与私有报告回读；实体 ABI/切网仍由用户终验。

Observation 字段为 `level,service_id,candidate_id,resource_id,link_id,target,action,spec_digest,`
`network_generation,result,observed_at,valid_until`，可选 `duration_ms` 为非负整数。
可选 `round_trip_ms` 也是非负整数，允许出现在成功的 resource/link `wireguard_dns` 或 resource
`hysteria2_tls` 观测中，并须有 `duration_ms >= round_trip_ms`。前者测量已建立执行 DNS 连接后的
请求/响应往返；后者只读取同次已认证 QUIC 连接实际 ACK 更新的平滑 RTT，不使用 QUIC 初值、
DNS、TLS/HTTP 总耗时或传输字节速率代替。两者是相应传输段的估计输入，包含的处理开销不同，
不是完整路径的 HTTPS 实测；业务结果仍独立校正估计。具体 WG 定义见下文。
字段缺席表示未测量，显式零表示毫秒精度下的实测零；缺席不补值，原有已签字节不变，schema 仍为 3。
可选 `hy2_transfer` 恰含 `duration_ns,rx_bytes,tx_bytes`；duration_ns 是正整数，两个字节数为规范 U64
十进制字符串且均大于零。它只允许成功的 resource `hysteria2_tls` 观测携带，并要求
`duration_ms` 存在且不小于 `floor(duration_ns / 1000000)`。缺席不改写旧报告或旧缓存原字节。
它记录本次真实认证 socket 从首次发送尝试至完成已验链的 233 响应及原有受限正文读取的单调时钟时长，
以及该 socket 实际读写的 UDP 有效载荷字节；包括 QUIC/TLS/HTTP3 开销和重传，不包括 IP/UDP 头。
两个方向均相对报告设备：TX 发往该资源承载节点，RX 由其返回。时长不含名称解析和先前失败地址的尝试，
外层 duration_ms 仍是原完整认证耗时。取消、认证失败及未完成测量不能生成吞吐值。
这只是小量认证探测的实际传输速率，不表示饱和容量、业务用量、Service 成功或新的选路排序输入。
level 为 `resource/link/egress/service`；不适用的四个 ID 字段固定为空字符串，不能缺席。
resource 层仅 resource_id 非空，link 层仅 link_id/resource_id 非空，service 层仅 service_id/candidate_id 非空；
egress 层四个 ID 字段均为空，来源由签名报告的设备身份确定，target 为完整探测 URL，action 固定
`https_request`。它由具备 internet_egress 职责且当前获准执行该请求的来源测量；同出口及相同实际
请求、TLS、解析和出站条件的消费者复用该项，不合并 Service 或 Policy 权限。
每条保留实际 target 和 action。spec_digest 分别绑定资源、Link+资源或候选规范内容。
按 `(network_generation,level,service_id,candidate_id,resource_id,link_id,target,action,spec_digest)` 排序且无重复。
目标为确切 HTTPS URL 或相应传输动作的确切坐标，不能用一个聚合颜色替代。

Resource 层的新样本 action 为 `hysteria2_echo` 或 `wireguard_echo`，只报告当前所选 Policy
允许的公开首跳。target 为资源的规范 dial_host:port，域名不替换成某次 DNS 答案。传输认证按
实际发送节点／资源复用；每次 admission_echo 还显式携带 PolicyID，接收端校验当前来源的首跳
资格。多个入口／出口候选共用同一资源及 Policy 的准入样本，不借另一 Policy 的回显证明准入。
实际在途请求的复用键也必须包含规范测量规格、动作及 Policy；不能只对观测分组区分 Policy，
却让底层共享请求忽略它。规格变化即使仍指向同一资源，也不能取得旧规格在途请求的结果。
WG 准入从本机认证诊断入口经同一 WG 来源访问该资源精确执行地址的固定端口，再发送原生
AdmissionEcho；不先经过要求业务连接上下文的包装。此诊断规则不能匹配普通目标，业务连接
仍须携带并通过当前逐连接上下文校验，不新增凭据、协议或访问许可。

spec_digest 为 `loom-resource-probe-spec-v3\0` 加
`C({policy_id,device_id,resource,dns_servers,credential_digest,request:{operation:"admission_echo",policy_id}})`
的 SHA-256；dns_servers 始终为数组。WG 还绑定 network_id 和该资源内实际 source_address。
credential_digest 为 `loom-resource-probe-credential-v3\0` 加 `C(规范传输凭据字符串)` 的 SHA-256；
WG 此处为实际发送公钥，Hy2 为稳定节点／资源凭据。派生自稳定 View，不从已删除的签名 RuntimeProfile 取件。

Hy2 先完成真实 QUIC/TLS 及登录，再在同一连接执行原生回显；WG 复用实际原生会话，通过自身
执行帧交换回显。响应必须对应操作、Policy 和本次 nonce。登录成功、握手或端口返回均不能
替代准入回显。取消不产生失败；超时和拒绝仅影响这一准入样本，不推断普通互联网整体失败。
duration_ms 为包含必要解析、建连及认证的完整耗时；round_trip_ms 仅为已建连后的回显往返，
不是握手耗时或线路纯 RTT。Hy2 可选 UDP 字节计数与纳秒时长来自同次实际 socket，不代表带宽容量。

消费端不得把该失败当作授权或拓扑失格。先比较当前 Policy 内仍合法的候选及各自诊断证据；
有合格备选时可避开失败诊断所依赖的路径，没有备选时仍可保留合法当前路径，冷启动也可
从合法集合稳定选择实际尝试项。不得仅因全部诊断失败就把普通互联网 selector 写成 reject，
或在图中删除所有失败测量边后声称无合法路径。撤权、资源失格或确实无合法拓扑仍须拒绝；
实际拨号及接收端逐连接检查不放宽，观测和 TTL 不改写，选择不构成 available 证明。
较新的真实 TCP 成功仅能反证同 Policy、候选、执行规格和来源网络代下明确经历的本机首跳
传输负面，且原生事件的实际开始毫秒须严格晚于失败；较早请求的迟到完成不构成恢复。
NativeTCP 的 MetricMillis 是同一原事件结束与开始毫秒之差，反算只还原该原值，不增加时间
字段；未绑定同次起止的 HTTPS 完成与耗时不作传输反证。TCP 成功不能替代 AdmissionEcho、
伪造 HTTPS 结果，或反证逐跳自由选路中未记录实际经过
的远端 Link。目标失败与后台恢复的既有约束继续成立，详见[客户端运行模型](../clients/client-runtime-model.md)。

Link 层的新样本同样使用 wireguard_echo／hysteria2_echo，只有 From 节点可报告。
resource_id 为接收资源；WG target 为其确定性原生执行地址与端口，Hy2 为该资源的规范拨号
域名/IP＋端口。后续 transport_echo 不声明某个 access 的首跳准入，不能与 admission_echo 混用。
当前有向规格为 `loom-directed-link-spec-v3\0` 加
`C({network_id,link,receiver_resource,source_node_id,source_wireguard_public_key,dns_servers})` 的 SHA-256。
原始来源网络代在样本中另行保留，接收与消费方核对相同规格，不把端到端 HTTPS 耗时补成段 RTT。
旧 wireguard_dns／hysteria2_tls 和旧资源对规格仅按原义验证历史原件，不生成新测量或当前运行 fallback。

来源使用固定 WG 公钥而 Hy2 RuntimeKey 单独变化时，当前有向规格还缺少独立的来源传输认证
变更绑定；须与稳定身份字段一起收敛后验证失效，不能把固定 WG 公钥当 Hy2 认证根的替代。

所有测量按节点共享请求率、并发、字节和超时预算。活跃项优先并给最久未测项公平机会；
预算不足延后执行，不能给旧样本续期。当前执行默认活跃周期三十秒、其余两分钟，成功有效期
十分钟、失败三十秒；这是供本地与真机验证的默认值，不是业务授权或固定探测条数。
测量周期、样本有效期和性能最小换路间隔各自独立，冷却期间继续测量。当前 WG 预算仍使用
预留估算，尚未完成 underlay 全字节及实际耗电验收，不据此宣称严格流量上限已经成立。
性能比较复用原样本有效期和来源规格，不另设成对时间差或第二有效期。现有运行内存中已经
达到改善门槛的待确认备选，可与当前路径一起提示本机测量优先级；异步完成、节点总预算、
公平轮转及原采样截止保持。该提示不是 wire 权威值、报告字段或持久用户选择。

本链 HTTPS action 固定 `https_request`；result 仅 `available/unavailable/unknown`。
时间均为 Time，必须 `observed_at < valid_until`；到 valid_until 即失效，接收方不能按接收时间延长寿命。
迟到报告可保留诊断，不能作为当前健康。超出本 View 授权、跨网络代、旧摘要或失效目标同样为 unknown，
不写回 Material。原件的规范解析、验签、持久高水位与历史保留不按当前时钟改变，当前显示另按以下规则计算。

Linux、Android 和 Windows 生成新报告时，完成现有范围处理及整个 Observation 集合的规范、同网络代、
唯一有序检查后，仅复制 `observed_at <= reported_at < valid_until` 的样本；时间由调用方注入，不读新时钟。
所有仍有效候选均保留，包括未选候选、失败和 unknown。原采样缓存、探测恢复排序、时间及截止不改写；
过期非法项也必须拒绝。过滤只发生于报告冻结前，不进入签名器、旧原件解码或发送重试；重试仍发送相同原文。
Android 内部桥接报告时间固定 UTC 三位毫秒，签名 wire 仍为原 Unix 毫秒。报告生成前已经过期且未成功
首报的样本不补入远端诊断历史，这是明确接受的诊断成本；本地缓存仍保留，既有合法过期原件继续可验签读取。

#### 接收端的限时观测投影

目标是让管理员区分当前范围内尚有效的运行回读与原始历史。报告调度与测量调度分开；
resource、link、egress 和 service 的成功样本最长十分钟、其他结果最长三十秒，始终以原截止为限。
原页面因缺少统一上限而全部保持未知。接收端对原报告作限时投影，不增加操作者配置或持久实体；
Linux 刷新频率的交付成本与有限余量见[客户端运行模型](../clients/client-runtime-model.md)。
运行、selector 和组件回读的窗口固定为三分钟，允许常规报告暂时迟到或丢失；超时只降低监控
可信范围，不撤权、不切断客户端业务、不从离线报告推断进程失败。

输入是当前授权/View、每设备最高已接受序列的原签名报告和调用方注入的 UTC 时间。设备与 control
应使用已同步 UTC；允许最多五秒的正向时钟差，用于覆盖本轮只读时钟边界及时间编码精度，
并不证明任意设备永远满足该前提。超过该范围的未来时间只显示原件和时钟待核对，不修改设备或
宿主时钟。报告内采样时间超过报告时间五秒也不能参与当前结果；合法原件仍保留，避免时钟回调
破坏签名历史。原始时间不会因接收、同步、重复报告或重启而重写。

1. 报告须已通过当前身份、公钥、View 与规范范围验证；不在有效范围的报告只保留历史。最高序列
   报告失效时不能回选旧报告。`reported_at <= now + 5s` 且 `now < reported_at + 3min` 才提供
   当前运行回读。报告本身不证明整机业务健康，也不证明此刻仍保持一条管理连接。
2. 逐条样本还须来自报告为 running、已应用同一 View 的执行，匹配该报告的网络代和当前资源、
   Link 或 Service/候选、实际目标、动作及规范摘要。停止或应用失败报告携带的旧样本只作历史。
   `observed_at <= now + 5s`、`observed_at <= reported_at + 5s`、`now < valid_until` 同时成立，
   才继续核对原窗口长度。当前工作区展示校验对 resource/service/link/egress 的成功窗口使用十分钟上限，失败或 unknown
   使用三十秒上限；它们是读回校验范围，不是测量周期、换路冷却或当前部署已支持全部层级的证明。超过上限时该样本不作为当前证据，不能裁剪原文后把它当合格样本。
3. 合格样本的展示截止为 `min(valid_until, reported_at + 3min)`；原 valid_until 到期即失效，
   五秒容忍不加在截止时间上。当前已失效的样本不得因另一个报告的接收时间续期。新报告携带同一
   尚有效的原样本时，只能恢复报告范围，不能越过样本原截止。
4. 各层分别归约：Link 只使用其 From 设备对该 Link 的样本，resource 只说明相应凭据的入口结果。
   Service 的测试集合仍须保留逐目标结果；若汇总全部成功、全部失败或混合/缺项，必须标明
   “所测网址”范围，不能将该汇总显示为整个普通互联网的可用性。空集合为 unknown。
   选路按客户端模型的默认覆盖优先、目标各自优选及固定出口只比传输执行，不能从页面汇总反推算法。资源或链路成功不能补足业务样本，
   一个 Service 的结果也不能变成整机健康。当前选择只由有效的 running、已应用同一 View 的
   selector 回读形成；历史 reported selection 继续保留，两者不互换。

domain、签名 wire、persistent 仍是原 Report 与 Observation，规范 schema 3、签名字节及原寿命
完全保持；runtime 是以上输入与 NowUTC 的纯计算。Web 的报告时效、逐条样本截止和路径状态只是
单向投影，可删除重建，不能接受回写；客户端本地的采样、缓存及选择窗口不由这些页面值倒写。
浏览器以同一 UTC 前提核对时间，只能缩短服务端给出的有效范围或在截止后显示未知；
不能把被服务端排除的样本自行恢复为当前。报告仍有效而某条样本时间待核对时，该样本及其依赖的
路径或 Link 当前结果一并降级，不能在两个页面保留互相矛盾的可用结论。
页面长开或实时连接中断时仍应到期降级，并保留编辑草稿、焦点和原始时间；浏览器用单调经过时间
防止本地时钟回调延长已接受的截止，不因此新增网络请求或反向恢复已排除的证据。
单调经过时间的基准属于本次已接受的服务端投影。下一份经服务端重新核对的投影到达时，以当前
浏览器 UTC 重新建立基准；浏览器时间曾跳到未来再纠正，不能让旧错误基准永久排除后续有效报告。
仅本地时钟恢复、旧页面重绘或计时器触发不能恢复已排除样本，服务端已排除的值也不能借此复活。

正常链为真实业务与 selector 回读 → 设备原签名报告 → 当前 View 验证与原件持久化 → 限时页面
投影 → 到期显示未知 → 同身份后续真实报告恢复。时钟修正会改变时间条件的判断，原采样、序列与
签名不因此改变；时效规则依赖上述 UTC 前提，不把签名有效当作时钟准确的证明。反例是原成功样本
尚有数分钟有效期但设备已长时间不再报告：当前运行和路径必须变为未知，历史成功仍可查看。
另一反例是设备给出极远的截止时间：原件可验签和保存，但不能因此长期显示当前可用。
最小验证覆盖各截止边界、超长及未来时间、范围与多目标归约、最高序列失效、原字节重启保全，
以及真实浏览器中的报告中断、自然到期、同身份恢复和草稿保留；不得新增 receipt store 或按接收时间续期。

接收者按当前设备授权、公钥、签名和规范值验证报告；按设备持久高水位比较 report_sequence。
同序列相同原始字节幂等；同序列不同字节拒绝并保留证据；更低序列不能覆盖最新报告。
诊断历史过期不能删除最高已接受序列对应的签名报告；最新索引从这些原始值重建，不按接收时间排序。
#### 报告原件的事务持久化

目标是持续接受真实运行报告，保留原件、高水位及全部分叉，并让成员补齐与进程重启继续成立。
原实现把所有原件合为一个规范 JSON 文件；即使消除重复编码、验签和解析树，集合仍会触及
单个输入的 64 MiB 上限而永久拒绝新报告。增大常数、删历史、缩短报告或降低采样频率都不解决
这个存储与生命周期不一致的问题。最小变化只替换原件集合的物理容器，不改变业务对象或协议。

唯一权威值仍是规范 schema 3 DeviceReport。`observations.db` 的 `reports` bucket 保存原件。
键为 `network_id || NUL || device_id || NUL || uint64_big_endian(report_sequence) || SHA256(C(DeviceReport))`，
值恰为原规范字节；签名、序列、身份、全部分叉与认证高水位均保持。当前最高位置、防重放和分叉
直接从原件 B+ 树定位，不另存 latest 或 floor。已有 control 缺库失败关闭，不初始化空历史。

正式在线 writer 只有现有 control daemon；设备上传与成员合并使用同一事务入口。daemon 持有一个
数据库句柄，退出时关闭；短读事务与串行写事务由数据库隔离，读取不占用写入许可。写者等待可
取消。控制服务取消或因监听失败退出时，先取消本实例的 HTTP 请求上下文，包括管理 live 与
设备配置等待，再沿原有 HTTP 关闭流程和 Runtime.Close 释放报告 owner；请求上下文不持久化，
服务退出不等于设备撤权或业务流停止。事务失败不留下部分原件或索引。启动核对受保护普通文件与 bucket，运行中核对文件身份以
拒绝原路径被删除或替换；不再为每次查询重新打开、映射和关闭数据库。迁移仍停服，第二个在线
数据库 owner 必须明确失败，不能通过进程级句柄 registry 接管。打开时允许短暂、有界地等待
已退出 owner 的内核文件锁释放；持续持锁则失败，不接管、不无限轮询，也不影响运行期短事务。去掉为逐次打开所设的共享／排他
许可、重复文件锁轮询及全量内存目录，不改变正常 UI/CLI 入口，也不增加操作者步骤。

原库增加一个可删除重建的 `report-index` bucket，保存三种基础定位：内容摘要到原件键、设备与
时间及链路规范到原件位置、序列范围到原内容 ID 集合摘要。基础定位没有签名、公钥、权限、最高序列、完成状态或
独立生命周期。时间索引分别使用原 reported_at、counter observed_at 和每个 Observation 的
observed_at；按原时间定位，不假定设备时钟单调。链路查询另以原 LinkID 与 SpecDigest 定位同一时间；一个原件的重复观测时间只生成同一个定位键。
基础定位不能用于证明原件有效；消费完整原件仍核对实际正文摘要、规范键和值及相应设备公钥。

同一索引下的 WG 派生子 bucket 由完整原件键定位，值只含原 network_generation、reported_at、可选
wireguard_counters 及实际验签使用的规范设备公钥。每份原件恰有一行，包括无 counters、分叉、未来及
历史撤权身份；与原件同寿命，不新增保留策略、赢家或 floor。公钥只供与当次已认证身份键精确比较，不能赋予身份，
也不是独立密码学证明。唯一 writer 完整验证原件后在同一事务派生，投影不可逆，只能由原文删除重建。

WG 行使用紧凑字段编码；同一子 bucket 内以内容摘要共享重复的静态字段，减少每次查询必须读取的页。
这只是上述可删除索引的无损物理表示，原件、签名输入、schema 3 wire 和完整原件键不变。
静态布局包含 network_generation、实际验签公钥、counters 存在位，以及存在时的 interface、epoch、
完整有序 peer 公钥及各 peer 的 LinkID/SpecDigest；存在位只能为 0/1。布局键为单个 NUL 字节后接
其规范字节的 SHA256，与禁止控制字符的原件所有者键不相交。布局不含虚构时间或计数，不拥有身份、
权限、进度、保留策略或独立生命周期，只是这些采样行共同引用的字节。每份原件的行仍以完整原件键定位，
依次保存布局摘要、reported_at，以及有 counters 时的 observed_at 和按布局顺序排列的各 peer RX/TX。
无 counters 与有 counters 但 peer 为空必须区分；时间和计数保存绝对原值，不保存差量。
公钥与摘要使用原始 32 字节，epoch 使用原始 16 字节；整数与集合长度使用最短无符号 varint，
时间仍须属于原 int64 毫秒范围。
interface 使用长度前缀 UTF-8；ID 使用单字节长度与原 UTF-8，长度 0 唯一表示后接 32 字节
SHA256 摘要，普通 ID 仍须满足原 128 字节边界且不能另编码同一摘要。空集合与可选缺失保持原义。
布局与行重构的值满足 `DecodeIndex(EncodeIndex(P(report))) = P(report)`，接受的布局与行字节也必须满足反向等式；
截断、非最短整数、未知存在位、越界长度、非法或乱序字段、尾随字节均拒绝。分配集合前按剩余
输入与每项最小字节宽度检查数量，再执行原字段验证，不能让短输入放大为无界分配。
唯一 writer 在原件验证后，同事务生成规范布局和采样行；布局摘要已存在时必须逐字节相同，否则拒绝。
短读事务同时复制采样行及所需布局，退出后完整重构原投影再运行原算法；事务内与当次查询内可有界复用
相同不可变布局，不新增跨请求缓存。缺布局、摘要不符、非规范布局或行、重构字段非法均使当次查询失败。
布局变化本身不能切断区间：仅 Link/spec 改变时设备总量仍按原规则连接，Link 范围则仍核对区间两端绑定。
共享布局损坏可能影响多行，不能以当前配置或其他布局补齐。原件未被删除，布局随整体重建清理，
不增加引用计数、后台清理或报告保留策略。
WG 子 bucket 的写入与重建使用固定 0.9 页填充率；不改变原件 bucket、时间索引、序列语义或统计算法。
历史定位按选中序列的稳定顺序查找，避免无序集合引入随机寻址；仍保留最高位置及全部相关分叉。
旧 JSON 或逐行重复静态字段的派生行不进入当前读取，不保留双解码路径。已有非空旧布局须明确拒绝启动，
提示正式离线重建，不能以启动时隐式转换或预热掩盖首次访问成本。部署须在正式停服锁与原件保全后显式执行
`prepare-report-index --rebuild`，完整验证原件并原子替换该子 bucket，再执行 `--verify` 后启动。
失败或取消保留原库，不改变签名原文和认证进度；新增操作成本是这次派生索引的受保护完整验签重建及停服窗口。
静态字段每次都变化的合法输入可能无法减少空间；以受保护同输入副本的大小、冷读和输出等价实测判断收益。

索引与新原件在同一事务内提交，只更新本批涉及的 ID、时间位置和序列范围摘要；一个新报告
不能触发全库目录复制、重建或验签。目录读取只遍历范围摘要，取 ID 只遍历请求的序列范围，
按内容 ID 取件直接定位原件。范围摘要仍以原有规范排序的完整 ID 集合计算，wire 不变。
索引 bucket 缺失时，在一个事务中从原件生成；中断回滚整个索引构建，下次可重建。已有索引由
唯一 writer 事务维护，正常读取不重新全库证明其完整性；需要检查整库时使用明确的离线检查，
不让页面或新报告承担这项工作。未知 bucket 或损坏的实际消费原件仍失败。

新报告在事务前核验规范值、签名及输入界限，事务中读取本批所有者的最高位置与输入位置，
每个位置包含全部分叉。未知低序列直接上传拒绝；成员补历史允许，不能覆盖当前最高值。
同序列相同原件幂等，同序列异文保留全部证据且不选赢家。提交成功后才确认，磁盘满、取消和
校验失败不确认；不确定提交按相同原字节重试。原件 bucket 的改变与定位更新原子生效。

历史查询在短事务内按所需时间窗口定位原件，额外固定该设备的最高位置及入选位置的全部分叉；
随后按序列倒序、有界复制原件，释放事务后解码、验签和统计。索引时间与链路范围仅用于排除
不可能改进当前小时桶或近期统计的原件；最高位置与分叉仍须回读，除 WG 派生读取外入选样本只来自原件。基础索引只缩小读取范围，不提供可展示
样本；最高位置损坏失败，最高位置分叉不回选旧值。查询开始后的追加或分叉由下一次查询体现。
时间窗口外位置不成为统计样本；流量只连接连续报告序列，跳过的位置与分叉不能被跨过拼接。
消费完整原件时，选中原件缺失、换文、损坏或取消使查询失败，不从缓存恢复正文；WG 的读取信任边界如下。
运行状态、Link、路径和流量仍
沿原时间、网络代、规范及授权规则投影，页面形式和指标含义保持。

同一原件通过规范检查与密码学验签的结果使用有界、按完整正文摘要及验证键区分的内存缓存，
不缓存完整报告对象；命中规范检查结果时只解析同一原字节，不重新证明其规范编码。每次
消费仍先从当前事务取实际字节并核对摘要和位置。缓存不保存当前授权、时效或健康判断，删除后
结果相同，不能遮蔽撤权、分叉或原件损坏；缓存容量不随累计历史无界增长。
同一次历史遍历对每份实际原件只计算一次内容摘要，完整读取所需的规范解码最多一次，位置核对
和后续验签复用这一份临时值；验签仍绑定本次要求的精确公钥。该值只在本次遍历中使用，
不进入跨请求缓存，
也不把先前公钥下的成功认证用于新身份。分叉和序列缺口仍切断流量区间，正文损坏、位置不符、
取消及无效签名的原拒绝规则不变。domain、wire 与 persistent 均保持原 schema 3 报告，runtime
只省去同原件重复解析与哈希，UI 仍消费同一历史投影。最小检查覆盖冷/热缓存结果一致、换键
拒绝、原件损坏、分叉/缺口与取消；以相同输入的查询耗时和分配量核对实际收益。
验签 proof 未命中时，从这份已经完整规范校验的原文移除唯一顶层 `signature` 字段，得到与
原 `C(unsigned(DeviceReport))` 完全相同的签名消息，再按原 domain 和精确公钥执行 Ed25519
验证；不再次构造或校验同一完整值。必需字段、可选字段及嵌套签名字段的原始规范字节均保留，
非规范原件或未知字段仍在此前的完整校验中拒绝。该消息只供当次验签，不保存正文或跳过密码学验证。
WG 历史直接读取上述小字段投影，不逐次读取、哈希和解码全部历史正文。每请求按当前授权、精确公钥、
真实查询时间及原算法处理窗口、最高位置、全部相关分叉、连续序列、epoch、时钟回调与覆盖；窗口时间索引
或最高真实原件集合明确定位的投影行缺失，以及实际读取的投影编码或字段无效，必须当次失败，不能补零。
短事务复制小字段后释放事务再计算，不增加跨请求统计结果缓存、小时聚合
或追加快路径。原件仍是唯一权威，投影不是完整 DeviceReport，不能交给其他原件消费者。
普通历史位置与分叉从这些完整原件键对应的小行定位，不能仅为检查位置再次触及大原件页；最高序列及其
全部分叉仍从真实原件定位并完整校验，缺失最高分叉的小行不得产生可用赢家。
此读取边界明确接受普通历史原件及派生投影的事后完整性异常可能延迟至离线完整性检查或重建发现；
例如不被本次时间窗口指向的非最高分叉派生行选择性丢失，可能无法由本次统计发现。
完整原件读取仍执行原拒绝规则。
最小检查覆盖原算法对照、无计数、U64、间隙、分叉、换代、未来、时钟回调及重启。
只需身份位置及三个运行标量的读取，在短事务内先计算实际正文摘要，再查询同一缓存；命中时
不复制整份正文，未命中才复制并在事务外完整解码和验签。两条路径均验证实际摘要、位置及
本次允许的精确历史键，不在事务内增加解码、验签或长窗口计算。
缓存内相同的历史身份及三个运行标量只保留一份不可变字符串，由引用它们的 LRU 项共同持有，
最后一项淘汰时释放；清空缓存同时释放全部共享值。条目、链表、映射、共享值及字符串的保守
空间计量都归入原件校验的 14 MiB 上限，不缓存报告正文；只有 WG 小字段投影携带实际验签公钥。

既存库缺 WG 子 bucket 时，以已认证历史键完整验证全部原件并原子生成。历史键来自已接受普通前缀的
设备绑定及认证成员证书链，覆盖初始/后来纯 control 身份和已撤权身份；冲突、缺键、Pending、Invalid
或前沿外材料不能用于补权，不尝试所有键直至验签成功。重建不恢复历史身份当前权限。
正式停服入口仍为 `loom control prepare-report-index`；无参数保留既有准备行为并补齐缺失 WG 投影。
互斥的 `--verify` 只读完整核对原文规范、实际摘要/位置、精确历史键签名及 WG 行和布局的缺失/多余/不一致，
包括无原件引用的孤立布局；
`--rebuild` 执行相同原件验证并以单事务替换 WG 子 bucket。监听锁、报告锁及数据库独占门禁沿用，
失败或取消回滚，原件、接收附注及旧投影保留；不宣称修复其他基础索引。部署前在受保护副本测量空间与耗时。

domain/wire 仍是原 schema 3 DeviceReport 与既有成员交换；persistent 的原件字节不变，新增 bucket
仅为原件的单向定位及 WG 小字段投影；runtime 使用同一数据库的短事务、窗口查询和有界缓存；UI 保留现有业务
回读。没有新权威实体、协议版本、双写 store、配置或保留策略；所有既存原件继续保留。

最小验证覆盖正常上传与成员批次原子提交、重复/低序列/分叉、损坏原件、写入取消和失败、
读统计期间新报告提交、时间回调和窗口/序列间隙、索引删除重建、正常关闭及重启原字节保全。
相同历史副本对照目录、当前读取、历史页面并发与报告批次的耗时和分配量，再沿正式成员通道和
真实页面回读；生产部署以精确制品和原件保全证据验收，不以索引生成或单项测试作为完成。

从当前 schema 3 集合切换必须显式执行 `loom control migrate-reports`，不在 daemon 启动时猜测或
兼容回读 JSON。迁移前停止对应 control，取得同一报告写锁，核对当前权威和所有原件签名，将原
集合逐字节保全到操作者指定的受保护证据路径。独立生成并重新读取数据库，逐条比较原规范字节、
总数、内容集合、高水位及分叉；全部相等才原子发布数据库，再比较并删除原 JSON 运行入口并同步
目录。迁移前后 DeviceReport 的解释完全相同，不重签、不改变序列或协议号。中断前只有旧集合时
可重试；两个容器同时存在时 daemon 拒绝启动，显式迁移只能在逐条相等后完成原入口删除；新容器
已写入不相同集合时拒绝继续迁移。证据不作为运行 fallback，旧集合 writer 与启动 reader 同项删除。

映射为：domain/wire 是原 DeviceReport；persistent 的权威值是 `reports` bucket 中的相同规范原件；runtime
按原件派生高水位、交换索引及当前报告；UI 沿原授权、View 和采样时间显示，不改变健康语义。
反例是“数据库存在但缺报告”或“相同序列换签名”：存在性不能证明迁移完成，同位置必须保留所有
不同原件。最小验证覆盖超过原总量上限后的正常追加与重启、逐条原字节及高水位/分叉保全、两个
writer、批次中途失败的原子性、非法键值与签名拒绝、迁移中断重试和双容器启动拒绝，以及正式
设备上传、成员补齐、真实页面回读、生产持续确认及重启。只有这些路径通过才算容量问题闭环。

报告序列只用于报告重放边界，不能当控制事实 floor、配置完成或全网传播证明。
普通 access 的接收响应仅为 `schema=3,report_sequence:U64,status="accepted"`，在认证私有通道返回；
只表示该签名报告已持久接受，不表示业务成功、配置已应用或其他 control 已收到。
服务节点报告的 listener、ACL、实际进程和返回路径逐项字段还须按现有运行回读入口补齐；
不能省去这些结果后宣称 schema 3 服务节点运行状态已可验证。

本链可用单目标、单候选验证真实运行、改权和撤权；这不规定多目标结果归约。
同 Service 多目标混合的页面摘要保留为 unknown；选路使用逐目标结果、默认覆盖与分段代价，
不得把首个目标、最新样本或传输成功当作整个 Service 的业务状态。

报告库的本地接收时间只服务于 [Events 的原件查询](../clients/web-ui-projection.md#events-的查询与原件接收时间)。
同一数据库的 `receptions` bucket 将原件键映射到首次接收 UTC 纳秒（8 字节 big endian），
`since` 是启用该本地附注的覆盖起点；原件、附注和 `report-index` 中的接收时间定位同事务提交。
它不保存事件内容、签名、权限、高水位或独立序列，不进入 report wire 或成员交换。删除索引可按
原件及附注重建；接收时间本身不能从设备采样时间重建，既存无附注原件保持未覆盖而不补造。
Material/成员证书使用同一受保护原文件 inode 的首次接收时间附注；签名原字节、规范 schema、
身份及既有认证进度均不变。此本地存储前向修订不恢复旧容器、双读或另设事件权威。

#### 设备相关测量的批量差量交付

设备沿现有私有认证入口 `/device/link-observations` 一次领取相关有向链路及出口测量，
不按 Service 分别请求。请求为 `schema:3,view_digest:Digest,cursor?:Text`；cursor 是
1～128 个 ASCII 字母、数字、`-` 或 `_` 组成的不透明引用，首次请求省略。
响应保存 `schema,network_id,device_id,view_digest,cursor,reset,removed,observations`。
reset 为 true 时 observations 是当前有界工作集的完整批次，removed 必须为 `[]`；否则两者
分别表示该工作集的更新与删除。工作集不声称包含全部获授权测量；未交付或过期项保持 unknown，
不改变权限、原件或原截止。调用方以本次请求所用的完整缓存合并差量，不使用另一设备、View
或并发请求的缓存替代。

测量项身份绑定原来源、level、来源网络代、resource、link、target、action 和规格摘要；
报告序列及报告摘要仅引用原件，不参与测量项身份。同项不能在一份差量中既删除又更新；
重复、未排序、删除未知项、无完整缓存时应用差量及错误接收范围均拒绝。删除和缓存丢失只丢弃
观测，不改变授权。已过期项不参加选择；收到重复报告或领取响应均不能重置原采样时间或截止。

control 在读取报告前，按当前授权范围与稳定查询坐标限制本次扫描、查询量、来源与字节；不先展开
全部来源、资源与网址的乘积后再截取。有限预算下公平轮转，暂无样本的项也推进位置。近期签名
报告可提供有限的软优先，不能被当作实时当前 Policy，也不能排除或饿死其他合法项。Service 与
网址的授权数量不由内部交付预算限制；规模增大可以降低更新频率，不能给旧样本续期。

现有不透明 cursor 由精确工作集的随机引用和固定长度的非授权轮转提示组成，不增加请求字段。
引用仍绑定设备及 View；提示只决定重新验证范围内的检查顺序。失效、切换 control 或重启后
返回 bounded reset，仍可依据提示继续轮转，不能永久回到首页。空页与未知页也进位；不依赖
时钟取模，否则领取周期可能使部分项永久饥饿。提示不是权限、样本、旧快照或第二份权威。

W 可保留先前已经验证、仍在原有效期且属于当前 scope 的行，与本页结果组合；否则链路页与出口页
可能始终无法同时参与路径计算。本页明确查到消失、规格或来源网络代变化时，删除相应旧行；
已知新来源代不与其旧代混用。没有检查的行只保留原期限，不声称重新验证；报告沉默不剪短
原样本寿命，Web 的报告年龄不参与选路。优先接纳本页有效
结果，容量不足时再从未被本页查询的旧行中淘汰；不能让较旧但仍有效的本页结果每次自淘汰而
永不交付。cache miss 从当前页重建，不借失去的引用恢复旧 base。

报告原件的读取与复制另有本次字节预算，同一原件在本轮复用，来源 head 的成本范围须单独
说明。不能把响应字节上限声称为总堆内存上限。达到预算时保留下一未处理查询的位置；能够
独占一页的有效行仅因页尾空间不足时必须在下一页重试，不能每轮跳过。没有样本才按已检查
进位。查询边界、原件和位置都是本次临时值，不新增报告权威、持久对象或管理流程。

先选定完整工作集 W，再由精确旧 W 计算差量。换出使用原 Removed；更新加 Removed 超出响应
预算时，发送新 W 的完整有界 reset，不截断差量。单份 W、最终规范响应与客户端累计快照分别
检查字节预算；新返回的 cursor 必须能保留对应精确 W，不能因该 W 本身超限立即自淘汰。缓存
总容量仍可淘汰旧引用，所有条目均可删除重建，不新增持久缓存。

客户端只在临时结果的 scope、排序、删除关系及完整规范字节均验证后，一次提交 snapshot 与
cursor。取消、换 View、超限或非法差量均保留原 base 与 cursor。不能自行裁剪 base 或删除到期
行后继续使用原 cursor；仅在运行投影时忽略到期项。服务器构造和编码在共享短锁外进行，锁内
只读不可变快照及插入、淘汰。原签名报告、既有报告数据库和配置 View 仍各自保持原职责。

domain 与签名 wire 不增加权威实体；persistent 原件不变；runtime 是可删除的查询位置提示、
工作集与缓存；UI 仍按收到的原时间显示，缺项为 unknown，不增加页面或操作。

最小验证覆盖：小响应累计超限的原反例；W 均合法但差量加 Removed 超限时 reset；客户端拒绝
超限且原 base 不变；每次 cache miss、空页和未知页仍遍历全部稳定查询；软优先不饿死轮转；
跨页链路与出口能够共同参与组合、页尾有效行不被永久跳过、原件读取达到预算后从未处理项续行；
重复报告与领取不续期；撤权、换 View、规格变化与精确删除；正式认证 HTTP、原签名报告、共享
领取及运行消费的一条正向链。
本节规定当前改造的交付语义，不表示分段选路及真实业务验收已经完成。

#### 共享测量的原件定位与跨报告保留

测量结果按测量项保留最近观测，不以“最高序列报告中出现了哪些项”判断整个测量集合。
报告 observations 可以只携带本轮完成的新样本；空集合不删除以前仍有效的样本。运行、组件和
当前选择继续由最高无分叉报告读取，不能从低序列恢复已停止或已失败的运行状态。

发送端只用有界、可删除的内存摘要集合去除已经获现有报告 ACK 确认的相同样本；摘要绑定网络、
设备公钥与完整原 Observation。先过滤、后签名，同一次报告重试始终复用同一原文。失败、取消或
错序 ACK 不记为已发送；并发请求可以重复携带尚未确认的样本。缓存淘汰和重启最多增加重复交付，
不能删除唯一原件、改变采样时间、降低报告序列或成为完成依据。此缓存不增加持久字段或交付回执。
Web 的测量集合也从同一原件定位读取，不能用最高报告的省略项覆盖它。

既有 observations.db 的 report-index 增加可删除重建的 measurement-items 子 bucket，只保存
原件位置。定位键由报告所有者、来源网络代、测量规格元组摘要、倒序采样时间及完整 Observation
摘要组成；值是已有报告原件键和其中的样本序号。规格元组包括 level、Service/candidate、resource/link、target、
action 和 spec_digest。相同样本在多个报告中出现只保留一份定位，选择最小原件键，不形成新测量。
同规格、同时间出现不同样本时不能按报告序列择一，当前结果为 unknown。

原件与定位同事务写入。子 bucket 缺失时在启动或正式离线索引入口的单事务内重建，不增加索引
版本、独立序列、权威值或运行扫描 fallback。消费时回读实际原件，核验规范值、签名、原件键及
样本定位；索引不能制造结果。没有匹配项时返回未知，不根据 URL 数量填充成功或失败。

领取相关样本时按当前测量规格定位，而不扫描所有报告或只取最后一份报告。来源最高报告须无
分叉、仍属当前身份且完整权限应用确认有效；确认来自原 running／applied 回读或上述部分应用的
permission_view_digest，不能接受未确认权限的 unknown。样本须匹配该来源当前网络代，原产生
报告也须具备相同资格。当前角色、资源、Service/Policy 和实际测量依赖分别再校验。无关 View 改变不废弃
依赖未变的原样本；保留原报告摘要和 View 绑定，不修改其字节。样本自身的原有效期始终不续期。

最小验证包含新报告省略仍有效项、重复旧样本、晚到报告和同时间冲突、来源切网/停止/分叉、
原件损坏、无关原件不被查询读取，以及删除定位后重建与原件逐字保全。

#### Events 运行变化的候选位置

目标是查询完整窗口、连续加载与导出时，不再为了少量运行变化读取窗口内每份相同运行值的报告。
原件已经持久化在 bbolt；增加内存或再建事件数据库不能消除重复工作。最小变化是在既有
`report-index` 内增加可删除重建的 `event-candidates` 子 bucket，只定位可能产生运行变化的原件。
它不保存运行值、事件内容、签名键、验证凭证、权限或完成状态，不是第二份报告或事件权威。

索引输入是已接受的原件位置、原规范报告的 `state/applied_view_digest/error_code` 和本机原接收附注。
所有者固定为 `(network_id,device_id)`，位置为所有者与报告序列。对于一个位置，按附注时间排序：
只有第一份原件可能在某个查询截止前唯一；其唯一截止区间为 `(first_at,second_at]`，没有第二份时
上端无界，同时间并列则区间为空。这里 `until` 不含等于它的附注，故上端闭合。没有附注的旧原件
在所有截止前都参与分叉判断：恰好一份时它作为前驱的区间为 `(-∞,first_annotated_at]`，多份时
没有唯一前驱；旧原件本身不生成接收事件。不能按采样时间或到达顺序假设序列、时钟单调。

有附注的唯一赢家满足以下任一条件时才保存候选位置：它是该所有者全库最小序列的基线；或它与
紧邻 `q−1` 位置的唯一赢家区间有非空交集，且三个运行标量不同。区间只在边界接触不形成交集。
这只是所有合法 `until` 的候选并集；实际查询仍回读该截止前全部分叉、全库最小序列及紧邻前驱，
按既有规则决定是否产生事件。`from` 只筛当前原件接收时间，前驱可在窗口外。晚到低序列会改变
原有全库最小序列规则，不能给旧位置永久保存基线。历史身份集合仍由查询原事实决定。

子 bucket 的正向键为 `e || network_id || NUL || reception_time || original_key`，值为空；
反向键为 `p || owner_prefix || sequence`，值是相同正向位置键，仅用于同事务替换和删除。
新增原件、附注与索引同一事务提交；每批只精确重算新增的 `q`、`q+1` 以及各所有者变更前后
最小序列，U64 最大值不计算溢出的后继。重复交付不改附注。重算可以删除旧候选，保证任意
合入顺序与完整重建的定位相同。没有额外版本、进度标记或持久查询状态；子 bucket 缺失时启动
在同一事务构建，中断全部回滚，reader 不把缺索引当空结果，不运行旧全量扫描 fallback。

构建按位置流式读取原件键和附注，仅对可能成为赢家的当前值及紧邻前驱完整规范解码并核对原件
摘要和存储键；不把构建结果当成密码学证明。查询消费候选当前值与实际前驱时，仍从实际原文
重算摘要、规范解码、完整领域校验，并按该查询的历史公钥核验签名和存储位置。单原件的规范
解码、验证与验签拒绝规则不变。索引排除的相同运行报告不再被每次查询消费，因此不承诺查询
发现未消费原件的损坏或缺少其历史验证键；整库完整性核查属于明确离线操作。合法原件集合的
事件、完整桶、分页与 CSV 必须与逐报告投影一致，不能从候选键构造任何可展示值。

对应关系仍是原 `DeviceReport` → 原规范字节及接收附注 → 可重建位置 → 实际原件核验 → 既有
Events UI；只有原件规范字节需要可逆，索引和 UI 均为单向投影。数据库 owner 停止后可用
`loom control prepare-report-index` 对既存库执行同一初始化，取得实际管理监听锁、报告锁和
数据库独占锁；不创建丢失的原库、不读取旧 JSON、不触发业务执行，也不改身份或原件。
部署新增成本仅是已有 control 分组重启前的一次离线索引构建，后续报告增量维护，无新配置。

最小验证覆盖不变与三字段变化、窗口边界、乱序及缺前驱、迟到分叉、同时间并列、接收时钟回调、
无附注旧前驱、晚到最小序列、U64 上界、取消回滚、索引删除重建和原件附注逐字节保全；实际
消费的候选/前驱损坏或错误签名仍拒绝。真实历史副本对照全量结果与冷/热耗时后，沿正式上传、
成员合入、重启与浏览器分页/筛选/导出验收。不恢复内存全库目录、持久事件正文或旧快照事件。

#### control 成员之间的报告差量

目标是设备向任一可达 control 上传后，其他有效成员能够读到同一原始报告及保留的历史。成员沿既有
认证通道补缺失的 DeviceReport，并合入上述唯一原件集合；不恢复旧认证头部、旧 reportRecord
或另一份报告库。没有新增操作者配置，也不改变设备报告、接受响应或原件字节的解释。

报告内容 ID 为 `SHA256(C(DeviceReport))`。只交换最高序号会漏掉等高历史缺口和同序号
分叉；原来每轮交换全历史目录、新报告触发整组 ID 重传，也不是查缺所必需。最小修正是从
同一原件集合派生稀疏二叉摘要树，只展开不相同的子树。没有新权威实体、同步完成状态或操作者配置。

序列 q 的树坐标为 `q-1`。Scope 固定为 `{device_id,first_sequence,height}`：height 是 4～64
的整数，first_sequence 为规范 U64，且 first_sequence-1 对齐 2^height；height=64 时起点只能为 1。
叶 height=4 覆盖最多 16 个序列位置，最后一个叶可包含 U64 最大序号；不枚举空位置，不做上界加法。
叶摘要是按内容 ID 升序的原件 ID 集合的规范字节摘要，分叉的各 ID 均保留。非空父节点摘要是
`SHA256(C([left_digest,right_digest]))`，空孩子用空字符串；两孩子均空时父节点不存在。
每台设备根为起点 1、height=64；最高非空叶只是最新报告的传输优先提示。

摘要树仅是原数据库中的可删除派生索引：原件与受影响叶及祖先在同一事务提交，首次建立或删除后
从与原件同事务维护的内容 ID 定位索引重建；该索引缺失时先沿原路径从原件重建它。
不为摘要树再次读取全部历史正文；按 ID 取件和 UI 消费仍逐件核对原文、
规范编码和签名。原件字节、高水位和接收时间不变。旧大范围索引在前向初始化中先收集精确键再删除，
已有新树时也清除遗留项；不能在删除后直接移动游标而漏掉相邻键，不保留
第二套交换路径。每个请求使用一个已提交读事务，不跨请求持有事务；并发新增由下一次求差补齐。
不保存成员游标、远端目录副本或传播完成回执。数据库读取失败不能返回缓存的成功值。

domain、签名 wire 和 persistent 权威仍只有 DeviceReport 原件；上述摘要索引、请求范围及缺集均
为单向派生，可删除重建。UI 仍从原件按当前授权、View、候选及采样时间投影，不把摘要或取数成功
当作可用性。只有原件与规范签名值要求往返；树不能反推授权或健康，也不制造报告序列 floor。

成员端点沿现有 `/internal/` 当前成员 TLS 门禁，管理员 socket、浏览器及设备通道不能调用。
同一 schema 3 的现行内部交换如下；Summary 是 Scope 加 digest，RangeIDs 是 Scope 加
`children:[Summary],report_ids:[Digest]`。

| 正式内部入口 | 规范请求与响应 |
|---|---|
| `GET /internal/report-ranges` | 无查询；`{schema:3,network_id,ranges:[Summary],heads:[Summary]}`，每个有原件的当前授权设备恰有一个根和一个最高非空叶，分别按设备排序；空集合使用空数组 |
| `POST /internal/report-ids` | `{schema:3,ranges:[Scope]}`，规范排序且非空、最多 8 项；`{schema:3,network_id,ranges:[RangeIDs]}` 恰好逐项对应请求。非叶 report_ids 为空，children 为至多两个非空半区的摘要；各半区跳过只有一个非空孩子的层，直到分叉或叶。叶 children 为空，report_ids 为本叶原件按序列降序、同序列按 ID 升序的无重复列表 |
| `POST /internal/reports` | `{schema:3,report_ids:[Digest]}`，按 ID 唯一升序且非空、最多 1024 项；`{schema:3,reports:[DeviceReport]}` 为请求顺序的非空前缀，可含多设备 |

范围按设备、起点升序、同起点 height 降序唯一排序。孩子严格位于请求的各半区、每半区至多一个，
不能是父节点自身、越界、重复或顺序不规范；最高叶提示与根的设备逐项对应。未知字段、查询参数、
旧范围请求、错误网络、非规范字节及范围均拒绝。索引沿原 64 MiB 上限，正文批次不超过 16 MiB、
单份仍不超过 8 MiB；下一份放不下只返回装下的前缀。索引不列撤权设备；取原件时再次校验网络、
当前设备公钥与签名。索引摘要只减少传输，不能代替原件验证或把有效签名放进错误范围。

成员报告响应沿标准 HTTP 协商独立的 gzip 编码；只在当前请求明确接受 gzip 且规范正文至少
1 KiB 时压缩。每个响应使用新压缩上下文，流式输出，不保留跨请求字典或另一份完整压缩正文。
压缩前后仍是同一份规范 JSON，签名、内容 ID、集合摘要及持久字节不变；未请求压缩时交付相同
原文，不是第二种业务协议。索引、原件批次和单件的既有上限均按解压后的正文计算；成员读取仍
有原期限，并在自动解压之外显式限制编码流和解压后的长度，空压缩块也不能绕过网络字节预算；
截断、解码失败、未知编码和任一超限不能提交部分报告。无需设备客户端或本机配置变更。
最小验证沿真实成员 TLS 覆盖协商和原文相等、截断压缩流后的原件保全与重试，以及压缩后的大批次
仍只返回原有未压缩字节边界内的前缀；生产同时计量实际线路字节，不能只以压缩样本代替流量回读。

接收先补原控制事实，再比较各设备根与最高叶。最高叶差异优先展开；其后从有差异根展开，逐步
比较本机同坐标摘要，相同即停止该子树，空层不产生网络往返。每次查询最多 8 个节点，缺失叶 ID
在各选中范围交替收集，每次成员尝试最多请求并耐久合并 64 个缺失原件，然后让出；新一轮重新
比较最高叶，防止历史积压阻塞新报告。同一设备历史分支优先较高序列；没有新缺项时继续补历史。
已有缺项时，累计八次索引展开后先请求已找到的原件，不为凑足 64 份继续展开。
反例是 U64 上界附近的稀疏历史：新报告已在最高叶中找到，继续遍历很多历史分支会耗尽期限，
导致下一轮又从头求差而一次也不提交。此工作量上限只使较小批次先落盘；没有发现缺项时仍沿
原摘要树查找，不能截断历史或制造完成状态。后续轮次从持久原件重新求差，最终保持同一集合。
提示不同只能改变传输顺序，不能改变集合、高水位、分叉裁决或当前状态。

根不同不表示最高叶之前的历史也不同。比较时，可在一个本机已提交读事务内，以远端最高叶摘要
替换本机同坐标叶，并把该叶之后的本机后缀置空，沿原摘要算法重算根。结果与远端根相同，才能
省去该根的历史展开；远端最高叶仍按原规则比较、取 ID、验签并合入缺失原件。这只是一次求差的
临时计算，不修改索引、原件或 floor，也不保存远端树、游标或完成状态。远端落后时，本机较新的
后缀不因此删除；最高叶之前有缺口或分叉时，重算根不同，必须继续原历史遍历。远端在两次请求间
增加报告由后续求差发现，不把独立读事务的提示当作同一快照承诺。

正常链仍是原设备上传、根及最高叶比较、缺失原件验签和同库持久化、其他成员及页面回读。domain、
规范 wire、persistent 与 UI 不变；runtime 只减少不必要的索引请求。最小验证覆盖同叶新增、跨叶新增、
远端落后而本机后缀更长、最高叶内分叉、此前历史缺口或分叉、稀疏 U64 上界，以及真实成员 TLS
下的请求字节、原件收敛、失败重试与重启。不能只比较最高序号或跳过历史来取得节流数值。

完整批次先核对所请求 ID 的非空前缀、叶范围、网络、规范编码和签名，再在原排他锁和一次事务中
原子合并。设备直接上传仍拒绝未知低序号；成员可补历史，但最高序号只从原件重建且永不降低。
同序号异值保留证据，最高序号分叉没有赢家；失败、超时、撤权及容量不足均不截断原件或降低 floor。
重复幂等、乱序收敛；中断与重启从实际集合重新求差，已落盘原件不重传。请求仍最多 15 秒，成员
尝试仍最多 60 秒，成员按[独立调度](control-model.md#4-普通写入与大规模增量同步)推进，失败不忙重试。
滚动替换期间不符的旧成员索引严格拒绝；原设备报告 schema 3 字节保持，不引入第二种交换 fallback。

并行成员可能同时发现相同缺件。正文请求之前，runtime 可短暂等待另一在途批次提交；等待最多
250 毫秒，结束后必须从原报告库重新核对每个内容 ID、网络和叶范围，只请求仍缺的规范升序集合。
等待不是互斥网络锁：已有批次仍在传输、失败或超出短等候时，其他成员沿自己的原期限独立取件；
取消立即退出。通知只覆盖一个在途调用的寿命，调用结束即释放，无成功含义；无论等待如何结束，
原件是否存在只由数据库决定。部分重叠、原件分叉、验证失败和持久化失败均不能使其他缺件消失。
不在网络等待期间占用数据库事务或写锁，不增加 ID 完成表、成员游标、远端目录或持久回执。
domain、wire、persistent 与 UI 不变；只有 runtime 的可删除在途通知和取件前的原库回读增加。
进程重启从实际原件重新求差。最小验证包括真实成员 TLS 的重叠/部分重叠取件、首批失败、慢成员
的独立回退及等候取消；不改变设备十五秒刷新、原件上限、历史范围或观测时效。

正常链：设备私有上传 → 原件及派生树同事务提交 → 另一成员比较根/最高叶 → 只展开差异并取
缺失原件 → 同集合持久化及重启 → 另一 control 的原管理页回读。无变化只交换每设备两个摘要，
新增报告不再发送整段已知 ID，索引开销不随保留历史的总长度线性增长。新增成本是每次写入更新
一条有限祖先路径、首次从原件建立可重建索引，以及差异树的有界往返，没有新操作步骤。

最小验证覆盖：长历史下无变化及新增报告的实际请求/响应字节；等高缺口、旧位置及最高位置的
分叉；稀疏和 U64 最大序号；跨设备最新优先且补历史期间有新报告；中断重启不重传；树删除重建
及事务失败原件保全；错误摘要/孩子/范围/签名/网络、撤权和容量拒绝；真实成员 TLS、正式设备
上传、所有 control 的 UI 当前及历史回读和生产重启。不得靠缩短历史、延长观测 TTL、改为单 control
或挪到另一个传输来宣称节流。

#### 共享 WG 的原始计数与流量派生

目标是使已有 Overview、设备、Link 流量图和 WG 实测速率有真实输入；明确排除以流量判断健康、线路容量、应用有效载荷计费、额外 WG 会话和 Hy2 套 WG。现有单共享用户态 WG 已保有每 peer 计数；宿主接口计数不能替代它，普通业务资源也不因此创建宿主接口。最小变化是读取这些现有计数，随同原设备报告签名、持久化和同步；无需操作者新增配置。

唯一新增的值是可选 DeviceReport.wireguard_counters：{interface,epoch,observed_at,peers}；它没有独立身份权威、store 或生命周期。interface 是实际 endpoint tag（resource:<ID> 或 wg-shared），epoch 为该 endpoint 实例建立时生成的 16 字节小写十六进制随机串；重建必换、重复读取不换。observed_at 是读取完成的 UTC 毫秒。peers 是本次真实已有统计与当前授权范围的交集，按规范 WG 公钥排序，每项 {public_key,rx_bytes:U64,tx_bytes:U64,links:[{link_id,spec_digest}]}。它不要求全部候选已经物化，未观测项不补零；旧全量报告仍是合法特例，原字段和签名字节不改。links 按 ID 排序，绑定该统计身份对应的现行相邻 Link；无 Link 的接入 peer 仍保留，空集为 []。同一 Link 不能出现在两个 peer。接收端逐项验证公钥属于当前允许范围且 Links 精确一致，不能因允许子集而放宽任何一项的授权。绑定从认证 View 的两端资源和现行 Link 摘要推导；不能把一个接口总量写到每个 peer。

累计统计归本 WG Device 实例内的远端公钥，不归可回收的协议 peer。现有接收／发送计数直接
写同一份小原子数；同公钥的新旧 peer 引用它，删除时不抄数、不结算 offset，因而旧握手
任务的迟到写入也不会丢失或重复累计。统计不持有 Peer、私钥、PSK、队列或协程；协议对象
仍按最后实际引用完全回收，不能用统计条目数证明实际 peer 数。统计随整个 Device 销毁，
不持久化、不由 control 生成，不新增报告字段、统计代或管理对象。空间随本实例实际见过的
不同公钥增长，不随连接重建、Service、Policy 或网址数相乘；此处不承诺恒定内存。仅因权限
暂时撤回不能清零这份统计，同身份重新授予与采样间隙可能使清零无法由旧报文字段识别。

读取入口复用本 generation 的带秘密认证回环 API 和既有 namespace dialer。计数只从已启动的用户态 WG 对象读取，API 不导出 UAPI 配置或私钥。RX 是原生实现接受的 WG 报文计数，TX 是原生发送成功的 WG 报文计数；包含实现计入的握手、保活、加密封装，不包含外层 IP/UDP 头，不是应用独占字节。每端独立测量，TX 不等于对端已收到。读取失败、没有 WG、实例关闭或执行未应用时省略整个可选值；不伪造零。实际已读回的零保持零。两项原子计数是短时间顺序读取，不宣称全网同时快照。

领域值、规范 wire 与持久原件均为原 DeviceReport 的同一个可选字段；unsigned 签名负载包含它，缺席仍保持既有 schema 3 原字节和签名。字段形式不变，允许已观测子集的消费者须先于该生产者激活；不改号、不改旧报告、不做双写。运行时从本 generation 当前已确认的权限映射真实统计公钥与 Link，计数不代替完整资源应用或路径可达证明；接收端逐项验证现行报告的绑定。历史只用原件签名与当前查询授权，不调用不相关的组件发布解析。UI 与聚合是单向派生，删除缓存后可重建。

聚合输入是同一持久设备当前公钥下、无同序列分叉的有效原报告，按报告序列回读相邻样本，序列缺口切断区间。相同 interface、epoch、network_generation，时间严格增加且不超过三分钟时，只对两份报告共同出现的 peer 逐项计算非下降增量；Link 查询另要求其公钥和两端 spec_digest 绑定均匹配。新增、缺失或计数回退的 peer 不补零，也不抹掉其他可比项；无可比项保持未知，不能跨中间缺席强接旧样本。同一采样重投去重，矛盾同时间样本和时钟倒退切断区间。失败、重建、撤权、未知范围不续期。完整落入查询窗口/UTC 小时的区间才能计入，不假设跨界区间内均匀流量；页面明确显示已观测 WG 部分及可比时间覆盖，该时间不代表全部 peer 覆盖。最近五分钟用 8×有效 TX 增量/有效秒数得到已观测传输速率，当前速率只使用本库最高唯一序列所报告的同实例与网络代；该最新报告缺样、分叉、已停止或最后样本超过三分钟时当前速率未知，Link 当前速率还要求该最新报告仍含对应 peer 和现行 Link 绑定，历史仍保留。未来报告不入历史；当前计数还须满足原报告时间五秒的采样容差，时钟矛盾不制造当前速率。

设备图按实际 peer 各计一次 RX/TX；网络只加每设备每 peer 的 TX，不再加接收端 RX，也不按有向 Link 重加。同一个 peer 被正反两条 Link 引用时，两条页面都明确是该物理 peer 的共享测量，不能声称按 Service 或有向策略拆分。链路详情两端分别统计 TX；网络多跳传输在各发送端确有开销，不等于唯一应用用量。无计数的 Hy2/Direct 不假装包含，UI 明确 WG 范围。

正常链：真实业务经过已有共享 WG → 读取计数 → 正式私有报告入口验签和原件持久化 → 相邻原件派生区间 → 浏览器显示相同范围、原时间和覆盖量 → 重启重读历史但新实例 epoch 切断旧计数。反例：双向 Link 共享 peer 时按 Link 求和会翻倍，禁止该求和。

最小验证：原报告字节/签名兼容和新字段严格规范拒绝；真实双 peer TCP/UDP 只有对应计数增长、重启换 epoch、无认证拒绝；原报告持久/同步/重启；增量正常、零、缺失、回退、跨界、分叉、撤权及双向共享不重复；三端采样入口与真实浏览器范围/空槽/速率回读；精确制品部署后业务与基础网络回读。


### 往返向量与最小反例

以下是规范值的字节向量；加密签名向量须由实现按上述精确域和 demo 测试键生成并交叉验证，
不得复制旧签名 golden。片段被接受不表示外围签名、因果依赖或成员证明已经有效。

| 输入字节或变化 | 结果 |
|---|---|
| `{"mode":"any","node_ids":[]}` | Scope any 的唯一字节 |
| `{"mode":"none","node_ids":[]}` | Scope none 的唯一字节，不能解成 any |
| `{"mode":"only","node_ids":["demo-a","demo-b"]}` | 接受已存在且合格的两个节点引用 |
| `{"node_ids":[],"mode":"any"}`、带空白/末尾换行的等价 JSON | 拒绝非规范键序或字节 |
| `{"mode":"any","mode":"none","node_ids":[]}` | 拒绝重复键，不能先丢弃一个键 |
| `{"mode":"only","node_ids":[]}`、`{"mode":"any","node_ids":null}` | 拒绝错误范围或歧义空值 |
| 同一签名负载加入空 `signature` 再验签，或将 NUL 换为换行 | 拒绝不同签名字节或目的 |
| 同一设备/Service/Policy，替换接收节点或资源认证摘要 | KDF 必须得到不同输出；不能跨接收方复用 |
| 对最新授权先保存 LKG，随后 runtime 应用失败 | 新 LKG/floor 保留，旧宽权限不恢复，报告运行错误 |
| 同一 Report 序列更换观测，或旧 View/网络代样本迟到 | 前者拒绝，后者不得变成当前业务成功 |

实现最先覆盖规范 domain/wire/persistent 往返、签发者/设备绑定、相反到达顺序的并发撤权、
同 Service 多条策略合法、跨服务歧义拒绝、空授权与历史 deny、同事务响应丢失恢复、KDF 接收方隔离、执行失败不复权和重启回读。
成员证明字段、服务节点执行/回读字段、传输真实探测动作、观测时限及生产前向映射尚未完成时应逐项报告阻碍；不能据此引入另一套运行契约，
也不能把本节文档完成或单目标局部验证称为整个业务工作项完成。

## Windows 数据面 manifest 的规范字段

数据面源码修订使用新的制品坐标和发布代，schema 3 的字段、签名域和原始已签包保持。源码审查
按 manifest 明示的制品坐标核对固定上游、补丁、构建输入与精确程序摘要；不能把一个可变的“当前
源码摘要”套到全部历史包上。旧 schema 3 包仍可按其原字节独立验签和被已有期望精确引用；新 writer
只生成本次审核的制品。运行安装仍按原单调代和精确包决定，不因新包失败选择历史包。这不是旧协议
decoder、旧配置 fallback 或新的发布状态。最小验证须同时保全原已签 catalog 的读取，并拒绝不同
修订之间拼接源码/程序、同代异值和低代安装。

修复后的 TUN 需要能在异常退出后保留域名地址对应的数据面。正式入口仍是 `loom client
package-windows`、三种交付包及客户端自己的组件验证；不允许把带补丁的二进制声明成官方原版。
该 manifest 是上述 release manifest 在 `windows-dataplane` 组件上的具体字段，不创建第二发布权威。
本节不激活 catalog，不迁移生产 signed-current floor。

| 值 | 唯一字段及约束 |
|---|---|
| manifest | `schema=3,kind="windows-dataplane",os="windows",arch,generation,version,audience="public",signature_domain="loom-release-manifest-v3",sing_box,wintun,files`；arch 仅 amd64/arm64，generation 为非零 U64，version 是修订后数据面制品坐标。当前组件不声明最低兼容版本。 |
| component | `path,sha256,size,version,source`，sing_box 额外包含上游 `commit`；sha256 为 64 位小写 hex，size 为正的有界 JSON 整数。两个组件的路径、摘要和长度必须与 files 中的同名项一致。 |
| sing_box source | `url,archive_sha256,evidence="go-module+reviewed-patch",upstream_version,module_sum,patch_sha256`；URL 定位固定上游 module ZIP，archive_sha256 是该 ZIP 的摘要，module_sum、上游 commit 和补丁摘要必须与审核的源码一致。制品 Go buildinfo 如实保留本地源码构建身份；不得伪造上游版本及 VCS 信息。 |
| wintun source | `url,archive_sha256,evidence="publisher-sha256+authenticode",authenticode_required=true,authenticode_publisher="WireGuard LLC"`；固定发布包摘要、目标 PE 架构及原生 Authenticode 均须成立。 |
| files | 按 path 严格升序排列的 `{path,sha256,size}`；精确覆盖两个运行文件、两个许可证及源码来源、补丁和构建方法。禁止额外成员、路径穿越、软链接及重复路径。 |

manifest 使用 `C` 编码，签名严格覆盖 `loom-release-manifest-v3\0 || C(manifest)`，签名放在
`manifest.sig`，自身不进入文件清单；ZIP 的摘要由外层发布记录覆盖，避免自哈希循环。相同输入产生相同
manifest 和 ZIP。签发者以受审核的精确源码及制品摘要确认来源；客户端只信任安装时固定的发布公钥，
验签后仍逐文件验长度、摘要、PE 架构及 Wintun 签名。

组件本机接受值固定为 schema 3 的 `{schema,current}`；current 为
`{id,arch,generation,sing_box_version,wintun_version}`，id 是原始规范 manifest 的 SHA-256。
版本坐标为 1～64 个 ASCII 字母、数字或 `._+-`，已接受的旧制品坐标仍可读取；不按版本字符串排序。
同 generation 只接受同 id；更低 generation 拒绝。先落盘并验证完整不可变 slot，再原子保存接受值，
之后才允许运行；崩溃只能留下未选中的完整 slot，重复同一安装可恢复。不得根据旧版本偏好选择 previous。
UI 和报告只从当前实际验证的文件投影组件摘要，不把签名有效解释为已运行。

旧 schema 1 manifest 和组件指针不进入新解码或自动迁移。此次显式替换须先保全旧指针及签名包原始字节，
再安装已核验的新组件；设备身份、DPAPI、认证 LKG、发布 floor 和 latch 不在组件目录中迁移或重置。
源码、配置及实际入口中的旧组件 writer、旧包解码和 previous fallback 同项删除。最小测试覆盖规范往返、
改包/错钥/旧格式拒绝、双架构 PE、签名来源、同代异值/回退拒绝、中断恢复和真实 Installed TUN 域名业务。

## Linux 客户端 manifest 的规范字段

Linux 安装包沿用独立发布签名权威，不从包内公钥自证可信。它的 `manifest.json` 使用同一规范 JSON，
字段固定为 `schema=3,kind="linux-client-bootstrap",os="linux",arch,generation,version,audience="public",
lifecycle="certified-lkg-runtime",signature_domain="loom-release-manifest-v3",platform_key_sha256,loom,sing_box,files`。
`arch` 只允许 amd64/arm64，generation 为非零 U64；version 是包内 Loom 的完整源码提交坐标，开发构建须
显式允许并标为 devel，不能伪造干净提交。包内 `manifest.sig` 和下载附件 `.sig` 均为同一个 64 字节 Ed25519
签名，覆盖 `"loom-release-manifest-v3\0" || C(manifest)`；不再写旧 schema 2 的 archive-hash 签名封装。

loom 与 sing_box 项均有 `path,sha256,size`，分别固定路径 `loom`、`sing-box`；Loom 另保存可追溯的 commit
与仅在开发脏构建时出现的 dirty；数据面另有 version、commit 和与 Windows 相同的源码证据 source。
二进制摘要及构建信息须对应同一审核源码、补丁和目标架构，不把本地 `(devel)` Go module 信息伪装为上游
未修改制品。许可证、源码补丁、准备/构建脚本和独立复现说明随包交付。

files 按 path 严格排序，项固定为 `path,mode,size,sha256`，覆盖所有业务文件，排除 manifest 本身、其签名及
checksums.txt，避免自哈希循环；只接受规定的普通文件、固定权限和路径，不接受链接、额外文件或重复项。
checksums.txt 覆盖包括 manifest 与签名在内的全部其他文件；archive 使用固定排序、时间和头部的 tar/gzip，
验证后重新编码须与收到的 archive 字节相等。下载 `.sha256` 仅核对整包传输；信任来自带外固定公钥对上述
规范 manifest 的验签。旧格式 decoder/writer 删除，既有原始包和发布 floor 仍按现网字节门禁保全。

domain 与 wire 均为这份 Manifest；安装制品保存相同原始字节，runtime 只消费核验后的程序和当前设备 LKG，
UI 只能投影验签结果及实际运行报告。此格式不创建 catalog、设备授权或第二安装状态机，也不自动授权生产
激活。正常链为精确源码构建 → 显式 generation 签名打包 → 带外公钥验证 → 正式安装入口 → 原身份运行/报告。
最小检查包括规范往返及确定性、源码/架构/文件篡改拒绝、旧格式/未知字段/重复字段拒绝，以及双架构真实包验证。

Linux 安装器在 `--capture mixed` 或 `--capture tun` 明确激活时，使用 root 保护的唯一 `current` 符号链接定位 releases 下的
规范 manifest 内容 ID；该 manifest 和原始签名共同表达本机已接受的发布代。缓存目录不是接受记录，
`--no-enroll` 不推进它。同平台低代与同代异值拒绝，同代同值可重试。先停止并禁用旧执行，验证精确程序
与清理，再写 unit 并原子推进 current；接受后启动失败只禁用执行，不回退 current 或设备认证状态。
unit 为已签模板、显式 capture 与本机路径的投影，不能有未核验 drop-in。TUN 只创建隔离 access
执行边界，不能在宿主初始 namespace 启动 TUN；切换 capture 不改变身份、授权或发布 floor。重试不能用包内公钥覆盖安装信任。
旧格式 current、已部署 signed-current floor 或未知旧入口不能作为初次安装绕过；它们仍按下面生产切换门禁处理。
新程序运行回读后仅 compare-and-delete 被替代的两个可执行文件，旧 manifest、原签名和源码证据保留。
接受后失败再重试时，从同一受保护 releases 目录内已验签的同平台较低代清单识别应退役程序；不新增旧指针
或安装 receipt。未来代缓存、未认证条目和其他文件不由此删除。

## Android 应用 manifest 的规范字段

目标是让操作者从现有 Releases 页面取得正式 APK，并将它的实际执行组件设为节点期望。
此前正式签名 APK 只作为本机交付文件存在，catalog 明确拒绝其 kind，因此无法形成该链。
最小变化增加既有 Artifact 的 Android 应用 manifest；它只描述不可变交付字节，不新增安装状态、
自动更新器或设备授权。操作者多执行一次应用签名清单打包，再沿同一 stage/publish 入口发布。

唯一 manifest 固定为 `schema=3,kind="android-application",generation:U64,application_id,version_code,`
`version_name,source_commit,aar_sha256,sing_box_version,artifact,native_libraries`。
generation 非零；application_id 固定正式包名；version_code 为正且不超过 Android 有符号整数范围，
version_name 为规范版本文本；source_commit 是编入 APK 的 40 位小写源码提交，aar_sha256 为 64 位小写 hex。
artifact 使用原 ReleaseArtifact，名称固定 `loom-android.apk`，media_type 为
`application/vnd.android.package-archive`，audience 固定 public，摘要和长度覆盖原始已签 APK。
native_libraries 恰好按 arch 排序列出 amd64/arm64，字段为 `arch,path,sha256,size`；path 分别固定为
`lib/x86_64/libbox.so` 与 `lib/arm64-v8a/libbox.so`，摘要和正的有界长度对应 APK 内未压缩的完整 ELF。
其他现有 UI 原生依赖仍随同一 APK 交付，不因此成为独立运行组件或引入新 ABI。

manifest 在 APK 外保存，避免 APK 签名及整包摘要循环。Ed25519 签名覆盖
`loom-release-manifest-v3\0 || C(manifest)`，独立发布公钥、不可变路径和 catalog 仍沿用原契约。
生成前使用固定 SDK 的 apksigner 验证完整 APK，读取实际唯一签名证书；正常 Android 安装仍独立执行其
签名和升级规则。发布签名不替换 APK 签名，也不允许安装工具清空身份或更换签名键以绕过升级。
sing_box_version 来自 AAR 随包携带的原始受审核 source-provenance.json，固定位置为
`assets/loom/source-provenance.json`，由 Gradle 同字节合并到 APK。该记录已用于 Linux/Windows 数据面，
不新建构建元数据 schema 或状态文件；缺少它就无法区分旧 AAR 与当前数据面版本，不能直接复制工具版本。
读取者按原来源记录的审核摘要识别版本，打包时核对 AAR 摘要、来源原件和两份库与 APK 完全相同；
只签发当前受审核版本。它表达期望坐标，实际版本仍由已加载 Libbox.version 回读。

所有读取者从 APK 的实际 DEX BuildConfig 核对 application_id、release/非 debug、version_code、
version_name、source_commit 和 aar_sha256，核对 native_libraries 的 ELF 架构及 Android Go buildinfo，
并重新核对整 APK 和库的摘要。未知 DEX/打包形态、重复 BuildConfig、重复 ZIP 路径、额外 libbox ABI、
错误文件/元数据/签名或非规范字段拒绝；不增加另一份 APK 构建信息 store 或旧包 fallback。
节点上的只读验签器消费平台签名及精确 APK 字节，无需部署 Android SDK；APK 签名证书由发布者的
SDK 对同一 APK 的验签回读覆盖，目标 Android 系统在安装时再次验证；不另复制一份可与 APK 分离的签名身份字段。

对应关系为同一 Manifest → 同一规范签名字节/发布目录 → Releases APK 下载及原期望组件引用 →
Android 原报告 → 版本页比较。页面同时提供原 manifest 与签名下载，不能只有无法独立验签的分离签名附件。
catalog 的平台为 android-any，因为一个 APK 同时交付两个 ABI；
期望坐标仍是 android-amd64/android-arm64。agent 的摘要是同一完整 APK、版本为 source_commit；
sing-box 的摘要是相应 ABI 原生库、版本为 sing_box_version。引用只按该 manifest 中明确存在的运行
组件/平台解析，不能把 any 当作任意平台通配。低代和同代异值依原发布目录规则拒绝，失败不推进 current；
安装代由 Android 既有版本规则处理，目录发布和普通期望事实均不自动安装或重置任何 floor。

最小验证覆盖 manifest 规范往返、错钥/改包/错 ABI/元数据与库绑定拒绝，真实 APK 与 SDK 独立读回，
正式 stage/publish 全目标回读、私有浏览器精确下载、正常期望写入及同机模拟器真实报告比较与重启。
实体安装/ARM64/物理切网不由本清单替代。

## Windows 应用 manifest 的规范字段

目标是从现有 Releases 取得 Installed MSI、Portable TUN ZIP、Portable Mixed ZIP，并将包内实际
agent 设为设备期望。已有数据面包只交付 sing-box/Wintun，无法表达这三种应用；最小变化是为已有
三种交付字节增加同一应用 manifest，不增加安装器、自动升级器、授权或安装状态。操作者在原构建后
多执行一次清单签发，随后仍使用同一 stage/publish。

manifest 固定为 `schema=3,kind="windows-application",edition,arch,generation:U64,source_commit,`
`installer_version?,artifact,components`。edition 恰为 installed、portable-tun、portable-mixed；arch
恰为 amd64/arm64；generation 非零，source_commit 为实际干净 Go 构建的 40 位小写提交。
只有 installed 有 installer_version，它是实际 MSI 的三段规范 ProductVersion，范围为 255.255.65535。
artifact 仍是 ReleaseArtifact；名称固定 `loom-client-windows-<edition>-<arch>.msi|zip`，installed
使用 MSI / application/x-msi，其余为 ZIP / application/zip，摘要覆盖原始完整交付文件。
components 使用已有四字段 ComponentReadback，按 component_id 严格排序：agent、sing-box，以及
仅 TUN 两种形态的 wintun；平台均为 windows-<arch>。agent 版本是 source_commit、摘要是包内 EXE；
另两项从同包内已独立验签的数据面 manifest 和真实文件取得。Portable Mixed 不制造未加载 Wintun 的期望。

发布工作站逐项核对原 ZIP 的固定普通文件集合、PE 架构、Windows Go 构建身份与干净 VCS，以及
内嵌数据面的原签名和文件。Installed 另要求原构建 ZIP，使用只读 msitools 检查实际 MSI 的产品、
版本、架构及嵌入 CAB；在无网络、仅临时输出可写的 sandbox 中提取，将每个文件与原 ZIP 逐字节
比较（只有 EXE 改为固定 loom-client.exe）。该审查不运行 MSI/custom action、不安装程序；未知
外部 CAB、额外文件或不同字节拒绝。交付形态由原构建及原生 --build-info 验收共同确认，静态 VCS
回读本身不证明程序已执行或形态行为成立。工作站调用方将这些实际输入交给纯签名函数，不持久化
另一份审查权威。相同显式字节、版本、代及密钥产生相同 manifest/签名。

签名仍覆盖 `loom-release-manifest-v3\0 || C(manifest)`，manifest 与 64 字节签名在原交付物外保存。
读取者验证规范字段、独立发布签名及完整交付摘要；ZIP 还独立重复包内程序核对。MSI 的组件及
ProductVersion 绑定来自签发工作站对同一原文件的读取，节点无需部署 Windows Installer 或 msitools。
Windows 安装后仍以真实进程/模块摘要报告，不能将 MSI 验签当作安装成功。平台签名不等于 Authenticode；
现有 preview 交付标识保留，外部代码签名按独立策略执行。

对应关系为同一 Manifest → 原规范签名字节/独立发布目录 → Releases 精确 MSI/ZIP 与原清单/签名
下载 → 原 ExpectedComponent 引用 → Windows 实际报告比较。catalog component_id 为
windows-client-<edition>，platform 为 windows-<arch>，因此现有三种交付同时存在而不改变目录唯一键。
页面选择期望时显示形态；installed 展示 MSI 版本，便携版展示源码提交。目录推进不改期望、不安装；
期望引用固定 manifest，即使另一个形态同源码也不能用另一个 EXE 摘要满足它。重试/低代/同代异值
沿原目录规则，失败不推进 current；MSI 升级与本机数据面单调代照常执行，不重置身份、DPAPI 或 floor。

最小验证覆盖规范往返、三形态/双架构与包内程序绑定、错钥/改包/额外路径/错 ABI/版本拒绝，真实 MSI
只读提取与原 ZIP 比对、正式发布与浏览器下载、同机 Windows 三形态真实 agent 期望比较和重启。
ARM64 执行、真实睡眠、物理网络切换及显示硬件仍由实体终验覆盖，不恢复旧发布/安装 fallback。

## 签名 catalog 与安装包、运行文件的对应

本节补齐既有 Release/Artifact 的交付索引，不新增控制权威、安装 receipt 或协议号。现行规范
manifest 包括 `linux-client-bootstrap`、`windows-dataplane`、`android-application` 与 `windows-application`。它们保持原始签名字节；catalog 只引用它们，
不能把整包摘要写成包内程序的运行摘要。Android APK、Windows 三种应用交付和通用 bootstrap 脚本各自的
非空 manifest 按各自交付边界定义；现行包含上述应用与下述通用脚本；未定义的 kind 拒绝，
不能使用任意 JSON 透传。

catalog 固定字段为 `{schema:3,generation:U64,entries:[]ReleaseEntry}`，generation 非零；entries 非空，
按 `(component_id,platform)` 严格排序且唯一。此处 component_id 表示交付组件，当前为两个程序包 kind
、`android-application`、三种 `windows-client-<edition>` 及 `linux-bootstrap-script`；程序包 platform 恰为 `<os>-<arch>`，通用脚本为 `linux-any`，双 ABI APK 为 `android-any`。
每项固定为 `{component_id,platform,manifest_digest,artifact}`；
manifest_digest 为原始规范 manifest 的 Digest。artifact 固定为 `{name,digest,size:U64,media_type,audience}`，
文件名为单个安全 ASCII basename，digest 为完整下载字节的 Digest，size 非零，当前 audience 恰为 public。
Linux archive 的 media_type 为 application/gzip，ZIP 为 application/zip，MSI 为 application/x-msi，通用脚本为 text/x-shellscript，APK 为 application/vnd.android.package-archive。
版本、源码、组件代及包内精确程序坐标由已引用的原 manifest 读取并核对，不另复制一份可独立修改的值。

签名为 64 字节 Ed25519，覆盖 `loom-release-catalog-v3\0 || C(catalog)`；规范 catalog 摘要定位不可变
`catalogs/<digest>/catalog.json` 与 catalog.sig。原 manifest 与原签名存放于
`manifests/<digest>/manifest.json` 与 manifest.sig；整包只存于 `bin/<digest>`。所有路径均从摘要确定，
不接受调用者提供任意相对路径。发布、下载与安装消费时，原包、manifest、签名与逐文件内容须同时验证；包中的原 manifest/签名
必须与外层引用逐字节相同，组件 ID、平台、媒体类型及公开受众必须相符。

私有下载 URL 同时固定 catalog digest 和 artifact digest；更新 current 后，已经打开的页面仍取得原先
选中的精确字节。读取被明确寻址的旧代 schema 3 catalog 只提供下载，不改变安装接受代、期望事实或 current，
也不接受旧格式。后续安装仍须独立验签并遵守已有组件代。损坏的目录、签名或制品使对应下载失败；当前签名目录或所引用的清单
不可验证时页面清空下载投影并显示不可用，不保留上次验证的卡片冒充当前结果。

可变 current 是 `{schema:3,catalog_digest}` 的规范定位值。发布工具先在同一根目录的排他锁内回读旧值，
核对操作者计划固定的旧 digest，拒绝低代及同代异值；不可变文件全部落盘并重新验签、验摘要后才原子
写 current。同代同值允许幂等重试。中断可留下未被 current 引用的完整文件，不能留下半个可接受对象；
已有摘要路径的不同字节拒绝覆盖。此处的防并发推进规则不代替生产节点已有 signed-current floor 的迁移证明。

对应关系为：Catalog/ReleaseEntry → 同一规范签名字节 → 独立 release store → 已核验下载清单/包验证器 →
Releases 页面；原 manifest 中 Loom/sing-box/Wintun 的文件摘要 → 实际程序回读 → 组件期望比较。
Linux 的 loom 对应既有运行 component_id=agent，数据面恰为 sing-box；Windows 数据面另有 wintun。
交付组件 ID 和运行组件 ID 各自描述既有对象，不以 ID 相同或“安装命令成功”替代该签名关系。
发布清单可删除重建的 UI 投影不能签发期望组件；期望仍须管理员普通 operation，应用仍须真实报告。

普通状态查询的目标是回读已签名的发布坐标及节点期望，不是反复执行安装验收。原实现每次页面
快照及设备 View 都在发布库互斥锁内哈希全部制品，即使清单解析已有缓存；实际浏览器中历史查询
仍返回有效观测，而全量状态持续超时。最小变化是同一发布库提供无状态的签名元数据读取：每次
独立验证 current 定位值、原 catalog 签名、所有被引用 manifest 的规范字节、签名、内容地址、
平台和组件绑定及 bootstrap 引用。运行坐标只由原 manifest 单向投影，不读取制品正文，也不等待
正文解析缓存的锁；无第二份持久值、验签记忆或新生命周期。发布、下载和安装仍验证实际制品。

反例：正文被删除或同长度篡改时，已签名坐标仍可展示并比较实际报告，但下载与安装必须失败；
不能用展示成功证明包可用。清单缺失、被篡改、错钥或跨条目引用时，元数据投影也须立即失败，
不能沿用旧卡片。重启及删除全部缓存不改变这些结果。操作成本没有新增配置或人工步骤，仅把
按实际文件消费的校验与小体积元数据投影分开。最小验证覆盖两种读取的坐标一致、正文损坏仅阻断
消费、原签名元数据损坏阻断投影，以及正常页面并发报告下的新鲜观测和实际下载。

### 节点期望组件的精确发布引用

`ExpectedComponent` 是已经定义的节点期望值，不是发布任务或安装状态。稳定身份由
`{node_id,component_id,platform}` 决定；删除该值会丢失管理员对这一个程序及执行平台的期望，
无法用下载 current 或其他节点的成功恢复它。规范字段恰为
`id,node_id,component_id,platform,catalog_digest,manifest_digest`；id 等于
`SHA256("loom-expected-component-v3\0" || C({node_id,component_id,platform}))` 的 Digest 表达。
两份发布摘要固定原始 schema 3 catalog 与其引用的 manifest；不保存 archive/ZIP 摘要作为程序摘要，
也不再复制一份可编辑的 version、运行摘要或制品内容。现有可解析组合为 Linux agent/sing-box 与
Windows agent/sing-box/wintun 与 Android agent/sing-box，平台为相应 OS 的 amd64/arm64；没有规范 manifest 的应用组件不能创建期望。

| 层 | 唯一表达与方向 |
|---|---|
| domain | 一个节点、运行组件、平台的精确发布引用；put 替换引用，delete 撤销引用 |
| wire / persistent | 同一 ExpectedComponent 随普通 schema 3 Material 规范签名及持久化；与其他事实一起同步和重放 |
| release store | 独立固定公钥验证的原 catalog、manifest 与制品；事实只引用它们，current 不参与解析 |
| runtime | 调用方先独立读取并验证引用的 release set，再交给纯投影解析程序坐标；DeviceView.expected_components 保持既有四字段 |
| UI | 管理员选择已核验组件；节点详情与 Device versions 展示期望引用、实际报告坐标和比较依据，未验证引用明确不可用 |

普通事实证明管理员签署了哪一个期望引用，发布签名证明该引用实际包含哪些程序。两者不可互相代替。
正式管理入口签发 put 前须通过独立 ReleaseSource 验证精确 catalog、manifest、平台与组件，
并验证节点 OS 及当前设备授权依赖；相同 request ID 重试返回原签名字节，不重新选择 current。
CRDT 接收与重放仍只按普通事实的签名、因果关系及规范字段接受引用，不因本机文件暂缺而删除事实或
重排签发链。每个 control 在生成 DeviceView、验证报告的当前 View 或展示期望坐标时，均须从自身固定
发布公钥独立验证原引用；缺少签名元数据、错签名、摘要或组件不符使受影响的期望投影不可用，不能降成空期望。
恢复原始已验证文件后可重新投影，无额外恢复状态。纯投影不查询磁盘、时钟、网络或随机数。

put 引用有效节点事实及原期望事实；陈旧依赖、同请求异值和未知字段拒绝。撤权/删除的节点不能取得
新的期望 View，已签引用仅保留为历史；同身份合法重新授权后才可再次消费。并发冲突沿既有目标冲突
规则失败关闭，不选择某个发布为赢家；delete 可清除有冲突或已撤权节点的期望，但不重置任何安装代。
重启从原事实和原签名发布字节重建，无第二份期望 store。发布目录推进、期望变更、实际安装和业务成功
是分别可回读的结果；本值没有执行进度、超时或自动回滚，也不授权绕过生产旧 floor 的迁移证明。

反例：管理员期望 catalog A 的 agent，随后下载 current 改成 B，仍必须回读 A 的原 manifest；即使
A/B 版本文本相同，也按精确程序摘要比较，不能把 B 的文件或整包摘要当作已满足 A。没有报告或缺少
新鲜性依据只显示缺项或带时间的 reported 比较，不能宣布已应用。

正常链为：已核验发布 → 正式 UI/CLI put → daemon 独立验签及普通事实持久化 → 同步/重启 →
DeviceView 精确坐标 → 客户端实际进程报告 → 管理员原入口回读。最小测试覆盖规范往返与原空值字节、
错节点/平台/manifest 拒绝、陈旧依赖、目录变化不改变期望、发布文件缺失后的失败与恢复、撤销/冲突、
重启及真实浏览器的提交和签名报告对照；不恢复 publisher observation、registry、receipt 或旧 SSOT 写入。

最小验证：规范往返及确定性；错钥、旧格式、字段/排序/媒体/受众和原包绑定拒绝；不可变文件损坏拒绝；
并发旧指针比较、同代同值重试、降代/同代异值拒绝；CLI 写入后重启回读、私有 Web 精确下载及安装消费。
所有生成函数只消费显式字节和代坐标；不读时钟、随机数或远端状态。正式生产 current 激活继续受下节
现网字节与生产切换门禁约束，现网旧 floor 原字节保全。

### 私有设备的精确签名包交付

Linux 自动更新沿现有 device tunnel，不扩大公开 Nginx 路由。三个无持久生命周期的交付值均使用
规范 schema 3：请求 `{schema,platform,view_digest}`；响应
`{schema,platform,view_digest,catalog_body,catalog_signature,manifest_body,manifest_signature}`；
下载请求 `{schema,platform,view_digest,catalog_digest,artifact_digest}`。platform 仅允许
linux-amd64/linux-arm64，摘要为既有 Digest。body 是原规范 JSON 字节的 UTF-8 字符串，解码后
逐字恢复原件；两个 signature 是原 64 字节签名的规范无填充 base64url，不是重签封装。
未知、重复、旧 schema、不规范字节、错平台、错 View 和错签名均拒绝。原 catalog/manifest 保持
既有签名域，DeviceView.expected_components 的四字段及其历史签名原文均不改变。

正式入口为 `POST /device/release` 和 `POST /device/release/download`。同一认证设备的当前
Projection 及独立验签的明确期望引用决定可交付包，View 摘要须与客户端持久接受值相同；
bootstrap、撤权设备、其他身份、歧义或缺签名材料不能下载。优先定位 agent 的明确包引用，
仅有数据面期望时定位其包；这只定位一个原子 Linux 包，不是选路或性能排序。包内所有已期望
组件都须与该 View 相符；客户端另外拒绝改变没有期望的组件，除非它与原已接受程序坐标相同。
不同期望可引用不同原 catalog，但同一个实际文件仍按相同版本/摘要核对。

交付缓存可删除；自动消费者独立验原 catalog、manifest、完整下载长度/摘要及包内原签名/逐文件
内容，再调用唯一安装锁。锁内接受前重读已持久 LKG，下载期间 View 变更则拒绝。公开 current
只负责下载展示，不参与此授权或接受代。原 daemon 保持唯一身份/配置/报告写入路径。
正常链为正式期望 put → daemon 持久 View → 私有精确包 → 同一 installer → 当前程序/业务/
签名报告回读；中断、低代、同代异值和重启继续使用原 Manifest/current，失败不恢复旧记录。

### 通用 Linux bootstrap 脚本的签名对应

脚本是已定义 Artifact 的一种交付，不新增安装事务或接受记录。既有包内 install.sh 只能在程序包已到达
后运行，不能满足一次粘贴、识别架构及先验后执行的入口；因此通用脚本的唯一职责是取得并验证那个包，
再调用同一 install.sh。删除它会恢复为操作者手动选包和传文件，不保留第二套身份或安装逻辑。

其 manifest 固定 `{schema:3,kind:"linux-bootstrap-script",generation:U64,artifact,packages:[]ReleaseEntry}`。
generation 非零，artifact 为 `loom-bootstrap-linux.sh` 的精确摘要、大小、脚本媒体类型及 public 受众；
packages 为非空、按平台严格排序的 Linux 程序包引用，必须逐项等于同一 catalog 中的原包条目。
manifest 与脚本分开保存，避免脚本包含自身摘要造成循环。签名为 64 字节 Ed25519，覆盖
`loom-linux-bootstrap-script-v3\0 || C(manifest)`，独立安装公钥与原包签名公钥相同；生成器只从已验证原包
和显式公钥、generation 生成确定性脚本，通用公开脚本不含任何 Invite、设备标识或秘密。

受保护交付入口验证当前 catalog 和原 manifest 后，将通用脚本摘要固定到完整 shell 块。公开 HTTPS 根地址
来自当前设备授权中的 distribution_urls，不能来自请求任意路径或根 .env；按规范 URL 排序读取验证，
把实际读回同一脚本字节且交付时仍获授权的入口作为候选。控制机可达不保证目标设备可达，因此目标端
分别为脚本和 archive 按同一有序集合尝试下载，每次均校验固定摘要，成功后才执行；全部失败则停止。
路径固定为该根下 `bin/<digest>`。无可验证入口时只显示交付不可用，
不生成假命令、不改变原 Invite 或重签。URL 只是寻址；签名决定公开受众和可信字节。

目标端完整块先关闭命令跟踪，在 owner-only 临时目录下载脚本并比较管理面固定的摘要；成功才用 quoted
heredoc 将 Invite 交给 `--invite-stdin`。通用脚本识别 Linux 和 amd64/arm64，核对所选 archive 摘要后解包，
使用固定发布公钥调用包内唯一 installer，显式 Mixed。未知平台、缺工具、HTTPS/摘要失败均停止并清理临时
文件；不更改系统代理、DNS、路由或终端历史设置。正式安装继续按已有身份、组件代、认证 floor/latch 和
失败恢复规则执行；公开文件读到不等于设备加入或运行成功。

domain Artifact/ReleaseEntry → 同一签名 manifest 与脚本字节 → 既有 release store → 纯脚本渲染/下载校验 →
同一 Web 邀请交付块；Invite 与 EnrollmentTransaction 的生命周期不变，完成、取消、到期后不再交付该块。
最小验证覆盖确定性与原包绑定、错钥/异值拒绝、实际 HTTPS 下载与校验、stdin 保密边界、损坏脚本不执行，
以及从管理入口复制到 Linux 正式 installer 的真实加入、报告和重启。不能用脚本语法检查或演示样例抵扣。

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

上述完整历史绑定的证明缺失不能宣称已经恢复。用户随后明确批准
[一次性替代授信起点](../operations/release-forward-cutover.md)：六节点原 floor 原位原字节保全，
已授权、正在运行且独立验签的现程序作为现行 Manifest/current 的接受起点。该批准只覆盖明确
现程序的对应；不补造历史，不解码旧 floor，不比较不同对象的代数，也不许可任意包或设备绕过绑定。
正常新域低代／同代异值拒绝、失败恢复、正式期望私有消费及六节点部署回读已完成，
详见 `deploy/evidence/2026-10-13-automatic-update/result.json`；不宣称恢复了缺失的旧历史绑定。

未获上述限定批准覆盖的转换仍须满足完整证明义务。只读核对进度见[实施状态](../progress.md)及其受保护
证据；逐节点 floor、对应签名载荷、公钥连续性、快照到新 manifest 的对应及真实运行制品必须形成完整
证明，才能填写切换记录。取得其中部分材料不能据此声称生产可用。

旧发布证据的离线 `loom verify <发布根>/<snapshot> -pubkey <固定公钥>` 按既有发布树读取
`snapshot.json`、原始 64 字节 Ed25519 `snapshot.sig`、`nodes/<owner>.json` 及发布根内
`bin/<sha256>`。必须先验原始 manifest 签名，再验证目录与 manifest 的快照 ID、逐节点包内容摘要、
每个二进制的长度与摘要；未知/重复字段、重复节点/平台和越界文件引用拒绝。此入口只读既存证据，
不运行生成器、不写 floor、不激活制品，也不把旧对象交给 schema 3 Authority。
完整快照通过不能代替与 floor 对应的 signed-current 载荷验签；缺失材料仍阻止切换证明成立。

### 设备服务授权修订的切换边界

Service、当前 Policy 及网址限制遵循[当前业务基线](control-model.md#服务与策略的当前业务基线)。
DeviceAuthorization/Invite 的 PolicyIDs 是可选集合，当前互联网只选择一条 Policy；Service 由它
唯一确定。旧 `schema,services:[{service_id,policy_id?}]` 偏好不能再作为必须保留的目标结构。

仍在同一 schema 3 内修订规范字段；原签名策略、Service、View 和本机偏好按原义保全。
显式一次性前向替换须保留身份密钥、high_water/floor、报告序列及 latch。不能按旧列表顺序
擅自挑选新当前 Policy，也不能合并多条规则或扩大权限；无法证明等价时须让用户明确选择。
原始执行段只作为受保护历史验签证据，不进入当前运行解码；新事实必须推进真实认证前沿，
同前沿不同 View 摘要仍拒绝。字段和迁移路径未完成前停止相关写入，不以旧 decoder fallback 绕过。

Policy 的 action 签名字段保持历史原义，新写入只能为 allow；历史 deny 不重解释为允许，
不进入可选运行集合。历史事实的验签和因果引用不能因业务设计更新而丢弃。
一次性迁移失败保留原件及原认证进度；成功后仅有一份当前偏好及 LKG，不长期双写、双读。

## 遇错时只修订这一份契约

3 号确定后，除非用户再次明确要求**新协议或新版本**，错误、字段遗漏、测试失败和实现偏差都通过修订
同一 3 号模型、实现与测试解决。不得追加 4 号、新的 `runtime_contract` 值、第二份 DTO/store、双写、
双读或长期旧格式 fallback；`EndpointGeneration`、源码提交号和制品版本也不是协议版本逃生口。

## 现网字节与生产切换

本节记录既往一次已授权生产切换的范围，不能作为当前或以后任务的写入、部署或删除授权。
这些步骤只说明当次如何保全并切换字节，不定义当前 Service/Policy 目标或后续迁移的自动批准。
当次用户明确授权删除旧版、正式切换和真实业务验证，不再以寻找历史 signed-current
原件作为该次替换的前置。该次授权只覆盖当次发布：按精确制品直接
替换正式服务，旧发布入口退出运行；已有身份、密钥、授权业务资料及原始记录受保护保留，
不把归档恢复成运行 fallback。新服务只消费当前规范输入，替换后须完成业务、报告及重启回读。
此授权不放宽宿主 TUN/netns、SSH 管理通道或现有 underlay 的保护边界。

该次执行从核验过的旧材料显式构造 schema 3 初始签名材料，保留同一网络、成员公钥、设备签名密钥及
管理员证书；沿当前 Invite/claim 和普通管理入口重新建立原授权的精确对应。旧签名域的认证序列与新域的
事实序列不是同一计数器，不能以同号或较大数字宣称连续；旧原始 floor、head 和签名字节单独封存，
新设备仅固定这次交付的当前 genesis，拒绝旧格式输入和任意替代根。发布 floor 原文件保持，当前服务不读取
旧 current，也未启用尚无单调消费证明的新 catalog。逐节点身份、公钥、原始文件摘要与精确运行制品的
对应只保存在受保护切换证据；这不是供未来自动迁移使用的第二 decoder 或第二权威。

3 号对象改变了现有签名 Material、成员证明及设备视图的字节和投影语义。已认证 head、已部署持久字节、
现网身份与密钥、数据、认证 floor 和不可回退 latch 必须保全，编号变化不授权重解释这些字节。其他未获此次
明确映射覆盖的状态与 3 号目标不相容时，冲突写入和生产切换保持失败关闭，不自动生成替代 genesis、清空信任或让旧路径继续
充当权威。由用户明确决定并验证前向切换办法后，才能启用相应生产写入；文档完成不视作业务完成。

### 规范编码中的类型检查复用

完整规范编码只递归检查一次相同 Go 类型的静态字段与方法约束；同一查询可以顺序复用这些
有限的类型、字段次序和规范字段前缀计划，查询结束即丢弃。集合中的每个具体值仍调用自己的
Validate，逐项检查循环、空值、UTF-8、集合及必填字段；计划不含原件、具体值或其验证结果。
解码按精确字段计划直接赋入新的类型值，完整校验后按原文长度预分配规范编码缓冲区，仍与
原文逐字比较，失败不修改调用者。摘要的规范小写十六进制检查、已验证观测的字段元组排序及
字符串普通段批量复制只替换等价的重复转码与分配。没有跨请求类型缓存、持久类型表或新的
授权来源，不改变 C 的输出字节、D 的拒绝集或 schema 3 的往返式；后续记录中的非法值不能
因类型已见而通过。

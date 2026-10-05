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
| `Material` | 网络、签发 control 与验证键、所引成员表、该键序列和前事实 ID、因果依赖、稳定目标、操作及对应内容、签名；genesis 固定初始成员、网络意图和管理员信任。 | 下方固定普通授权链的操作、ID、签名及规范字节，以及 genesis、初始成员表和 NetworkIntent 外层；未定非空子值、DNS/LAN 分配与发布期望操作仍须补齐，不用全量 network.update 代替。 | 管理 operation、事实同步、持久重建与运行消费仍需实现；字段表不抵扣正式验收。 |
| 成员承诺、投票、证书 | 基础表、轮次、发起者、成员、完整投票史、按键已验证前缀、后继提案、封存点和同轮多数签名。 | 初始表、内容 ID、完整后继载荷及历史／前缀／签名集合的字段与排序见下文；非空后继的验证和持久投票运行尚未实现，正式入口明确拒绝。 | control 加入、移除、换键及离线设备验证连续成员证明需要相同的签名字节；不能用初始表代替后继证明。 |
| `NetworkIntent` 内的 `TransportResource` | 稳定资源 ID、种类、承载节点、interface/listener 身份、拨号坐标和公开认证参数；共享首跳与中继复用同一资源，私钥留在本机。 | 下方固定资源公共字段及 Hy2 的 CA/校验名、凭据和接收端 ACL 投影；WG 的普通设备参与身份和地址投影、各 Link 真实探测动作仍须与 adapter 入口核对。真实执行以实施状态为准。 | WG、Hy2、私有 TLS 的真实身份校验、资源复用和参数变化后的观测失效；无公网域名不能成为关闭 Hy2 验签的理由。 |
| 设备授权内的 `RuntimeKey` 与凭据派生 | 只在 control 间保管根密钥；派生绑定设备、Service、Policy、用途、资源和接收节点，不向设备交付根密钥。 | 下方固定 32 字节根密钥、HKDF-SHA256、最小 info、输出及执行失败收口，不用整份授权/Policy 摘要引入无关换钥。资源认证值及实际凭据/ACL 替换仍须完成；现网旧凭据不能直接解释为新凭据。 | 同一授权在客户端与服务节点产生匹配且用途隔离的凭据；撤权、策略替换或换钥后旧凭据的拒绝不能依赖旧派生规则。 |
| `DeviceView` 与 envelope | 单设备配置、签发者资格、连续成员证明、签发者事实前沿、View 摘要、设备绑定与签名。 | 下方固定普通互联网授权的外层字段、摘要和设备绑定；连续成员证明及服务节点执行回读仍是完整 writer 的前置。 | 配置领取、认证 LKG 原子保存、离线恢复与运行消费须验证同一完整 View，不能拼接或补造缺项。 |
| Invite、claim、resume | Invite 的签发者/锚/设备/职责/PolicyIDs/入口/一次性约束；首次 claim 的设备公钥、目标端识别的平台与 request ID；Invite 不预锁平台，平台随绑定事实及设备授权签名；resume 同事务同密钥同平台。 | 下方固定普通加入的交付、请求、绑定与响应；申请 control 的条件授权及多数后继仍须完成成员消息的字段规格。 | SSH、脚本与二维码共用加入协议；目标平台绑定、同事务恢复和重复提交拒绝需要统一字节。 |
| 设备 report 与逐条 Observation | 当前 View 摘要、按设备递增序列、真实观测与运行回读；观测绑定设备、网络代、层级、Service/候选或 LinkID、实际目标及规范摘要，缺失或失效为 unknown。 | 下方固定普通 access 报告字段、签名、时间编码及重放拒绝；最大可接受寿命、时钟偏差、服务节点 listener/ACL/返回路径的逐项回读仍须补齐。 | 当前路径、业务状态、链路测量和部署回读的新鲜性及重放拒绝；不能由签名有效或单项成功推定其他范围仍可用。 |
| release catalog 与 manifest | generation、组件/平台、不可变文件摘要、长度、媒体类型、受众、版本和最低兼容约束，发布密钥签名。 | catalog 与 manifest 的分层字段、路径规则、排序、签名和摘要字节；旧 floor 与新发布坐标的迁移证明。 | 精确制品验签、下载、期望摘要与实际应用对照，以及维持既有反重放边界的生产切换。 |

资源身份与 KDF 的语义依据是[控制模型的凭据派生](control-model.md#21-material规范签名事实)和
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
| 接收端传输用户名 | `loom-inbound-user-v3\0`；`{"device_id":ID,"service_id":ID,"policy_id":ID,"resource_id":ID,"receiver_node_id":ID}`；只作当前进程的 auth_user 投影，不新增身份 |
| 接收端 ACL 摘要 | `loom-inbound-acl-v3\0`；当前资源的完整 InboundCredential 有序数组，包括允许和排除范围；空授权为 `[]` |
| Link 规范摘要 | `loom-link-spec-v3\0`；`{"link":完整Link,"resource":完整TransportResource}` |
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
target_kind: service | policy | device | invite | endpoint | resource | link | probe_target | expected_component
target_id: ID
operation: 下表中的精确操作名
payload: 对应的唯一类型
signature: Signature
```

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
| `resource.put`、`link.put`、`endpoint.put` / 对应种类 | 下述完整值；入口只由承载 control 签发；本机私钥路径不进入 payload |
| `resource.delete`、`link.delete` / 对应种类 | `{"id":ID}`；共享资源删除收口全部引用，Link 删除只收口引用它的候选 |
| `probe_target.put` / probe_target | `id:ID,url:HTTPS_URL`；仍是已有共享目标池的元素，不拥有独立探测组生命周期 |
| `probe_target.delete` / probe_target | `{"id":ID}`；不改变设备权限 |
| `expected_component.put` / expected_component | 下述 ExpectedComponent；依赖有效设备授权及已审阅的同目标前值，签发前独立验证精确发布引用 |
| `expected_component.delete` / expected_component | `{"id":ID}`；只撤销该期望，不删除程序、不降低安装 floor 或改变设备权限 |
| `conflict.resolve` / 被解决目标种类 | `conflicts:[]Digest,action:put或delete`；put 另含对应完整 `value`，delete 不含 value；引用须覆盖全部冲突，不能通过此操作绕过成员资格/已绑定 control 事务或设备墓碑 |

以上为本链所需操作，不新增管理员证书、成员治理或发布操作的编码。那些入口仍须遵循各自模型，
待其精确字段确定后修订同一 schema 3；不得把未定义 payload 当任意 JSON 接受。

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

上述消息没有省略的空集合；ControlConfig 的 join/invalidation 只在对应操作出现，其余操作出现即拒绝。
genesis 拒绝 target_node_id、origin_promises、join 和 invalidation。delete 与 target_node_id 一起构成该
节点的不可复活删除事实；不再增加第二份墓碑实体。add 的事务、公钥、目标及所引条件授权必须一致，
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

字段明确不表示动态成员运行已经实现。未完成完整后继验证和持久投票运行时，正式入口明确拒绝非空
successors 与后继写入；不得把元素声明成空类型、任意 JSON 或跳过验签。真实 genesis 加空链与后续
完整链属于同一证明结构，不存在 N=1 或测试专用 decoder，也不能称成员治理已经完成。

### 初始 NetworkIntent 的字段与引用边界

genesis.network_intent 的字段集固定为下表；schema 为整数 `3`，其余字段均为集合，空值恰为 `[]`。
这只是现有网络意图的初始值，不增加可独立写入的 store 或全量更新操作。非空集合必须逐元素使用对应
唯一规范类型、检查排序与全部引用；不能用 `[]any`、原始 JSON 或“当前没用到”跳过校验。

| 字段 | 元素及排序、引用 |
|---|---|
| services | 本节 Service；按 id 排序；互联网 matcher 非空，局域网值不能伪装成互联网 Service |
| policies | 本节 Policy；按 id 排序；service_id 须引用同一初值中有效 Service；节点范围不得引用不存在或不具对应职责的节点 |
| resources | 本节 TransportResource；按 id 排序；owner_node_id 须具有该资源所需资格；公开认证值按资源种类严格校验 |
| links | 本节 NetworkLink；按 id 排序；节点、方向、资源及 probe_target 同时合法；非空元素不能靠资源握手替代真实探测动作定义 |
| business_probe_targets | `id:ID,url:HTTPS_URL`；按 id 排序；这是共享目标池，不自动分配 Service 权限 |
| dns_records | 精确 `.loom` DNS 的既有值集合；稳定 id 排序；同名冲突、通配及保留名 `control.loom` 拒绝；其完整非空 wire 字段尚待补齐 |
| public_trust | 数据面 TLS 和网站信任根的公开值集合；稳定 id 排序；用途及公开证书须与其引用资源/入口一致；完整非空 wire 字段尚待补齐 |
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
非空值规范；Hy2 authentication 的字段固定于下文。Link 探测动作、LAN、
DNS、公开信任及发布期望中的未定非空值仍有明确缺口。这些输入必须指明缺项并拒绝，不能先落盘后补规范。
空集合是合法新网络的无配置初态，不是允许忽略其非空内容的测试协议；正式入口与测试使用同一个 decoder，
对已规定元素执行同一检查，对未规定元素同样拒绝。补齐元素时修订同一 schema 3；既有 genesis 原始
字节和锚不变，新增普通事实逐对象生效，不把空集合事后解释为隐含默认对象。

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

普通互联网 Service 字段为 `id:ID,name:Text,kind="internet",matchers:[]Matcher`，集合非空。
Matcher 是 `kind,value` 两字段：`dns_exact` 精确主机、`dns_suffix` 域及其逐标签子域、
`ip_prefix` 为 IPv4/IPv6 Prefix。DNS 使用小写 ASCII A-label，无末尾点、通配星号或空标签；
后缀不匹配相似字符串，例如 `demo.example` 不匹配 `notdemo.example`。按 `(kind,value)` 字节排序。
精确 IP 以 /32 或 /128 表达，不另设歧义 matcher。Service 删除或目标修改后，同设备目标归属不唯一的
请求拒绝，不按 Service 列表位置择宽规则。LAN Service 的网关/映射沿控制模型处理，不能编码成互联网 matcher 冒充。

Policy 字段为 `id,name,service_id,action,entry_scope,relay_scope`；互联网 Policy 还必含
`exit_scope,allow_direct,local_egress_devices`。action 仅 `allow/deny`；Scope 唯一形状为
`{"mode":"any|only|none","node_ids":[]ID}`。any/none 必须为空，only 必须非空，ID 排序去重；
LAN Policy 出现三个互联网字段即拒绝。deny 仍完整保存规则和设备选择，运行投影不给业务权限。
id/service_id 为 ID、name 为 Text、allow_direct 为布尔值、local_egress_devices 为 ID 集合；
每个节点引用须满足现有位置及职责规则。NodeID 不可为终点保留值 `direct`。
这些资格检查用于新写入；已持久策略的节点后来失效时保留原 ID，相关候选退出，不能把 only 改为 any。

DeviceAuthorization 字段为 `id,name,platform,device_public_key,responsibilities,policy_ids,distribution_urls,runtime_key,`
`transaction_id,invite_material_id,binding_material_id`。platform 固定为 `android/linux/windows`，
职责是规范排序的 `access/forward/internet_egress` 子集；control 由成员链额外投影，不能被这个数组授予。
普通加入职责非空；上文已有初始 control 的首次设备绑定允许普通职责为空，由已验证成员资格提供 control。
PolicyIDs 可为空，没有 access 则必须为空。同 Service 最多一条 Policy；新分配时
未知/冲突/悬空引用和歧义目标组合均拒绝。已分配引用后来失效，原分配仍可回读但不再产生相应权限。
RuntimeKey 是 control 生成的 Secret32，不是设备身份私钥。

设备还可带 `dns_servers:[]IP`，由同一 `device.put` 公开命令管理，表示该设备已认证的
underlay 解析器集合；非空时按规范 IP 文本排序去重。未配置唯一表示为字段省略，显式空数组、null、
主机名、带 zone 的地址和非规范 IP 均拒绝。这个可选值不改变已签发的省略字段字节；
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
首次 bootstrap 未持有 View，先验证完整 Invite，再只用其中已签名的 dns_servers 解析其固定签发者入口；
未配置解析器的具名入口拒绝，字面地址不需 DNS。已绑定但未取得 View 的 claim/resume 仍使用同一 Invite，
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

TransportResource 字段为 `id,kind,owner_node_id,listener_id,dial_host,dial_port,authentication`，
Hy2 可另外保存 `link_only:true`，表示仅经显式 Link 使用；false 的唯一编码是省略该字段。
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

NetworkLink 字段为 `id,from_node_id,to_node_id,from_resource_id,resource_id,initiator_node_id,purpose,probe_target`。
当前 WG 中继中，from_resource_id 与 resource_id 分别固定引用 From、To 的 WG 资源；两端不同且都有 forward
职责，initiator_node_id 为其中一端，purpose 固定 `relay`。资源各提供一个 /32 或 /128 接口地址；只投影对端精确
peer 和路由。相反业务方向使用另一 LinkID，复用这两个资源及同一物理建连方向。删除资源使依赖 Link 失效。
probe_target 恰为 `resource_id,host,port,action`；resource_id 引用 To 节点的 Hy2 listener，host 是 To 的 WG 地址，
port 与该 listener 的拨号端口一致，action 固定 `hysteria2_tls`。该动作只证明 WG 上的认证传输，不证明 Service 业务。
From/To、两端 WG 资源、发起端及 purpose 是 Link 的不可变身份关系；修改须使用新 LinkID。

Policy 可另外保存正整数 `max_hops`，限制受管节点链的节点数量；省略表示没有额外跳数限制，候选仍拒绝重复节点。
这保留已有部署的路径限制，UI 修改其他 Policy 字段时也必须保留它。公开首跳和本机 hybrid Link 起点应用同一限制。

数据面凭据固定采用 RFC 5869 HKDF-SHA256：IKM 为解码后的 32 字节 RuntimeKey；salt 为原始
`loom-runtime-key-v3\0`；输出 L=32 字节后作无填充 base64url。本链的 info 为下列最小绑定对象的 C 编码：

```text
network_id, device_id, service_id, policy_id,
resource_id, resource_auth_digest, receiver_node_id, purpose
```

所有 ID 与当前有效授权、固定所属 Service、共享资源和接收节点精确一致。最终出口的 purpose 为 `service-auth`，
不携带 relay_target。中继接收用途为 `relay-auth`，info 另外包含 `relay_target:{link_id,resource_id}`，固定下一段 Link
和它的目标 Hy2 资源。两种用途不能互换；中继 ACL 只允许该 Link 对端 WG 地址上的目标 UDP 端口，不能访问 Service
或其他宿主目标。设备持有完整 Hy2 outbound 链的逐跳凭据，中间节点只持有本 listener 的入站凭据；末跳再执行 Service ACL。
resource_auth_digest 只绑定资源 authentication，用于落实资源认证身份变化后旧凭据退出的既有要求；
不绑定整个资源的显示/拨号值。设备或策略改名、给同一设备增加另一 Service 的授权，不是此服务
换钥的理由，不能把整份 authorization_material_id 或完整 Policy 摘要塞入 KDF 而制造这种扰动。
撤权、deny 或移除该策略时，不存在此服务的凭据投影；相同 Policy 的规则收缩必须由真实入站 ACL
收口并拒绝超范围目标，不能只凭 KDF 输入变化声称撤权完成。下列反例约束最终字段选择：

| 变化 | 必须结果 |
|---|---|
| 仅修改设备或 Policy 的显示名称 | 已有该服务凭据及实际访问权限不因改名改变 |
| 保留 Service A 授权，另给该设备分配 Service B | A 的派生输入和凭据保持不变；B 单独投影 |
| 撤销 Service A，或将其策略改为 deny | A 的出站凭据、接收端入站凭据/ACL 退出；应用失败也不得恢复，B 不因 A 撤权取得或失去权限 |

此最小绑定落实当前有效授权及撤权期间拒绝旧值的要求，不承诺“撤销后显式重新授予同一 Policy”仍
永久禁用历史派生值。如果另有这种增强需求，须先明确它与重新授予的关系，再决定是否需要仅与该授权
范围相关的输入；不能自行新增授权代号、权威记录或用整份设备事实摘要代替论证。资源 authentication
的精确规范值和实际入站替换未验证前，不把 KDF 单测通过当生产撤权完成；这不阻止本节最小绑定的纯函数实现。
客户端与接收节点得到匹配派生值，其他节点既不得取得 RuntimeKey，也不得取得本节点之外的入站值。
本机 selector API 属于 HostAdapter 的本机受保护执行输入，不用虚构的 Service/Policy ID 派生业务权限。

新认证 View 与 floor 先原子保存；再替换相关入站凭据、ACL、出站与实际进程。应用失败只保留新认证状态，
运行状态为 error/未应用，旧的已撤销权限必须停止，不能从旧配置或 rollback snapshot 恢复。
创建对象的所有权只能由实际创建与精确回读证明；遇到未知现存对象不得把“曾在旧 View 中出现”当所有权。
清理失败保持失败并报告，不自动重复应用。跨节点传播期间未获撤权者的旧状态不等于已全网撤权。

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
发行者所引表的完整成员证明，不能用自称的当前表替代。首次拨号只使用已验证 payload.endpoint 的坐标和
认证身份，并核对承载者就是 issuer、模式含 bootstrap；不能因另一入口可达就替换它。沿用已有扫码/复制入口，传输字符串唯一为 `loom://enroll#` 加完整 `C(BootstrapInvite)` 经 zlib
无损压缩后的无填充 base64url。zlib 使用 RFC 1950 单流、无预置字典、固定压缩等级 9；统一编码器
确定输出，解码后重新编码须与原交付字符串逐字节相同。压缩与解压正文各限 8 MiB；拒绝尾随字节、
拼接流、其他前缀、空白、旧未压缩交付及第二种 JSON 包装，不提供回退。解压结果仍须是完整原始规范
JSON 并逐层验签，Material 的签名字节不变。重新显示/复制使用原字节，不重新签发。成员数始终只是
ControlConfig 数据；证明增长超出单个二维码容量时，UI 明确报告无法生成二维码，保留同一原字节的
复制与加入文件入口，不删成员、缩短证明、换身份或静默更换媒介。本链不引入分片交付状态。

claim 和 resume 的字段均为 `schema=3,network_id,genesis_digest,transaction_id,invite_material_id,`
`request_id,device_public_key,platform,signature`。使用各自既定签名域，身份私钥在设备生成。
首次 claim 仅交 issuer；服务端核验端点 bootstrap 模式、完整 Invite、当前签发资格、职责/媒介、期限、
平台能力和一次性绑定，再签 bind 事实。平台只表达目标端识别结果，不是硬件证明；不能因此扩权。
resume 必须与已持久绑定的 request ID、公钥和平台完全一致；响应丢失不能重新生成 RuntimeKey 或身份。

普通加入响应字段为 `schema=3,transaction_id,state`，state 为 `open/bound/completed/cancelled/expired`；
completed 必须另有完整 `device_view` envelope，其余状态不带 View。响应经认证私有 tunnel 取得，
响应状态只投影事实；成功授权须由下面的 View 验证，状态字符串本身不能推进 LKG 或 floor。
绑定、完成、终结由事实恢复，没有 approval/complete writer、pending-device 或安装回执权威。

EndpointGeneration 的普通值字段为 `id,generation:U64,owner_control_id,host,port,server_name,spki_sha256,`
`certificate_digest,modes,state,drain_until:Time,preference`；generation 至少 1，modes 为 `bootstrap/device/web` 排序集合，
state 仅 `prepared/serving/draining/retired`，preference 为 0～65535 整数。certificate_digest 只定位公开
证书字节，本机秘密文件引用不在 wire。draining 的 drain_until 必须大于 0，其他状态固定为 0；
正式状态变更入口核对 draining 截止期晚于请求时刻，纯值校验不读时钟。到期关闭本代已有会话，
retired 的写入还须回读本代 Active 为 0。合法阶段转换、承载者退出和正式/回环 Web 证书边界仍按既有模型执行。

### DeviceView、成员证明与唯一 LKG

私有 tunnel 使用 TLS 1.3 和 ALPN `loom-tunnel/3`。每帧为四字节网络序长度及一个完整 C(JSON) 值；
接收者超出资源边界时拒绝，不截断值。hello 为 `schema=3,mode,endpoint_id,generation:U64`，
bootstrap 另带完整 `invite:BootstrapInvite`，device 另带 `device_id`，两种字段不得混用。
device challenge 为 `schema=3,nonce`，nonce 为 32 随机字节的无填充 base64url；proof 为
`schema=3,signature`，设备以 `loom-device-tunnel-proof-v3\0` 加 `C({hello,challenge})` 签名。
认证成功回应 `schema=3,status="ready"` 后，同一连接承载私有 HTTP。bootstrap 只能访问同一邀请的
claim/resume；device 每次请求仍检查当前设备授权。SPKI 摘要为 `sha256:` 加 X.509
RawSubjectPublicKeyInfo 的 SHA-256 小写 hex，证书摘要同格式但哈希完整叶证书 DER，均不加 JSON 或签名域。
客户端同时验证这两个摘要、名称、serverAuth 用途和有效期；仅握手成功不能制造运行健康。

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

本链 DeviceView 的字段为 `schema=3,device_id,name,platform,device_public_key,responsibilities,policy_ids,`
`services,policies,resources,links,endpoints,dns_servers,business_probe_targets,routes,runtime_profile,`
`inbound_credentials,expected_components`。所有集合显式出现；没有相应授权时为空集合。
View 职责包含普通设备授权与成员表的有效投影；其中 control 只能来自已经验证的成员表。
runtime_profile 仅 access 出现，包含 `kind="sing_box",config`，config 是 C 编码的 JSON 字符串，
包含候选 outbound、Service selector 与权限规则；平台本机 capture/listener 和本机 API secret 由
HostAdapter 投影，不可扩大签名 selector 的成员。无业务权限的 access 仍须能表示拒绝业务的合法运行配置，
不能因 routes 为空而拒绝认证配置。forward/出网的入站值由当前权限单向投影，不接受本机自填 ACL。
Linux 的本机 selector 另可选择既有 `reject` block，以表达该 Service 没有可用候选，并在启动时默认拒绝。
它仅减少运行时转发，不增加候选或改写签名 profile/LKG；拒绝位置不进入 Selection 或候选报告。
业务观测过期后按同一授权重新选择，其他 Service 与服务节点 listener 不因单项业务失败停止，详见
[Preference 与 Selection](../clients/client-runtime-model.md#preference-与-selection)。

services/policies/resources/links/endpoints 均使用上述完整值，引用仅限该设备可消费范围；
policy_ids 保留设备原分配；policies 只包含当前有效值，缺失的所选策略或缺失所属 Service 表示该权限已收口，
不能使完整认证 View 因没有业务权限而被拒绝。运行候选、凭据或 allow 规则引用缺失值则必须拒绝；
有效策略仍按 Service 检查唯一性。dns_servers 是规范排序 IP 集合；business_probe_targets 的项为
`service_id,targets:[]HTTPS_URL`，按 Service ID、URL 排序，目标须匹配该 Service 且设备所选策略 allow。
无适用目标保留空集合，不能填入硬编码公网目标。expected_components 的项为
`component_id,platform,version,artifact_digest`，按组件和平台排序；发布记录的验签仍需其独立契约。
HTTPS 目标池在现行模型中没有限于 443 的业务约束；非默认端口仍须精确授权和按原 URL 校验证书。
TLS 校验名始终是原 URL 的主机名，HTTP authority 保留非默认端口；地址尝试或代理不能将二者换成
拨号 IP，也不能跟随重定向后把另一目标的结果记给原 URL。各端实际端口消费的证据见[实施状态](../progress.md)。

候选身份字段为 `service_id,first_resource_id,node_chain,link_ids,final_exit`；Direct 与本机出口的
first_resource_id 为空且两条链为空，final_exit 分别为 `direct` 和设备 NodeID。一跳有首跳资源而无 LinkID。
RouteCandidate 在这些字段外还有 `id,spec_digest,scope`；id 和 spec_digest 按本节摘要规则计算，
scope 固定为 `service:` 加 Service ID。入站凭据项为
`device_id,service_id,policy_id,resource_id,receiver_node_id,credential,allowed_targets,excluded_targets`；credential 为
前述 KDF 输出，互联网 allowed_targets 是规范排序 Matcher 集合，只能来自该 Service 及当前策略的
获授权投影，不能由 credential 持有者扩张。excluded_targets 为该来源设备其他当前所选 Service 的
matcher 去重并集（包括 deny），同样显式、规范排序。先拒绝 excluded，再允许 allowed，默认拒绝；
这保持 Service 后继修改造成交集时的拒绝语义，不把凭据本身当成目标授权。每项按
`device_id,service_id,policy_id,resource_id,receiver_node_id` 排序且唯一；凭据用户名由这组规范字段的
摘要派生，不通过有歧义的字符串拼接。它只表示发往 receiver 的现行一跳权限，不是中继下一跳 ACL。

一跳 Hy2 的第一资源 owner 必须同时符合 Policy 入口和出口范围并有 internet_egress；节点链恰好
为 `[owner]`，LinkIDs 为空。签发端按完整 Projection 检查 owner 资格，只向 access 交付实际可消费的
远端资源；接收端另取得自身承载资源及其入站凭据。接收端 services/policies 可包含这些入站引用，
其自身 PolicyIDs 仍只表示自身 access 分配，不能填入来源设备的 PolicyIDs。access 的派生密码留在
同一认证 runtime_profile 对应 Hy2 outbound 中；检查该配置时只将密码当私有投影输入，其他拨号、
信任、候选和授权规则均须由 View 重建并比较，不从配置反写领域事实或增加 fallback。

接收端按 Hy2 请求实际携带的 FQDN/IP 执行目标规则；不得用 sniff SNI 为任意 IP 请求扩大权限。
本机 TLS 引用及监听坐标仅定位执行输入。撤权先耐久接受新 View，再关闭旧进程和存量 QUIC 会话，
然后建立新 generation；仅热换 user 表不能撤销已认证会话。失败保持新 LKG 并报告 error，重启不复权。
共享 listener 的合法会话因此可能短暂中断；不为避免中断保留旧 ACL、凭据或第二状态源。
完整中继与 WG 参与地址的执行字段仍单独待补，不能从一跳成功推定它们已实现。

验收顺序固定为：严格规范解码 → 固定网络锚 → 连续成员证明与签发资格 → 完整 envelope 签名 →
View 摘要 → 设备 ID/公钥/平台 → 内部引用及授权/运行映射 → 已见前沿。任何一步失败都不覆盖原 LKG。
只在合法连续多数证书明确封存的键上适用前沿例外；原高水位和不可回退 latch 不删除，其他键不回退。
前沿验收通过后，成员证明、完整 envelope 和逐键高水位在同一次原子持久替换中保存，成功后只有一个 LKG。
平台 preflight、进程启动、业务探测和 report 成功均不参与认证验收；它们失败也不能撤销已经接受的新授权边界。

### Report 与逐条观测

DeviceReport 字段为 `schema=3,network_id,device_id,report_sequence:U64,view_digest,network_generation,reported_at,`
`selections,observations,runtime,components,signature`，report_sequence 至少 1，签名域固定 `loom-report-v3\0`。
设备在发送前将下一序列与本机身份状态持久保存，重试只重发同一原始报告；崩溃允许序列跳号，不允许复用。
selections 每项为 `service_id,candidate_id`，按 Service ID 排序，表示实际 selector 回读；没有实际选择则为空。
runtime 为 `state,applied_view_digest,error_code`；state 仅 `running/error/stopped/unknown`，
无故障时 error_code 为空字符串，不能承载含秘密的错误正文。运行摘要必须来自实际加载结果，失败时不能将
当前获认证 View 摘要冒充已应用摘要；尚未加载任何 View 时 applied_view_digest 为空字符串。
承载 Hy2 的运行报告另有非空可选 `resources`，按 resource_id 排序；纯 access 不写空的替代集合。
每项为 `resource_id,listener_id,listen,certificate_digest,acl_digest`，其中 listen 为本机实际监听的
规范 IP:Port，certificate_digest 是对该 listener 完成真实 QUIC/TLS 验证所见叶证书 DER 的摘要；
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

对应关系为实际 APK/执行映射 → 原 ComponentReadback → 原 schema 3 签名报告/观察持久值 → 设备版本页面；
没有新的安装权威、配置字段或组件状态 store。当前完整 APK 的直接库映射是唯一已实现交付形态，
未知 split/提取形态不能猜测文件；应用 manifest 未定义前不能从这些运行报告倒写发布期望。
最小验证覆盖无期望时 APK/库摘要回读、另一文件或 ABI/偏移拒绝、文件变化、报告平台约束，以及
原签名 APK 在同机模拟器的真实业务、受保护身份重启与私有报告回读；实体 ABI/切网仍由用户终验。

Observation 字段为 `level,service_id,candidate_id,resource_id,link_id,target,action,spec_digest,`
`network_generation,result,observed_at,valid_until`，可选 `duration_ms` 为非负整数。
level 仅 `resource/link/service`；不适用的四个 ID 字段固定为空字符串，不能缺席。
resource 层仅 resource_id 非空，link 层仅 link_id/resource_id 非空，service 层仅 service_id/candidate_id 非空；
每条保留实际 target 和 action。spec_digest 分别绑定资源、Link+资源或候选规范内容。
按 `(network_generation,level,service_id,candidate_id,resource_id,link_id,target,action,spec_digest)` 排序且无重复。
目标为确切 HTTPS URL 或相应传输动作的确切坐标，不能用一个聚合颜色替代。

本链 HTTPS action 固定 `https_request`；result 仅 `available/unavailable/unknown`。
时间均为 Time，必须 `observed_at < valid_until`；到 valid_until 即失效，接收方不能按接收时间延长寿命。
迟到报告可保留诊断，不能作为当前健康。超出本 View 授权、跨网络代、旧摘要或失效目标同样为 unknown，
不写回 Material。最大可接受寿命和设备时钟偏差容忍仍待按业务采样频率、离线成本与时钟来源确定：
过长会保留旧成功，过短或零容忍会把有效路径频繁降为 unknown。现有模型没有足够依据给出数字，
因此本节不自行猜测这两个数值；补齐同一规则之前，不能实现生产的新鲜性判定器，
也不能直接信任设备给出的任意未来 valid_until。

接收者按当前设备授权、公钥、签名和规范值验证报告；按设备持久高水位比较 report_sequence。
同序列相同原始字节幂等；同序列不同字节拒绝并保留证据；更低序列不能覆盖最新报告。
诊断历史过期不能删除最高已接受序列对应的签名报告；最新索引从这些原始值重建，不按接收时间排序。
接收实现可以在内存保留同一规范历史的解码结果，但每次写入都须在既有排他锁内重新读取并核对受保护文件
的精确字节；字节改变时重新严格解码，缺失、非规范或权限错误仍拒绝。缓存可删除重建，不另存序列、完成状态
或第二份历史。新报告只插入既定规范排序位置，保留全部原签名字节、重放边界与分叉证据；不能靠清空历史、
缩短报告内容或先确认后落盘解决确认超时。最小验证包括并行 writer 的新值回读、缓存后的非法文件拒绝、
两种到达顺序的同序列分叉、重启和原始字节相等。
报告序列只用于报告重放边界，不能当控制事实 floor、配置完成或全网传播证明。
普通 access 的接收响应仅为 `schema=3,report_sequence:U64,status="accepted"`，在认证私有通道返回；
只表示该签名报告已持久接受，不表示业务成功、配置已应用或其他 control 已收到。
服务节点报告的 listener、ACL、实际进程和返回路径逐项字段还须按现有运行回读入口补齐；
不能省去这些结果后宣称 schema 3 服务节点运行状态已可验证。

本链可用单目标、单候选验证真实运行、改权和撤权；这不规定多目标结果归约。
同 Service 多目标混合成功/失败、多个可比指标的优先级仍按客户端模型的待决点另行明确，
不得把首个目标、最新样本或传输成功当作整个 Service 的业务状态。

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
同 Service 重复策略、空授权与 deny、同事务响应丢失恢复、KDF 接收方隔离、执行失败不复权和重启回读。
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

Linux 安装器在 `--capture mixed` 明确激活时，使用 root 保护的唯一 `current` 符号链接定位 releases 下的
规范 manifest 内容 ID；该 manifest 和原始签名共同表达本机已接受的发布代。缓存目录不是接受记录，
`--no-enroll` 不推进它。同平台低代与同代异值拒绝，同代同值可重试。先停止并禁用旧执行，验证精确程序
与清理，再写 unit 并原子推进 current；接受后启动失败只禁用执行，不回退 current 或设备认证状态。
unit 为已签模板与显式本机路径的投影，不能有未核验 drop-in。重试不能用包内公钥覆盖安装信任。
旧格式 current、已部署 signed-current floor 或未知旧入口不能作为初次安装绕过；它们仍按下面生产切换门禁处理。
新程序运行回读后仅 compare-and-delete 被替代的两个可执行文件，旧 manifest、原签名和源码证据保留。
接受后失败再重试时，从同一受保护 releases 目录内已验签的同平台较低代清单识别应退役程序；不新增旧指针
或安装 receipt。未来代缓存、未认证条目和其他文件不由此删除。

## 签名 catalog 与安装包、运行文件的对应

本节补齐既有 Release/Artifact 的交付索引，不新增控制权威、安装 receipt 或协议号。当前已存在两种规范
manifest：`linux-client-bootstrap` 和 `windows-dataplane`。它们保持原始签名字节；catalog 只引用它们，
不能把整包摘要写成包内程序的运行摘要。Android APK、Windows 三种应用交付和通用 bootstrap 脚本各自的
非空 manifest 按各自交付边界定义；下面补齐通用脚本，Android APK 与 Windows 应用尚未定义的 kind 拒绝，
不能使用任意 JSON 透传。

catalog 固定字段为 `{schema:3,generation:U64,entries:[]ReleaseEntry}`，generation 非零；entries 非空，
按 `(component_id,platform)` 严格排序且唯一。此处 component_id 表示交付组件，当前为两个程序包 kind
及 `linux-bootstrap-script`；程序包 platform 恰为 `<os>-<arch>`，通用脚本为 `linux-any`。
每项固定为 `{component_id,platform,manifest_digest,artifact}`；
manifest_digest 为原始规范 manifest 的 Digest。artifact 固定为 `{name,digest,size:U64,media_type,audience}`，
文件名为单个安全 ASCII basename，digest 为完整下载字节的 Digest，size 非零，当前 audience 恰为 public。
Linux archive 的 media_type 为 application/gzip，Windows 数据面 ZIP 为 application/zip，通用脚本为 text/x-shellscript。
版本、源码、组件代及包内精确程序坐标由已引用的原 manifest 读取并核对，不另复制一份可独立修改的值。

签名为 64 字节 Ed25519，覆盖 `loom-release-catalog-v3\0 || C(catalog)`；规范 catalog 摘要定位不可变
`catalogs/<digest>/catalog.json` 与 catalog.sig。原 manifest 与原签名存放于
`manifests/<digest>/manifest.json` 与 manifest.sig；整包只存于 `bin/<digest>`。所有路径均从摘要确定，
不接受调用者提供任意相对路径。原包、manifest、签名与逐文件内容须同时验证；包中的原 manifest/签名
必须与外层引用逐字节相同，组件 ID、平台、媒体类型及公开受众必须相符。

私有下载 URL 同时固定 catalog digest 和 artifact digest；更新 current 后，已经打开的页面仍取得原先
选中的精确字节。读取被明确寻址的旧代 schema 3 catalog 只提供下载，不改变安装接受代、期望事实或 current，
也不接受旧格式。后续安装仍须独立验签并遵守已有组件代。损坏的目录、签名或制品使对应下载失败；当前目录
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

### 节点期望组件的精确发布引用

`ExpectedComponent` 是已经定义的节点期望值，不是发布任务或安装状态。稳定身份由
`{node_id,component_id,platform}` 决定；删除该值会丢失管理员对这一个程序及执行平台的期望，
无法用下载 current 或其他节点的成功恢复它。规范字段恰为
`id,node_id,component_id,platform,catalog_digest,manifest_digest`；id 等于
`SHA256("loom-expected-component-v3\0" || C({node_id,component_id,platform}))` 的 Digest 表达。
两份发布摘要固定原始 schema 3 catalog 与其引用的 manifest；不保存 archive/ZIP 摘要作为程序摘要，
也不再复制一份可编辑的 version、运行摘要或制品内容。现有可解析组合为 Linux agent/sing-box 与
Windows sing-box/wintun，平台为相应 OS 的 amd64/arm64；没有规范 manifest 的应用组件不能创建期望。

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
发布公钥独立验证原引用；缺文件、错签名、摘要或组件不符使受影响的期望投影不可用，不能降成空期望。
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

上述是证明义务，**尚不是一份已批准的迁移算法**。只读核对进度见[实施状态](../progress.md)及其受保护
证据；逐节点 floor、对应签名载荷、公钥连续性、快照到新 manifest 的对应及真实运行制品必须形成完整
证明，才能填写切换记录。取得其中部分材料不能据此声称生产可用。

旧发布证据的离线 `loom verify <发布根>/<snapshot> -pubkey <固定公钥>` 按既有发布树读取
`snapshot.json`、原始 64 字节 Ed25519 `snapshot.sig`、`nodes/<owner>.json` 及发布根内
`bin/<sha256>`。必须先验原始 manifest 签名，再验证目录与 manifest 的快照 ID、逐节点包内容摘要、
每个二进制的长度与摘要；未知/重复字段、重复节点/平台和越界文件引用拒绝。此入口只读既存证据，
不运行生成器、不写 floor、不激活制品，也不把旧对象交给 schema 3 Authority。
完整快照通过不能代替与 floor 对应的 signed-current 载荷验签；缺失材料仍阻止切换证明成立。

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

用户已在当前部署任务明确授权删除旧版、正式切换和真实业务验证，不再以寻找历史 signed-current
原件作为本次替换的前置。该授权优先于本文此前列出的发布机制迁移证明流程：本次按精确制品直接
替换正式服务，旧发布入口退出运行；已有身份、密钥、授权业务资料及原始记录受保护保留，
不把归档恢复成运行 fallback。新服务只消费当前规范输入，替换后须完成业务、报告及重启回读。
此授权不放宽宿主 TUN/netns、SSH 管理通道或现有 underlay 的保护边界。

本次执行从核验过的旧材料显式构造 schema 3 初始签名材料，保留同一网络、成员公钥、设备签名密钥及
管理员证书；沿当前 Invite/claim 和普通管理入口重新建立原授权的精确对应。旧签名域的认证序列与新域的
事实序列不是同一计数器，不能以同号或较大数字宣称连续；旧原始 floor、head 和签名字节单独封存，
新设备仅固定这次交付的当前 genesis，拒绝旧格式输入和任意替代根。发布 floor 原文件保持，当前服务不读取
旧 current，也未启用尚无单调消费证明的新 catalog。逐节点身份、公钥、原始文件摘要与精确运行制品的
对应只保存在受保护切换证据；这不是供未来自动迁移使用的第二 decoder 或第二权威。

3 号对象改变了现有签名 Material、成员证明及设备视图的字节和投影语义。已认证 head、已部署持久字节、
现网身份与密钥、数据、认证 floor 和不可回退 latch 必须保全，编号变化不授权重解释这些字节。其他未获此次
明确映射覆盖的状态与 3 号目标不相容时，冲突写入和生产切换保持失败关闭，不自动生成替代 genesis、清空信任或让旧路径继续
充当权威。由用户明确决定并验证前向切换办法后，才能启用相应生产写入；文档完成不视作业务完成。

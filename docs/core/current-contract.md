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
| 私有入口与 Invite | `EndpointGeneration` 定义入口身份和生命周期，只由承载它的 control 签发，承载者失去 control 资格时一并退出；Invite 是 control 签名的一次性受限能力，固定发行者、首次信任锚、目标设备、职责与授权。首次 claim 只由发行者处理；扫码签名内容限 `access`。 | 已加入设备以设备身份使用认证管理通道；入口可达不授予成员或业务权限；`control.loom` 解析为 web 模式入口。 |
| 设备授权与视图 | `DeviceAuthorization` 是签名事实的有效结果；普通职责由有效 control 单签，`control` 只由成员表投影。`DeviceView` 由有效 control 对设备相关配置、成员证明和事实前沿签名；设备原子保存信任绑定、完整 LKG、不可回退 latch 与单调的已见高水位。连续多数证书仅可对明确封存的键把新 View 验收前沿降至封存序列，原高水位与 latch 保留，旧 LKG 只在验收失败时保留，成功时原子替换唯一 LKG；留任 control 在证书验收前已持久接受且可验证的超限撤权自动重签，原始证据全失时可能复权，必须标记可见差异和剩余未知风险。其他键、成员链和既有全局认证 floor 不回退。 | 运行时、报告和 UI 仅从获授权的视图与真实观测生成；不能由视图、报告或颜色倒写权威。 |
| 发布记录 | 发布签名密钥签署的不可变 release catalog 与制品 manifest；规范签名负载包含 schema 3、单调发布 generation，以及每项的组件 ID、目标平台、制品摘要、长度、媒体类型、受众、版本和可选最低兼容版本，签名覆盖所有这些字段及规范排序。发布私钥引用来自 `LocalDeploymentConfig.signing_key`（`LOOM_SIGNING_KEY`）；验签公钥由验证方受保护的安装信任输入固定，发布前须与签发密钥的公钥核对，不从待验 catalog 或 Web 响应取得。签名 release store 独立于控制事实；可变 `current` 指针只定位待验 catalog。 | `Projection` 只按摘要引用期望组件；Web 仅展示验签且逐文件核验通过的 catalog。公网 Nginx 只分发受众为通用公开的制品；设备与节点报告实际运行坐标，只有报告与期望摘要相符才能显示已应用。 |
| 客户端本机值 | `DeviceIdentity` 私钥与信任绑定、已见 floor、完整 LKG、唯一 `Preference`，以及 Android/Windows 保存用户命名、稳定本机 ID 与恢复意图的 profile catalog；各自严格 schema、原子持久往返。 | 候选、Selection 与 UI 每次从这些值和宿主回读重建；这些值不作为网络权威上传。 |
| 本机部署输入 | [配置模型](../operations/configuration-model.md)规定的六键规范 `.env`，密钥和证书正文留在受保护本机输入。 | 只生成本次部署计划与脱敏结果，不保存 control 或 DNS overlay 的第二份事实。 |

控制面 Web 只使用网站服务端证书和 admin 客户端证书。网站根证书必须有 critical `.loom` DNS 约束和全 IPv4/IPv6 IP 排除，且目标浏览器已实测执行这些约束才可导入，根私钥不得进入 control；control 仅持有 `control.loom` 网站叶私钥，网站根与成员/传输 CA 分离。普通已加入 access 可打开私有
`control.loom` 入口页；管理数据和操作要求 admin 证书，受信 admin 名单由普通事实维护、所有 control
一致。reader 证书、read capability 和对应的第二套页面权限不是本契约的一部分。
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

## 遇错时只修订这一份契约

3 号确定后，除非用户再次明确要求**新协议或新版本**，错误、字段遗漏、测试失败和实现偏差都通过修订
同一 3 号模型、实现与测试解决。不得追加 4 号、新的 `runtime_contract` 值、第二份 DTO/store、双写、
双读或长期旧格式 fallback；`EndpointGeneration`、源码提交号和制品版本也不是协议版本逃生口。

## 现网字节与生产切换

3 号对象改变了现有签名 Material、成员证明及设备视图的字节和投影语义。已认证 head、已部署持久字节、
现网身份与密钥、数据、认证 floor 和不可回退 latch 必须保全，编号变化不授权重解释这些字节。现网状态
与 3 号目标不相容，冲突写入和生产切换保持失败关闭，不自动生成替代 genesis、清空信任或让旧路径继续
充当权威。由用户明确决定并验证前向切换办法后，才能启用相应生产写入；文档完成不视作业务完成。

# Enrollment 与 Endpoint 核心模型

[设计入口](../README.md) · [控制权威模型](control-model.md) · [唯一现行契约](current-contract.md) · [实施状态](../progress.md)

本文定义设备取得一次受限加入资格、绑定本机密钥、领取私有配置及使用服务入口的现行语义。
控制权威来自[控制权威模型](control-model.md)的签名 `Material`、`ControlConfig` 成员表链及确定性
`Projection`；本模型不另建共识、成员或设备授权的权威。具体实现状态与生产切换阻碍见
[实施状态](../progress.md)。

## 边界与不变量

1. 公网 Nginx 只提供伪装网站和明确认证为通用公开的不可变 `Artifact`；Invite、claim、resume、
   设备配置、报告和管理 API 均不在公网网站上暴露。
2. 只有当前有效的 `control` 能签发 Invite。签发本身就是加入批准，不再等待第二次管理员批准。
   普通设备加入、非 control 职责与授权变更和删除，由任一有效 control 签发；后来管理该设备的
   control 不必是 Invite 签发者。
3. 先选择职责，再确定交付方式：职责恰好为 `{access}` 时使用二维码；包含 `forward`、
   `internet_egress`、`control` 中任一项时使用 SSH 或 sh bootstrap 脚本，不使用二维码。
   三种媒介复用同一 claim、身份、授权、配置与报告协议；签发、客户端解码及首次 claim 均校验
   职责与签名媒介匹配，不能只依赖 UI。角色组合还必须受目标平台实际运行能力支持。
4. 首次 claim 只能交给签发该 Invite 的 control；转发到其他 control 不构成首次绑定。签发者失联时
   这张 Invite 不可用于首次加入；可等待其恢复，或由有效 control 对新的稳定 ID 重签。
   原目标 ID 只有按下述事务终结规则释放后才可复用。
   完成加入后可从已同步该设备事实的其他有效 control 领取配置，设备也可由其他 control 管理。
5. `access`、`forward`、`internet_egress`、`control` 是可组合的职责；不存在 `server` 业务角色。
   `control` 资格只由多数签名的成员表决定，Invite 中的意向本身不赋予 control 权限。
6. `EndpointGeneration` 和签名 `DeviceView` 决定设备可使用什么；`Observation` 只说明在相应网络代
   最近实际发生了什么。授权不等于可达，暂时不可达也不修改授权。
7. 设备稳定 ID 由 Invite 指定，跨事务保持唯一：签发者拒绝与已知节点、设备或 control 成员 ID
   冲突的 Invite；不同 Invite/绑定即使各以事务 ID 为事实目标，仍按其占用的设备 ID 检查唯一性。
   未终结事务与已完成设备身份重复占用同一 ID 时，相关授权都不投影。
   分区中并发产生的同 ID 加入按此跨事务唯一性规则失败关闭；若已有 control 增员证书，该证书仍留在成员链，
   但冲突 ID 的设备认证和运行授权暂停，须经成员门禁处理错误成员。不以显示名、平台或职责覆盖旧身份。
   删除留下防复活事实；重新加入使用新的稳定身份和密钥。
8. 设备本机生成并保护私钥。现有身份、密钥、数据、认证 floor 与不可回退 latch 的前向切换未验证前，
   不把新文档语义静默解释为已部署字节的语义；正式入口拒绝旧格式和旧协议。

## 控制输入与五个核心概念

控制输入是已验证的成员表链和签名事实集合。`Projection` 从有效事实确定性重建，包含
`NetworkIntent`、设备授权、管理员证书名单和入口代；发布记录由发布签名密钥签署，不是控制事实，
`Projection` 只按摘要引用期望组件。仅看见 `Material` 字节、网络握手或报告，不代表该事实
已通过签发者资格、因果依赖和冲突规则校验。无多数连接时，有效 control 仍可签发普通加入与授权；
变更 `control` 资格才需要旧成员多数签名。单个 control 的本地接受不是全网即时一致的证明。

本模型自有概念为 `EndpointGeneration`、`Artifact`、`BootstrapCapability`、
`EnrollmentTransaction` 和 `DeviceView`；运行观测复用客户端模型的 `Observation`。
`Invite`、claim、resume、证书证明及响应包是这些概念的交付值或操作，不另有生命周期。

删除任何一个概念都会破坏明确需求：没有 `EndpointGeneration`，入口地址、证书与 SPKI 无法原子轮换，
设备也无法区分新旧入口；没有 `Artifact`，公网 Nginx 无法校验哪些制品可以公开分发；没有
`BootstrapCapability`，首次加入缺少限定签发者、职责与一次性的可验证授权，“扫码只许 access”无处表达；
没有 `EnrollmentTransaction`，claim 请求或响应丢失后无法恢复同一绑定，会产生第二身份；没有
`DeviceView`，设备只能拿全网事实或由各入口各自拼配置，无法做按设备签名的 LKG 与 floor 校验。
它们都不是新的治理权威：`EndpointGeneration` 与 Invite 生命周期是控制事实的类型，
`EnrollmentTransaction` 与 `DeviceView` 是 `Projection` 的派生值，`Artifact` 由发布签名负责。

### `EndpointGeneration`

一个逻辑私有入口在某一代上的完整配置，以稳定入口 ID 和单调 generation 标识。规范值包括
承载 TLS listener 的 control 节点、客户端地址、校验名与 SPKI、已受保护的证书引用、允许的
bootstrap、device 与 web 模式、阶段及 serving 期间的偏好；可选 edge 只转发字节，不终止认证或处理 claim。
同一入口 ID 固定承载 control，新代与阶段推进只由该 control 签发，代序号因此单调；换承载节点使用新入口 ID。
承载 control 失去 control 资格（卸任、强制撤销或整体删除）时，它承载的全部入口随该后继证书一并退出投影：
已验证该证书的设备不再把它们当作入口候选，`control.loom` 的新投影不再解析到它们，诚实运行时关闭
已有会话且承载节点停止相应 listener；证书不能强制失格节点实际停服，也不能终止尚未获知证书的会话。
不需要、也不接受它再为这些入口发布阶段变化。换键不影响入口。
处于 serving 的 web 模式代构成 `control.loom` 的解析结果。同一浏览器 URL 使用的地址须在该 URL 的
客户端端口提供服务；非默认 HTTPS 端口须在 URL 中显式给出，A/AAAA 不提供端口。地址和入口声明表示可尝试，不能构造 `available`。

```mermaid
stateDiagram-v2
    [*] --> prepared
    prepared --> serving: 验证材料和真实入口
    serving --> draining: 新代可用后停止分配新连接
    serving --> draining: 新代正式回读失败，立即停止新连接并签收口
    draining --> retired: 受保护会话结束
```

`prepared` 不供普通客户端选择；仅允许操作者以候选地址和预定校验名定向预检，且不发布到设备候选或 `control.loom` DNS。`serving` 可分配新连接，`draining` 仅允许已存在会话在明确期限内结束，
`retired` 不得再启动。明确期限由签名的 `drain_until` 表达为 UTC Unix 毫秒；draining 时大于 0，
其他状态固定为 0。进入 draining 的正式入口核对其晚于请求时刻；纯规范值校验不读时钟。
adapter 到期关闭该代已有会话，转为 retired 前必须回读该代 Active 为 0，不凭期限已到推测会话已清理。
轮换时可短暂有两个 serving 代；偏好来自签名事实，不建立额外状态机。
新代未通过证书、端到端访问和回读时，旧代不提前退休。轮换失败保持最后经验证的阶段和安全 floor。
TLS 就绪预检按实际协商协议各建一次连接：bootstrap 与 device 共用 `loom-tunnel/3`，不在同一
超时预算内重复握手；web 的 `http/1.1` 仍须单独验证。它只证明该协议的地址、证书、名称和 SPKI，
不能代替后续 bootstrap capability 或设备签名认证。反例是 tunnel 成功但 web 协商失败：整体预检仍失败。
公网映射落在非 control 节点时，edge 只做已有端口上的 TCP 转发；它不持有 control 或设备签名密钥，
不会因转发而获得 control 资格。外部 DNS provider、DNS-01 与 ACME 自动签发或续期不属于本模型。

web 模式的网站叶证书到期前，操作者使用独立离线保管的网站根私钥手工续签。承载 control 在本机生成新叶私钥与 CSR，
以已认证的成员身份将 CSR 摘要、节点 ID、入口 ID 和当前成员链证明绑定交给操作者。离线签发时验证 CSR 签名、
公钥、成员资格及目标入口；签发器按固定模板生成扩展，不照抄 CSR 请求：SAN 仅含 `control.loom`、
EKU 仅 `serverAuth`、`CA=false`，KeyUsage 不含 `keyCertSign`。叶私钥留在承载 control，
只有证书链经受保护渠道返回。

承载者核对链、名称、用途、有效期与本地私钥匹配后，以新证书引用建立下一 `EndpointGeneration`。
在 prepared 阶段用候选地址及 SNI `control.loom` 定向预检 TLS 与 Web；通过后才签发 serving 阶段，
再用目标浏览器从正式入口回读，成功后旧代转为 draining、retired。正式回读失败时只让**新代**
停止接受新连接并推进 draining；其会话结束后 retired，旧代证书尚未过期时继续 serving。
若签收口事实暂不可用，本机新 listener 仍先失败关闭并保留待补的阶段事实，不能因 DNS 缓存仍指向
该代而继续服务。证书到期后，已有 serving 声明也不能使新连接通过 TLS，
须失败关闭并在运行观测、本机 CLI 中显示到期故障，不按本机时钟改写签名阶段或 DNS 投影。
根证书不变则浏览器无需重导入；根轮换另需受保护信任锚迁移。

对每个 serving web 叶证书，用已验证的 `NotAfter` 和调用方注入的 UTC 时间计算剩余有效期。
剩余时间进入固定 30 天窗口时，admin 页面与本机 `control inspect` 显示入口、到期 UTC 时间和剩余时间并提醒续签；
过期显示故障，证书缺失或无法验证显示 `unknown`。该诊断不写控制事实，也不按时钟改变签名阶段或 DNS 投影。

同一入口若还承担 bootstrap 或 device 模式，新代须对这些模式分别预检，且不能悄悄改变旧代的校验名或 SPKI。
新 Invite 不得绑定会在 Invite 有效期内到期的旧代证书；已发的 Invite 仍固定旧代，计划轮换时旧代在证书有效期内
保留至这些事务完成或终结。若旧代先过期，剩余 Invite 失败关闭，须按原事务终结规则处理后重新签发，
不能把旧 Invite 静默指向新代。

### `Artifact`

`Artifact` 是内容摘要寻址的不可变通用制品，具有规范摘要、长度、媒体类型、签名引用和受众，
由发布签名密钥签署的发布记录声明，不是控制事实。同一摘要的字节不可覆盖。只有发布签名明确标为通用
公开受众的 Artifact 能经公网 Nginx 只读分发；设备专属配置、token、身份材料、报告和含秘密的归档永远
不能借名称伪装成 Artifact。

### `BootstrapCapability`

`BootstrapCapability` 是由签发 control 签名的 Invite 规范值，字段为：网络 ID 与 genesis 摘要
（初始信任锚）、签发者稳定 ID 与验证键、签发时有效的成员表链证明、只允许访问签发者的引导入口
（其 `EndpointGeneration` 身份）、事务 ID（即邀请 ID，`EnrollmentTransaction` 以它为稳定 ID）、
目标设备稳定 ID、显示名、精确的职责与所选 PolicyIDs、交付媒介、到期时间和一次性防重放约束。
Invite 固定所选 PolicyIDs，每条策略的 ServiceID 创建后不可改变；不复制一份可独立修改的服务绑定或策略规则。
签发时验证 Policy 与所属 Service 有效，且同一服务最多选一条。共享策略的后继修改按正常规则作用于引用
它的邀请和设备；claim 时引用已删除/冲突则拒绝，不替换为另一策略，deny 不授予业务权限但可完成设备加入。
界面回读当前规则与邀请签发时的策略选择，不能声称规则内容永久冻结。
Invite 不要求管理员预选操作系统。设备平台由目标端识别，在首次 claim 中随设备公钥、事务和
request ID 一起签名，并由签发者写入绑定事实及设备授权。平台用于制品选择和运行能力检查，不授予职责。
设备通过操作者可信的 SSH、脚本或扫码交付固定网络锚，不相信 Invite 自称的新网络或新成员表。
签名与成员证明均验证后，才可向所列入口发起首次 claim。签发者首次绑定前还须确认自己在当前有效
成员表中；已被撤销的 control 不能沿旧 Invite 新授予权限。

Invite 中已签名的可选 `dns_servers` 也是首次 bootstrap 的解析输入：验证完整 Invite 后，具名入口只经这些
字面解析器查询，保留原 TLS 名称、SPKI 和签发者绑定，不借系统 DNS 或 hosts。字面入口不需要解析器；
具名入口未配置解析器或查询失败时保留同事务身份并提示连接错误。继续加入仍用原 Invite、request ID 和密钥；
取得认证 View 后，新连接使用 View 中的当前解析器。查询和连接共用平台 underlay socket 适配，不新增持久答案。

扫码的签名媒介字段必须是扫码，职责必须恰好是 `access`；二维码解码器、签发入口及
签发者首次 claim 服务端都校验，不能仅靠 UI 隐藏其他选项。其他媒介的 Invite 重新编码成二维码时，
签名媒介字段不是扫码，解码器拒绝；媒介字段只约束诚实客户端，Invite 本身须按其职责范围保护。
首次加入前的入口连接结果只是本机引导诊断，不是经设备认证的 `Observation`，网络失败不扩大 capability
范围。首次有效 claim 固定设备本机生成的公钥及稳定 request ID，同一事务只接受一个 request ID；
同一请求重试只得到同一绑定结果，
其他密钥、职责或授权不可接管。同一 Invite 不能登记第二个身份。

#### 平台识别与职责选择

添加设备先以复选框选择 `access`、`forward`、`internet_egress`、`control`，四项可组合，
再由职责决定交付方式。设所选职责为 R：空集合或未知职责拒绝；R 恰好为 `{access}` 时唯一方式
为二维码；R 含其他职责时只允许 SSH 或 sh 脚本。不能因为 R 含有 access 就给组合职责发二维码，
也不向纯 access 提供 SSH/脚本。签发入口、解码和 claim 对同一 R/媒介组合得到相同的接受或拒绝结论。

角色控件始终可修改；添加方式从所选角色派生，不能反过来禁用或偷偷删除角色。
草稿从纯 access 改为组合职责时，保留设备名称和所选策略草稿，改为待选 SSH/脚本；从组合职责变成
纯 access 时交付方式变为二维码。这些都是未提交的草稿变化，不触发安装或签发。
只要仍含 access，就保留所选 PolicyIDs；移除 access 的策略分配处理遵守 Web 表单规则。
已签 Invite 的职责与媒介不可修改，需按原事务终结规则重新签发。

SSH 经操作者受保护的连接输入到达目标，先只读识别 OS/架构和安装条件，再签发并执行安装；
识别失败时保留输入并阻止安装，不默认猜 Linux。脚本在目标机器执行时识别 OS/架构，选择匹配的
已验证制品；sh 脚本只用于包含其他职责的设备，不改变邀请授权。扫码由已安装客户端
识别平台。签发前平台未知时，页面显示“待设备加入时识别”，不能显示管理员猜测的平台或伪造检测成功。

sh 方式交付一个带 HTTPS URL、完整 Invite 与安装器精确 SHA-256 的**完整多行 shell 块**，一次复制并粘贴
到目标机的 root shell（操作者可事先通过 sudo 进入），不要求第二次粘贴、先手动下载或传送脚本文件。
受保护管理面先验证发布清单，再从清单中取得
允许公开的通用不可变安装器 URL 和对应摘要，将两者固定在同一块中；不能从尚未验证的下载响应取得预期摘要。
完整块携带当前授权中已由控制端读回验证的分发入口，按规范 URL 排序。控制端的可达性不替代目标机器的
可达性：目标依次尝试这些入口，每次脚本和程序包下载均核对固定摘要；连接失败或异值可继续下一入口，
全部入口失败才退出，不能把未验证的响应交给 shell 或 installer。邀请只在下载与校验成功后交给原 installer，
各入口不是新的安装事务，也不改变已有身份、接受代或加入事实。
目标端先将安装器下载到仅操作者可读的临时目录，核对完整字节的 SHA-256，成功后才执行；全部入口下载失败、校验工具或
摘要比对失败立即停止并清理临时文件，不能先执行安装器再让它证明自身可信。安装器随后继续核验各平台制品及
Invite，再进入同一受限 bootstrap claim。

本次完整 Invite 通过 quoted heredoc 送入安装器的 `--invite-stdin`，不放入进程 argv、环境变量、公开 URL
的路径/查询串或公开脚本内容；heredoc 内容不作 shell 展开，结束标记不得与 Invite 内容冲突。命令、安装器和
错误处理均不得打印 Invite 或启用含它的命令跟踪。显示与复制使用同一完整块，不能截断或用省略号替代实际值。
该块只在受保护的管理交付界面显示和复制，复制不重新签发 Invite；命令、邀请 ID 与设备详情保持对应，完成、
取消或过期后不再交付旧块。这不增加公开 Enrollment 接口或另一种授权实体。

一次粘贴的块包含 Invite，终端可能将其写入交互历史或会话记录；用户已明确接受这一交付方式的终端历史风险。
这项选择不放宽上述 argv、环境变量、公开 URL 和应用日志边界，也不宣称 heredoc 能阻止终端记录；不自动改写
操作者的 shell 历史设置。

安装条件包括目标现有的 Loom 安装、持久身份与原加入事务。发现已有身份时先核对该身份及事务，
进入现有设备管理或同事务继续，不能覆盖密钥、清空状态或静默签发第二个身份；无法完成检查时拒绝新安装。
SSH 中断只说明未取得执行结果，不证明安装失败。重试先回读目标和签发者，再继续同一 Invite、request ID
及已绑定密钥；签发已接受而安装回执缺失时，不重建规则或邀请。二维码、脚本与 SSH 都按同一事实恢复，
不增加安装完成 store，也不把脚本下载或 SSH 命令返回替代设备授权与运行报告。

已知目标不支持所选职责时，签发前拒绝；平台未知的脚本/扫码邀请在目标安装与首次 claim 时再次检查。
签发者只接受当前支持的规范平台值，并核验该平台能够承担邀请中的**全部**职责；不支持、缺失或
未知平台均拒绝，不静默删除角色或部分加入。设备自报平台不是硬件证明，不能由此扩权。
首次绑定签名覆盖平台、设备公钥和邀请；同事务重试必须保持该绑定，平台变化或换密钥不能作为 resume。

平台值在 domain、claim wire、绑定事实、设备授权与 View 中含义一致，按统一契约规范往返；
安装检查和 UI 只读显示，不新增平台 registry 或授权来源。旧 Invite 中固定平台的已签字节不可静默
重解释；此处是 schema 3 目标修订，规范字段与前向切换仍受[现行契约](current-contract.md)约束。

#### 二维码的使用场景

二维码用于把一次加入邀请交给 **access 设备**。选择此方式时，邀请的职责集合必须恰好为
`{access}`；不能带 `forward`、`internet_egress` 或 `control`，也不能因为一台设备同时有
access 职责，就为它的组合职责生成二维码。此限制同时作用于管理签发入口、客户端解码和首次
claim 校验。界面文案统一为“二维码加入 · 仅 access”，不以“移动设备”代替角色条件。

| 操作者的需求 | 正式入口和允许的操作 | 身份及邀请的结果 |
|---|---|---|
| 添加一台 access 设备 | Add Device 选择二维码，审阅职责、服务策略、签发者、入口和有效期后签发 | 新 Invite 固定新设备 ID；设备本机识别平台、生成密钥并首次 claim |
| 邀请已签发但还没使用，重新打开二维码 | 从邀请详情读取同一张仍有效、未取消的邀请 | 只重新显示原邀请，不创建新事务或延长期限 |
| 已开始加入，但请求或响应丢失 | 客户端用保留的同一事务、request ID 和本机密钥继续 claim/resume | 继续同一次绑定；另一把密钥不能接管 |
| 邀请未绑定就过期或取消，需要换一张 | 先验证旧事务已终结，再沿 Add Device 重新签发 | 新事务、新期限；目标 ID 仅在确认已释放且没有删除墓碑时可复用 |
| 已入网设备更改服务权限 | 管理员从设备详情提交授权修改，设备沿私有认证通道领取新 View | 保留身份及密钥，不生成加入二维码 |
| 已入网 access 设备丢失本机身份，需要重新添加 | 设备详情进入“重新添加”草稿，明确列出旧身份停用、新身份及将重新授予的权限，再执行下述替换链 | 新 Invite、新设备 ID、新本机密钥；不复活旧身份 |

“重新添加”复用现有设备删除与 Invite 入口，不新增恢复 token、二维码 store 或身份替换权威：
先由管理员明确提交旧设备删除，当前 control 验证墓碑生效后，再依赖该删除事实为新 ID 签发
access 邀请。签发失败时旧身份保持已删除，页面显示“旧身份已停用，新邀请未签发”，以同一
请求重试；不回滚墓碑。新身份加入前没有新设备权限，重新扫码也不等于运行 Ready。
页面分别显示旧身份撤销的传播结果和新设备的加入结果；分区中旧节点尚未收到撤权时，不能称
全网已经断开。重启后从删除事实、Invite 和绑定事实重建结果，不依赖浏览器草稿判断完成。
已有旧 ID 的删除墓碑永久保留；显示名称可在新草稿中复用，但不能因此复用身份或密钥。

仅暂时离线或仍保有本机身份的设备使用重连、配置同步或原事务 resume，不需要重新添加。
组合职责及 control 设备不走 access 二维码替换入口；control 的整体删除仍须成员多数证书。
已完成、已过期或已取消的邀请不继续显示为可供新设备使用的二维码；邀请码和 capability
只能在受保护的管理员交付界面显示或下载，不进入事件、普通列表、日志和公开制品。

以上是目标使用链。当前源码的邀请二维码接口及 existing-node rejoin 旧入口不构成这一流程
已经实现的证据；目标 schema 的正式入口、持久化、撤权消费和重新加入仍须按实施状态验收。

### `EnrollmentTransaction`

`EnrollmentTransaction` 将一次 Invite 的签发、claim 绑定、完成或终止投影为同一个稳定事务 ID。
其可恢复状态由签名 Invite、签发者持久接受的绑定事实、普通加入的设备授权事实、取消/到期事实及申请
`control` 时的 `ControlConfig` 成员证书确定；不建立与这些事实并行的可写事务权威或第二份审批记录。
claim 绑定事实只能由 Invite 签发者签发，须在因果依赖中引用该 Invite 事实 ID，并固定请求 ID、设备
公钥与一次性约束；普通加入的设备授权事实也只能由同一签发者签发，须依赖绑定事实，并固定事务 ID、
设备 ID、公钥、准确职责与 PolicyIDs。普通事务在该授权事实通过验证后直接投影为 `completed`，没有独立
完成事实。申请 control 且包含其他职责时，签发者或已验证绑定的其他有效 control 先签对应的条件授权
事实（含所需 `RuntimeKey`），其因果依赖必须直接包含绑定事实 ID，因而可追溯到 Invite；该事实在成员证书形成前不赋权；证书须绑定 Invite/事务 ID、设备 ID、绑定
公钥与条件授权事实 ID，签署者验证它与 Invite 和绑定精确一致。纯 control 的条件授权 ID 为空。
control 完成状态直接由已验证的旧成员多数后继证书与被引用的授权事实投影，不等待事后单签完成事实。
缺少引用、引用不符或由其他 control 签发的绑定/普通加入授权事实一律拒绝；普通事实不能伪造 control 完成。
签发者在回答 claim 之前持久化精确的规范事实及一次性秘密引用；请求或响应丢失后继续同一事务。

```mermaid
stateDiagram-v2
    [*] --> open: control 签发 Invite
    open --> bound: 签发者接受首次 claim
    bound --> completed: 普通加入授权事实验证通过
    bound --> completed: 成员证书绑定事务、公钥与所需条件授权
    open --> expired: 验证无绑定的到期事实
    open --> cancelled: 验证无绑定的取消事实
    bound --> bound: control 到期或取消仅发起作废提案
    bound --> expired: 普通加入到期事实；control 须多数作废证书
    bound --> cancelled: 普通加入取消事实；control 须多数作废证书
```

`open` 尚无设备密钥绑定；`bound` 已绑定且不再重新生成身份。若申请 control，多数签名尚未齐备
时保持 `bound`，UI 从该请求和签名进度显示“等待成员签名”，不是临时成员。`completed` 表示加入所需的授权事实与成员证书（如需）已经验证；当前运行授权仍受撤权和冲突投影约束，不表示设备运行
`ready`。后续撤权或冲突收缩当前授权，不倒写完成证据。终态 `expired`、`cancelled` 不产生新权限。未绑定的 control 意向 Invite 只接受签发者在自身连续
事实序列中签发、引用该 Invite 且先于任何绑定的取消/到期事实作为终结；此后同一事务的绑定无效。
普通 Invite 只在完成前按签发者引用该 Invite 的有效终结事实处理。已绑定的 control 意向 Invite
可由任一有效 control 提出取消或到期作废提案，签发者失联不阻止请求；单签取消/到期事实若存在也只算请求。
必须由旧成员多数证书固定该 Invite/事务 ID 与取消或到期原因，才可进入 `cancelled`/`expired` 并释放
目标设备 ID；到期提案由签署者核对 Invite 的签名期限。即使绑定后尚未发出成员提案，
仍须按同一规则作废。较高轮若必须继承原加入提案，即使取消请求或期限已到，仍可先形成加入证书；原事务由证书完成，
随后按既有节点整体删除规则另行移除全部职责；仅卸任 control 保留其他职责，不能代替取消整次加入。
已经成立的原事务仍为 completed，不改成 cancelled。作废证书形成前保持待决，不释放 ID。Invite 的签名期限约束首次 claim
及首次合法投票，不否决按轮次规则继承的既有投票；后续新加入事务仍须重新验证期限。
Invite 在可验证的取消/到期终态前持续占用目标设备 ID；完成后由设备身份继续占用该 ID。
本机时钟、普通取消/到期请求或 UI 隐藏都不能清除已绑定 control 加入的阻塞。

UI 从 Invite 预留的 DeviceID 展示“待加入”的节点详情，并在同一详情持续回读绑定、授权、成员签名
和运行结果。待加入条目只是 Invite 的单向投影，不是新建的设备授权或临时 control，不计入已加入设备
与有效成员数量，也不建立 pending-device 或安装任务权威。交付页只展示本次 SSH 执行结果、专用脚本
或纯 access 二维码；不另设加入进度/成功入口。成员签名等待是同一节点详情的条件内容。
安装执行、加入授权和运行观测分别表达：SSH 丢失结果是执行 unknown，脚本下载和二维码展示不能产生
完成证据；脚本在联系签发者前失败时，控制端只能显示尚无加入请求，不能编造远端日志。关闭网页不取消
有效 Invite 或已经发起的加入；重开页面从既有事实与可验证执行结果恢复，不以浏览器计时器推进状态。

普通加入在签发者验证 claim 后，由它签发并持久接受一份绑定该事务的设备授权事实；完成状态由该事实
投影，不再请求管理员二次批准。设备授权携带签发者生成的 `RuntimeKey`：它是按设备、Service、Policy
和用途派生数据面凭据的根密钥，**不是设备身份私钥**，不能替代设备本机 Ed25519 签名。`RuntimeKey`
只保存在控制事实中并在 control 间加密同步，不下发给任何设备或节点；DeviceView 只携带由它派生的凭据，
它也不进入 Web、公开 Artifact、事件或错误日志。

若 SSH 或脚本 Invite 意向含 `control`，claim 先绑定精确设备公钥；组合职责在提案前再签条件授权事实，
仅在成员证书形成后投影。然后按[控制模型](control-model.md) §2.2 的轮次规则请求旧成员对绑定该 Invite/
事务 ID、设备 ID、公钥与所需条件授权事实 ID 的后继 `ControlConfig` 签名。签署者验证
设备身份、Invite 意向、条件授权事实、当前基础成员表与本机轮次承诺，自动签署或拒绝，不增加第二次人工审批；
因此多数门禁不防御单个被攻破的 control，见[控制模型](control-model.md#5-control-成员生命周期)。
多数证书形成前，该设备的任何职责
都不生效，不交付 View，不能投票、签发 Invite 或管理网络；多数证书形成后，各验收方验证证书及所引事实即投影为完成，其他有效
control 可交付证书与 View。交付丢失只影响设备获知结果，不撤销控制权威中的资格；设备在本机取得并验证证明前
不能运行这些职责。分票或成员失联时旧成员表保持有效，发起者在更高轮次继续。绑定后的
取消或到期只请求按同一轮次规则安全作废该 Invite/事务 ID，
同样需要旧表多数在线；作废证书形成前事务保持待决。若最高轮可能项是原加入，须继承并可完成该加入，
然后按既有节点整体删除规则另行移除全部职责；请求不能让失联者阻塞所有后继。
普通 `device.revoke` 不能绕过成员门禁删除 control 节点；整体删除必须由同一多数证书携带节点墓碑，
使非 control 职责及其依赖同时退出投影。

### `DeviceView`

`DeviceView` 是面向**一个**已认证设备的私有投影，包含设备身份、职责、授权的 Service/Policy、
Endpoint generation、可见的共享 `TransportResource` 与显式中继 `NetworkLink`、首跳资源、
业务探测目标、DNS overlay 与获授权的局域网虚拟前缀。它不包含其他设备的秘密或全网事件集，
也不成为独立治理权威。首跳不要求 `NetworkLink`；只有显式中继路径携带有序 LinkID。
同一 LinkID 当前链路和资源的规范字节派生 `link_spec_digest`；规范改变使旧观测回到 `unknown`。

交付 envelope 由当前有效 control 对完整 View 签名，附网络锚、从设备已固定成员表到当前成员表的
连续多数签名证明、签发者事实前沿和 View 摘要。**签发 control** 必须先验证构成 View 的普通事实、
所声明因果依赖及前序链已经补齐并在当前成员表封存规则下生效，再按当前 `Projection` 签发完整 View；
不能用待补齐、冲突暂停或已失格键的新事实制造设备权限。设备不接收全网原始事实，无法独立重算
这些因果闭包；**客户端**只验证固定网络锚、连续成员链、签发者资格、envelope 签名与规范摘要、
本设备身份/公钥绑定、View 仅含本设备可消费的值且内部引用/形状自洽，以及本机已见前沿。
客户端不能从 View 独立证明每项新权限确由哪些原始事实授予；这属于签发 control 的验证责任。
除连续多数证书明确封存的验证键外，前沿
不得回退，成员证明也不得倒退。封存证书只允许将**该键**的新 View 验收前沿降至证书封存序列；
原已认证高水位与不可回退 latch 仍保存；验收失败时保留旧 LKG，成功时原子替换唯一 LKG，其他键与现网全局认证 floor 不回退。
留任 control 对自身证书验收前已持久接受、可取得原始事实及前序的超限撤权自动重签为引用原事实的
后继事实，并在本机运行授权放宽或交付新 View 前验证其效果。若原始事实全失，不能由 View 或高水位重建；设备仍可凭证书接受按封存点计算的新 View，
已发现的授权差异标记待管理员复核，未知遗漏可能导致复权，不能宣称已完整保全所有撤权。
首次固定的锚不能由响应包自称的新锚取代。验证通过后，设备原子保存信任绑定、完整 last-known-good
View、原已见事实高水位、身份私钥引用及不可回退 latch。Linux 用受保护的本机存储，Android 每个 profile
使用按本机 ID 隔离的应用私有存储，Windows 每个 profile 使用其 DPAPI 边界；错误新值不能覆盖旧 LKG。

签名 View 仅证明签发 control 当时已知的事实，**不能证明不存在尚未传来的撤权**。分区期间
另一 control 的撤权传播后，当前权限可能收缩；客户端收到后立刻提升本机 floor 并撤销对应运行投影。
离线 LKG 不会被远程改写，服务端仍应拒绝已知撤权身份的新配置、报告和连接。

具有 `forward` 或 `internet_egress` 职责的节点从同一 View 投影数据面连接、入站用户（仅对本节点
有效的派生凭据）、ACL 与下一跳；共享资源握手不能代替业务授权。仅获 `forward` 不得执行最终公网出网，仅获
`internet_egress` 不自动共享本地 LAN。私钥与服务端 secret 留在节点受保护本机配置，不进入 View。
运行时对资源、listener、ACL、实际进程及回程路径逐项回读后，才报告 `running`。

### `Observation`

`Observation` 的完整语义见[客户端运行时模型](../clients/client-runtime-model.md#observation-与可用性)。
本文只规定它由实际传输/业务动作产生并经设备认证私有通道报告，按设备、网络代、Service、
候选及有效期约束；状态为 `available`、`unavailable`、`unknown`。链路报告包含 LinkID 和当前
`link_spec_digest`，不同 WG/hy2 链路分别观测。共享资源握手或一个 HTTPS 目标成功，不证明另一条
链路或另一 Service 可用。缺失、过期和摘要不匹配回到 `unknown`，ICMP 不能填充业务成功。首次绑定前
的引导连接诊断不作为设备签名 report 进入 `Observation`。

设备签名 report 至少须覆盖：网络与设备身份、设备持久递增的报告序列、当前完整 View 摘要、底层
网络代、报告时间、本次已运行 Service 的实际选择、逐条 Observation、实际运行组件的发布坐标，以及
forward/出网节点的 listener、ACL、进程和返回路径回读。每条 Observation 保留其来源动作、观测层级
（资源、LinkID 或 Service 业务）、实际目标、结果、采样时间与有效期；LinkID 层级携带当前
`link_spec_digest`，Service 候选携带有序链路摘要及其候选规范摘要。签名必须覆盖这些原始结果与
摘要，不能只签一行 UI 状态或只签 WG 字段。report 不包含 `RuntimeKey`、私钥、派生密码或整个
控制事实集合。接收者按设备公钥、当前授权和 View 验签，旧报告序列不得覆盖新值；跨 View 摘要、
跨底层网络代、超出目标 Service/Policy、过期或规范摘要不匹配的条目只投影为 `unknown`，不回写
`Material`。不同 control 交换的是已验证报告及序列，不以接收先后选择较旧结果。

报告记录的有效性按“设备 + 网络代 + 观测层级 + Service/候选或 LinkID + 实际目标 + 当前规范摘要”
分别判断：一个 WG LinkID 的结果不能替代同节点对上的 Hy2 LinkID，也不能以 transport 成功替代
HTTPS 业务成功。当前文档仍缺 report 逐字段字节、具体观测时间／有效期编码、最大可接受寿命与
设备时钟偏差处理、相同序列不同签名内容的拒绝规则；这些在[字段级阻塞](current-contract.md#已确定的签名边界与字段级阻塞)
补齐前，不能实现 schema 3 报告 writer/decoder 或声称报告过期算法已封闭。

## 私有入口与运行时

首次加入使用 Invite 指向签发者的受限 bootstrap tunnel。私有 TLS tunnel 校验证书 SPKI 与
独立 ALPN，bootstrap 模式验证完整 capability；已绑定设备使用设备 Ed25519 挑战签名及当前授权。
claim、resume、DeviceView 与 report 仅在这些认证后的私有连接内承载。加入后设备自动尝试签发者的
设备认证入口作首次管理、配置和报告入口；绑定、授权事实（如需）及成员证书（如需）传播到其他有效 control 后，也可以使用它们的
相同认证服务。连接可以使用已有共享 WG、hy2 或私有 TLS 资源；没有专属 WG 接口或显式 `NetworkLink` 仍可领配置。
连接资源只提供承载，服务分别验证设备、control 成员和业务权限。所有已知数据入口失效时，
已加入设备仍可经当前 `EndpointGeneration` 的设备认证模式领取修复 View 并报告 `unknown`；
它不再次使用 Invite，也不开放新权限。该入口不可达时保持经验证 LKG 并记录本机不可达。

普通 access 的共享首跳、Direct/Auto/指定最终出口候选由 View 和客户端模型投影；有序中继
LinkID 只用于确实配置的中继邻接。forward 节点共享 LAN 时，View 仅向显式获授该局域网 Service 及其 Policy 的 access
下发虚拟前缀及固定网关候选；设备不能自行提交任意 CIDR。Linux 的 TUN、策略路由和 DNS 只在
[宿主网络安全记录](../incidents/2026-09-21-host-network-takeover.md)规定的隔离边界内运行，
不修改开发宿主初始 network namespace 或 LAN 路由器。

设备报告携带当前 View 摘要、所选候选、实际运行组件的发布坐标（制品摘要与版本）、节点职责对应的
数据面运行回读和各链路真实结果。服务端逐项验证签名、设备授权、事实前沿、LinkID 与规范摘要；旧摘要的
报告不能将新连接标绿。观测记录可过期，不写入控制 `Material`。实际组件与 `Projection` 引用的期望组件
或发布记录规定的最低版本不一致时，只如实报告实际坐标与不一致，不能标记为已完成部署。

## 跨层同构

| 概念 | Domain | Wire | Persistent | Runtime / UI |
|---|---|---|---|---|
| 控制输入 | 成员链、有效 `Material`、`Projection` | 规范签名事实与证明 | 控制模型唯一权威 | 只读投影；Web 显示本地已见前沿与冲突 |
| `EndpointGeneration` | 稳定入口与生命周期 | 规范 generation 声明 | 签名事实；缓存可重建 | listener、入口候选与 `control.loom` 解析；UI 分列期望与观测 |
| `Artifact` | 内容摘要与受众 | manifest、摘要寻址字节 | 不可变内容与发布签名，不是控制事实 | 校验后下载；UI 显示签名和发布位置 |
| `BootstrapCapability` | 签发者限定的单次加入权限 | 唯一规范签名 Invite | 规范签发事实及事务约束 | 首次 claim 校验；UI 只显示摘要与期限 |
| `EnrollmentTransaction` | 同一事务的状态投影 | claim/resume、签名响应及成员证明 | 可重建的签发、签发者绑定/普通授权、终结事实与 control 成员证书 | 一行状态，不另存审批权威 |
| `DeviceView` | 一个设备的可消费配置 | 完整签名 View 与成员证明 | 服务端可重建；客户端原子保存 LKG/floor | 候选和运行输入；UI 仅显示脱敏摘要 |
| `Observation` | 限时实际结果 | 设备签名 report | 独立可过期记录 | 选路与 `available/unavailable/unknown` |

`EndpointGeneration`、`BootstrapCapability`、`Artifact` 与 `DeviceView` 的 wire 与持久字节按
[唯一现行契约](current-contract.md#往返与拒绝)可逆往返；`EnrollmentTransaction` 状态、运行时与 UI
只是单向投影：

```text
DeviceView           = ProjectDevice(Projection, DeviceIdentity)
AuthorizedCandidates = Project(DeviceView)
SelectedCandidate    = Select(AuthorizedCandidates, FreshObservations, Preference)
```

其中 `Projection` 按[控制模型](control-model.md)计算，DeviceView 由某个有效 control 签名交付；Web 页面按
[控制面 Web 投影](../clients/web-ui-projection.md)生成。这些箭头均为单向投影；UI 颜色、运行时连接或本机
缓存不能写回控制事实。

二维码、复制字符串与加入文件承载同一完整 BootstrapInvite 的规范交付值：`loom://enroll#` 加
固定等级 9、无字典的单流 zlib 无损压缩 C(JSON) 后的无填充 base64url，详见
[唯一现行契约](current-contract.md#inviteclaimresume-与配置交付)。解压后仍逐字节规范校验并验证
完整成员证明及 Material 签名，不接受旧未压缩交付。成员数不设专用模式；单二维码容量不足时明确
显示无法生成二维码，并保留同一值的复制、加入文件交互，不能截断证明或暗换身份。本链没有分片状态。
二维码优先使用中等纠错；相同完整字符串超过该容量时，可使用标准低纠错等级，仍逐字节承载同一交付值。
低纠错仍装不下时，私有回读明确给出容量错误，页面不显示损坏的图片。显示尺寸随码的实际模块数扩大，
保留静区与像素边界；改变纠错等级或图像尺寸不改变 Invite、签名、成员证明或加入请求。
最小验证覆盖正常、中等容量不足但低纠错可承载、所有等级都不足，以及独立扫码解码后的原字节比较。

## 正常业务链

```mermaid
sequenceDiagram
    participant Admin as 管理员
    participant Issuer as Invite 签发 control
    participant Device as 新设备
    participant Peers as 其他 control
    Admin->>Issuer: SSH / 脚本 / 扫码选择职责与授权
    Issuer-->>Device: 签名 Invite（指定 Issuer）
    Device->>Device: 本机生成身份密钥
    Device->>Issuer: 受限首次 claim（签名设备公钥）
    Issuer->>Issuer: 持久签发绑定事实
    alt 普通加入
        Issuer->>Issuer: 签发绑定事务的设备授权事实
    else 申请 control
        Issuer->>Issuer: 先签非 control 职责的条件授权事实（如需）
        Issuer->>Peers: 请求绑定该事实的后继成员表签名
        Peers-->>Issuer: 当前成员多数证明
    end
    Issuer-->>Device: 完成结果与签名 DeviceView
    Issuer-->>Peers: 按签发者前沿传播事实差量
    Device->>Issuer: 设备认证配置及运行报告
```

1. control 签发固定职责、PolicyIDs 和首次入口的 Invite；扫码仅签 `access`。
2. 设备验证可信网络锚、签发者及 Invite，生成密钥并只向签发者 claim；issuer 在响应前持久绑定。
3. 普通加入由 issuer 单签设备授权事实并本地接受；申请 `control` 时先签所需条件授权事实，再按轮次
   自动收集旧成员多数证书。证书形成前该设备任何职责都不生效，形成后由证书与所引事实直接完成事务。
   其他 control 后续按事实差量同步，并可独立
   管理该普通设备。
4. 设备验证签名 View、成员链及已见前沿，原子保存信任和 LKG；运行时按授权范围建立首跳与
   中继候选，进行最少真实探测并报告。无匹配业务探测目标仍可加入，业务状态为 `unknown`。
5. 响应丢失时从签发者 resume 同一事务；完成后可从任一有效 control 读取当前设备配置。

## 失败与恢复

- **签发者失联**：尚未首次 claim 的 Invite 等待签发者恢复；其他有效 control 可使用新稳定 ID 重签；
  原 ID 只有按事务终结规则释放后才可复用，不转移首次绑定。已加入设备可使用其他有效 control 的
  认证配置入口；申请 control 的绑定已成立且成员证书已形成时，其他有效 control 可交付该证明与 View。
- **control 多数暂缺**：普通加入与授权仍可由有效签发者本地接受；申请 `control` 的事务保持
  `bound`，不得提前赋权。已加入设备可使用经验证 LKG。
- **签发者后来被撤销**：尚未 claim 的 Invite 不再赋予首次加入权；已有效事实按其签发键的封存序列
  验证，已形成的 control 加入证书直接决定事务完成，其他有效 control 可交付证明与 View。客户端
  拒绝用自称的新成员表绕过证明。
- **承载 control 失去 control 资格**：验证后继证书的设备将其入口移出候选并关闭会话，诚实承载节点
  停止 listener；不能由证书保证失格节点停服或未获证书的会话终止。设备改用其他有效 control 的入口；
  以它为签发者、尚未 claim 的 Invite 按上一条处理。
- **请求丢失或重复**：签发者从已持久事实恢复相同 request ID、密钥绑定与结果；不同公钥或扩大
  scope 拒绝，不重生随机材料或第二个身份。
- **成员证明不连续、View 签名错误或未经证书限定的前沿回退**：拒绝新 View，保留旧 LKG。
  仅被连续多数证书明确封存的键可按封存序列验收；原高水位和 latch 不回退。证书验收前已持久接受且可验证的超限撤权
  须由留任键自动重签；无法取得原始证据时记录可能复权，不从 UI、缓存或高水位补造撤权。
- **撤权晚到**：权限收缩并撤销相关连接、路由、DNS 和候选；离线旧 LKG 不能证明当前仍有权。
- **入口/资源/链路不可达**：只更新相应 Observation；一个资源成功不使全部引用链路变绿。
  设备可用其认证恢复入口领修复 View，入口自身不可达则仅保留本机 LKG。
- **轮换或证书验证失败**：新 generation 不进入 serving，旧代保持已验证状态；不自动启动外部
  DNS provider 或 ACME。

## 最小必要测试

1. schema 3 的 Invite、事务事实、入口、Artifact 和 DeviceView 完成 wire/持久往返；1、2 号、未知及歧义输入拒绝。
2. 二维码重新显示不延长有效期；同事务同密钥 resume，已消费码不能绑定第二身份；
   丢失身份重新添加须先验证旧身份墓碑，再签新 ID 邀请，签发失败不回滚删除。
   SSH、脚本、扫码走同一 claim 和 report；组合职责使用二维码、纯 access 使用 SSH/脚本均在发行、
   客户端解码和签发者 claim 校验三处拒绝。SSH 识别失败不能安装，已知目标不支持的职责在签发前拒绝；
   脚本一次粘贴块的安装器摘要来自已验签清单，下载失败或摘要不符不执行；完整 Invite 经 quoted heredoc
   及 `--invite-stdin` 原样交付，不进入 argv、环境、公开 URL 或日志，不把终端历史风险写成已消除；
   未知平台在目标执行与 claim 时识别并校验全部职责，不能部分加入；绑定后的重试不能换平台；首次 claim 交非签发者失败，完成后其他 control
   可管理并供给 View；非签发者签发或缺少 Invite/绑定因果引用的绑定、普通加入授权事实被拒。
3. Invite → 本机生成密钥 → issuer 持久绑定 → 普通授权完成；无二次审批。响应丢失、重启、重复
   resume 得到同一身份和结果，换密钥接管失败；分区中不同事务 ID 的两张 Invite 占用同一设备 ID
   时两者授权都不投影，已签成员证书保留但冲突 ID 的认证失败关闭。
4. 同一次 SSH/脚本加入申请 control 与普通职责，绑定后先签条件授权，证书引用其事实 ID、公钥和设备 ID，
   自动取得 N=1/2/3 所需多数签名；未形成证书时任何职责都不生效，证书形成后不依赖签发者再签完成事实；
   分票后以更高轮次继续；绑定后取消或到期在安全作废证书前不释放 ID，若最高轮可能项为原加入，
   须先继承并可形成原成员证书，再按既有节点整体删除规则移除全部职责；
   响应丢失不改变证书已验证方的完成投影，设备在取得证明前不本地运行；
   后继证书必须绑定 Invite/事务 ID 与设备公钥，未绑定的 control Invite 只以签发者连续事实序列中的
   终结事实释放 ID。
5. 首次尚无 `NetworkLink` 仍能取得配置和共享数据入口；同一节点对 WG/hy2 LinkID 独立回读，
   规范变化使旧观测失效；无业务目标为 `unknown`。
6. 轮换依次经历 prepared、并行 serving、draining、retired；公网 edge 只做字节转发，
   公网 Nginx 不出现设备专属路径；非承载 control 签发的入口事实被拒，`control.loom` 只解析到
   web 模式 serving 代，同一浏览器 URL 使用的地址须提供一致客户端端口；承载 control 卸任后，已获证书的投影排除其入口与 `control.loom` 地址，
   诚实运行时关闭会话与 listener；失格节点继续监听或客户端未获证书时不声称全网会话已终止。
   网站叶续签需验 CSR 签名和当前成员/入口绑定，prepared 以候选地址及 `control.loom` SNI 预检，
   serving 后经真实浏览器回读才让旧代退出；以注入时间验证有效期 30 天边界、过期和未知证书的
   管理页及 `control inspect` 回读，过期证书使新 TLS 连接失败，不能按本机时钟改写签名入口或 DNS。
7. 客户端验证连续成员证明、签名 View、设备绑定和 floor 后原子保存；证明缺失、晚到撤权或
   新值损坏不覆盖 LKG；封存序列低于已见高水位时仅对该键允许证书限定的前沿例外，
   保留原高水位与 latch；验收失败保留旧 LKG，成功时只保存新 LKG；留任 control 在证书验收前已持久接受且可验证的超限撤权自动重签，
   原始证据全失时标记可能复权并接受证书限定的新 View，不把未知遗漏称为已解决。
   forward/出网节点的实际进程与 ACL 回读不由握手成功代替。
8. `RuntimeKey` 不出现在任何 DeviceView、Web、事件、日志与报告中；forward/出网节点只得到仅对本节点
   有效的派生凭据。

## 禁止恢复

- 旧 `CertifiedHead`、Raft/QC、stable→joint→stable 或历史材料解码作为现行加入前提；
- 签发后再次要求管理员批准、由非签发者首次绑定或扫码授予超出 `access` 的职责；
- `server` 业务角色、每加入一节点就新建 WG 接口或强制生成 `NetworkLink`；
- capability、claim、receipt、approval、DeviceView 各自维护业务权威或第二个状态机；
- 公网设备配置/报告路由、旧协议 fallback、从传输握手或 UI 绿灯推断业务可用；
- 用外部 DNS provider、ACME、证书续期或宿主初始 netns 变更来“修复”加入失败。

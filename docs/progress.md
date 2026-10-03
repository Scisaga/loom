# 实施状态

文档与原型复核日期：2026-10-03；既有实现缺口沿用 2026-09-30 的核对范围，新增目标另列。原生截图、VM 和生产证据保留各自的记录日期与范围。本文只记录已核实结果与缺口，不定义第二套协议。完成须满足
[正式入口与回读门禁](README.md#完成判定)。本轮修订设计文档、原型及其生成器，没有修改业务实现、执行生产部署、
读取生产私有证据或重做实体机验收；文档、组件、测试和页面存在均不等于业务完成。

## 已完成的局部结果

| 结果 | 已核实的范围 | 不代表 |
|---|---|---|
| 设计入口与单一目标契约 | [设计入口](README.md)、[控制模型](core/control-model.md)及[现行契约](core/current-contract.md)描述一套目标语义；[项目指引](../AGENTS.md)同步了四项职责、普通事实同步、成员多数门禁及旧材料拒绝规则。 | 源码、已签名现网数据或正式入口已按新模型运行。 |
| 客户端与 Web 产品资产 | Web、Android、Windows 界面源码及既有视觉基准仍在工作树；[视觉审查模型](clients/client-ui-visual-review.md)规定回读办法。 | 真机交互、签名发行或线上运行验收。 |
| 2026-10-02 文档与原型修订 | 澄清成员资格与交付、整次加入取消、本机出口身份、LKG 接受与运行失败及旧 overlay 退出边界。Web 原型补全冲突影响引用、修正 LAN 网关与详情返回；Android 明确放弃本机加入的范围，诊断按 Service/目标展示有效观测。脚本保留 root shell 中一次粘贴，先校验摘要再执行，并提示已接受的终端历史风险。撤回离线 View 导入、持久暂停及额外提交门槛。 | 原生交互、安装器或生产运行已实现。 |
| 2026-10-03 文档与原型审查修订 | 三端统一由明确需求与现行模型确定目标，旧截图只作差距对照；补 Windows 首次空态、Android 业务失败仍连接状态，区分导入、运行与业务结果；集中列明算法、字段和证书未决点。检查范围见下方审查记录。 | 已决定未决方案、更新原生基准、修改业务实现或完成新的业务验收。 |
| 管理员现有访问 | 用户已明确报告：管理员笔记本保存由 control 生成的 `admin.p12` 与密码文件，已安装相关证书且能正常访问现有中控；SSH 转发到本机 `127.0.0.1` 是其明确的开发调试路径。 | 当前重建分支具备等价领证命令、目标 schema 3 管理员名单和 `control.loom` 网站证书已部署；本轮没有读回笔记本证书属性或重做浏览器登录。 |
| Linux 宿主事故处置 | [事故记录](incidents/2026-09-21-host-network-takeover.md#已落地防复发措施)记录了宿主恢复、初始 netns 拒绝、service quarantine 与禁自动重启。 | 专用 capture namespace、无 TUN 转发/出网恢复或 Linux 客户端完成；本轮未重新读回宿主生产状态。 |

## 未完成的业务结果

| 工作项 | 当前可确认的基础 | 尚缺的完成证据或结果 |
|---|---|---|
| 设备服务授权与管理原型 | 用户明确要求 Policy 固定属于一个 Service、节点仅选 PolicyIDs；核心、Enrollment、运行时和 Web 文档已修订目标关系，二维码限定为纯 access，并区分继续加入与重新添加；通用添加页先多选角色，再确定交付：纯 access 仅二维码，含其他角色仅 SSH/sh；平台改为目标端识别、claim 绑定。 | 当前 Service.policy、DestinationGrants、Enrollment 选项和 QR/rejoin handler 仍是旧实现，尚未完成 Policy.ServiceID、allow/deny、any/only/none 范围、PolicyIDs、平台识别与绑定的规范字节、正式写入、View/ACL 消费及生产前向切换；SVG 仅为目标设计，不证明功能已上线。 |
| 签名事实与大规模同步 | 现有 Material 存储、控制通信和[目标模型](core/control-model.md)可供改造。 | 当前控制实现仍以 Raft 日志和 QC 决定普通写入，并按完整材料 ID 列表轮询；尚无单 control 签发的规范事实、逐签发键序列/前哈希、只按自身声明依赖判定的接收规则、因果依赖、差量前沿、确定性并发处理（撤权优先、冲突目标暂停投影）、加密的事实同步、分区/重启恢复及只向受影响设备分发视图的正式闭环。 |
| control 成员门禁 | 现有成员身份和验证键有代码基础。 | 旧成员按轮次多数签名的后继表链、持久承诺与完整投票历史、作废提案、失格键封存序列与原始 tip/多数前缀证明、仅对该键的多数证书前沿例外与原已见高水位保全、证书前已持久接受且证据完整的超限撤权自动重签、整体删除的同证书节点墓碑、双签分叉失败关闭、N=1/2/3、离线设备成员证明及生产回读均未按目标模型实现；现有 joint/Raft/QC 不能抵扣。 |
| Invite 与节点生命周期 | 私有 claim/resume/report、Endpoint 入口及平台加入代码存在。 | SSH、bootstrap 脚本、扫码共用规范 Invite；扫码签名内容及服务端仅许 `access`；首次 claim 只由签发者处理；无第二次人工批准；组合职责的条件授权事实与成员证书绑定、跨事务设备 ID 冲突收口；加入时申请 control 自动收集多数签名；任一后续 control 可改权或删除、普通节点墓碑与依赖投影清理，以及正式持久/运行时回读尚未闭环。 |
| 可复用传输与中继链路 | 现有 WG `NetworkLink`、设备报告和部分私有 TLS/Hy2 adapter 存在；Enrollment 不自动添加 WG 链路。 | 不随逐设备参与而改写的稳定 `TransportResource`、普通 access 按授权复用首跳、仅中继需显式 LinkID、同节点对 WG/hy2 并存、链路规范摘要、每链路真实探测和运行时读回尚未接通。现有报告字段偏向 WG，不能填造 Hy2 的 WG interface/handshake。 |
| Direct／Auto／指定出口与业务探测 | [客户端模型](clients/client-runtime-model.md)规定同出口一跳和中继并存、真实观测与 selector 回读。 | 一份认证 HTTPS 目标池按 Service 和授权派生目标集合、不同设备/Service/Policy 范围各自探测/选路、无目标 `unknown` 及最小真实探测尚未实现；当前 DeviceView 仍是平铺列表，Linux 运行时只取首项目标并有硬编码公网回退。不得把传输成功或 ICMP 提示冒充业务成功。 |
| DNS overlay | 目标只允许精确 `.loom` A/AAAA，`control.loom` 指向私有 Web 入口，解析不授予权限。 | 规范签名记录、冲突拒绝、按设备投影、私有解析器、网站根 critical `.loom` DNS 约束与全 IPv4/IPv6 IP 排除、根私钥脱离 control 并由操作者离线保管、各 control 本机 CSR 与手工续签、仅含 `control.loom` 的网站叶、受保护安装及新入口代切换、目标模型的 admin 页面逐入口 30 天提醒、过期失败关闭、浏览器实际验链、隔离运行与正式回读均未实现；DNS provider、DNS-01 和 ACME 自动签发/续期仍不在本工作项。 |
| 共享局域网 | 目标由 `forward` 声明、control 签发等长 IPv4 虚拟映射，经所属 Policy 与节点 PolicyIDs 投影授权。 | 自动无池分配与三次冲突重分配、已入网 access 授权编辑、CIDR Service 匹配、网关 ACL、精确路由、DNAT/必要 SNAT、停止/删除回读与隔离运行均未实现；不得修改宿主初始 netns 或 LAN 路由器。 |
| 控制面 Web 与管理员领证 | 页面与[Web 投影模型](clients/web-ui-projection.md)保留；用户已确认 `admin.p12`/密码文件和现有中控登录可用，并将 SSH 回环访问定为开发调试路径。 | 当前重建命令缺 control 生成与交付管理员 P12 的等价入口；SSH 调试链须与入网后 DNS `control.loom` 访问分别验收。既有部署记录显示网站 CA 私钥曾复制到 control、回环入口依赖 IP SAN；当前安装材料属性和私钥位置待读回。目标仅含 `control.loom` SAN 的网站叶无法验证浏览器的 `https://127.0.0.1` 调试 URL，其持续调试证书边界未定。新网站根切换须单独核对并读回，不提前破坏已可用管理员入口。代码仍有 reader 证书和 read capability，受信 admin 名单仍是本地配置；签名事实写入、成员门禁、敏感数据权限和旧 SSOT/registry 路径退出均缺正式闭环。 |
| Android | 界面源码和[本机配置模型](clients/android-profile-model.md)已有；文档已区分认证 LKG、运行 active 与后续业务观测。 | 当前 Android 运行代码仍在 DNS/HTTPS 探测成功后才接受候选，与无目标时保持 `unknown`、认证运行可先成立的目标规则不符；签名 Release、私有入网、一跳与同出口中继 fallback、切网/重启/撤权及真实设备显示回读仍缺；历史 debug 包或旧勾选不能抵扣。 |
| Linux | 本机身份/LKG、runtime 与 fail-closed 门禁已有代码基础。 | 无 TUN 的转发/出网平面恢复；专用 namespace 内 access capture、精确清理、异常退出/重启以及 SSH、LAN、WG、DNS、代理和公网返回路径回读。[installer 失败路径](../internal/clientdist/package.go)仍可能重新 `enable --now` 先前 unit，必须加安全所有权及现行授权门禁；旧 migration overlay 不再列作目标安装流程，schema 3 激活须拒绝依赖它的计划，前向映射获准且新路径回读后才能按所有权归档和删除旧入口；现有 finalize 仅删除 overlay 不能抵扣；正式 access service 维持安全暂停。 |
| Windows 既定客户端交付 | 三种交付形态的源码、UI 基准和[同机 VM](operations/windows-test-vm.md)流程存在。 | 私有入网到运行、报告、安装的正式入口与生产读回；VM 不能替代 ARM64、真实睡眠、物理网络切换和显示硬件实体机验收。外部签名尚未启用。 |
| 本机 `.env` 瘦身 | [配置模型](operations/configuration-model.md)定义严格六键白名单目标，其中 Gandi token、本机节点键和默认 SSH 配置可省略。 | 现有私有配置的一次性迁移、可选键规范编码的严格 loader、正式部署结果及受保护读回；模型写好不等于迁移完成。 |
| 签名发布闭环 | [配置模型](operations/configuration-model.md)已有操作者、部署计划、publisher 与逐节点执行的目标流程；现有代码有旧 signed-current 发布和节点 floor。 | schema 3 catalog/manifest 的规范字节与验签、不可变分发到 `current` 指针原子推进、控制事实中的组件期望摘要更新、节点实际运行坐标报告及用户回读均未闭环；旧 floor 到新发布记录的反重放证明并入生产切换，不由这条流程重置。 |
| 唯一规范输入 | [现行契约](core/current-contract.md)规定规范字节、严格拒绝和单向投影。 | [Material 解码器](../internal/control/model.go)仍接受旧格式，[控制存储](../internal/control/store.go)仍有旧初始化/恢复路径；[设备代码](../internal/control/enrollment.go)的 `runtime_contract` 仍有多个值和投影分支，发布 catalog 仍为旧 schema。需收为各目标对象唯一的 schema 3 语义，拒绝旧材料及分支，且不重放历史格式。 |
| 字段级同构 | 文档已规定 domain、wire、persistent、runtime、UI 的边界，并列出[字段级阻塞](core/current-contract.md#已确定的签名边界与字段级阻塞)。 | schema 3 的 `Material` 各操作、成员证明、`DeviceView`、claim/resume/report、发布 catalog/manifest、按 Service 探测、DNS 与局域网映射仍缺完整字段表、规范字节、拒绝向量与往返验证；这同时是文档和代码阻塞，不能凭语义描述开始生产 writer。 |
| 生产切换 | 现网身份、密钥、认证字节、floor 与不可回退 latch 受保护；目标对象编号已定为 schema 3。 | 目标模型与已签名材料不兼容，现网 signed-current 的 generation/载荷摘要/快照反重放 floor 也没有与 schema 3 catalog 可验证的前向映射；尚无用户决定并验证的切换办法、受保护证据和生产读回。必须停止冲突写入并保持切换受阻，不能自动生成空 genesis、重置 floor 或以旧格式作长期 fallback。 |

## 反复投入仍未闭环的部分

1. **版本与权威分叉。** 多套状态曾各自充当“当前”；现有 `runtime_contract` 继续在同一格式内承载多套投影语义。
   需要统一写入、解码、持久恢复与客户端消费；除用户已批准的 schema 3 外不再添格式号，也不用兼容分支绕开已签名字节冲突。
2. **控制治理。** 已有 Raft/QC、成员转换及 Enrollment 局部实现，但它们未形成用户确认的单 control 普通治理、
   多数成员门禁和大规模差量传播；继续保留并行权威会延长混乱。生产迁移未解决前不能宣称完成。
3. **Linux capture 安全。** 宿主网络接管表明报告变绿、endpoint 排除与临时路由不能证明 underlay 安全；
   专用 namespace、所有权清理与真实新连接验收仍缺，正式 service 继续 disabled/inactive。
4. **客户端正式运行闭环。** Android、Windows 有源码、debug 包和 VM 投入，真机切网、ARM64、正式发行及
   同一私有模型的运行读回仍缺，不能把局部结果记为完成。

Service 定义目标、Policy 固定所属服务且可复用、节点只选 PolicyIDs 已进入目标文档与原型。
“不限”只用于已分配策略的路径条件，无分配/deny 不产生业务授权；限定出口删除不会放宽为不限。
完整规则编辑集中在 Policies，节点页仅选择、移除或替换；同节点同服务拒绝重复策略。
LAN mapping 仍是同一 local_network Service，终点固定为所属网关。当前 SPA、Service.policy、
AllowedServers 与 DestinationGrants 尚未表达这些值；规范字节、持久/运行消费、重试及生产前向
切换都待正式入口验收，不以 SVG 宣称上线。

节点流程保持同一设备/邀请上下文：SSH 提交后显示执行结果，sh/QR 提供本次交付物，后续加入和运行
统一回读节点详情；原独立 enrollment 原型已合并为详情中的状态。待加入记录仅投影预留身份，不产生授权。
control 多数签名等待、执行失败/未知与加入完成均保留，关闭网页不取消异步执行；当前 SPA 尚未接入。
SSH 中断继续原邀请；修改设备复用既有策略时只保存设备授权，不宣称创建了新策略。配置、runtime、
业务和历史流量分别回读。旧服务 Tab 和节点内嵌规则表单已移出目标稿。没有执行真实安装、加入或生产切换。

具名局域网和 DNS overlay 已纳入当前设计但仍未实现；公网 DNS provider/ACME 不属于当前核心范围。
更早设计只可作取证，不能成为现行规范或正常解码输入。

## 文档与原型审查记录

本节承接原型说明中的历史检查结果，不把旧记录改成此次复验。原型目标与当前差距仍见
[目标原型与实现对照](clients/prototype-review.md)。

### 既有 Windows 视觉记录

以下沿用此前记录，原记录未单列执行日期；此次未重做原生录制或 VM 验收。

此前记录的标题栏图标修复通过调整 `favicon.svg` 取景和资源栅格化消除了下缘裁切；当时由原生渲染器
重新录制八张 PNG，每张与旧基准仅在标题栏图标区域有 338 个像素变化，侧栏图标没有变化。

此前原型调整记录已完成八张 SVG 的 XML、原有场景文案、控件几何、重复生成和文字重叠核对，并检查了 1×、1.5×、2× 渲染。
展开详情与底部视图统一采用右侧主区滚动，侧栏和标题栏固定。这些检查只验证原型，不能替代原生内容或 DWM 验收。

此前在同机 Windows 11 VM 的交互 RDP 桌面捕获了三档 DWM 合成窗口，`GetDpiForWindow` 分别实读
96、144、192 DPI。96 与 192 DPI 截图可见较小的外角弧度，144 DPI 截图左上角接近直角；三档均未达到
SVG 表达的 10 DIP 目标圆角。截图保存在被忽略的
`deploy/evidence/ui-prototype-rebuild/rdp-window-{96,144,192}.png`。这些单帧只证明各自 RDP 会话中的合成结果，
不抵扣实体显示器、跨屏移动或长期窗口行为的验收。当前源码已设置圆角偏好和非合成回退 region；
`WM_PRINT` 只核对内容，不能用它的方角判断 DWM 外框。后续 Windows 产品实现须修复并再次回读外角差距，
不能改写原生内容基准掩盖它。该次原型视觉调整没有重新执行这些 VM 或原生像素验收。

### 2026-10-02 原型检查

此前修订以 Git 中原有的 `misaka-v1` 图稿作视觉参照，调整 Web 拓扑、按 Service 的路径详情和签名事实页。

当日复核已在 Chrome 检查 Android 的加入错误和诊断两稿，Web 的 LAN 创建、冲突对比/确认、
脚本交付及路径导航。路径从失败、未知、WG、Direct 与 LAN 未确认筛选进入详情，切换页签再返回及前进/后退，
均保留来源服务与筛选。脚本显示与复制的换行一致；合成安装器仅在下载及摘要成功后执行，下载失败、摘要错误与
安装失败分别保留失败结果并清理本次临时目录，Invite 只在标准输入中交付。此项检查使用本地替身，不访问公网或启动业务。
32 张 Web SVG 再次生成的字节保持一致；SVG XML、唯一 ID、链接、生成器语法、仓库安全检查及 diff 格式检查通过。

### 2026-10-03 文档与原型审查修订

按用户确认的清单，统一设计入口、原型说明、视觉审查及两端 README 的目标与证据关系；原型场景表
区分正常流程、异常状态和历史实现对照，并允许暂无原生截图。Web 视觉规格集中到原型说明，字段来源、
操作及状态语义继续由 Web 投影模型负责。旧检查记录移入本节，保留原日期、范围和证据限制。

Windows 目标稿由八张变为九张：新增首次列表空态，补 `join-empty` 异常来源，侧栏导入失败与主体一致，
展开路径区分业务目标/采样/有效期和 selector 回读。Android 目标稿由九张变为十张：运行失败稿保留
已保存认证配置并显示 VPN 启动失败；新增 VPN 仍连接、单个业务目标失败而另一服务未知的状态稿；
配置就绪稿明确认证配置已保存。原生 PNG 仍分别为 Windows 八张、Android 九张，未更新。

选路模型列明多目标归约、指标优先级和平局规则的待决问题；统一契约对照字段缺项与受影响行为；
管理员文档集中签发者、验链锚、多 control 补发能力及 SSH 回环网站 TLS 四项未决边界。没有新增
算法、编码格式、证书方案或协议版本，也没有用原型样例补造规范字段。

已检查所改文档的本地链接与章节锚点、十九张客户端 SVG 的 XML 与唯一 ID、Windows 生成器语法及
九张目标 SVG 重复生成的字节一致性；新增和修改的七张客户端稿已渲染并逐图复看。仓库安全与 diff
格式检查通过。现有三十二张 Web SVG、两张已修订 Android 加入错误/诊断稿和十七张原生 PNG 的
文件摘要保持不变。预览输出位于被忽略的 `out/doc-prototype-review-confirmed/`。
本次未修改业务源码、测试代码或原生基准，未执行业务构建/测试、原生录制、VM 或生产验收。

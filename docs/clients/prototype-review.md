# 目标原型与实现对照

[设计入口](../README.md) · [客户端视觉审查](client-ui-visual-review.md) · [Web 投影](web-ui-projection.md)

Web、Android、Windows 的目标原型均依据用户明确要求与现行模型制定。已有实现和原生截图用于核对
有效交互、视觉延续和实现差距，不限定目标流程、业务状态、文案或场景数量。原型与模型不一致时，
应在设计审查中明确修订；实现完成由正式业务入口和运行回读验证，原生截图负责视觉验证。
SVG 是可编辑的界面沟通稿，不读取 wire 或持久状态，也不参与客户端或 control 的运行判断：

```text
用户明确要求 + 现行模型 → 三端目标原型 → 正式实现 → 业务回读 / 原生视觉验收
已有实现 + 原生截图 + 历史验收 → 有效能力与差距对照
```

domain、wire、persistent 的可逆性仍由各自核心模型规定；SVG 只是有损展示，不存在从 SVG 反推授权、
观测或部署完成的操作。已有有效交互和视觉尽量保留；场景增删或纠错按需求说明覆盖变化，允许目标稿
暂无原生截图。原生 PNG 仍由生产 UI 渲染，不随 SVG 改稿更新。历史检查记录见
[实施状态](../progress.md#文档与原型审查记录)。
生成器内部使用 `demo-*` 合成身份；按已确认的界面要求，Web 画面使用
`control-a`、`relay-west`、`media` 等显示别名，去掉 `Prototype`、`sample data` 和 `demo-*` 水印或占位名称。
这些别名仍然不是现网身份；地址与域名继续使用 RFC 5737 和 `example`。

## Windows：原生场景与目标视觉设计

基准目录为 [`clients/windows/testdata/ui-golden/`](../../clients/windows/testdata/ui-golden/)，截图由生产
`portableGUI` 在 Windows 11 VM 上以 96 DPI、`876×614 DIP` 渲染。当前有八张原生基准和九张目标 SVG；
存在对应 PNG 时用场景 ID 关联，首次空态只有目标稿。PNG 是 `WM_PRINT` 内容基准，不包含 DWM 外角和阴影。
SVG 依据目标行为，通过 [`scripts/generate_windows_prototypes.py`](../../scripts/generate_windows_prototypes.py) 生成；
它只读取固定合成内容和公开图形资源，不读取本机配置、身份、网络或时钟，不接入原生截图流程。
原生实现与目标布局的视觉差距须另行回读；下表列明行为及证据差异，截图存在不证明业务链已完成。

| 场景 | 类别 | 原生 PNG | 可编辑 SVG | 目标行为与当前差距 |
|---|---|---|---|---|
| `profiles-empty` | 正常流程 | 暂无 | [原型](../../assets/client/windows/profiles-empty.svg) | 首次列表为空，只有添加入口；无设备身份、当前连接和删除操作；尚无对应原生基准 |
| `connected` | 正常流程 | [截图](../../clients/windows/testdata/ui-golden/connected.png) | [原型](../../assets/client/windows/connected.svg) | 已连接、自动模式、按 Service 区分实际结果；目标布局待原生回读 |
| `path-expanded` | 正常流程 | [截图](../../clients/windows/testdata/ui-golden/path-expanded.png) | [原型](../../assets/client/windows/path-expanded.svg) | 目标 URL、Service/候选范围、业务采样/有效期及 selector 回读时间分别表达；旧 PNG 未体现新增说明 |
| `profile-rename` | 正常流程 | [截图](../../clients/windows/testdata/ui-golden/profile-rename.png) | [原型](../../assets/client/windows/profile-rename.svg) | 重命名保留输入及焦点；目标布局待原生回读 |
| `join-draft` | 正常流程 | [截图](../../clients/windows/testdata/ui-golden/join-draft.png) | [原型](../../assets/client/windows/join-draft.svg) | 导入邀请并加入保存后才进列表；另一连接运行是示例上下文，不是新增前提 |
| `join-empty` | 历史实现对照（异常条目） | [截图](../../clients/windows/testdata/ui-golden/join-empty.png) | [原型](../../assets/client/windows/join-empty.svg) | 已有条目缺加入身份或完整配置；原连接继续；不是首次使用或新增的下一步 |
| `join-error` | 异常状态 | [截图](../../clients/windows/testdata/ui-golden/join-error.png) | [原型](../../assets/client/windows/join-error.svg) | 侧栏与主体均为导入失败；旧侧栏“连接错误”不再限制目标文案 |
| `viewport-bottom` | 正常流程 | [截图](../../clients/windows/testdata/ui-golden/viewport-bottom.png) | [原型](../../assets/client/windows/viewport-bottom.svg) | 固定视口底部、滚动与完整服务行；目标布局待原生回读 |
| `fixed-tun` | 正常流程 | [截图](../../clients/windows/testdata/ui-golden/fixed-tun.png) | [原型](../../assets/client/windows/fixed-tun.svg) | 指定最终出口、TUN 形态与当前选择；目标布局待原生回读 |

`join-draft` 与 `join-empty` 不是连续两步。正常入口是侧栏“＋”→ 输入名称、导入邀请 →
“加入并保存”→ 受保护的加入身份及认证配置提交后，新配置进入列表并保持断开；原有连接继续运行。
首次启动由 `profiles-empty` 表达，点击添加进入相同的 `join-draft` 表单，不会自动创建空配置。
草稿图中的另一条运行连接只是独立合成上下文，首次使用不要求它存在。
具体入口约定见 [Windows 客户端](../../clients/windows/README.md#normal-user-flow)。

`join-empty` 来自原生截图 fixture 直接构造的“列表已有条目，但未加入”状态；现有实现仍有读取既有条目后
缺少加入身份或完整认证配置的显示分支。这不证明它属于正常新增链路，也不能把截图保留要求解释为
“先保存空配置，再导入邀请”。该场景仅保留作异常条目对照，不能替代 `profiles-empty` 的正常首次空态。
场景来源写入 SVG 元数据与本表，不把测试构造说明放进产品页面。

### 目标布局与线条

原型保持中文、浅色、`876×614 DIP` 窗口、176 DIP 侧栏及 10 DIP 外框圆角。
尺寸均按 SVG 的 1 单位对应 1 DIP 表达，统一使用下列尺度：

| 项目 | 目标规格 |
|---|---|
| 主内容边界 | `x=200` 至 `x=852`，距侧栏及窗口右侧各 24 DIP |
| 内容间距 | 卡片内边距 16 DIP；分组间距 24 DIP；行内按 8、12、16 DIP 排列 |
| 侧栏配置 | 每行高 64 DIP，行间距 8 DIP；为 32 DIP 重命名输入框和下方状态文字留出独立空间 |
| 面板组 | 12 DIP 圆角、无描边；标题与操作在面板内，分隔线贯穿面板全宽 |
| 滚动条 | 轨道与滑块右缘贴住窗体内缘 `x=875.5`，不留额外右边距；正文留白独立保留 |
| 滚动底界 | 内容裁切和轨道延伸到窗体内底缘 `y=613.5`；24 DIP 末尾留白属于可滚动内容，不得形成固定底部空带 |
| 操作控件 | 正文按钮、输入框、出口选择统一高 32 DIP、圆角 8 DIP；系统标题栏和图标按钮单独布局 |
| 路由模式 | 三段各宽 80 DIP；选中项四周留白均为 4 DIP，绿色填充、白色文字，不叠加内外两圈描边 |
| 描边 | 需要描边的控件及分隔线 0.75 DIP；路径和普通图标 1 DIP；状态图标 1.25 DIP |
| 文字层级 | 页面标题 20 DIP、分组标题 14 DIP、正文与控件 12 DIP、说明 11 DIP |

路由模式、固定出口选择和辅助说明在同一区域对齐；路径行的名称、观测摘要及状态垂直居中对齐，
节点与标签的距离一致。加入表单沿用同一控件和间距尺度，空状态、错误状态使用相同操作位置。
减少重复边框和无意义留白，不能通过删掉证据、状态、入口或缩小视口来获得整齐效果。

对齐与间距进一步遵循以下规则：

- 连接状态单行区域高 64 DIP，状态图标、标题和按钮居中；TUN 说明增加 24 DIP 内容高度，
  后续模式行和路径面板随内容顺延，两段分组间距均保持 24 DIP。设备标识底栏高 48 DIP、垂直居中。
- 侧栏重命名输入框保留 12 DIP 左内距，与状态文字至少相隔 4 DIP；编辑态与普通态使用同一行高，
  光标位于文字末尾之后。侧栏底部说明沿用原有上下留白。
- 路径节点直径为 32 DIP，四个中心等距排列；首尾各预留 80 DIP 标签列，标签不侵入面板的 16 DIP 内边距。
  节点与箭头、节点与标签的间隔均为 8 DIP。展开证据按 24 DIP 行距排列，说明块上下各保留 16 DIP。
- 观测摘要在固定列内右对齐，状态区域预留 80 DIP；只读标签内部使用 12 DIP 左右内距、4 DIP 状态点和
  8 DIP 图文间隔。带展开箭头的按钮左右各留 16 DIP，文字与箭头相隔 8 DIP。
- 加入表单的辅助说明距对应操作 12–16 DIP；空态与错误态共用相同的位置与间距。
  只读信息底栏与操作按钮底栏分别按内容居中，不把多余空白作为固定面板高度保留。

### 与 Android 共用的组件样式

Windows 参考 Android [连接页](../../assets/client/android/connection-connected-auto.svg)与
[配置页](../../assets/client/android/configuration-ready-multiple-profiles.svg)的面板分组，
采用同一浅绿灰画布 `#F0F4F1`、白色内容面、浅绿连接状态面 `#F7FBF8` 和绿色选中填充 `#239B68`。
深浅层级与状态语义共用，控件尺寸仍适配桌面：保留 32 DIP 高度、横向逐跳路径和固定侧栏。

“当前选路”是一个完整白色面板，标题、展开/收起按钮、各 Service 的路径与观测证据都在组内。
连接状态脚注、选路标题、各 Service 和展开说明的分隔线均贯穿所属面板的左右边界；
文字与控件仍保留 16 DIP 内边距。展开说明仍属于该 Service，不再套独立描边面板。
可用状态用浅绿标签、测量未知用中性灰标签；节点与箭头维持中性细线，不能把服务级业务成功投影为逐跳健康。
连接操作、模式选择、说明按钮与普通输入框共用圆角和颜色层级；状态标签是只读信息，不是操作按钮。
三个加入场景的右侧主体也各自使用一个白色圆角面板：新增页将说明、表单和提交操作归组，
未加入与导入失败页将状态、导入或重试操作、当前连接提示归组。页标题及删除入口位于面板外；
面板沿用 12 DIP 圆角、16 DIP 内边距和贯穿全宽的分隔线，空态与错误态的控件位置保持一致。
组件样式对齐不自动更新任何一端的原生实现或 PNG 基准。

### 原型最小核对

- 按目标需求核对场景覆盖，不以原生基准数量冻结目标；选中配置与当前运行配置分别表达，不能把未加入配置画成已断开现有连接。
- 首次空态不画配置行、设备身份、当前连接或删除操作；保留添加入口，与异常条目对照分开。
- 新配置尚未导入邀请时保存不可用；保留邀请文件、二维码粘贴、导入失败后的重试，以及保存后保持断开的说明。
- 重命名保留未提交输入及焦点；连接状态保留设备标识和断开入口；固定出口保留出口名称、前置路径自动选择和 TUN 说明。
- 按 Service 展示路径，真实可用与测量未知不能合并；展开内容区分业务目标、范围、采样时间/有效期与当前选择回读时间。
- 固定视口中保留展开后的溢出及滚动底部场景；检查滚动范围、内容裁切和侧栏不随主区滚动。
  底部场景使用与首屏相同的完整面板和行高，完整显示服务 4–7，顶部可见服务 3 的路径尾部。
  未到内容末尾时，路径面板可以延伸并裁切于窗体底缘；不能在未显示完的服务下固定预留背景空带。
- 重新生成应得到相同 SVG；逐页检查 XML、控件尺寸、等距内留白、文字溢出和遮挡，并在原始尺寸及放大后查看线条。

展开详情与底部视图统一采用右侧主区滚动，侧栏和标题栏固定。原型检查记录见[实施状态](../progress.md#文档与原型审查记录)，
不能替代原生内容或 DWM 验收。

### 原生验收边界

`WM_PRINT` 只核对内容，不能用它的方角判断 DWM 外框；外框须由 DWM 合成截图回读。
既有 RDP 合成结果与 10 DIP 目标圆角仍有差距，详细条件和证据范围见
[历史视觉记录](../progress.md#既有-windows-视觉记录)。这些结果不抵扣实体显示器、跨屏移动或长期窗口行为验收，
也不能通过改写原生内容基准掩盖差距。

## Android：Compose 场景

提交的唯一原生基准目录为
[`clients/android/app/src/screenshotTestDebug/reference/.../HomeScreenshotTestKt/`](../../clients/android/app/src/screenshotTestDebug/reference/io/github/scisaga/loom/HomeScreenshotTestKt/)。
下表已有 PNG 的模式在该目录内各匹配唯一文件，文件名含渲染器生成的哈希；使用
`scripts/ui-review preview android` 可在 `out/ui-review/android/baseline/` 得到稳定场景名副本。
原生基准固定为中文、浅色、`fontScale=1.0`、`412×915dp`。当前有九个原生基准、十张目标 SVG。

| 场景 | 类别 | 原生 PNG 文件名模式 | 可编辑 SVG | 目标行为与当前差距 |
|---|---|---|---|---|
| `connection-disconnected-unjoined` | 正常流程 | `*connection-disconnected-unjoined*.png` | [原型](../../assets/client/android/connection-disconnected-unjoined.svg) | 未加入/未连接及加入入口；固定截图不证明加入链已完成 |
| `connection-connected-auto` | 正常流程 | `*connection-connected-auto*.png` | [原型](../../assets/client/android/connection-connected-auto.svg) | 已连接、当前路径、按 Service 展示；目标运行规则仍待正式入口验收 |
| `connection-error` | 异常状态 | `*connection-error*.png` | [原型](../../assets/client/android/connection-error.svg) | 认证配置已保存、VPN 启动失败，无 active；旧 PNG 的业务失败推导未连接不再作为目标 |
| `connection-business-failed` | 异常业务观测 | 暂无 | [原型](../../assets/client/android/connection-business-failed.svg) | VPN 已连接，具体目标失败，另一 Service 独立为未知；同连接页状态，无对应原生基准 |
| `configuration-not-joined` | 正常流程 | `*configuration-not-joined*.png` | [原型](../../assets/client/android/configuration-not-joined.svg) | Android 可先有未加入本机配置；区别于 Windows 正常新增流程 |
| `configuration-ready-multiple-profiles` | 正常流程 | `*configuration-ready-multiple-profiles*.png` | [原型](../../assets/client/android/configuration-ready-multiple-profiles.svg) | 区分认证配置已保存、当前连接和模式；旧 PNG 未体现保存文案 |
| `configuration-join-error` | 异常状态 | `*configuration-join-error*.png` | [原型](../../assets/client/android/configuration-join-error.svg) | 原事务重试；放弃本机资料不撤销远端设备；目标文案尚未落入原生基准 |
| `diagnostics-connected` | 正常运行与未知观测 | `*diagnostics-connected*.png` | [原型](../../assets/client/android/diagnostics-connected.svg) | Service、目标、采样/有效期分别展示；旧原生诊断仍为汇总探测文案 |
| `profile-picker` | 正常流程 | `*profile-picker*.png` | [原型](../../assets/client/android/profile-picker.svg) | 当前连接与浏览配置分开；请求切换中的状态尚无原生截图 |
| `notification-warning` | 异常提示 | `*notification-warning*.png` | [原型](../../assets/client/android/notification-warning.svg) | 通知警告不改变连接和业务结果；截图不证明系统通知权限流程 |

Android 的正式 Activity 与截图 fixture 共用 `LoomHomeScreen`。真机尺寸和系统栏可能不同，
因此真机截图只用于设备交互回读，不与固定 Layoutlib PNG 逐像素比较。

加入错误稿保留同一事务重试；“放弃本机加入”清理本机未完成的加入资料，不代表远端设备已撤销。
诊断稿分别展示 `demo-web` 对 `web.example` 的有效观测，以及 `demo-api` 对 `api.example` 尚无当前网络
有效观测的状态；局部成功不代表全部业务可用。连接错误稿表达 VPN 启动失败而认证配置保留；
业务失败稿表达 VPN 仍运行、`demo-web` 的具体目标失败、`demo-media` 尚无有效观测，失败不传播到其他服务。
这两种场景不新增页面导航；状态来自现有配置接受、运行回读和业务观测的不同输入。
Android SVG 直接维护，无独立生成器；原型文案与原生截图的差异需在后续实现后验收。

## Web：目标页面与当前实现差距

Web 原型由 [`scripts/generate_control_center_prototypes.py`](../../scripts/generate_control_center_prototypes.py)
确定性生成到 [`assets/control-center/`](../../assets/control-center/)，使用固定英文文案和合成数据。
现有浏览器场景截图在被忽略的 `out/ui-review/web/current/`，由真实 Web handler 和 Chrome fixture 生成；
该 fixture 仍带旧业务语义，所以不能作为目标原型的内容依据。
目标原型保留控制中心原有的紧凑顶栏、分层信息布局、可辨识的筛选与编辑控件，以及有明确数据来源的图表；
签名事实、实际观测与应用回读仍按现行模型分别呈现。示例图表不得用缺失数据补造健康或部署结果。

Overview 与 Topology 保留双圈构图：设备位于两条同心椭圆上，节点名称朝外排布，首跳和
显式中继边分别绘制；Topology 保留 Service 筛选、链路选择和右侧详情。两条椭圆仅用于布局，
不表示职责、授权等级或网络连接。蓝色表示设备报告的路径选择，节点圆点只表示运行报告是否新鲜。
右侧小环形图表示九条 LinkID 中五条有当前可用观测。九条中继记录逐行保留，WG 与 hy2 的观测独立展示。

### 文件命名与导航分组

文件按顶部一级导航从左到右使用两位组号 `01` 至 `09`：主页面用 `<组号>-<导航名>.svg`，
子页面和状态稿用 `<组号>-<导航名>-<场景>.svg`，同组页面共用序号。无管理导航的私有入口使用
`10-entry-guest.svg`，排在菜单页面之后。所有文件仍放在同一个目录；文件名只表达导航归属，
不改变页面内容、业务路由或职责组合。

| 一级导航 | 文件名 | 覆盖场景 |
|---|---|---|
| Overview | `01-overview.svg` | 总览 |
| Nodes | `02-nodes.svg`、`02-nodes-*.svg` | 设备列表；三种添加草稿；`add-ssh-result`、`add-script-delivery`、`add-qr-delivery`；统一 `detail` 内的待加入、成员签名及完成状态；`access-edit` / `access-result`；`rejoin`、`lan-mapping` |
| Topology | `03-topology.svg` | 拓扑 |
| Live paths | `04-live-paths.svg`、`04-live-paths-detail.svg` | 两层：左侧服务与右侧设备同页 → 设备路径详情；服务切换和设备筛选均不离开主页面 |
| Services | `05-services.svg`、`05-services-lan.svg`、`05-services-dns.svg` | 互联网服务、局域网服务与精确私有 DNS |
| Policies | `06-policies.svg`、`06-policies-new.svg`、`06-policies-lan.svg` | 互联网/LAN 策略管理与创建 |
| Releases | `07-releases-*.svg` | Linux、Android、Windows 与部署回读 |
| Events | `08-events.svg` | 事件 |
| Administration | `09-administration.svg`、`09-administration-administrators.svg`、`09-administration-certificates.svg`、`09-administration-configuration.svg` | 同级的控制节点、管理员、网站证书、当前配置；操作与结果都在原视图展开 |
| 无管理导航的私有入口 | `10-entry-guest.svg` | 未提供 admin 证书的入口 |

### 业务入口与职责

按用户确认的关系，Service 定义互联网网址/地址范围或某节点共享的 LAN；Policy 固定属于一个
Service、定义允许/拒绝及路径规则；节点只选择 Policy。同服务可以有多个策略，同一节点最多选一个。
策略里的“不限”表示所有合格节点，未选策略则没有该服务权限。创建、复制和共享编辑都进入 Policies；
节点添加/权限编辑/重新添加仅用策略多选标签和只读摘要，不再套服务页签或规则编辑器。
Services 展示所属策略，Policies 展示所属服务和引用节点，避免操作者在两处重复绑定。
`02-nodes-access-result.svg` 仍为指定设备的保存反馈，不是通用 operation 台。

添加设备先多选职责，纯 access 仅二维码，含其他职责仅 SSH/sh。角色可修改，平台由目标执行识别并在
claim 绑定。access 选择策略时标签同时显示服务；没有 access 不显示该区域。策略页的入口、出口及
中间转发并列展示“不限 / 指定节点 / 不允许”，限定节点时用可搜索的 tag selector，清空限定标签不是自动不限。
`06-policies-lan.svg` 展示入口改为指定节点的未保存草稿，包含已选标签及展开的复选列表；勾选后保持
列表展开，支持连续多选，标签顺序不代表路径顺序。保存前不改变其他页面读取的既有不限规则。
LAN 策略终点只读固定为服务网关，不显示互联网出口或 Direct。
二维码和重新添加仍遵循[二维码场景](../core/enrollment-endpoint-model.md#二维码的使用场景)。

现有 `app.js`、`enrollmentOptions`、`inviteQR` 和
`createExistingNodeRejoin` 仍有旧模型，不能作为新业务链的验收证据；待实现范围见
[实施状态](../progress.md)。原型最小检查为生成器重复生成一致、逐图 XML/浏览器渲染、文字边界及
设备/服务/策略引用人工核对，不以伪造的扫码 payload 或旧 handler 测试宣称流程可用。

### 图表与数值的对照

原有 SVG 与当前 [`app.js`](../../internal/control/static/app.js) 的 Overview、Topology 和设备详情均有
流量展示，目标保留这些能力。计数口径参考当前
[`projectTraffic`](../../internal/control/observations.go)：来自有效报告的同端点、同接口、同 epoch
相邻计数器增量；排除计数下降、epoch 变化和超过三分钟的间隔。已变更规范且只有旧范围报告的链路不填入
新的流量序列，旧实现其他模型语义不随图表移入原型。

| 页面 | 目标图表/数值 | 范围与缺失展示 |
|---|---|---|
| Overview | 24 小时 WireGuard TX 柱状图、已观测总量、逐设备 RX／TX | 逐发送端累加，重复的对端 RX 不再计入总量；未知设备显示 `unknown` |
| Nodes | 每行当前状态、24 小时状态采样条、RX／TX 小柱图及总量 | 状态样本与流量分别取值；未知留空，明确失败才显示红色；流量柱按设备分别缩放 |
| Topology | 无底框连线度量；表格合并展示 RTT、速率、波动，并列 24 小时状态条和传输小柱图；右侧两端 TX 分组图 | 历史条使用链路自身观测，逐链路流量与右侧同源；WG 与 hy2 独立；当前状态与历史分开 |
| Live paths | 汇总设备数与路径分布；详情保留完整业务耗时、24 小时响应时间柱及业务状态条、各段独立测量 | 汇总不合并设备度量；详情限定设备、Service、目标和候选，成功、失败、未知分别表达 |
| Device detail | 当前设备的 RX／TX 分组柱状图和分项总量 | 仅统计该设备接口；RX 与 TX 分列，不合并成网络总量 |

图中纵轴为 GiB／小时，横轴为最近 24 小时；空心虚线列表示没有有效增量的时段，不能解释为零流量。
固定输入包含 22 个有有效增量的小时及两个未知小时。该覆盖数不承诺每分钟或所有端点都有报告，数值是
已观测部分的累计。生成器从同一组固定序列计算图形、总量和列表，历史观测不会让缺失的当前运行报告变绿。
当前 `TrafficBucket` 未输出足以在 UI 中细分每个空档成因的元数据，所以原型不把空档直接标成计数器重置。

设备状态采样条每小时只表达最后一条有效 runtime 样本，不表示整小时持续在线。场景覆盖历史明确失败、
运行报告过期但仍有历史流量，以及手机业务可用而 runtime／流量未知。RX／TX 小柱图与 Overview、
设备详情复用同一计数序列，不另填一组装饰性数值。

链路测量恢复原有的延迟、带宽与波动展示。WG 的带宽是指定发送端五分钟内有效增量的实际平均速率，
hy2 则是该传输自己的实测探测吞吐；都不是容量承诺。波动为 15 分钟成功 RTT 样本的 P95−P50，
不能写成逐包 jitter。统计口径对应现有 [`LinkQuality`](../../internal/traffic/quality.go) 和
[`linkmetric`](../../internal/report/linkmetric.go) 的相关能力；旧存储、聚合键或协议不因此恢复。
原型分别覆盖缺失、过期、规范改变、只有一个 RTT 样本和有效零速率。选中 WG 的连线标签、右侧和
列表由同一固定输入生成；未知 hy2 不借用 WG 指标。方向、时间窗口、覆盖时长和样本数保留在详情或提示中。
链路历史条每小时取当前规范范围内最后一条有效链路观测，沿用设备列表的图形样式，但不复制设备状态。
场景覆盖明确失败后恢复、当前报告过期仍有有效历史、从未观测及规范改变后无匹配历史。九条 LinkID
均保留状态与流量的小时位置；逐链路 TX 总量及覆盖小时从同一流量序列计算。

当前 SPA 已有流量卡与柱状图，但 Topology 的流量卡取网络汇总，设备详情的柱图取发送量，缺失小时也未
明确留位。当前 `Link` 投影只有延迟，`TrafficBucket` 只有小时字节数，不能据此计算五分钟有效覆盖速率或
15 分钟 RTT 分位数；后续接线须从已核验报告投影足够的测量输入。设备行监控、所选 LinkID 双端图、
RX／TX 分组图、未知占位和完整链路测量是界面迭代目标，不能把 SVG 当成产品验收。

下表只核对展示所需输入与当前差距，不从合成图表反推报告字段或补造采样；计算规则仍由
[Web 投影](web-ui-projection.md#页面和状态)定义。

| 指标 | 必要输入与范围 | 缺失时显示 | 当前实现差距 |
|---|---|---|---|
| 24 小时 RX／TX | 同端点、接口、epoch 的有效相邻计数器及时间；网络/链路按发送端 TX 聚合 | 无有效增量的小时留空，零值须有有效样本 | SPA 的网络/所选 LinkID、设备 RX/TX 范围尚未统一，缺失小时未明确留位 |
| runtime／链路状态采样 | 每小时对应设备运行或 LinkID 范围内最后有效样本及时间 | 无样本为空心，明确失败才为失败色 | runtime 已正式验收；LinkID 状态条已接线，开发检查及生产验收进度见实施状态，不能用流量或业务成功填充 |
| 当前 transport RTT | 精确方向、LinkID、传输、规范摘要、网络代的最新有效 RTT | 缺失或过期为 unknown | 当前 Link 的延迟字段尚未接入签名链路度量，完整来源与范围仍须接通 |
| WG 五分钟实测速率 | 同一发送端有效字节增量、实际覆盖秒数及五分钟窗口 | 无有效时间覆盖为 unknown | 当前小时 TrafficBucket 不足以还原五分钟覆盖时间 |
| Hy2 探测吞吐 | 该传输真实单跳动作的字节、耗时及对应观测范围 | 无本传输结果为 unknown | WG 偏向的当前报告不能供给 Hy2 结果，不能借用 WG 数值 |
| 十五分钟 RTT 波动 | 同范围成功 RTT 原始样本、时间与样本数 | 少于两个有效样本为 unknown | 单个 Link 延迟与小时流量都不足以求 P95−P50 |
| 业务结果与 HTTPS 耗时 | 设备、Service、候选、实际目标、网络代、规范摘要、结果、采样/有效期 | 无有效结果为 unknown；失败没有成功耗时 | 逐设备/Service/实际目标结果与小时历史已接通并按实施状态验收；缺指标不能推导性能排名 |
| 事件分桶 | 同查询窗口内的去重事件身份、类型、本 control 接收时间及保留覆盖 | 未覆盖留空；完整覆盖且无事件才为零 | 当前 SPA 尚未接入目标的完整筛选窗口聚合与连续加载 |

### 页面场景

主页面使用同一组示例：`demo-work` 在 Services、Overview、Events 和 Configuration state 中
一致显示冲突暂停，没有有效 matcher 或候选；`demo-phone-f` 的 `demo-video` 业务结果可用，但其设备
运行报告仍为 `unknown`。Windows 发布稿没有已入网目标，因此期望与应用阶段均不能标为已完成。
补充的局域网创建稿明确表示创建前草稿，不与主页面已存在的映射混作同一时刻。
添加设备的三张图是不同目标的未提交草稿：SSH 的 workstation 已检查合成目标为 Linux、没有旧身份，
选择 access + forward，并选择已有 media-access 与 office-lan；脚本的 new-relay 为 forward + internet_egress，
没有访问策略；二维码 new-phone 仅 access，选择已有 direct-access，平台等待首次 claim 识别。
服务分别由策略推导，不单独选择。media-access 允许 Direct 及经 internet-exit 的受管路径，入口与中间
转发不限；office-lan 允许到固定网关 relay-west 的合格路径。不限只枚举现有合格资源，不制造可达性。
图中已有选择是场景输入，不是表单自动授权。原 SSH 的 LAN Tab 状态已移除，LAN 规则在策略页独立展示。
三种添加结果分别复用各自草稿的名字、职责与策略选择。QR 对应 `demo-invite-qr` / `demo-access-g`，
脚本对应 `demo-invite-script` / `demo-relay-g`；交付时均为 open，尚未收到 claim，“尚未授权”是已知状态。
脚本稿提供一条带 HTTPS URL 的完整命令和“复制命令”，可在目标机器的 root shell 中一次粘贴；无需先下载或传送脚本文件。
完整多行块从通用不可变 HTTPS URL 下载到私有临时目录，以受信发布清单中的精确摘要核验成功后才执行；
quoted heredoc 将 Invite 经标准输入传入安装器，不放进其进程参数、环境变量或 URL。下载或校验失败均不执行，
退出时只清理本次临时目录。显示与复制保留相同完整换行，不以省略号代替可执行内容。
一次粘贴可能把 Invite 保存到终端历史；这是操作者已明确接受的取舍，复制入口同时提示该风险，不再要求第二次粘贴。
示例的 `download.example` URL、固定合成摘要和 `demo-invite-payload` 都是不可用的占位值，不是已发布制品或规范 Invite，
不能据此宣称 schema 3 安装器已实现。QR 图标同样不含可用 capability。两者后续都链接同一 DeviceID 的详情。
SSH 对应 `demo-invite-ssh` / `demo-laptop`，默认稿展示实际执行成功且加入已完成、运行未报告；同文件还保留
执行失败、连接中断未取得结果的独立场景。后两种不能靠重新签发重试，须先检查目标并继续原邀请。
这些独立场景不增加主页面六台设备的数量，签发后的待加入记录也不算已授权设备。

原独立 enrollment 两张稿已合并进唯一节点详情。QR 随后 completed 时，new-phone 绑定并获授
media/direct-access，平台由 claim 确定为 Android / arm64，运行与业务仍 unknown。脚本完成后的示例
展示加入完成、已收到配置，但真实设备报告 runtime 启动失败；这不倒退加入，也不能反推缺失的安装日志。
control-c 的脚本加入在多数证书前仅为 bound，forward + control 均未生效；完整证书及其引用事实经本机验证后的场景在同一
DeviceID 显示已加入、runtime unknown。设备尚未收到证明不撤销已经成立的资格，交付和本机运行分别回读。
原型不会把不同设备拼到同一可见页面，也不靠点击推进业务状态。

`02-nodes-access-edit` 展示 relay-west 将 media 的 media-access 替换为已有 direct-access；
`02-nodes-access-result` 区分既有策略与已本地接受的设备授权，其他 control、配置、runtime 和业务
仍 unknown。`02-nodes-detail` 展示同一设备保存后的 direct-access。此组是主页面之后的独立操作场景，
不创建策略、不改变手机使用 media-access 的关系，不填造新业务观测。
`02-nodes-rejoin` 是丢失身份后的替换确认草稿，尚未删除旧设备或签发新邀请。

`02-nodes-detail.svg` 是唯一设备详情稿，按
[设备详情的职责组合](web-ui-projection.md#管理页面的分工)共用身份、状态和设备操作。
它展示 `demo-forward-c` 增加 access 职责、获得 media 后，完成上述 `demo-video / demo-direct-policy` 策略替换的场景，
不与主页面仅 forward 的角色集合混作同一时刻。当前配置、运行、所选路径及该设备的媒体业务
都等待新范围的回读，显示 unknown；原有有效接口流量仍作为历史观测展示。未变更的 WG 资源
保持自己的当前可用观测，不能替代新配置应用。页面同时保留服务权限、当前路径、资源、LinkID、
RX／TX 图表和共享 LAN，分别进入左栏的“概览 / 访问策略 / 转发与 LAN / 身份与操作”。
默认概览直接展示状态与流量，切换时设备与策略引用不变。组合职责节点丢失身份时使用现有删除、添加设备操作；
重新添加快捷入口仅保留在纯 access 场景。
同一 SVG 的其他 fragment 展示加入中的设备：概览突出等待条件，“身份与操作”回读具体执行与加入记录；
只有尚未绑定且有效的交付物可重开。普通未知执行与 control 多数签名等待分别有恢复操作，无二次人工批准。

实时路径只保留两张原型：`04-live-paths.svg` 左侧服务导航、右侧设备列表；`04-live-paths-detail.svg` 为设备路径详情。
默认选中 media，普通图片预览即可同时看到服务与设备，不需要先跳转服务页；设备表前不放路径分组表。
目录仍为 media、office-network、private-app 和 work-apps；work-apps 保持冲突暂停，private-app 没有分配。
列表采用独立的多设备合成场景，共四台已加入设备、
五条设备/服务分配：手机的 media、workstation 的 media 与 office-network、new-phone 的 media、
relay-west 的 media。此场景比 Services/Policies 的单设备编辑稿更晚，不把那些页面的使用者数量
与本稿混作同一时刻，不增加 Service 或 Policy 对象。

media 下手机和 workstation 均报告相同 WG 中继路径，分别有目标成功和 HTTPS 503；new-phone
已选择 Direct，但尚无该目标业务结果；relay-west 已替换为 direct-access，设备尚未确认新范围。
因此 media 是四台设备、两种已确认路径和一台路径未知，不能把其四条候选当作四台设备。
office-network 下 workstation 的路径选择与目标结果均未知。同一 workstation 出现在两个服务的设备列表中，
第一层全网设备总数仍去重为四台，不能把五条服务分配冒充五台设备。服务计数、路径筛选与设备清单从同一组
绘图输入派生；路径汇总不平均业务耗时、不叠加共享链路速率，未知选择也不借用旧路径计数。

点击左侧服务只更新右侧设备列表和所选标记，并清除旧服务的设备搜索与筛选；服务目录保持可见。
设备表上方提供搜索及路径/目标结果快捷筛选，快捷范围互斥且不暗中叠加，选择“全部”清除筛选。
默认 media 清单含全部四台设备，成功设备也可直接进入详情；服务已经固定，不在每行重复服务列。
目标结果与更新时间放在同一列，保留来源与缺失原因。点击具体设备才进入第二层详情，所有入口携带同一设备与 Service。
详情去掉必选设备/服务下拉框，保留只读范围与返回设备列表的入口。手机详情仍选中
`demo-phone-f` 的 `demo-video / demo-policy`，设备报告 Auto 模式及
经 `demo-control-a`、`demo-egress-e` 访问 `media.example` 的 WG 路线。业务当前成功，设备 runtime
仍未知。中继段测量与 Topology 的 `demo-link-wg` 共用输入；首跳检查、完整 HTTPS 耗时和业务历史
是各有范围的独立合成观测，不通过链路 RTT 或流量推算。Direct 业务可用但没有可比较耗时；一跳出口
的入口报告过期，原位展开原因；hy2 中继没有当前报告。候选仍由设备选择，不在图中发明“最快”结论。
筛选下方只读回显策略的访问、Direct、入口、转发与出口限制；当前成功只对应 `media.example/health`，
图中的速率标为共享 LinkID 速率。下方“候选路径 / 历史采样”页签共用一个区域。24 小时业务图保留
20 个成功、2 个明确失败、2 个未知小时，表示每小时最后一个匹配样本，不是完整请求数或连续在线率。

两张原型分别有默认可见的页面；服务切换、筛选、历史页签和异常场景是同页状态，可用 fragment 定位，
不增加页面层级，也不是操作者修改设备状态的开关。等待确认场景为 relay-west 已换成
`demo-direct-policy`，新范围尚无回读，旧 WG 路线只作历史预览；过期场景保持原策略，但当前选择已
超过有效期，不能显示旧绿色结果，但历史页签仍保留原 WG 路线的 24 个样本，窗口明确截止于最后
报告（12 分钟前），不把历史成功移到现在。deny 场景是 `demo-policy` 后续禁止访问的独立快照；
未授权场景是手机没有 `demo-private` 的策略，不新增策略对象。等待确认、deny 和未授权场景不借用
默认场景的当前观测或历史图。
LAN 场景选中已加入的 `demo-laptop` 与 `demo-office / demo-lan-policy`：固定网关为 `demo-forward-c`，
示例目标 `198.51.100.42` 在网关映射到 `192.0.2.42`；路径仅为获授权候选预览，设备选择、首跳及目标
结果未知。中继段仍只读同一 `demo-link-a-c` 的共享观测，没有为该目标编造业务样本。

| 实时路径预览 | 可直接打开的原型 |
|---|---|
| 第一层：左侧服务目录，右侧所选服务的设备 | [服务与设备](../../assets/control-center/04-live-paths.svg) |
| 第二层：当前路线、候选与历史页签、异常原因 | [设备路径详情](../../assets/control-center/04-live-paths-detail.svg) |

主页面的同页预览包括 [WG 路径筛选](../../assets/control-center/04-live-paths.svg#paths-service-media-wg)、
[目标失败](../../assets/control-center/04-live-paths.svg#paths-service-media-failed) 和
[LAN 服务设备](../../assets/control-center/04-live-paths.svg#paths-service-office)。详情中的
[24 小时历史页签](../../assets/control-center/04-live-paths-detail.svg#paths-current-history)与候选使用同一范围；
[失败](../../assets/control-center/04-live-paths-detail.svg#paths-failed-candidates)、
[Direct](../../assets/control-center/04-live-paths-detail.svg#paths-direct-candidates)、
[等待确认](../../assets/control-center/04-live-paths-detail.svg#paths-pending-candidates)、
[LAN](../../assets/control-center/04-live-paths-detail.svg#paths-lan-candidates)沿用同一详情布局。
补充的[报告过期](../../assets/control-center/04-live-paths-detail.svg#paths-expired-candidates)及其
[历史](../../assets/control-center/04-live-paths-detail.svg#paths-expired-history)、
[禁止访问](../../assets/control-center/04-live-paths-detail.svg#paths-denied-candidates)、
[未授权](../../assets/control-center/04-live-paths-detail.svg#paths-unassigned-candidates)也只作为详情状态。

两个文件各自的默认画面可在缩略图、编辑器预览和 `<img>` 中直接查看；浏览器打开可操作服务导航、筛选与页签。
主链只有服务与设备同页 → 设备路径详情。浏览器返回恢复当前服务及设备筛选，详情返回链接打开同一服务的设备列表。
管理链接的数据路由携带同一设备/服务/策略。只有存在对应
选中对象的目标原型才添加文件跳转，没有手机详情稿时不错误打开默认的 relay-west。最小复核覆盖
两个文件与两层上限、默认同时显示服务和设备、服务切换与筛选不离开主页面、空/暂停服务不残留前一个服务的设备、默认静态预览、跨文件链接、页签的鼠标/键盘与浏览器前进后退、状态切换不残留当前路线、LAN 不出现互联网选路字段、24 小时
样本保全、汇总计数与成员一致、组内失败不被成功覆盖、候选不计入已选路径、布局边界与生成确定性。
服务暂停沿用 work-apps 已有冲突事实，并提供 Configuration state 的冲突对比入口。

原 Observations 的通用矩阵和两块规则说明已移除；过期、缺失、不同传输不可互相代替等语义在对应
候选和图表中保留。部署回读留在设备详情及 Releases。当前 SPA 的 `/routing` 仍按旧 policy scope
组织路径，尚未接入本稿的服务汇总、实际路径归组、逐设备 Service/Policy、完整目标、业务历史和原位异常展示。

Services、DNS、Policies 及 `07` 至 `09` 的管理稿沿用这种组织方式。服务和策略目录分别保留
四个与三个对象，选中有效对象时编辑草稿，使用者列表从设备授权派生；字段旁不另建 Policy 绑定。
新增的 LAN 服务详情选中同一个 office-network，展示网关 relay-west 和虚拟到本地的地址映射，
没有增加第五个 Service。节点详情中的 LAN 区域按网关过滤同一目录，创建入口仍签发 Service。
策略页选中 media-access 时固定显示所属 media、目标、完整路径限制及唯一的 android-phone 引用；
共享保存影响引用，复制另存不改原对象。LAN 状态选中既有 office-lan，终点仍是 relay-west。
新建状态以 private-app 的 demo-private-access 为未保存草稿：allow、普通 Direct 和路径不限作为
新建默认。草稿不增加目录已保存的三条策略，也不自动分配给任何设备。
DNS 将保留名的两个入口答案归入一行，普通记录的编辑在原位展开，解析观测仍为 unknown。

发布目录固定为 generation 42，共九个已验签精确文件，每平台三个；三张图的选中文件均未声明最低
兼容版本。每行补齐 `Download` / `Copy link`，APK、Windows 安装包与 portable 的按钮直接标明下载对象，
受限文件保留认证分发说明；这些是目标交互，不给合成制品编造真实可下载 URL。
Linux 的 `demo-forward-c` 有同组件、平台与摘要的匹配回报，Android 的 `demo-phone-f`
缺少新鲜回报，Windows 没有已入网部署目标。Device versions 的五行保持一匹配、一不同、三未知：
`demo-egress-e` 期望 `sha256:6b…`，当前报告 `sha256:51…`，原因及交付情况未知；其余未知分别来自
手机无新鲜报告、`demo-control-a` 未报告应用摘要、`demo-forward-b` 报告过期。摘要都是合成缩写，
不是可复制的完整发布坐标。

Events 的筛选控件及 Apply/Clear 排在一行、统一高 42 px，默认 Last 72 hours / 10 min buckets。柱状图使用固定
`2030-01-01 10:50 UTC` 作为窗口结束，共 432 个十分钟区间；合成历史记录的类型、时间与计数由同一
输入生成，图例总数、各柱段及列表总数一致。原有六条记录作为首批加载内容保留，新增更早的合成历史用于
展示 72 小时分布；不把六条列表记录冒充完整窗口。底部展示已加载数量和 Loading earlier events，表示
页面滚动到底继续加载，不使用翻页控件。悬停显示每桶类型数量，列表标记沿用同一颜色。
该合成窗口明确完整覆盖；实际历史未覆盖区间须按 Web 模型显示缺失。结果列仍是接收当时的状态，
冲突历史链接当前 Configuration state。
后者保留五个目标和两个独立签发者前沿；列表优先显示影响，签发序号放入来源详情。
`demo-work` 的对比状态展示两条冲突引用和目标差异，选择 A/B 后再确认提交；结果状态只确认本地
恢复投影，不代替其他 control 接收或设备应用。默认与解决后的 fragment 是不同的合成时刻。
对比与提交确认均展示本机已知的受影响引用：`demo-work-access` / work-access、已分配设备
`demo-laptop` / workstation，以及未绑定 Invite `demo-work-phone-invite` / join-work-phone，
其目标为 `demo-work-phone` / work-phone、职责 access、期限 `2030-01-02T00:00Z`。
这些属于独立冲突场景，不加入主页面的设备计数；冲突期间相关设备授权投影与 Invite claim 暂停。
页面明确已知范围，远端尚未同步的引用不能宣称已完整列出。
证书按固定 `2030-01-01 00:00 UTC` 计算本机剩余 24 天，peer 回读陈旧而未知；成功续签场景的新叶
有效至 `2031-01-01 00:00 UTC`。下载、请求、导入、预检、切换和浏览器回读分别绘图，不把尚未执行的
步骤预先标为已完成。当前 SPA 的相应旧页面仍需按
[管理记录的阅读顺序](web-ui-projection.md#服务发布与管理记录的阅读顺序)接线，SVG 不是部署回读。

| 场景/页面 | 目标原型 | 当前界面迭代重点 |
|---|---|---|
| Overview | [overview](../../assets/control-center/01-overview.svg) | 双圈拓扑、24 小时 TX 柱状图和设备 RX／TX；成员前沿、授权、运行及应用回读分开 |
| Devices | [nodes](../../assets/control-center/02-nodes.svg) | 每个稳定设备一行，保留职责、授权、服务策略、当前状态与证据，并展示状态历史和 RX／TX 小柱图 |
| Device detail | [统一设备详情](../../assets/control-center/02-nodes-detail.svg) | 同一页组合服务权限、当前路径、转发资源、LinkID、RX／TX 与局域网服务；身份和设备操作共用 |
| Topology | [topology](../../assets/control-center/03-topology.svg) | 双圈拓扑、独立 WG/hy2 观测；选中连线及逐链路的延迟、实测速率、RTT 波动和历史流量 |
| Live paths | [服务与设备](../../assets/control-center/04-live-paths.svg) · [路径详情](../../assets/control-center/04-live-paths-detail.svg) | 两层；左侧服务导航、右侧设备表；详情含候选/历史页签及 LAN 范围 |
| Services | [互联网服务](../../assets/control-center/05-services.svg) · [局域网服务](../../assets/control-center/05-services-lan.svg) | 统一目录；互联网目标或 LAN 网关及地址映射；从设备授权回读使用者，无全局 Policy 选择器 |
| Policies | [互联网策略](../../assets/control-center/06-policies.svg) · [新建](../../assets/control-center/06-policies-new.svg) · [LAN 策略](../../assets/control-center/06-policies-lan.svg) | 策略固定所属服务；允许/拒绝、范围模式及引用节点明确；完整编辑与复制在此完成 |
| Device versions | [device versions](../../assets/control-center/07-releases-deployments.svg) | 按设备对照期望与实报摘要；不一致行原位展开，未知逐行说明原因 |
| Events | [events](../../assets/control-center/08-events.svg) | 单行筛选、72h / 10min 类型堆叠柱状图、三列历史；展开事件说明当时影响，再链接当前对象状态 |
| Administration | [控制节点](../../assets/control-center/09-administration.svg) · [管理员](../../assets/control-center/09-administration-administrators.svg) · [网站证书](../../assets/control-center/09-administration-certificates.svg) · [配置状态](../../assets/control-center/09-administration-configuration.svg) | 四项左侧导航；成员与同步分离，管理员公开叶授权，网站证书手工续签，原位解决配置冲突 |
| Add Device | [SSH](../../assets/control-center/02-nodes-add-ssh.svg) · [脚本](../../assets/control-center/02-nodes-add-script.svg) · [二维码](../../assets/control-center/02-nodes-add-qr.svg) | 角色决定交付；只选择策略，服务与规则只读；平台由目标识别 |
| 添加交付与结果 | [二维码交付](../../assets/control-center/02-nodes-add-qr-delivery.svg) · [SSH 执行结果](../../assets/control-center/02-nodes-add-ssh-result.svg) · [脚本交付](../../assets/control-center/02-nodes-add-script-delivery.svg) | 具体交付物或执行结果；后续统一链接对应设备详情；异步执行不依赖网页停留 |
| Releases | [Linux](../../assets/control-center/07-releases-linux.svg) · [Android](../../assets/control-center/07-releases-android.svg) · [Windows](../../assets/control-center/07-releases-windows.svg) | 目录摘要、文件列表、选中文件的设备应用；文件验签和设备回报独立 |

补充状态稿：[无 admin 私有入口](../../assets/control-center/10-entry-guest.svg)、
[设备修改后的本地接受与应用结果](../../assets/control-center/02-nodes-access-result.svg)、
[网站证书](../../assets/control-center/09-administration-certificates.svg)。过期的 Web TLS 无法呈现该入口的浏览器管理页；
从其他有效 control 入口或受保护本机 CLI 诊断，不把过期页画成可直接操作的恢复入口。

Administration 的四个文件对应四个同级内容视图，均使用相同左侧导航；续签、添加、撤权和解决冲突
不另建文件或页面层级。浏览器打开下列 fragment 可查看同页的固定操作/结果场景，按钮链接只是原型
演示；下载控件标明交付对象和认证边界，不生成虚构的证书、CSR、API 地址或可执行命令。

| 视图 | 同页场景 |
|---|---|
| Control nodes | [成员和待加入节点](../../assets/control-center/09-administration.svg) · [按签发者查看同步依据](../../assets/control-center/09-administration.svg#sync) |
| Administrators | [已选公开证书](../../assets/control-center/09-administration-administrators.svg#add) · [验链失败](../../assets/control-center/09-administration-administrators.svg#invalid) · [本地授权结果](../../assets/control-center/09-administration-administrators.svg#added) · [本机补发指引](../../assets/control-center/09-administration-administrators.svg#replace) · [撤销确认](../../assets/control-center/09-administration-administrators.svg#revoke) · [本地撤权结果](../../assets/control-center/09-administration-administrators.svg#revoked) |
| Web certificates | [公开下载](../../assets/control-center/09-administration-certificates.svg#downloads) · [准备续签](../../assets/control-center/09-administration-certificates.svg#renewal) · [绑定请求已生成](../../assets/control-center/09-administration-certificates.svg#request) · [选择签回文件](../../assets/control-center/09-administration-certificates.svg#import) · [导入失败](../../assets/control-center/09-administration-certificates.svg#import-failed) · [预检通过](../../assets/control-center/09-administration-certificates.svg#ready) · [切换后等待浏览器验证](../../assets/control-center/09-administration-certificates.svg#verify) · [新入口验证失败](../../assets/control-center/09-administration-certificates.svg#activation-failed) · [验证成功并退出旧入口](../../assets/control-center/09-administration-certificates.svg#complete) |
| Configuration state | [差异](../../assets/control-center/09-administration-configuration.svg#compare) · [采用 A](../../assets/control-center/09-administration-configuration.svg#review-a) · [采用 B](../../assets/control-center/09-administration-configuration.svg#review-b) · [新冲突需重读](../../assets/control-center/09-administration-configuration.svg#changed) · [A 的本地结果](../../assets/control-center/09-administration-configuration.svg#resolved-a) · [B 的本地结果](../../assets/control-center/09-administration-configuration.svg#resolved-b) · [签发来源](../../assets/control-center/09-administration-configuration.svg#sources) |

当前 `internal/control/static/app.js` 的 `/ssot` 已显示 schema 3 签名事实前沿、成员、管理员、公开网站根的
导入/下载和证书到期信息。网站 CSR 生成、签回叶导入、入口预检/切换及续签尚未接到这组原型网页流程；
已有正式 CLI 和隔离软件验收见[实施状态](../progress.md)，不能抵扣对应网页交互。
管理员本机补发的签发者、信任锚及多 control 签发能力仍待模型补齐，
目标原型中的验链/授信合成结果不是已具备该能力的证明；用户已实际完成过管理员包取回、导入及登录
的操作史继续保留，见[管理员交付模型](../operations/admin-access.md)。原型按钮不签发证书、不修改现网信任
或管理入口，也不是已实现的生产功能。

节点详情的加入状态均在同一 SVG 内预览，单独用浏览器打开下面的 fragment 链接；这只是固定场景，
不是页面内的业务状态切换器：

| 同一设备/方式 | 等待或执行结果 | 后续状态 |
|---|---|---|
| new-phone · QR | [等待扫码加入](../../assets/control-center/02-nodes-detail.svg#detail-qr-waiting-overview) | [已加入，运行未报告](../../assets/control-center/02-nodes-detail.svg#detail-qr-joined-overview) |
| new-relay · sh | [等待执行](../../assets/control-center/02-nodes-detail.svg#detail-script-waiting-overview) | [已加入，运行失败回读](../../assets/control-center/02-nodes-detail.svg#detail-script-joined-identity) |
| workstation · SSH | [执行成功](../../assets/control-center/02-nodes-add-ssh-result.svg) · [执行失败](../../assets/control-center/02-nodes-add-ssh-result.svg#ssh-failed) · [结果未确认](../../assets/control-center/02-nodes-add-ssh-result.svg#ssh-unconfirmed) | [已加入](../../assets/control-center/02-nodes-detail.svg#detail-ssh-joined-overview) · [失败后的原次记录](../../assets/control-center/02-nodes-detail.svg#detail-ssh-failed-identity) · [中断后的原次记录](../../assets/control-center/02-nodes-detail.svg#detail-ssh-unconfirmed-identity) |
| control-c · sh | [等待成员签名](../../assets/control-center/02-nodes-detail.svg#detail-control-waiting-overview) | [成员证书已形成](../../assets/control-center/02-nodes-detail.svg#detail-control-joined-overview) |

输入和操作另有同一路由内的状态稿：

- [设备权限编辑](../../assets/control-center/02-nodes-access-edit.svg)：只增加、移除或替换策略，服务自动推导；保存或取消；页面将当前授权与未提交草稿分开。
- [重新添加 access](../../assets/control-center/02-nodes-rejoin.svg)：审阅旧身份删除、新 ID 邀请和重新授予的服务/策略；暂时离线与同事务 resume 不使用此入口。

- [精确 DNS 编辑](../../assets/control-center/05-services-dns.svg)：Services 的 DNS 标签，两个名称共三个答案；
  `control.loom` 合并显示两个 serving 入口且只读，普通记录在选中行下展开名称、A/AAAA 类型、答案及所属 LAN。
- [局域网服务创建](../../assets/control-center/02-nodes-lan-mapping.svg)：设备详情中预选网关的创建表单，只选择网关已认证
  报告的前缀，展示自动分配的等长虚拟前缀和固定网关；创建后进入统一 Services 目录。随后为该 Service 创建 Policy，
  再给访问节点分配策略；映射不绑定全局唯一策略。

以上共 32 张路由页面及补充状态稿，均为可编辑矢量。Live paths 只保留两张稿，对应主页面与设备路径详情；
交付/加入分支及策略创建/编辑也是既有入口的状态，
不增加独立产品导航或权威状态。生成器写入正式 SVG 后须逐图渲染核对，并再次运行
比较文件摘要；只预览临时渲染图不能算更新了 README 引用的原型。程序解析、边界检查和仓库测试通过仅代表
相应检查通过，视觉质量仍需与旧版及目标截图逐项审查，不自动表示用户已经接受该设计。

### 布局与间距

Add Device 的三种媒介共用 880 px 宽的居中纵向表单，标题与字段对齐，不使用外层面板、步骤编号、
角色卡片或独立 Review 面板。角色用一行复选框，SSH/sh 用紧凑切换控件，二维码只显示方式文字。
访问策略为一组多选标签，下方平铺所选策略的所属服务和规则摘要；规则编辑进入独立策略页。
标签可搜索、删除和换行，无 access 时整个区域消失。邀请设置收起，底部仅数量、取消及主动作。
权限编辑和重新添加复用同一策略选择区，不为不同场景强撑同样高度。策略页的节点限制用范围模式
配合 tag selector，LAN 固定网关与互联网出口明确区分。SVG 表达控件和状态，搜索、替换、草稿保留、
焦点与提交行为以 Web 投影文档为准，不把静态图当作已实现交互。

统一设备详情改为与 Policies 一致的左侧导航、右侧内容，宽 1586、高 1040；仅保留一个 SVG，
内部按职责显示分区，浏览器独立打开可演示，作为普通图片嵌入时显示默认概览。交付稿的“打开节点详情”
链接定位对应设备，左栏切换保持同一设备与加入状态。授权、配置、runtime 和业务状态仍各自表达，
已有设备的完整 RX/TX 序列保留，撤权/删除放在身份分区。最小检查覆盖添加→交付→对应详情、各状态与分区、
默认/未知 fragment、鼠标与键盘导航、前进/后退、内容边界、图表数据不变与无关原型不变；
核对待加入无授权、control 等待无临时权限、未报告不伪造失败、完成不等于运行、旧交付页引用已清理。
这种页面选择只是 UI 展示，不新增领域、wire、持久或运行时状态。

其余流程沿用相同方式：权限编辑、重新添加、添加交付、SSH 执行结果、操作反馈、LAN
服务创建和无 admin 私有入口使用纵向内容；Services、Policies、DNS 的目录/记录查询部分保留，
编辑区使用无外框的表单。只读身份不伪装成可编辑输入，删除操作与主保存按钮分开，当前事实、
未提交草稿及待回读结果保留各自语义。流程页不强制等高，不以另一张说明卡填补留白。
列表和监测页面保留面板式布局。Nodes 在每行并列状态采样条与 RX／TX 小柱图；Topology 增加选中链路
的三项测量，连线数字使用无背景、无边框的纯文字。链路表按链路、当前度量、状态历史、传输历史四列
组织，合并端点与身份、合并三项度量；详细统计在悬停和右侧展示，每行保留小时采样。
Live paths 只有两层：服务导航与设备表在同一主页面，切换服务或点击数量仅筛选右侧设备；设备行直接打开路径详情。
详情只读显示已携带的设备/服务，当前路线下以候选/历史页签共用内容区；页签、返回主页面及浏览器前进/后退
保留来源 Service 与筛选。直接打开详情而无来源时，返回该 Service 的全部设备。来源 fragment 只保存导航上下文，
不决定授权、路径或健康。服务列表与设备清单使用开放分隔线，不嵌套面板；历史图和逐段度量保留。
Services 与 Policies 的目录去掉逐项卡片外框，主编辑区保持开放，删除操作独立放在底部。
DNS、Device versions、Events 和 Administration 合并成对象列表与原位展开内容；
筛选只出现一次，状态、依据和关联入口跟随对应对象，不再旁置通用规则卡。
Releases 以验签摘要、三列文件列表、设备应用结果组织，取消把验签与应用混合的步骤进度。
展开区域使用同一列表的留白或浅底色，不再嵌套面板；Overview 保留现有布局。

面板沿用当前 Web 界面的贯穿分隔线：48 px 标题栏下的横线连接左右边框，指标栏及已有分栏的竖线
连接上下边框。面板内部的章节线、表头线和行分隔线也延伸到各自容器边缘；文字与控件仍保留内边距。
相邻面板以 16 px 为主要间距，标题线下首个控件至少留 16 px，正文至少留 12 px。

同类表格记录使用等高基础行；多答案 DNS 行按实际内容增高，展开详情独立占位。
单行值、状态徽标与相邻的双行内容在行内垂直居中。选中背景覆盖完整行高，
不会跨行或与分隔线错位。Events 的筛选工具栏、设备列表、签名事实、发布表格及表单页均按此核对，
表格底部说明使用独立空间，不挤入最后一行。Overview 增加内容高度，让设备列表与右侧面板底部对齐。

所有图形、文字、柱状图、坐标轴和双圈拓扑均保留为 SVG 元素。正式文件须逐页渲染，检查正文与徽标对齐、
行距、内边距、分隔线、SVG 边界、图例和节点标签；几何检查不能代替视觉复看。
Overview 为 `1586×1140`，Nodes 为 `1586×1120`，Topology 为 `1586×1680`；流程稿宽 1586、高度随内容变化，
一次粘贴脚本交付稿高 1112，为完整命令、历史风险提示与后续入口分别保留空间。
Live paths 的服务与设备合并页高 944、路径详情高 1224，宽均为 1586；同页服务切换、筛选和详情页签共用对应文件。
Services、Policies 的编辑状态高度随内容变化，DNS 高 1110；Linux / Android Releases
高 1150，Windows 无目标场景高 1060，Device versions 高 1240；Events 高 1552；Administration 的
控制节点高 984、管理员高 1160、网站证书高 1192、配置状态高 1224。同页结果共用对应视图高度。
页面宽度均为 1586，不为凑齐统一高度添加无关面板。

检查历史与原型修订范围统一记录在[实施状态](../progress.md#文档与原型审查记录)。

Web 原型呈现现行模型目标，不表示当前 SPA、控制协议或生产切换已经完成。后续开发以正式私有 Web 入口
提交 operation、control 持久接受、运行端消费和浏览器回读验收；不能以 SVG、Chrome fixture 或端口可达代替。

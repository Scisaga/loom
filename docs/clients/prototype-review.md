# 界面原型与验收图对照

[设计入口](../README.md) · [客户端视觉审查](client-ui-visual-review.md) · [Web 投影](web-ui-projection.md)

本目录中的 SVG 是可编辑的界面沟通稿。Android 与 Windows 的已实现内容以生产 UI 生成的原生截图为对照；
Windows 圆角外框是目标设计，须另外由 DWM 合成截图回读。Web SVG 是现行模型的目标投影，
现有浏览器截图仅记录实现差距。原型不读取 wire 或持久状态，也不参与客户端或 control 的运行判断：

```text
已认证领域值 + 有效运行观测 → 运行时/UI 单向投影 → 原生界面/截图 → 客户端原型
现行 Web 模型 + 固定合成数据                     → Web 目标原型
```

domain、wire、persistent 的可逆性仍由各自核心模型规定；SVG 只是有损展示，不存在从 SVG 反推授权、
观测或部署完成的操作。生成器内部使用 `demo-*` 合成身份；按本轮明确的界面要求，Web 画面使用
`control-a`、`relay-west`、`media` 等显示别名，去掉 `Prototype`、`sample data` 和 `demo-*` 水印或占位名称。
这些别名仍然不是现网身份；地址与域名继续使用 RFC 5737 和 `example`。

## Windows：原生内容与目标外框

基准目录为 [`clients/windows/testdata/ui-golden/`](../../clients/windows/testdata/ui-golden/)，截图由生产
`portableGUI` 在 Windows 11 VM 上以 96 DPI、`876×614 DIP` 渲染。下表每行的 PNG 和 SVG 使用同一场景 ID；
PNG 是 `WM_PRINT` 内容基准，不包含 DWM 外角和阴影。SVG 外框统一画成 10 DIP 圆角的目标自定义窗体。
实际 Windows 标题栏图标的下缘裁切已通过修正 `favicon.svg` 取景和资源栅格化消除；因此本轮由原生渲染器
重新录制八张 PNG，每张与旧基准仅在标题栏图标区域有 338 个像素变化，侧栏图标没有变化。

| 场景 | 原生 PNG | 可编辑 SVG | 应核对的状态和文案 |
|---|---|---|---|
| `connected` | [截图](../../clients/windows/testdata/ui-golden/connected.png) | [原型](../../assets/client/windows/connected.svg) | 已连接、自动模式、按 Service 分开的当前路径及真实/未知观测 |
| `path-expanded` | [截图](../../clients/windows/testdata/ui-golden/path-expanded.png) | [原型](../../assets/client/windows/path-expanded.svg) | 展开详情、当前选择回读和测量范围 |
| `profile-rename` | [截图](../../clients/windows/testdata/ui-golden/profile-rename.png) | [原型](../../assets/client/windows/profile-rename.svg) | 侧栏配置重命名及输入焦点 |
| `join-draft` | [截图](../../clients/windows/testdata/ui-golden/join-draft.png) | [原型](../../assets/client/windows/join-draft.svg) | 加入草稿、邀请文件/二维码入口、尚未提交 |
| `join-empty` | [截图](../../clients/windows/testdata/ui-golden/join-empty.png) | [原型](../../assets/client/windows/join-empty.svg) | 空加入表单和不可用提交动作 |
| `join-error` | [截图](../../clients/windows/testdata/ui-golden/join-error.png) | [原型](../../assets/client/windows/join-error.svg) | 加入失败及可回读的错误提示 |
| `viewport-bottom` | [截图](../../clients/windows/testdata/ui-golden/viewport-bottom.png) | [原型](../../assets/client/windows/viewport-bottom.svg) | 固定视口底部、滚动和控件位置 |
| `fixed-tun` | [截图](../../clients/windows/testdata/ui-golden/fixed-tun.png) | [原型](../../assets/client/windows/fixed-tun.svg) | 指定最终出口、TUN 形态与当前选择 |

本轮在同机 Windows 11 VM 的交互 RDP 桌面捕获了三档 DWM 合成窗口，`GetDpiForWindow` 分别实读
96、144、192 DPI。96 与 192 DPI 截图可见较小的外角弧度，144 DPI 截图左上角接近直角；三档均未达到
SVG 表达的 10 DIP 目标圆角。截图保存在被忽略的
`deploy/evidence/ui-prototype-rebuild/rdp-window-{96,144,192}.png`。这些单帧只证明各自 RDP 会话中的合成结果，
不抵扣实体显示器、跨屏移动或长期窗口行为的验收。当前源码已设置圆角偏好和非合成回退 region；
`WM_PRINT` 只核对内容，不能用它的方角判断 DWM 外框。后续 Windows 产品实现须修复并再次回读外角差距，
不能改写原生内容基准掩盖它。

## Android：Compose 场景

提交的唯一原生基准目录为
[`clients/android/app/src/screenshotTestDebug/reference/.../HomeScreenshotTestKt/`](../../clients/android/app/src/screenshotTestDebug/reference/io/github/scisaga/loom/HomeScreenshotTestKt/)。
下表 PNG 列的模式在该目录内各匹配唯一文件，文件名含渲染器生成的哈希；使用
`scripts/ui-review preview android` 可在 `out/ui-review/android/baseline/` 得到稳定场景名副本。
所有场景固定为中文、浅色、`fontScale=1.0`、`412×915dp`。

| 场景 | 原生 PNG 文件名模式 | 可编辑 SVG | 应核对的状态和文案 |
|---|---|---|---|
| `connection-disconnected-unjoined` | `*connection-disconnected-unjoined*.png` | [原型](../../assets/client/android/connection-disconnected-unjoined.svg) | 未加入/未连接及加入入口 |
| `connection-connected-auto` | `*connection-connected-auto*.png` | [原型](../../assets/client/android/connection-connected-auto.svg) | 已连接、当前路径、按 Service 逐跳展示 |
| `connection-error` | `*connection-error*.png` | [原型](../../assets/client/android/connection-error.svg) | 连接失败及错误回读 |
| `configuration-not-joined` | `*configuration-not-joined*.png` | [原型](../../assets/client/android/configuration-not-joined.svg) | 尚未加入的配置页及添加入口 |
| `configuration-ready-multiple-profiles` | `*configuration-ready-multiple-profiles*.png` | [原型](../../assets/client/android/configuration-ready-multiple-profiles.svg) | 多配置、当前连接、认证配置和 Direct/Auto/指定出口 |
| `configuration-join-error` | `*configuration-join-error*.png` | [原型](../../assets/client/android/configuration-join-error.svg) | 加入失败的配置页 |
| `diagnostics-connected` | `*diagnostics-connected*.png` | [原型](../../assets/client/android/diagnostics-connected.svg) | 诊断页的真实运行和观测范围 |
| `profile-picker` | `*profile-picker*.png` | [原型](../../assets/client/android/profile-picker.svg) | 选择配置；截图标示当前连接和正在选择的配置，请求切换中的状态尚无原生截图 |
| `notification-warning` | `*notification-warning*.png` | [原型](../../assets/client/android/notification-warning.svg) | 通知警告与连接状态，不以通知颜色补造健康 |

Android 的正式 Activity 与截图 fixture 共用 `LoomHomeScreen`。真机尺寸和系统栏可能不同，
因此真机截图只用于设备交互回读，不与固定 Layoutlib PNG 逐像素比较。

## Web：目标页面与当前实现差距

Web 原型由 [`scripts/generate_control_center_prototypes.py`](../../scripts/generate_control_center_prototypes.py)
确定性生成到 [`assets/control-center/`](../../assets/control-center/)，使用固定英文文案和合成数据。
现有浏览器场景截图在被忽略的 `out/ui-review/web/current/`，由真实 Web handler 和 Chrome fixture 生成；
该 fixture 仍带旧业务语义，所以不能作为目标原型的内容依据。
目标原型保留控制中心原有的紧凑顶栏、分层信息布局、可辨识的筛选与编辑控件，以及有明确数据来源的图表；
签名事实、实际观测与应用回读仍按现行模型分别呈现。示例图表不得用缺失数据补造健康或部署结果。

本轮以 Git 中原有的 `misaka-v1` 图稿作视觉参照，并重新设计拓扑、按 Service 的路径详情和签名事实页。
Overview 与 Topology 恢复原有的双圈构图：设备位于两条同心椭圆上，节点名称朝外排布，首跳和
显式中继边分别绘制；Topology 保留 Service 筛选、链路选择和右侧详情。两条椭圆仅用于布局，
不表示职责、授权等级或网络连接。蓝色表示设备报告的路径选择，节点圆点只表示运行报告是否新鲜。
右侧小环形图表示九条 LinkID 中五条有当前可用观测。九条中继记录逐行保留，WG 与 hy2 的观测独立展示。

### 图表与数值的对照

原有 SVG 与当前 [`app.js`](../../internal/control/static/app.js) 的 Overview、Topology 和设备详情均有
流量展示，本轮保留这些能力。计数口径参考当前
[`projectTraffic`](../../internal/control/observations.go)：来自有效报告的同端点、同接口、同 epoch
相邻计数器增量；排除计数下降、epoch 变化和超过三分钟的间隔。已变更规范且只有旧范围报告的链路不填入
新的流量序列，旧实现其他模型语义不随图表移入原型。

| 页面 | 已恢复的图表/数值 | 范围与缺失展示 |
|---|---|---|
| Overview | 24 小时 WireGuard TX 柱状图、已观测总量、逐设备 RX／TX | 逐发送端累加，重复的对端 RX 不再计入总量；未知设备显示 `unknown` |
| Topology | 选中 LinkID 的两端 TX 分组柱状图、链路列表的 TX 数值与相对条形图 | 图、列表和选中 LinkID 使用同组输入；当前可用性独立于历史流量 |
| Device detail | 当前设备的 RX／TX 分组柱状图和分项总量 | 仅统计该设备接口；RX 与 TX 分列，不合并成网络总量 |

图中纵轴为 GiB／小时，横轴为最近 24 小时；空心虚线列表示没有有效增量的时段，不能解释为零流量。
固定输入包含 22 个有有效增量的小时及两个未知小时。该覆盖数不承诺每分钟或所有端点都有报告，数值是
已观测部分的累计。生成器从同一组固定序列计算图形、总量和列表，历史观测不会让缺失的当前运行报告变绿。
当前 `TrafficBucket` 未输出足以在 UI 中细分每个空档成因的元数据，所以原型不把空档直接标成计数器重置。

当前 SPA 已有流量卡与柱状图，但 Topology 的流量卡取网络汇总，设备详情的柱图取发送量，缺失小时也未
明确留位。本稿的所选 LinkID 双端图、设备 RX／TX 分组图和未知小时占位是后续界面迭代目标；本轮没有
改动 SPA 或报告协议，不能把这些 SVG 表示当成产品已经实现。

### 页面场景

主页面使用同一组示例：`demo-work` 在 Services、Live paths、Overview、Events 和 Signed state 中
一致显示冲突暂停，没有有效 matcher 或候选；`demo-phone-f` 的 `demo-video` 业务结果可用，但其设备
运行报告仍为 `unknown`。Windows 发布稿没有已入网目标，因此期望与应用阶段均不能标为已完成。
补充的局域网创建稿明确表示创建前草稿，不与主页面已存在的映射混作同一时刻。

| 场景/页面 | 目标原型 | 当前界面迭代重点 |
|---|---|---|
| Overview | [overview](../../assets/control-center/overview.svg) | 双圈拓扑、24 小时 TX 柱状图和设备 RX／TX；成员前沿、授权、运行及应用回读分开 |
| Devices | [nodes](../../assets/control-center/nodes.svg) | 每个稳定设备一行，展示四项可组合职责及授权，不再用旧 `server` 角色 |
| Device detail | [node-detail](../../assets/control-center/node-detail.svg) | 授权、Policy grants、资源/LinkID、运行坐标、RX／TX 历史和局域网映射 |
| Topology | [topology](../../assets/control-center/topology.svg) | 双圈拓扑、独立 WG/hy2 观测、所选 LinkID 的流量图和逐链路数值 |
| Live paths | [live-paths](../../assets/control-center/live-paths.svg) | 按 Service 展示 Direct/Auto/指定出口、一跳与同出口中继及真实业务结果 |
| Services | [services](../../assets/control-center/services.svg) | 展示 matcher、Policy、按 Service 探测目标、精确 `.loom` DNS 和局域网映射 |
| Deployments | [deployments](../../assets/control-center/deployments.svg) | 签名期望与设备实际应用回读分开，未回读不显示为完成 |
| Events | [events](../../assets/control-center/events.svg) | 脱敏签名事实、成员变化、报告与冲突，不复制原始秘密或建立事件权威 |
| 原 SSOT 页 | [signed-state](../../assets/control-center/signed-state.svg) | 改为签名事实与成员前沿的只读治理投影，不编辑旧 SSOT 文件 |
| Add Device | [add-device](../../assets/control-center/add-device.svg) | SSH、脚本、扫码的授权边界；扫码仅 `access`，普通加入不二次审批 |
| Releases | [Linux](../../assets/control-center/releases-linux.svg) · [Android](../../assets/control-center/releases-android.svg) · [Windows](../../assets/control-center/releases-windows.svg) | 逐平台展示已验签精确制品、期望摘要及真实应用回读 |

补充状态稿：[无 admin 私有入口](../../assets/control-center/guest-entry.svg)、
[观测过期与未知](../../assets/control-center/observations.svg)、
[本地接受/传播/冲突及成员签名](../../assets/control-center/operations.svg)、
[邀请与控制成员加入](../../assets/control-center/enrollment.svg)、
[网站证书有效期](../../assets/control-center/certificates.svg)。过期的 Web TLS 无法呈现浏览器管理页；
证书稿只展示有效期窗口和远端 `unknown`，过期诊断应从受保护本机 CLI 回读。

输入和操作另有两张同一路由内的状态稿：

- [精确 DNS 编辑](../../assets/control-center/services-dns.svg)：Services 的 DNS 标签，包含 A/AAAA 类型、
  精确私有名、地址输入、保留 `control.loom` 行及提交后的本地接受语义。
- [局域网映射创建](../../assets/control-center/node-lan-mapping.svg)：设备详情中的创建表单，只选择网关已认证
  报告的前缀，展示自动分配的等长虚拟前缀、固定网关、默认专用 Policy 和既有 Policy 的附带授权。

以上共 13 个路由页面和 7 个补充状态，均为可编辑矢量。生成器写入正式 SVG 后须逐图渲染核对，并再次运行
比较文件摘要；只预览临时渲染图不能算更新了 README 引用的原型。程序解析、边界检查和仓库测试通过仅代表
相应检查通过，视觉质量仍需与旧版及目标截图逐项审查，不自动表示用户已经接受该设计。

### 布局与间距

面板沿用当前 Web 界面的贯穿分隔线：48 px 标题栏下的横线连接左右边框，指标栏及已有分栏的竖线
连接上下边框。面板内部的章节线、表头线和行分隔线也延伸到各自容器边缘；文字与控件仍保留内边距。
相邻面板以 16 px 为主要间距，标题线下首个控件至少留 16 px，正文至少留 12 px。

表格在同一张表内使用等高行；单行值、状态徽标与相邻的双行内容在行内垂直居中。选中背景覆盖完整行高，
不会跨行或与分隔线错位。Events 的筛选工具栏、设备列表、签名事实、发布表格及表单页均按此核对，
表格底部说明使用独立空间，不挤入最后一行。Overview 增加内容高度，让设备列表与右侧面板底部对齐。

所有图形、文字、柱状图、坐标轴和双圈拓扑均保留为 SVG 元素。正式文件须逐页渲染，检查正文与徽标对齐、
行距、内边距、分隔线、SVG 边界、图例和节点标签；几何检查不能代替视觉复看。
Overview 为 `1586×1140`，Topology 为 `1586×1080`，其余 Web 稿为 `1586×992`。

Web 原型呈现现行模型目标，不表示当前 SPA、控制协议或生产切换已经完成。后续开发以正式私有 Web 入口
提交 operation、control 持久接受、运行端消费和浏览器回读验收；不能以 SVG、Chrome fixture 或端口可达代替。

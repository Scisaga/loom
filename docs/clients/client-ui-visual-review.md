# 客户端 UI 视觉审查模型

本文定义 Android 与 Windows 原生界面的视觉审查闭环。它只为既有
[客户端运行与选路模型](client-runtime-model.md)增加可再生证据，不增加 wire、持久化或运行时权威实体。

## 必须结果与边界

已实现界面的生产 UI 代码是原生截图的唯一渲染源。固定业务投影经平台原生渲染器生成 PNG；获批 PNG 是回归基准，
`current`、`diff`、manifest 和 HTML 图廊都是可删除重建的审查输出：

```text
权威领域状态 + 真实运行观测
  → UI 单向投影
  → 固定视觉场景 fixture
  → Compose Layoutlib / Win32 Direct2D、DirectWrite
  → baseline + current + diff
  → VS Code Simple Browser 图廊
```

首期不声称覆盖 Android 相机画面、系统权限页、真实 VPN 连接、Windows UAC/托盘、多显示器、
物理 DPI、ARM64、睡眠唤醒或物理网络切换。这些仍由对应真机或实体机里程碑验收。

可编辑 SVG 原型以已获批客户端截图为业务场景对照，并表达后续迭代的目标设计。Windows 原型中的
圆角外框、间距、线宽和控件布局均可与当前原生基准不同；同一场景 ID 表示状态对应，不表示像素一致。
Web 原型则按[现行 Web 投影](web-ui-projection.md)表达目标内容，现有 Web 截图仅供差距核对。
全部场景、来源和差异见[原型与验收图对照](prototype-review.md)。原型不是客户端截图基准、
运行时输入或领域权威；未来设计变更仍须落到生产 UI，再由原生截图和正式业务入口回读。

Web 目标稿逐页同时核对旧图稿、当前界面中仍然有效的展示能力和现行模型：Overview 与 Topology
保留双圈拓扑，Overview、Topology、设备详情分别保留网络 TX、所选链路 TX、设备 RX／TX 图表。
标题横线贯穿面板宽度，已有分栏的竖线贯穿面板高度；表格分隔线和选中背景贴合完整行。
检查标题线下留白、卡片内边距、文字与徽标居中、表格行高、图例与标签位置，并渲染正式 SVG 复看。
固定合成数据的来源写在[图表对照](prototype-review.md#图表与数值的对照)中，界面稿使用简短显示别名，
不添加原型或示例数据水印。几何检查通过只证明检查范围内没有冲突，不代表视觉审查通过。

## 有限概念

| 概念 | 含义 | 删除后破坏的结果 |
|---|---|---|
| `VisualScene` | 平台内唯一、稳定且人工可引用的场景 ID，以及一份固定 UI 输入投影 | 无法把意见、PNG 和回归结果对应到同一状态 |
| `Baseline` | 已人工批准并提交的原生 PNG | 无法判断生产 UI 是否发生视觉变化 |
| `Current` | 当前源码按同一场景与环境重新渲染的 PNG | 无法审查待批准结果 |
| `Diff` | 对 baseline/current 解码为 RGBA 后逐像素比较的可视投影 | 无法定位变化像素 |
| `RenderEnvironment` | 会影响原生像素的固定平台、尺寸、DPI、语言和 renderer 版本 | 无法区分代码变化与环境漂移 |

这些概念都不属于客户端领域状态。`VisualScene` 只在测试源码中存在；PNG、元数据和图廊不能被
运行时读取，不能完成 Enrollment、连接、选路或健康判定，也不能倒写客户端事实。

场景 ID 在各平台内稳定。重命名等同于删除旧场景并增加新场景，必须作为整组 baseline 变更接受审查。

## 逐层映射

| 层 | Android | Windows | 约束 |
|---|---|---|---|
| domain | 既有 Device、CertifiedLKG、Preference、Selection、Observation | 相同客户端模型 | 本文不新增领域值 |
| wire | 既有私有设备 wire | 既有私有设备 wire | 不变，截图 fixture 不解码 wire |
| persistent | Android Keystore 中的既有客户端权威 | Windows DPAPI 中的既有客户端权威 | 截图不读写持久状态 |
| runtime | `StateFlow` 与 HostAdapter 的真实运行投影 | `portableGUI` 消费的真实运行投影 | fixture 以固定值代替外部输入 |
| UI | `HomeUiState` → `LoomHomeScreen` | 生产 `portableGUI` 与 Win32 控件 | 只由上层单向投影 |
| render | Compose screenshot/Layoutlib | Direct2D/DirectWrite 的确定性内容截图；另由 DWM 合成截图验外框 | `WM_PRINT` 不验证窗口圆角或阴影 |
| review | PNG、metadata、manifest、HTML | PNG、metadata、manifest、HTML | 全部可删除重建 |

domain、wire 与 persistent 仍满足各自核心模型的可逆性要求。UI、fixture 和像素是有损单向投影，
不存在也禁止定义 `decode(PNG)` 或 `load(gallery)` 回到领域状态的映射。

Android 正式 `Activity` 通过 `LoomHomeRoute` 读取 `StateFlow`、调用 manager 并处理权限或系统副作用；
`LoomHomeScreen` 只接收不可变 UI 投影、当前标签和回调。截图与正式入口共用后者。CameraX、Android
权限页与 VPN 系统页不由假页面代替。

Windows 原生截图场景集中复用生产 `portableGUI`、真实 Win32 控件、Direct2D/DirectWrite 及已有 `WM_PRINT`
内存捕获；此链路不能使用 HTML、SVG 或独立页面代替生产 UI。
[`scripts/generate_windows_prototypes.py`](../../scripts/generate_windows_prototypes.py) 仅生成设计沟通用 SVG，
不接入 `scripts/ui-review`，不生成或更新原生 baseline，也不作为 Windows 运行时的另一套 UI。
其固定合成内容和布局规格见[Windows 原型](prototype-review.md#windows原生场景与目标视觉设计)；
原型重复生成、几何检查和人工渲染检查只验证设计稿，不证明原生控件、DPI 或业务交互已实现。

## 场景集合与环境

Android 基准固定为中文、浅色、`fontScale=1.0`、`412×915dp`：

- `connection-disconnected-unjoined`
- `connection-connected-auto`
- `connection-error`
- `configuration-not-joined`
- `configuration-ready-multiple-profiles`
- `configuration-join-error`
- `diagnostics-connected`
- `profile-picker`
- `notification-warning`

Windows 内容基准固定为浅色、96 DPI；初始产品窗口为 `876×614 DIP`：

- `connected`
- `path-expanded`
- `profile-rename`
- `join-draft`
- `join-empty`
- `join-error`
- `viewport-bottom`
- `fixed-tun`

fixture 只使用 `demo-*`、固定时间和示例数据，不访问 Keystore、DPAPI、网络、相机、libbox 或系统
身份。动画、光标、焦点、时钟和异步状态必须冻结。Windows 元数据还固定系统 build 和 renderer；
环境不一致直接失败，不能静默重录。

Windows 的正式外框验收另在同一 Windows 11 VM 以 96、144、192 DPI 捕获真实 DWM 合成窗口，核对
`876×614 DIP`、10 DIP 圆角、阴影、标题区、缩放后的控件位置和 TagSelect 弹层。`WM_PRINT` 输出只能
用于内容像素回归，不能替代这组三档合成截图。

## 允许的转换与失败语义

审查状态只有以下转换：

```text
生产代码 --preview--> Current + Diff + Gallery
整组人工批准 --record all--> Baseline' --严格 verify--> 已批准
生产代码 --verify--> 与 Baseline 逐像素相同，或失败
```

- `preview` 不修改 baseline。像素或尺寸变化会显示在图廊中并可正常完成；编译、渲染、环境不符、
  baseline/current 缺失或多出场景必须失败。
- `record all` 只接受 Android 与 Windows 全部场景，不支持局部批准；写入后自动严格验证。
- `verify` 要求场景集合、尺寸和每个解码 RGBA 像素完全一致。
- 重复原生渲染不稳定时修复 fixture 或 renderer；不得以容差、模糊比较或扩大遮罩隐藏漂移。
- 失败不改变 baseline。删除 `out/ui-review/` 后重新执行命令即可恢复所有临时证据。

## 正常业务链与最小测试

正常链为：修改生产 UI → 执行 `scripts/ui-review preview all` → 在 VS Code Simple Browser 审查三栏与
叠加滑块 → 按场景 ID 提意见并修改 → 再次 preview → 整组批准后执行 `record all` → 检查 Git binary
diff → 执行 `verify all`。

最小测试集覆盖：完全相同、单像素变化、尺寸变化、baseline 缺失、current 多出、HTML 转义与稳定
排序；Android 必须生成九个场景；Windows 必须在固定 VM 连续两次生成相同场景和 PNG 哈希。现有
Activity instrumentation、Win32 控件、DPI、键盘和布局测试仍是独立门禁。

## 明确禁止恢复

- 不用手工 SVG 替换 Android/Windows 的原生截图基准或推断已实现行为；
- 不维护独立于生产控件的截图专用页面或第二套 renderer；
- 不提交或引用手工复制的 `current` 截图，规范文档只引用 baseline；
- 不让 PNG、golden、manifest、场景 fixture 或测试 helper 拥有业务生命周期或完成判定；
- 不因公共 Windows runner 的像素漂移降低固定本机 VM 的严格门禁。

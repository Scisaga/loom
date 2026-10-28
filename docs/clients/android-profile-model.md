# Android 本机配置模型

[设计入口](../README.md) · [客户端运行与选路模型](client-runtime-model.md)

本文定义 Android 如何在同一应用中保存、命名、浏览和切换多份连接配置。
它只是现有 `DeviceIdentity` 、`CertifiedLKG` 和 `Preference` 的本机聚合边界；每份
`CertifiedLKG` 都包含签名 `DeviceView`、连续成员表证明、签发者事实前沿及该 profile 的单调 floor，
不是第九个网络权威概念，也不改变一台 Android 设备同时只运行一条 VPN 的约束。

## 有限概念

`AndroidProfileCatalog` 是唯一新增的本机权威值，包含有序的 `ConnectionProfile`
列表和一个 `viewed_profile_id`。每个 `ConnectionProfile` 只有：

- 不透明、稳定的本机 `id`，只用来隔离同一应用内的存储和运行输入；
- 用户可编辑的 `name`，用于选择、连接确认和标题回读。

删除 catalog 将无法表达“同一 Android 应用保存多份配置并给每份命名”。
删除稳定 `id` 将使不同配置的身份、LKG 和选路偏好无法隔离。删除 `name`
则只能向人显示内部标识或哈希，直接破坏配置选择和连接回读。

`viewed_profile_id`、`requested_profile_id` 和 `active_profile_id` 是同一稳定 `id` 的三种关系，
不是三个 profile 或新状态机：

| 关系 | 事实来源 | 含义 |
|---|---|---|
| viewed | catalog | UI 正在浏览或编辑哪份配置 |
| requested | 用户连接意图 | 哪份配置被明确请求连接或恢复 |
| active | VPN 运行时 | 哪份配置已通过认证校验、TUN 启动和 selector 回读；业务健康另由实际观测决定 |

浏览另一份配置不得修改 requested 或 active；只有明确的“连接/切换”操作可以修改
requested。active 只能由真实 VPN 结果单向产生，不能由 catalog 或 UI 倒写。

## 关系、转换与不变量

1. 创建生成一个本机不透明 `id` 和规范名称，然后把它设为 viewed；新行没有身份或 LKG。
2. 名称去除首尾空格后必须非空且在 catalog 内唯一；重命名只替换该 `id` 的
   `name`，不替换设备身份、LKG、路由或 VPN。
3. 选中只替换 viewed。用户点击连接后，requested 才指向该 `id`。
4. 当且仅当该 `id` 的认证 LKG 校验、libbox/TUN 启动及 selector 回读成功时，active 才指向它。
   DNS/HTTPS 探测随后按授权 Service 产生 `available`、`unavailable` 或 `unknown`；无匹配目标时
   保持 `unknown`，不阻断 active，也不把 active 当成业务健康。
5. 切换先停止旧运行时，再使用新 `id` 走同一连接链；认证或运行时应用失败停留在新配置的错误状态，
   不跨配置自动恢复旧连接，也不建立多 VPN manager 或切换状态机。
6. 正在 requested/active 的行必须先断开才能删除；断开后可以删除任意行，包括最后一行。删除先取消并等待该行的本机工作，
   再原子提交不再可见的 catalog，
   再删除该 `id` 命名空间中的身份、候选 LKG、偏好和观测；崩溃残留不得再被加载。
7. catalog 可以为空。空目录的 `viewed_profile_id` 恰为 `""`，非空目录的该值必须引用其中唯一行；ID 和名称都不重复；
   名称是 1–64 个字符的规范 Unicode 且不含控制字符。

## 跨层对应

| 事实 | Domain | Wire | Persistent | Runtime | UI |
|---|---|---|---|---|---|
| catalog 行 | `id + name` | 无对外 wire；Android 内部 Intent 只传已验证 `profile_id` | 受保护的规范 catalog JSON | 只读行集合 | 配置列表、选择器、重命名 |
| viewed | catalog 中一个 `id`，空目录时缺席 | 无 | 与 catalog 同步提交，缺席规范编码为 `""` | Compose 当前编辑输入或空投影 | 单选标记或添加配置入口；不声称已连接 |
| 配置内容 | 该 `id` 关联的现有身份/LKG/Preference | 仍使用私有 Enrollment/config/report wire，不传 catalog 名称 | `p.<id>.*` 受保护槽 | 按 `id` 显式加载 | 加入、配置版本和选路偏好 |
| requested | 用户想运行的 catalog `id` | 内部 VPN Intent 中的 `profile_id` | 与 `desired_connected` 原子保存 | 启动/恢复调用的显式输入 | “正在连接 <name>” |
| active | 已被宿主真实消费的 catalog `id` | 无权威 wire | 不持久化为运行事实 | VPN 成功后的只读投影 | 标题和“当前连接 <name>” |
| 设备名称 | 认证 `DeviceView.name` 的设备属性 | 原有 DeviceView 与 Android host DTO 的 `name` 不变 | 随 LKG 保存 | active 的辅助信息 | 可显示为辅助信息，绝不替代 profile name |

catalog 是本机值，没有网络 wire 编码。它的规范持久编码必须满足：

```text
decode(encode(AndroidProfileCatalog)) = AndroidProfileCatalog
load(save(AndroidProfileCatalog))      = AndroidProfileCatalog
```

未知字段、重复键、非规范 JSON、非规范 ID/名称、重复 ID 和悬空 viewed 都失败关闭。
空目录也使用同一 schema 1 本机 catalog 编码；既有非空目录字节不变。空目录只能搭配空 viewed，
不接受空目录中的悬空 ID，也不接受非空目录缺少 viewed。删除最后一行提交这一空值，清除该行的连接意图，
再清理该行命名空间。重启读取已有空目录，不生成替代配置或恢复已删除身份；用户明确点击“添加”后才创建新行。
名称到 UI 及 requested/active 到标题都是单向投影，不必也不得从 UI 标题反解运行事实。

## 恢复与失败语义

认证状态读取与执行投影分开：同一次 Go 投影只完整验证一次 View，各子投影复用该调用已验证的值，
不引入可跳过校验的公开开关。Android 只复用与当前完整持久字节一致的可删除读取结果；读取失败、
字节变化或删除必须失效，缓存不能替代加密记录、单调性检查或原子持久回读。UI 的 ready/digest
与执行投影从同一份已接受状态派生，未加入时没有执行投影。运行准备保留独立 underlay 查询与取消。
候选解析、偏好校验和选择等确定性错误在创建 VPN 前报告；只有进程与 selector 实际应用并回读后
才能产生 active。错误需指出失败输入与实际字节数，不能把空输入和超限混成同一消息。
最小测试覆盖重复读取不重复投影、字节变化及损坏失效、持久接受后运行失败保留 LKG、稠密拓扑
正常选择，以及连接/取消/重启保持原身份与报告序列。签名 schema 和认证原件不改变。

配置页的扫码入口使用扣除系统栏和刘海后可见区域居中的独立弹窗。原页面保持原滚动位置，弹窗打开期间不能操作背景；
取景画面本身为方形，按可见宽高缩小并限制最大尺寸，不再嵌入配置列表或套外围白色卡片。
关闭按钮、背景空白及系统返回沿同一个取消回调收起弹窗。权限申请和相机错误在取景区域内表达，
保留重新授权和关闭入口；完成或取消在用户事件中立即封闭本次识别交付，不等待下一帧移除组件。
关闭解绑本次相机预览、分析与线程，已排队的旧识别回调不得再导入邀请。
识别结果仍沿当前 profile 的原 `importInvite` 入口处理，一次打开最多交付一次结果。
domain、wire、persistent 和加入认证均不变化；`scanning` 仍只是 Compose 的临时可见性，
Activity 重建后不恢复相机或创建新的加入意图。UI 只映射打开、关闭、权限和相机的真实结果，
不保存另一份邀请、事务或完成状态，操作者无需新增步骤。
最小检查覆盖方形取景适配横竖屏、居中与背景位置保持、关闭按钮/空白/返回取消、重新打开和相机释放；
不能用静态截图抵扣真实相机的生命周期回读。

LAN 冲突检查的本机接口地址由 Android Java `NetworkInterface` 只读枚举，作为准备运行和
签名报告调用的显式输入交给共享 Go 核心；不让 Go 自行依赖 Android 上不可用的接口枚举路径。
只采集 UP、非 loopback 的 IPv4 地址与前缀长度，不扫描主机，不保存另一份网段状态。
核心排除 Loom 自有地址并规范化连接前缀；其他隧道仍参与冲突检查，不能据此授予 LAN 共享。
读取失败用未知表达，阻止该 LAN 的捕获与业务；成功读回空集合与失败不同。
底层网络切换或已有网络的地址变化时，沿原 VPN 生命周期重新准备捕获边界；相同地址的重复回调不重启。
这些是原 `local_networks` 报告值的来源，不改变认证 View、profile 身份或网关授权。

全新安装没有旧单槽时，按创建规则建立不含身份和 LKG 的首个 `primary / Loom A`，等待正常 Enrollment；
不把“无旧槽”当作升级失败。首次升级时，只有旧单槽已包含**完整且可按现行 schema 3 严格验证**的身份、信任绑定、floor、
不可回退 latch 与认证 LKG，才能单向迁移为 `primary / Loom A`：先验证，再将这些原始认证字节
逐字节写入 `p.primary.*`，独立回读成功后提交 catalog 作为迁移标记，最后删除旧键。
无法证明旧槽符合现行格式时，包括只有 1、2 号材料的情形，不提交可运行的 `primary`，
不把旧字节送进 schema 3 decoder、重放或作为 fallback；原始身份、材料、floor 和 latch
按受保护切换证据保全，等待经验证的前向迁移办法，不自动生成替代身份或清空状态。
标记存在后只读新槽，不保留双读、fallback 或兼容层。旧的单配置 VPN 恢复意图也只允许在
现行槽完整迁移后一次映射到 `primary`；迁移后 requested ID 缺失、非法或已删除时必须拒绝恢复，
不得用 viewed 代替。

空目录在连接页和配置页显示添加入口，不初始化 Enrollment 或选路的空 ID，不显示扫码、连接及刷新旧配置的操作。
顶部显示应用名称；新建配置后继续走现有扫码加入链。配置行菜单、选择面板及确认弹窗使用同一浅色中性表面、
绿色选择强调及明确的删除颜色，不沿用组件默认的异色背景；菜单仍保留重命名、断开前禁止删除及取消行为。

进程重启时恢复 catalog 和被保存的 requested ID，但 active 仍为空；只有重走认证 LKG、
运行时应用和 selector 回读后才重新产生 active；后续业务检查只更新该 Service 的观测状态。
配置失败保留该行和其认证 LKG，显示明确错误；
已接受 View 而资源域名缺解析器时，加入仍已完成，明确显示“已加入，认证配置已保存；运行未就绪”。
libbox 启动失败已经结束本次实例，平台继续释放自己的 TUN 和监视回调，不保留已结束实例阻挡下一次重试。
停止时清理未确认保留运行错误与空 active，不将异常抛出为进程崩溃或显示成功停止。
重试沿原身份同步；不删除身份、重扫新邀请或用内置 bootstrap 解析器补齐已接受 View。
本次连接已终止时清除持久 desired，运行投影暂保留失败的 requested ID 只用于给错误归属；
它不是 active，也不得自动恢复或切换到 viewed/另一行。重试、删除该行或发出另一连接请求后替换该错误投影。

加入中断后的重试复用保留的同一 Invite、request ID 和设备密钥。配置页的“放弃本机加入”
沿用现有确认操作：只清理本机待加入资料，不删除 Keystore 设备密钥，也不撤销控制面设备。
本机放弃不证明远端事务已取消、目标 ID 已释放或旧 Invite 可以重新使用。

## 正常业务链与最小测试

一条正常链：用户在配置页创建“Loom B” → 为该行完成私有 Enrollment 并保存其 LKG
→ 在连接页选中 Loom B → 点击连接 → VPN 按 Loom B 的 `id` 读取、应用并回读真实结果
→ active 变为该 `id`，业务探测按实际结果另行更新 → 应用标题显示 `LOOM · Loom B`，辅助行显示 Android、连接状态、
设备名称或成员表证明状态。内部 ID、成员表/事实摘要和长哈希不得出现在标题或配置选择中。

最小测试集只覆盖风险等价类：

1. 非空与空 catalog 的规范编解码往返及重复、悬空、非规范值拒绝；删除最后一行并重启仍为空，随后可新建；
2. 现行 schema 3 旧单槽在 catalog 提交前完整复制回读，提交后不再读旧键；1、2 号或不完整
   旧槽保全原始字节和 floor/latch，不能产生可运行的 `primary`；
3. 真机沿正式入口验证 A/B 隔离、显式切换、重启回读和安全删除；空列表可操作，菜单可关闭且颜色与页面一致，不回读哈希。

## 禁止恢复

- 不恢复旧 profile manager、每配置 manager、切换 phase/gate/journal 或后台调度器；
- 不用 DeviceView 的设备名、成员表/事实摘要或随机 ID 代替用户配置名；
- 不把 viewed 投影为已连接，不持久化 active，不从 UI 倒写运行事实；
- 不保留旧单槽双读、跨 profile fallback、公开配置下载或 v1 路径。

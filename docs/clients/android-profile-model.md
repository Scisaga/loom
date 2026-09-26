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
| active | VPN 运行时 | 哪份配置已真实完成验证、TUN 启动和业务检查 |

浏览另一份配置不得修改 requested 或 active；只有明确的“连接/切换”操作可以修改
requested。active 只能由真实 VPN 结果单向产生，不能由 catalog 或 UI 倒写。

## 关系、转换与不变量

1. 创建生成一个本机不透明 `id` 和规范名称，然后把它设为 viewed；新行没有身份或 LKG。
2. 名称去除首尾空格后必须非空且在 catalog 内唯一；重命名只替换该 `id` 的
   `name`，不替换设备身份、LKG、路由或 VPN。
3. 选中只替换 viewed。用户点击连接后，requested 才指向该 `id`。
4. 当且仅当该 `id` 的认证 LKG、libbox/TUN 和真实 DNS/HTTPS 结果成功时，active 才指向它。
5. 切换先停止旧运行时，再使用新 `id` 走同一连接链；失败停留在新配置的错误状态，
   不跨配置自动恢复旧连接，也不建立多 VPN manager 或切换状态机。
6. 正在 requested/active 的行必须先断开才能删除，最后一行不能删除。删除先取消并等待该行的本机工作，
   再原子提交不再可见的 catalog，
   再删除该 `id` 命名空间中的身份、候选 LKG、偏好和观测；崩溃残留不得再被加载。
7. catalog 不为空；`viewed_profile_id` 必须引用其中唯一行；ID 和名称都不重复；
   名称是 1–64 个字符的规范 Unicode 且不含控制字符。

## 跨层对应

| 事实 | Domain | Wire | Persistent | Runtime | UI |
|---|---|---|---|---|---|
| catalog 行 | `id + name` | 无对外 wire；Android 内部 Intent 只传已验证 `profile_id` | 受保护的规范 catalog JSON | 只读行集合 | 配置列表、选择器、重命名 |
| viewed | catalog 中一个 `id` | 无 | 与 catalog 同步提交 | Compose 当前编辑输入 | 单选标记；不声称已连接 |
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
名称到 UI 及 requested/active 到标题都是单向投影，不必也不得从 UI 标题反解运行事实。

## 恢复与失败语义

首次升级时，旧单槽只能单向迁移为 `primary / Loom A`：先验证并逐字节写入
`p.primary.*`，独立回读成功后提交 catalog 作为迁移标记，最后删除旧键。标记存在后
只读新槽，不保留双读、fallback 或兼容层。旧的单配置 VPN 恢复意图也只允许一次映射到
`primary`；迁移后 requested ID 缺失、非法或已删除时必须拒绝恢复，不得用 viewed 代替。

进程重启时恢复 catalog 和被保存的 requested ID，但 active 仍为空；只有重走认证 LKG、
运行时应用和业务检查后才重新产生 active。配置失败保留该行和其认证 LKG，显示明确错误；
本次连接已终止时清除持久 desired，运行投影暂保留失败的 requested ID 只用于给错误归属；
它不是 active，也不得自动恢复或切换到 viewed/另一行。重试、删除该行或发出另一连接请求后替换该错误投影。

## 正常业务链与最小测试

一条正常链：用户在配置页创建“Loom B” → 为该行完成私有 Enrollment 并保存其 LKG
→ 在连接页选中 Loom B → 点击连接 → VPN 按 Loom B 的 `id` 读取、应用并回读真实结果
→ active 变为该 `id` → 应用标题显示 `LOOM · Loom B`，辅助行显示 Android、连接状态、
设备名称或成员表证明状态。内部 ID、成员表/事实摘要和长哈希不得出现在标题或配置选择中。

最小测试集只覆盖风险等价类：

1. catalog 规范编解码往返及重复、悬空、非规范值拒绝；
2. 旧单槽在 catalog 提交前完整复制回读，提交后不再读旧键；
3. 真机沿正式入口验证 A/B 隔离、显式切换、重启回读和安全删除，不回读哈希。

## 禁止恢复

- 不恢复旧 profile manager、每配置 manager、切换 phase/gate/journal 或后台调度器；
- 不用 DeviceView 的设备名、成员表/事实摘要或随机 ID 代替用户配置名；
- 不把 viewed 投影为已连接，不持久化 active，不从 UI 倒写运行事实；
- 不保留旧单槽双读、跨 profile fallback、公开配置下载或 v1 路径。

# Loom · 客户端接入设计

> **状态:** 设计生效；C0 显式部署目标与生命周期拆分已实现；Linux 加入码、P-256 CSR
> 绑定、节点预置与签名分发代码已实现；Windows 已建立独立 Service 外壳、三模式
> 本地偏好核心、签名 bundle 验证缓存、DPAPI 秘密仓库、严格 hydration 与加密候选提交，
> 以及签名数据面包、Wintun Authenticode、可执行预检和进程监督边界；Windows 首次启动
> 导入二维码与 Portable Mixed 数据面激活已在本机闭环；Linux access-only 的 signed
> decommission、身份吊销与秘密清理已闭环；服务端已提供复用 v5 Observation 与
> self-check v1 的 NAT Device 接收适配器；Android 的原生宿主、扫码/文件加入、Keystore
> 身份、签名 pull/cache、候选激活恢复与可信上报已在代码和 Emulator 闭环，正式环境部署、
> 真机入网与移动端 selector/可靠性仍待验收；服务器职责/其他平台的通用双重吊销仍待实现
>
> **日期:** 2026-09-07；开发与构建环境于 2026-09-07 核对
>
> **适用范围:** Windows、Linux Server 与 Android 接入设备；v1 不考虑 Linux Desktop
>
> **上位约束:** [设计文档](design.md)中的模型、安全边界与控制平面不变量仍是
> 当前实现的事实来源；统一 Device、内部 Enrollment 协议和版本化对象图的迁移目标见
> [Device 生命周期与交付架构](device-lifecycle-and-delivery.md)，本文只展开平台客户端交付。
> 具名局域网访问是尚未实现的独立目标态，
> 见 [Local Network 专题](local-network.md)。若专题与设计文档冲突，以设计文档为准。

---

## 1. 结论

客户端不应实现三套独立网络栈。三类平台共用 sing-box 数据平面、Loom 的签名
配置格式、设备身份和调度语义，只为操作系统生命周期做薄适配。

| 平台 | 流量接管 | 客户端形态 | 结论 |
|---|---|---|---|
| Windows 桌面 | TUN 主接管 + 同规则的本地 `1080` mixed | Windows Service（v1 目标态）；托盘 UI 可分阶段交付 | 需要薄客户端；规则由中控下发 |
| Linux Server | 本地 `1080` mixed，由进程显式使用 | Loom + sing-box 二进制分发包 | 不开发独立 GUI |
| Android | `VpnService` TUN | Android App，内嵌 sing-box | 必须开发 App；规则由中控下发 |

这里的“一个入口”是一个**逻辑策略入口**：请求先由中控 matcher 映射到 Service，
再映射到既有 `AccessDeclaration`。Windows 同时暴露 TUN 与 `1080` 是为了适配不同
应用，并不形成两套策略；两者必须使用同一份中控规则。选择“默认德国”也复用
这个入口，不新增德国端口。Linux 为迁移旧部署而保留的端口覆盖属于兼容/高级
能力，不是日常入口或 Service 页面的产品模型。

客户端只提供一个顶层路由模式控件，且只有三种模式：

- **Direct**：全部接管的业务流量从设备本地直连，不进入 Loom 服务器路径；
- **Auto**：完整使用中控签名下发的 `Host → Service → Policy`，路径由 Agent 自动选择；
- **指定出口**：从当前全部在役 `egress_capable` 节点中选一台作为全部接管业务流量的最终出口，
  最终一跳固定，但到该出口之前的路径仍由 Agent 自动择优。

客户端不能手选 Current Paths；路径只读展示运行时结果。三态是本机受控偏好：
客户端只切换本地 selector，不编辑中控规则或生成的 sing-box 配置；Auto 规则与
指定出口列表仍来自最后一份验签通过的配置包。

静态导入现成 sing-box 兼容客户端可用于验证链路，但它不提供完整的签名 pull、
设备吊销、Loom 调度、离线排名与可信观测，不能作为最终托管方案。

---

## 2. 当前实现边界

当前代码已经把接入方式明确分成 `android`、`windows-desktop` 与 `linux-server`，
并能按平台生成 TUN 或 mixed inbound。旧的含糊值 `desktop` 会被校验器拒绝。Linux
侧已有中控 Devices 列表、一次性加入码、真实二维码
与加入文件、可复制的内部兼容 `loom://enroll` URI、签名 `tar.gz` 分发包，以及从本地 P-256 CSR
到 SSOT 自动发布、ready bootstrap 和首次 signed pull 的安装闭环。是否已经部署到
生产应以[当前状态](status/current.md)为准，不能用仓库代码状态代替上线核验。

仓库能力与生产部署是两条独立事实；是否已经部署和完成真机验收，以
[当前状态](status/current.md)为准：

| 能力 | Linux | Windows | Android |
|---|---|---|---|
| sing-box 配置渲染 | 已实现 | 配置形状部分可复用 | TUN-only bundle 与严格 hydration 已实现 |
| 系统生命周期 | systemd 已实现 | Portable 前台、受限 Service broker、Job Object 与更新恢复已实现；amd64 实机 TUN 启停、宿主崩溃恢复和安装器生命周期已验收 | 原生 `VpnService`、前台通知、幂等启停与 Emulator TUN 已实现；真机网络切换/Doze 待验收 |
| 配置 pull 与验签 | Loom CLI 已实现 | signed current、generation floor、snapshot 签名、节点 bundle 哈希与 current/previous 验证缓存已适配；缓存会在 hydrate 前完整复验并激活通过预检的候选 | signed current 镜像选择、防回退、完整签名链重放与 candidate/current/previous 事务已实现 |
| Agent 调参 | Go Agent 已实现 | 已接入候选链、决策 scope、探测预算与 selector | Stage 3 已接入签名候选计划、预算轮测、阈值阻尼、三态约束与 selector 原子切换；真机受管配置验收待完成 |
| 安全存储 | 0600 本地文件 | Installed 使用 machine-scope DPAPI 与安装器创建的受限 ACL；Portable 身份、vault 与候选使用用户范围 DPAPI；未另加 CNG 存储 | 不可导出 Keystore P-256 身份与 AES-GCM 应用私有存储已实现 |
| 安装与升级 | 已有签名 `tar.gz`、校验与安装器；后续版本仍走 signed pull | 双架构 ZIP/MSI 已实现；可配置 SignTool 验签构建，正式签名需要实际证书 | Linux 可重复构建 debug APK；私有发布签名与覆盖升级演练属于 Stage 4 |
| 加入网络/二维码 | 中控与 Linux CLI 已实现 | 三个 edition 已接入原生 GUI、二维码/加入文件解析和安全绑定；Installed 普通用户托盘经受限 IPC 加入 | 中控 Android Device、二维码/加入文件、CSR 身份绑定与崩溃恢复已实现；正式环境真机待验收 |
| 可信运行态上报 | `/status` 拉取与 gossip 已实现 | 现有两签 producer 已通过原生与实机上报 204、健康/故障和停止后 stale 验收 | Keystore 外部签名的 canonical v5 + self-check v1 producer 已实现；服务端纵向测试为 204，生产真机待验收 |
| 设备吊销 | access-only 支持单步直接移除/吊销，也保留 signed decommission；服务器职责的依赖迁移未完成 | 中控可直接撤销 access-only 身份与专属凭据；不远程删除 Windows 本机文件 | access-only 中控身份/凭据吊销沿用统一事务；真机撤权与旧缓存收敛待 Stage 4 验收 |

当前渲染器已按显式部署目标拆开平台无关配置与 Linux 生命周期产物：参考矩阵中的
`phone` 和 `workstation` 只生成各自平台路径正确的 sing-box 配置，不再携带 systemd、
Linux Agent、Linux report 或 `/etc/loom` 内容；Linux Server 保持原有产物。Windows
Installed 的 MSI/普通用户 IPC 和现有 v5 两签上报已实现，并在 amd64 实机完成最小闭环；
Windows Agent 调参与 Android Stage 3 selector 已进入代码。当前无实际 Authenticode
证书的 Windows 构建及无固定升级签名密钥的 Android 构建都不是正式分发包。

Windows C3 已开始：`internal/clientcore` 实现严格的 Direct / Auto / 指定出口偏好、
授权变更和撤权后 fail-closed，并以平台原子替换保存非秘密偏好；`internal/clientupdate`
复用现有 signed current 协议，先持久化 generation floor，再验证 snapshot 签名、设备
绑定与 bundle 哈希，最后原子推进 current/previous 验证缓存。`clients/windows` 提供
不依赖 `cmd/loom` 的 Windows Service/三版原生 GUI，可交叉编译 amd64 与 arm64；
导入中控为既有 Device 生成的二维码后会执行周期 pull，尚未加入网络时明确保持 disconnected。
`internal/clientsecret` 已实现 DPAPI machine scope、禁用 UI、用途绑定 entropy 的 vault
与加密候选；`internal/clientruntime` 每次 hydrate 前重放本地完整签名链，只接受唯一的
Windows sing-box 配置，严格检查秘密齐备、无 Linux 路径、TUN/mixed 共用路由规则、
selector/detour 引用、fail-closed、回环控制端点和对应 edition 的受管 CA 路径，再原子提交
current/previous 候选。三个 Windows edition 已在成功 pull 后接入这条链路。二维码导入
会在内部把身份、vault、CA、release anchor、pull 坐标和随发行包携带的数据面槽作为一次
事务提交，不再要求用户运行注册命令或选择组件。当前已钉住并验证官方 sing-box/Wintun
输入，实现平台签名组件包、immutable current/previous 槽、Wintun Authenticode、真实
`sing-box check` 和 Windows Job Object
监督边界；宿主已调用 `sing-box run` 并实现启动失败/运行期崩溃的进程内恢复。端到端
可信健康、跨重启持久回滚、named pipe、MSI、ProgramData ACL 与 Loom 代码
签名仍未接入。进程 Running、bundle 验签成功、候选
已提交或组件已选择都不能解释成 VPN 已连接。

当前生产 Linux 已收敛为 `127.0.0.1:1080` 一个中控托管的 mixed 入口，1081–1083
不再监听。固定 SG/DE 由中控的 Service 选择对应声明，不再由客户端选端口。
底层模型、校验、sing-box 渲染和中控只读视图已经支持在同一 managed mixed/TUN
上复用设备 `default_declaration`；它只处理 Auto 模式下未命中 Service 的流量，
不是客户端顶层三模式。
Windows 的三个宿主已接入原生 GUI、签名 pull、数据面和 Agent 计划；Android
宿主、正式入网链与三态 selector 已接线。参考矩阵中的 Windows 形状已经收敛为 TUN + 同规则的
`127.0.0.1:1080` managed mixed。生产 Linux 端口原语义仍必须保留或显式
下线，不能把既有端口静默改成另一条规则。
中控已经提供需要运维会话的 `default_declaration` 查询/写入 API，并以 revision
保护 SSOT 原子更新；但它只修改 Auto 下未命中 Service 时的 catch-all，与客户端
本地 Direct / Auto / 指定出口三态无关。Windows 已实现共享 selector 和受保护的本地偏好
存储，三个 Windows GUI 已展示连接状态；Android 保存并应用签名计划约束下的本机
三态偏好。两者都不应调用该运维接口。
当前结构化 Service 与数据面只实现 exact hostname 和 `.suffix`；本文后续的 Windows
IP/CIDR 与 Android package matcher 是 v1 目标，尚未进入 SSOT 模型、校验或渲染，
不能把原型中尚未接线的页面当成已交付能力。

---

## 3. 目标与非目标

### 3.1 目标

1. 中控先创建 Device；用户启动客户端并导入该 Device 的短时二维码即可加入网络，不经邮件或 IM 传明文配置。
2. 客户端只接受平台签名且未回退到低代次的配置。
3. 控制中心不可用时，客户端继续使用最后一份已验证配置转发流量。
4. 同一份访问声明在不同平台保持相同的授权、候选和 fallback 语义。
5. 设备可被单独吊销，不依赖删除其他设备共享的配置。
6. 平台适配失败时显式阻断安装，不把 Linux 产物伪装成 Windows/Android 包。
7. Auto 模式统一经过中控 matcher → Service → `AccessDeclaration`，各平台只按
   系统能力呈现接入面，不另建本地策略模型。
8. 设备提供 Direct、Auto、指定出口三个顶层模式；指定出口可选择任一在役
   `egress_capable` 节点，且只固定最后一跳。

### 3.2 非目标

- 不自行实现代理协议、TLS、WireGuard 或 Android VPN 网络栈。
- 不 fork sing-box 来承载 Loom 控制逻辑。
- 不让客户端获得完整 SSOT、其他设备凭据或无权访问的服务清单。
- 不让移动端加入常驻 WireGuard/Headscale mesh。
- 不依赖控制中心在线参与数据转发。
- 不承诺连接建立后的无损路径迁移；切换只影响新连接。
- 不允许 Windows/Android 客户端本地新增或修改 matcher、Service、声明定义或
  fallback；客户端只能切换三种顶层模式，并在指定出口模式选择已下发节点。
- v1 不提供同一域名按账号选择不同固定出口的 profile。L4/TUN 看不到账号身份，
  该能力需要显式 profile、SDK 或 L7 代理，留待后续版本另行决策。

---

## 4. 客户端共同不变量

### 4.1 数据平面只有一个实现

所有平台都使用受版本约束的 sing-box 核心。Loom 负责生成候选、授权和路由规则，
客户端宿主负责启动、停止与观察核心。平台 UI 不能自己维护第二份路由判断。
Windows 与 Android UI 中的规则、Service、声明定义和当前路径均为只读；连接、
断开、重连和诊断属于生命周期操作。唯一的本地路由偏好是 Direct / Auto / 指定出口
三模式；客户端可以离线切换，但只能使用签名配置已经授权的规则、出口和凭据，不能
形成第二份 matcher、Policy 或候选模型。

### 4.2 配置与秘密分离

签名配置包只包含 `${secret:...}` 引用。设备加入网络后取得的凭据只进入本机安全
存储，安装前在本机合并。控制中心静态分发树和普通缓存节点不得出现明文秘密。

### 4.3 签名高于传输信任

HTTPS 保护传输，平台签名证明内容。客户端必须验证：

- 平台签名；
- 设备/节点绑定；
- 配置包内容哈希；
- deployment generation 与本地 floor；
- 客户端能够理解的 schema 和最低版本；
- 本设备确实在该快照中拥有配置。

下载点可以被替换或缓存，但不能使客户端接受被篡改、属于别人的或已回退的配置。

### 4.4 离线继续运行

网络失败、控制中心停机或更新校验失败时，不删除当前工作配置。客户端继续运行
最后一次成功安装的版本，并把“控制面不可达”与“数据面不可用”分开显示。

### 4.5 fail closed

未知 schema、凭据缺失、签名失败和声明候选集为空都必须明确失败。Auto 模式完全
服从中控规则，未匹配 Service 时按中控配置的 fallback 处理。任何错误都不得自动
切换到 Direct 或指定出口；Direct 只在用户明确选择时启用。

### 4.6 顶层路由模式是唯一可写偏好

三个模式共用同一个 TUN/mixed 入口，不增加模式专用端口：

```text
Direct          → 全部本地直连，不生成 Loom 服务器路径
Auto            → Host → Service → Policy → Agent 自动选择完整路径
指定出口(node)  → 全部接管的业务流量最终从 node 出口；Agent 自动选择到 node 的前置路径
```

指定出口列表直接来自 SSOT 中全部在役 `egress_capable` 节点，不显示任意 IP 输入框。
固定出口只钉住服务器轴的最后一跳，不得关闭 Agent 对前置中继的完整路径探测与择优。
Current Paths 始终是只读观测，不是这三个模式的选择器。

签名配置包必须携带本设备获授权的出口节点与对应候选材料。客户端只在受保护的本地
偏好中原子保存模式（指定出口时再保存节点 ID），并切换本机 selector；控制面离线时
仍可依据最后一份已验证配置切换。偏好可以随状态上报供观察，但不是 SSOT 期望态，
无需为每次切换触发全网发布。若后续配置撤掉当前固定出口的授权，客户端保持选择可见、
明确标为不可用并 fail closed，不静默改成 Direct 或 Auto。

### 4.7 当前服务端接口与本地三模式的边界

当前中控实现的是运维端点：

```text
GET /api/control/default-exit?node=<node_id>
PUT /api/control/default-exit
Content-Type: application/json

{"node":"win01","declaration":"de-fixed","revision":"<sha256>"}
```

GET 返回 `node`、当前 SSOT `revision`、当前默认策略和授权选项。每个选项只有
`id/name/mode/available`，不返回凭据、候选链、节点 IP 或完整拓扑；`id=""`、
`mode="none"` 表示未匹配即阻断。PUT 只接受 GET 返回且 `available=true` 的策略，
旧 revision 返回 HTTP 409，未知字段、任意节点/IP 或无权策略均被拒绝。成功写入
`access.default_declaration` 后，仍由现有发布器生成签名快照。

该接口是现有 catch-all 编辑器，不是客户端三模式接口：它没有 Direct 状态，也不能
表达“Auto 完全服从中控规则”和“全部接管业务流量固定最终出口”的顶层互斥关系。
三态不需要新增 SSOT 字段或写 API；UI 不得把现有接口包装成三模式后端。

端点只接受中控的 SameSite 运维会话，并要求 JSON PUT；当前没有 CORS，也不接受
数据面凭据充当控制面身份。Windows/Android 客户端不得保存运维 cookie 或调用它。

---

## 5. 总体架构

```text
                         Loom 控制中心
                ┌─────────────────────────┐
                │ 加入二维码 / 设备身份    │
                │ 签名配置 / generation   │
                │ 排名与可信观测           │
                │ 吊销与凭据轮换           │
                └────────────┬────────────┘
                             │ HTTPS
                signed bundle│ 目标增强：mTLS
                             ▼
        ┌──────────────── 客户端公共逻辑 ────────────────┐
        │ 加入 · pull · 验签 · 防回退 · secret hydrate  │
        │ 配置预检 · selector 控制 · 状态 · 最后可用版本 │
        └───────────┬─────────────┬─────────────┬────────┘
                    │             │             │
             Windows Service   systemd     Android VpnService
                    └─────────────┴─────────────┘
                                  │
                             sing-box 核心
                                  │
                         Loom 服务器链 → 目标
```

公共逻辑优先从现有 Go 包中提取，而不是在 Kotlin、Windows UI 与 CLI 中分别重写
验签、generation、候选和配置语义。平台无法直接复用 Go 运行时时，可通过稳定的
本地库边界或窄协议复用；不得复制一份行为略有差异的验证器。

---

## 6. 客户端组件边界

| 组件 | 职责 | 不负责 |
|---|---|---|
| 平台宿主 | 权限申请、前后台生命周期、服务启停、通知 | 候选生成、授权判断与本地策略编辑 |
| 配置客户端 | current 获取、快照下载、验签、防回退、原子安装；保存并应用本地三态偏好 | 数据转发、编辑中控规则或 Current Paths |
| 安全存储 | 设备私钥、客户端证书、凭据、API secret | SSOT 存储 |
| sing-box 核心 | TUN/mixed、DNS、出站协议、selector | 设备加入和应用更新 |
| 调度适配 | 使用已下发候选、测量、阻尼切换、保存最后排名 | 扩大候选集 |
| 状态与观测 | 当前版本、连接状态、有限 L4 指标、问题摘要 | 上传访问内容 |

客户端收到的是本设备最小配置，不是完整拓扑。服务器地址、候选 tag 和必要的
服务匹配可以出现；其他设备、平台密钥私有部分和无关声明不得出现。

---

## 7. 流量接管方式

### 7.1 TUN

TUN 适合无法逐个配置代理的应用，承担系统流量兜底。它需要系统权限，并必须排除：

- 客户端自身的控制面连接；
- sing-box 到第一跳服务器的连接；
- 本地回环与必要的局域网流量；
- 平台要求不能进入 VPN 的系统流量。

这里的“局域网排除”只是在避免 TUN 递归或破坏本机连接，不等于发布或访问远端
局域网。后者必须显式选择目标地址域，并受独立授权约束，见
[Local Network 专题](local-network.md)。

错误的 TUN 路由可能造成控制连接递归或设备失联，因此新配置必须先离线预检，
启动失败时恢复上一个工作配置。

### 7.2 mixed

mixed 同时提供本地 HTTP 与 SOCKS5 入口，适合浏览器、开发工具、CI、容器和
systemd 服务显式接入。v1 日常只提供 `127.0.0.1:1080` 一个遵循中控规则的 mixed
入口；Windows 的 mixed 与 TUN 使用同一份 matcher → Service → `AccessDeclaration`
映射，Android 不提供 mixed。

Linux Server 默认只使用 mixed，避免改默认路由后锁死 SSH。应用使用
`socks5h://127.0.0.1:1080`，让代理端解析域名，避免本地 DNS 结果使出口判断失真。
HTTP 代理仍可复用同一个 mixed 监听。

旧“端口绑定声明”只在 Linux 作为命名明确、默认仅回环监听的兼容/高级覆盖保留，
用于迁移已有脚本或临时 CLI 强制出口。它仍受目标授权、候选集与 fail-closed 约束，
不得扩权，也不得出现在 Service 页面的主流程中。Windows/Android 不渲染或编辑
这类覆盖；生产既有端口迁移必须显式完成，不能静默复用端口号改变含义。

### 7.3 Windows Portable 与安装版

Portable 与 TUN/mixed 是两个维度：Portable 表示不通过 MSI 注册持久服务，TUN/mixed
表示流量接管方式。产品和测试说明必须使用完整名称，不能只写“Portable”让用户猜测
是否需要管理员权限或是否会修改系统网络。

| 运行形态 | 接管范围 | 管理员权限 | 系统改动 | 推荐用途 |
|---|---|---|---|---|
| **Portable Mixed** | 仅显式使用本机 HTTP/SOCKS 代理的应用 | 不需要 | 不创建虚拟网卡、不改系统路由 | 默认开发模式、浏览器、IDE、CLI |
| **Portable TUN** | 纳入 TUN 路由的系统 TCP/UDP/DNS 流量 | 导入二维码不需要；当前预览启用 TUN 前要求以管理员身份重启 | 加载 Wintun、创建虚拟网卡并修改路由；退出必须恢复 | 不支持代理的应用、UDP/QUIC、全局接管测试 |
| **安装版** | TUN 主接管 + 同规则 mixed | MSI 安装需管理员；日常 UI、导入和连接不需要 | MSI 注册 Service、创建受限 ProgramData ACL；普通用户经本机管道操作 | 常规 Windows 客户端 |

Portable TUN 只是“不装 MSI、不注册常驻 Service”，不是“零安装痕迹”或“普通用户 TUN”。
若启动失败、进程崩溃或电脑关机，下一次启动必须识别并清理遗留适配器/路由，再决定是否
恢复 previous。由于 Portable 文件通常位于用户可写目录，提权进程不得直接信任相邻 DLL：
必须重放 Loom 包签名与哈希校验、验证 Wintun Authenticode、限制 DLL 搜索路径，并从受
保护的运行槽启动。

Portable 状态默认放在 `%LocalAppData%\LoomPortable`，凭据使用用户范围 DPAPI；正式
安装版使用 `%ProgramData%\Loom`、机器范围 DPAPI 和受限 ACL。Portable ZIP 目录本身只
是运输载体，不是秘密存储。两种 Portable 形态与安装版都复用相同签名配置和 Direct /
Auto / 指定出口语义。Mixed 不保证覆盖未配置代理的应用、应用自带 DNS 或全部 UDP；
需要这些能力时才选择 TUN。

当前构建脚本会生成 `installed`、`portable-mixed`、`portable-tun` 三种内嵌身份（各含
amd64/arm64），并为每个 edition 生成一个完整 ZIP。ZIP 内包含 edition 对应的 EXE、
固定名称 `windows-dataplane.zip`、`PREVIEW-NOTICE.txt` 和静态链接依赖的许可证；客户端自动定位并验签组件，
不接受用户提供的组件路径。六个 ZIP 全部构建和验证成功后才进入发布阶段，并最后更新
`windows-clients-SHA256SUMS`；该清单是整组构建的提交标记，消费者必须据此拒绝中断造成的
部分发布。Windows 上另用 WiX 构建双架构 MSI，独立验证输入 ZIP 清单后最后发布 MSI
清单。构建默认输出未签名预览包；显式配置证书时先签 EXE 再打包，并独立签名 MSI。
要求正式签名的构建缺证书或时间戳就失败，不把预览包标成已签名发行。

三个构建复用同一套原生 GUI 和加入核心。Installed 普通用户界面经受限本机 named pipe
调用 SCM 服务，服务持有 machine-scope DPAPI 身份并运行现有加入/更新/数据面状态机。
MSI 将操作用户固定为安装时的 Windows 用户；管道只允许该用户和管理员，拒绝远程访问。
UI 在发送二维码凭据前核对管道服务 PID 与 SCM 注册记录。IPC 只接受状态查询、本地
连接配置的添加/选择/重命名、加入、连接、断开、签名配置已授权的出口偏好和本地删除；
配置操作使用有界标识和名称，由服务解析受保护目录，不接受任意路径、命令或配置正文。
产品状态机是：`未加入网络 → 导入二维码 → 正在加入 → 已加入 → 连接`。
二维码 PNG 与 `.loom-invite` 文件是同一次加入的等价输入；导入不会创建第二个 Device。
原生 Win32 GUI 使用“左侧连接配置列表、右侧选中配置详情与主动作”布局。侧栏加号将
右侧内容区切换为加入表单，左侧列表保留并暂时禁用；先提供二维码 PNG 或 `.loom-invite`
邀请并填写本地名称，校验后再提交加入，不因打开或取消表单而留下空配置。表单保留
与首页一致的一层白色内容卡片，不叠加居中模态框；卡片内部直接排列名称输入、邀请
说明与文件选择、粘贴按钮，不再嵌套上传卡片。
加入请求已经提交后的 pending 身份与恢复资料仍受
DPAPI 保护，失败时可继续重试，不能为了隐藏草稿而丢弃已经领取的身份。加入成功后
保持未连接，点击“连接”才接管流量。列表单击只改变查看对象；双击名称在原位置编辑，
Enter 保存、Esc 取消，也支持 F2 或右键重命名；不再常驻名称输入框和“保存名称”按钮。
名称只在本机保存，重命名不重启连接；实际连接另有状态标记。连接另一配置时，
先完整停止并等待原配置宿主退出，再启动新宿主，同一时间最多一个配置连接中或已连接。
每份配置独立保存 DPAPI 身份、签名候选、出口偏好和 Agent 证据；原单配置身份就地保留，
不迁移或重建身份。删除已断开的条目只清除该条目本地资料，不影响其他配置。
窗口标题栏、侧栏、状态与路径卡片使用统一的 Misaka 自绘外观，保留窗口拖动、缩放、
最小化、最大化和关闭语义。名称编辑与文件选择继续使用系统输入能力；支持选择或拖入
本地文件，不接受包含 bearer token 的进程参数。
尚未绑定的条目明确显示“未加入”，不能用本机名伪造 Device 或已连接网络。

状态文字左侧与列表条目都有对应图标：连接中为蓝色进度、已连接为绿色、断开中为灰色
进度、未连接为灰色、失败为红色；连接中允许取消。进度动画只刷新图标区域，同一份状态
轮询不重排或重绘整个窗口。连接后的“当前选路”按 Service 使用独立卡片，只读绘制
“本机 → 实际服务器链 → 服务目标”的路径图；节点数量与名称来自实际路径，目标地址
不成为服务器节点。展开详情显示完整路径的当前/最佳质量、健康、切换原因与读取时间，
不把单个服务的质量当成全局延迟，也不把服务器分段 RTT 标在图上冒充客户端测量。
Auto/固定出口复用当前共享 Agent 的
GET 读回投影，按签名 plan 映射 chain；Direct 同样 GET 验证授权零跳候选。界面后台至多
每五秒读取一次，不发探测、不写 selector、不增加报告。断开、出口切换或激活代次变化
清除旧路径，读取失败显示未知，缺测量不显示虚构的零值。该区域代表当前 selector 选择，
已有长连接可能仍沿用之前的路径。

通知区图标显示连接状态，关闭主窗口只收起到托盘，显式“退出 Loom”才停止当前前台
进程。Windows 的 EXE/Explorer、任务栏、窗口标题栏和通知区基础图标必须直接使用
`internal/webui/favicon.svg`；只允许从该 SVG 生成多种原生 ICO 尺寸，不得以重新绘制、
改色、反色、Windows 专用衍生图或 `loom-logo-v4.svg` 替换。已连接状态只允许在 favicon
右下角叠加 Windows 原生绿色盾牌，不改变底层 favicon。`assets/loom-logo-v4.svg` 仅用于
窗口左上角产品名旁的大尺寸品牌区。这是 Windows 客户端的固定资产规则，不以“小尺寸
优化”为理由更换图形。二维码
导入不启动 TUN、不改路由，也不要求管理员权限；Portable TUN 只在随后启用数据面前检查
管理员令牌，并由 GUI 在这个边界请求 UAC 重启。`config\client.json` 最后写入，作为普通启动可见的加入
完成标记；失败或 pending 时继续复用 DPAPI 保护的原身份，已加入状态拒绝被另一二维码
静默覆盖。发行物内嵌部署平台公钥；它是公开的发行验证信任锚，不是 Device 凭据、连接密钥
或中控地址。干净首启只等待二维码，不读取该公钥；导入或恢复加入事务时才加载它。提交一次性加入码前，客户端先完成组件签名/架构校验，
再把二维码携带的平台公钥 SHA-256 指纹与发行包内嵌公钥在本地比对，避免拿错部署包
后才消费加入码，也不为此增加另一条公网 API 或反向代理依赖。schema 1 registry 中尚未
消费的旧邀请在服务端升级时全部失效，不保留缺少该字段的旧二维码兼容路径。
当前 Portable 预览把二维码 pending 数据、ready 恢复日志和身份放在当前用户 DPAPI 下保护；
中控只允许同一 token、CSR、request ID、平台和 Device facts 在一小时恢复窗口内重放，
下次启动可继续，`config\client.json` 提交后立即清除 pending token。Installed 经 Service
使用 machine-scope DPAPI 与 `%ProgramData%\Loom`；安装器将目录设为 SYSTEM/管理员独占。
服务启动时检查目录所有者、ACL、重解析点和硬链接，拒绝将用户可写的旧预览状态当成可信机器状态。
全局进程锁阻止两个 Windows GUI 同时运行或两个数据面争抢端口/TUN，最终完成标记使用
create-only 提交；数据面锁覆盖整个 joined workload，不在子进程更新切换间释放。

Portable Mixed 已完成原生二维码解析、身份绑定、signed first pull、回环监听与干净停止。
Windows amd64 已验证 Portable TUN 三轮启停后的网卡/路由/监听清理、宿主崩溃后的子进程
退出与签名状态恢复，以及 Installed 的 MSI 安装、普通用户 GUI 加入、授权出口切换和
连接/断开；机器凭据对普通用户不可读。健康报告复用既有两签协议，停止后由中控显示 stale。
MSI 卸载保留受保护身份以供重装；主动删除身份使用已断开的客户端入口。
签名构建流程已经接好；正式 Authenticode 签名需要实际证书。ARM64 实机及不同物理网卡、
显示器组合仍需各自验收，交叉构建不能替代实机证据。

---

## 8. 平台设计

### 8.1 Linux Server

Linux 服务器是第一优先级，也是当前实现最接近完整的客户端形态。

**部署形态：**

- `loom` 静态二进制；
- sing-box 固定版本；
- `loom-pull.timer`、`loom-agent.service`、`loom-report.service`；
- 一个中控托管的 `127.0.0.1:1080` mixed 日常入口，不创建 TUN；
- 可选的 Linux 兼容/高级覆盖入口，仅用于既有脚本迁移或显式 CLI 强制出口；
- 配置位于 `/etc/loom`，运行状态位于 `/var/lib/loom`；
- 秘密文件 root 所有、0600。

应用通过环境变量、显式 SOCKS/HTTP 参数、容器环境或 systemd drop-in 接入。安装
工具不应自动修改全局 `HTTP_PROXY`，因为这会影响包管理、控制通道和无关服务。

Direct / Auto / 指定出口共用 `socks5h://127.0.0.1:1080`，不新增端口。指定出口
可以是任一在役 `egress_capable` 节点，但前置路径仍由 Agent 自动择优。

**交付物：** Linux 统一交付已实现为可校验的 `tar.gz`，包含 Loom、钉住版本的
sing-box、manifest、文件哈希与安装器。节点专属 systemd unit 不固化在通用包中，
而是在加入完成后的首份签名 bundle 中通过现有事务安装。当前没有 deb/rpm 或通用
卸载器，Linux 也不开发独立客户端 GUI。具体操作见
[Linux 客户端安装](linux-client-install.md)。

### 8.2 Windows

Windows 不需要新的网络核心，但需要平台宿主：

**功能原型（定义布局与交互，不作为窗口逐像素实现）：**
[Windows 客户端首页 v2](../assets/client/windows/loom-client-home-misaka-v2.svg) 与
[重命名、添加和连接状态 v2](../assets/client/windows/loom-client-interactions-misaka-v2.svg)。
浅色 Misaka 外观采用紧凑配置侧栏、36 DIP 自绘标题栏、连接摘要和当前选路面板；各服务
在同一白色面板内逐行展示，用贯穿面板的细线分隔，测量标在对应连线上。交互沿用首页完整窗口、侧栏和单层白色
内容卡片：重命名只增加条目内编辑框，添加在右侧卡片直接排列表单，不嵌套上传面板；
连接中只更新原摘要状态。三个 edition
共用布局，以实际运行方式显示系统 TUN 或本地代理状态。原型中的 `demo-*` 身份与路径
与连线数值只用于说明结构，均为合成示例；[v1](../assets/client/windows/loom-client-home-misaka-v1.svg)
保留为早期视觉参考，当前交互与分段测量显示以 v2 为准。
窗口标题和托盘提示统一为 `Loom (Portable TUN) 已连接 · demo-work`，随版本、
连接状态和名称更新；有连接正在运行时显示实际连接，未连接时显示当前查看的配置。
展开详情时按链路分组，标题 12 DIP、正文 11 DIP，时间与诊断信息另行排列。每个服务按
自身内容计算行高，不共享最长行高；当前选路右侧不再显示用途提示。详见
[选路详情原型](../assets/client/windows/loom-client-route-details-misaka-v2.svg)。
出口列表打开时，滚轮在列表内浏览候选；移到右侧页面滚动时取消未确认的选择并收起列表，
不会切换出口。页面滚动直接批量平移控件，不重算详情行高；背景和子控件一并刷新。

- v1 目标态由 Windows Service 以受控权限运行配置客户端和 sing-box；
- 托盘程序只调用本机受限控制接口，显示状态、启停和当前路径；
- 首次启动若尚未加入网络，前台界面显示“导入二维码”；该动作绑定中控中已经创建的 Device；
- 连接信息只展示选中配置的加入状态、设备身份、操作系统与证书/配置状态，不是远端节点管理；
- TUN 用于系统流量主接管，`127.0.0.1:1080` mixed 用于明确设置代理的开发工具；
  两者使用同一份签名配置和同一个顶层路由模式；
- matcher、Service、声明定义和 fallback 只读展示；用户只可在签名配置给出的列表中
  选择 Direct / Auto / 指定出口，指定出口列表只含全部在役 `egress_capable` 节点；
- Current Paths 按 Service 只读展示实际读回路径，不提供节点点选、路径选择或 Apply；
- 设备密钥和凭据使用 DPAPI/CNG 保护；
- Portable 的配置与状态放入 `%LocalAppData%\LoomPortable`；Installed 目标态放入带受限
  ACL 的 `%ProgramData%\Loom`，都不写入用户下载目录；
- 安装器负责服务注册、TUN 驱动依赖、卸载与恢复；
- 程序和安装器必须经过 Windows 代码签名。

v1 目标产品形态是 Windows Service + TUN + 一个同规则 mixed；托盘 UI 可以后补。若
实现阶段先交付 mixed-only 预览，必须明确标注“非全局接管”，且不能宣称 v1 已完成
或设备已完全受 Loom 管理。

Windows 睡眠或网络切换后应重新探测，但沿用切换阻尼，不能把一次 Wi-Fi 重连当作
配置失效。服务升级与配置更新是两条流程：配置走 Loom 签名快照；程序升级走签名
安装包并保留可恢复版本。

**实现栈（三版 GUI 与 Installed MSI/IPC 已建立，正式签名依赖实际证书）：**

- 新增依赖收敛的纯 Go Windows 客户端入口，不把包含发布器、SSH 接入和 Linux
  生命周期的 `cmd/loom` 整体搬到 Windows；
- 后台使用 Windows Service，平台适配通过 `golang.org/x/sys/windows/svc` 和带
  `windows` build tag 的窄实现完成；
- 三个 edition 使用纯 Go 调用 Win32 自绘窗口和路径图，复用系统输入、字体与文件选择
  能力；直接复用共享加入和运行状态机，不依赖 WebView2、.NET、Node、外部字体或额外
  GUI 运行时。品牌图形使用规定的既有资产，其他图标用简单矢量绘制；静止状态不启动
  连续渲染循环，状态变化与动画只使必要区域失效，保持小体积与低空闲开销；
- 高权限 Service 持有设备密钥、配置与 sing-box 生命周期，普通用户 UI 只通过带
  Windows ACL 的本机 named pipe 读取状态和执行已定义操作；
- 数据平面使用钉住版本的 sing-box Windows 制品和官方签名 Wintun，不自行构建或
  分发同名驱动；
- 设备密钥与凭据使用 DPAPI/CNG，安装器使用 WiX/MSI，发布制品由 Windows SDK
  SignTool 做 Authenticode 签名和验证。

**当前 Linux 开发环境的边界：** 可以开发共享 Go 核心、三模式本地 selector、
签名 pull/回滚状态机和本地控制协议，也可以为这些纯 Go 组件做 Windows 交叉编译。
现有 `cmd/loom` 是包含接入、发布和 Linux Agent 的全量控制程序，仍依赖 `flock`、
`O_NOFOLLOW`、`Stat_t` 等 Unix 接口，不能直接作为 Windows 客户端交叉编译；Windows
实现应新增依赖收敛的独立程序入口，而不是把全量控制端搬过去。实测
`GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/loom` 会在这些 Unix 接口
处失败；安装 MinGW 不能修复错误的程序边界。纯 Go Service 与嵌入式页面不要求
.NET、MinGW 或 Node；本机目前也没有这些工具、Windows SDK、WiX 或代码签名工具。
合理流程是 Linux/WSL 完成共享核心、独立 Windows 入口和单元测试，再直接在 Windows
实体宿主完成 GUI、Service、TUN/Wintun、睡眠恢复、安装器和签名验证。

### 8.3 Android

Android 必须提供应用宿主，因为只有应用可以通过 `VpnService` 接管其他 App
流量并满足前台服务生命周期要求。

**界面原型：** [Android 客户端首页](../assets/client/android/loom-client-home-misaka-v1.svg)

Android App 包含：

- 加入网络二维码扫描与 `.loom-invite` 文件导入；
- Android Keystore 中的设备密钥；
- 配置 pull、平台验签、防回退和最后可用配置；
- sing-box Android 核心；
- `VpnService` 与常驻通知；
- 当前路径、连接状态、有限诊断与手动重连；
- 最小调度适配：读取候选/排名、执行切换、离线沿用、回传 L4 观测。
- 中控下发的 package/domain/IP matcher、Service 与声明关系；界面只读展示生效
  结果；用户只能选择 Direct / Auto / 指定出口三种顶层模式。

**实现栈（Stage 3 已进入代码，生产真机入网与移动可靠性验收待后续阶段）：**

- Kotlin + Gradle Kotlin DSL 作为平台宿主，Jetpack Compose 负责原生 UI；
- Android `VpnService` 建立系统 TUN，并按平台要求运行前台 Service 与常驻通知；
- 使用钉住版本的 sing-box `libbox.aar` 承担 TUN 和代理数据平面，不复制协议实现，
  也不把上游客户端的 profile/规则编辑模型带入 Loom；
- 将平台无关的 Loom 验签、generation floor、最后可用配置和 selector 状态机抽成窄
  Go 包；确需在 Android 复用时再评估通过 `gomobile bind` 生成独立 AAR，不为共享代码
  先引入整套绑定，也不在 Kotlin 中另写一套行为略有差异的验证器；
- 设备身份密钥进入 Android Keystore；应用私有目录只保存签名配置、状态和不能放进
  Keystore 的最小材料；
- Emulator 用于 Compose、加入网络、权限和基本 TUN 流程，真实 Android 设备负责扫码、
  移动网络/Wi-Fi 切换、Doze、厂商后台限制、重启和长期运行验证。

2026-09-07 已在 Linux x86_64 服务器完成原生宿主、Stage 2 正式入网和 Stage 3 选路代码：固定包名的
Kotlin / Compose 工程、二维码/加入文件、Android Keystore P-256 身份与 AES-GCM 私有存储、
支持平台外部签名器的共享 Go 核心，以及一次 `gomobile bind` 生成的 sing-box `1.11.4` +
Loom core 单运行时 AAR。客户端先校验二维码中的平台公钥指纹，再提交同一 Keystore key
绑定的 CSR；signed pull 先持久化 generation floor，再完整重放 current/manifest/bundle
签名链，候选只有在 libbox 启动及真实 DNS/HTTPS 探测通过后才提交，否则恢复 previous。
可信上报复用 canonical v5 与 self-check v1，并由 Keystore 对共享核心准备的原文签名。
同一签名 bundle 还携带数据型移动调度计划；共享 Go 核心校验它与 sing-box selector、
候选顺序、显式链和探测用户完全一致，并执行计划作用域隔离、候选预算轮换、窗口聚合与
切换阈值。Kotlin 宿主只负责生命周期、Keystore 加密状态和已认证的回环 selector 事务。

中控已能创建 access-only Android Device，生成不夹带 Linux 安装说明的二维码/加入文件，
配置 Android TUN-only SSOT，并按精确 bundle 引用返回秘密；服务端纵向测试覆盖 claim pending
与幂等 replay、ready、签名配置和可信报告 204。API 35 x86_64 Emulator 覆盖正式标识与三态
入口、Keystore、签名 fixture、DNS/HTTPS 穿过 TUN、断开释放和再次连接。上述是仓库和
Emulator 证据；未部署的中控代码、开发签名 APK 或模拟器 204 不能冒充生产手机已经入网。
Direct / Auto / 指定出口会保存本机偏好并驱动 selector；生产受管配置下的故障切换与
Wi-Fi/蜂窝、Doze、进程回收仍需 Stage 4 真机验收。

Android 不安装 Linux 版 Loom Agent、systemd unit、`/etc/loom` 路径或 Loom
二进制自更新器。应用更新通过应用商店、企业 MDM 或签名 APK 渠道完成；Loom 只
更新配置和排名。

Android 同时只能有一个活动 `VpnService`。因此它不加入 Tailscale/Headscale
mesh；需要访问 mesh 内网时，由被授权的 Loom 服务器代为转发。Auto 模式由中控
规则按 package、domain 或 IP 匹配 Service；Direct 与指定出口是互斥的顶层覆盖。
相同 package 内同一域名的多账号无法由 L4/TUN 可靠区分，profile 能力不进入 v1。

### 8.4 开发、构建与验证环境

“能在某个系统生成制品”不等于“已经验证该平台语义”。平台无关逻辑尽量在 Linux
和 CI 中测试，操作系统生命周期、权限、驱动和安装事务必须在对应系统运行。

| 工作 | Linux / CI | Windows 实体机或 VM | Android Emulator | Android 真机 |
|---|---|---|---|---|
| 共享 Go 核心、配置验签与 selector 单测 | 主环境 | 可复测 | 通过 AAR 间接验证 | 最终复测 |
| Windows Service 未签名 `.exe` | 可交叉编译 | 安装与运行验证 | — | — |
| Windows Portable 原生 GUI | 可交叉编译 | 文件选择、窗口生命周期与 DPI 布局已验证 | — | — |
| Windows DPAPI、签名组件包、Wintun 与可执行预检 | 可交叉编译、验证 Loom 包签名和 PE/build identity | DPAPI、WinVerifyTrust、真实 `sing-box check` 与 Job Object 已验证 | — | — |
| Windows TUN 激活、CNG、MSI 与 Loom 代码签名 | 只能准备共享逻辑和输入 | 必须完成管理员权限、驱动/路由恢复、安装和签名终验 | — | — |
| Android APK/AAB | 可无界面构建 | Android Studio 开发最方便 | UI/权限/基本 VPN | 移动网络与生命周期终验 |

2026-09-03 已通过 WSL interoperability 直接在 Windows x64 宿主运行交叉编译的测试
程序：真实 DPAPI machine/user-scope 加解密、用途错绑/密文篡改拒绝、Windows `MoveFileEx`
原子替换、signed update/cache、使用真实 DPAPI 的 hydrate/candidate 链路，以及 Service
handler 的 start → disconnected → stop 生命周期均通过。随后用一次性提权事务将 PE
临时注册为 Manual SCM 服务，以 LocalSystem 完成 Running → Stopped，再删除服务和受
保护 DACL 暂存目录；原有 preference 的哈希与时间未变。另一个一次性 SYSTEM 任务成功
解密并校验由普通用户创建的 machine-scope vault，证明跨服务账号恢复成立，也证明 DPAPI
不能替代文件 ACL。之后又在同一宿主完成官方 sing-box/Wintun 输入钉住、平台签名组件
包、immutable 槽、Wintun WinVerifyTrust、真实 `sing-box check` 和 Job Object 终止核验。
随后又用临时 HTTPS 控制端点完成 Windows 二维码加入、用户 DPAPI 身份/vault、
signed first pull、无 TUN 的 Portable Mixed `sing-box run`，跨过启动宽限期后干净停止；
没有创建 TUN 或修改路由。临时服务、任务与 fixture 均在核验后删除。持久/开机 SCM、
最终 ProgramData DACL、真实 TUN 激活与清理、端到端健康/跨重启回滚、MSI 与 Loom 代码
签名仍需继续终验。

**推荐工作站：** 有真实 Windows 机器时，在 Windows 上 clone 同一仓库，用它同时
承担 Windows 原生客户端、Android Studio 和 Android Emulator。Windows 只构建明确
的客户端目标；当前含 Unix API 的全量 `cmd/loom` 与全仓后台测试继续在 Linux、WSL2
或 CI 运行。不要为两个平台复制 SSOT、matcher、Policy 或 selector 模型。

目标代码边界已经开始建立，并保持到构建系统无需猜平台：

```text
clients/windows/       Windows Service、薄 UI 外壳与安装器
clients/android/       Kotlin/Compose、VpnService 与 Android 打包
internal/clientcore/   两个平台复用的平台无关 Go 核心
```

Android Emulator 本身就是专用虚拟机。它应直接运行在 Windows 实体机的系统虚拟化
上，或直接运行在独立 Linux builder 的 KVM 上；不要把它放进 Windows VM 再做嵌套
虚拟化。嵌套方案会增加性能、USB/相机和网络语义的不确定性，却不能替代真机测试。

**控制设备不是默认客户端开发机。** 是否能运行 Windows VM 或 Android Emulator，
由部署者在本地根据 CPU 虚拟化、`/dev/kvm`、内存、磁盘和当前负载核对；这些现网
硬件信息属于部署状态，不写入版本库。控制面承担生产职责时，不应默认再承载桌面 VM
或 Emulator。

确需在独立 Linux builder 建一台临时 Windows 开发 VM 时，最小栈为 QEMU/KVM + Q35
+ OVMF UEFI + swtpm 2.0 + qcow2。初期使用 QEMU user-mode NAT，安装画面和 RDP 只
绑定 `127.0.0.1` 并经 SSH 转发；不要先引入 libvirt bridge 去改动已有 Docker、
WireGuard 和 nftables。Windows 介质只能使用用户提供的合法 ISO 或微软正式
Evaluation ISO。该 VM 足以做 Service、UI、安装器与基本 TUN 集成，但真实睡眠、
Wi-Fi/有线切换和长期桌面行为仍由实体 Windows 终验。

若没有 Windows 工作站、只需 Android CI，则在**独立** Linux builder 安装 OpenJDK、
Android command-line tools、SDK、platform-tools、Emulator 和 x86_64 system image，
直接使用 KVM 跑 headless Emulator；只有自行重建 native AAR 时才增加 NDK。不安装
Android-x86 通用 VM。无界面 APK 可以在独立 builder 构建；生产控制设备不作为日常
Android Studio 或 Emulator 工作站。

---

## 9. 加入网络与设备身份

### 9.1 加入码与交付方式

管理员先在控制中心创建 Device，直接选择平台、Responsibilities、Destination grants
以及 `forward` 所需的 direction。客户端仍按自身构建目标报告平台，中控要求它与邀请
精确一致；客户端不能在 claim 时选择或扩张职责。加入码不携带运行时路由模式或手选出口
参数；加入完成后再由客户端选择 Direct / Auto / 指定出口。加入载体内容包含：

- 控制中心地址；
- 短 TTL、单次使用的随机 token；
- 过期时间和协议 schema。

纯 `use_loom` 创建成功后页面呈现二维码图片、备用 `.loom-invite` 加入文件和同一份
可复制的 `loom://enroll#…` 内部协议 URI。包含 `forward` 的 Linux Device 不提供二维码或
加入文件，只把该 URI 作为本地 shell 或管理员 SSH 登录目标机后执行同一 bootstrap 的
一次性标准输入；中控不保存 SSH 凭据。Windows
Portable 还可在中控页面复制二维码图片后直接按 `Ctrl+V` 或点击“粘贴二维码”；图片只在
内存中解析，不写临时文件。这三种 access-only 载体
共享 TTL 与单次消费状态；原始 token 只在创建结果中出现，列表不能再次取回。URI 的
fragment 由客户端本地解析，token 只在内部 claim POST body 发送，不进入 HTTPS query。
它们不包含长期凭据、完整平台公钥或设备私钥。设备绑定不得依赖浏览器指纹，必须基于客户
端本地生成且不可导出的非对称密钥。

加入入口的 TLS 验收必须在受支持的 Android 真机系统信任库上执行，不能只用服务器侧
OpenSSL/curl 判定。服务端必须发送能一直构建到目标系统已有根证书的完整兼容链；例如
Let’s Encrypt Generation Y 的默认 ECDSA 链应继续经交叉签名构建到 ISRG Root X1，不能只
发送终止于部分设备尚未信任的 ISRG Root X2 的短链。客户端不得通过跳过主机名、证书或
系统时间校验来兼容错误链；部署时须按 CA 当前公布的 Chains of Trust 核对完整链。

### 9.2 加入流程

```text
管理员在中控创建 Device 和一次性加入码
    ↓
客户端导入 access-only QR/文件，或在 Linux 本地/SSH 会话执行 shell bootstrap
    ↓
设备在安全存储中生成 P-256 私钥，只上传签名有效的 PKCS#10 CSR
    ↓
控制中心校验平台和 CSR，原子消费加入码并绑定既有 device_id / platform / canonical SPKI 指纹
    ↓
先预置秘密、提交同一 SSOT，并等待现有 publisher 确认精确版本
    ↓
返回节点证书、CA、平台公钥、release authority、节点秘密与分发坐标
    ↓
客户端执行现有 signed pull，验签、hydrate、预检并原子安装
    ↓
客户端上报首份可信状态后，才可由运行态观测判定 online
```

Device 详情页的 Runtime evidence 只展示经过现有信任链验证的运行问题原文；未签名或
身份校验失败的客户端自述不能作为该问题详情。

加入网络不是单独的“注册客户端”流程，也不是日常连接动作。二维码导入只绑定中控中
已经创建的 Device，不创建第二条记录。重连、网络切换、更新配置、更新程序和重新启动都
继续使用现有设备身份，不得再次要求二维码。首次 POST 前，Windows 在本地比较二维码中的
部署公钥指纹与发行包内嵌公钥。加入码一旦成功绑定，中控只允许同一 token、同一 CSR、
同一 request ID、平台和 Device facts 在限定的一小时恢复窗口内幂等重试；当前 Windows
Portable 预览将这组 pending 数据用当前用户 DPAPI 保护，并在加入提交后清除 token。
Installed 经受限 Service broker 使用 machine-scope/受保护 ProgramData。其他 CSR 身份重复消费、未知/不受支持的平台、设备 ID
已被另一身份绑定、SSOT revision 冲突或签名验证失败都不得留下部分加入状态。
加入码在成功绑定前过期时，详情页可重新生成加入码，旧码立即失效；纯 `use_loom`
Device 可显示二维码，包含 `forward` 的 Linux Device 只提供 shell/SSH 辅助交付。若已加入的纯
`use_loom` Device 丢失或删除了本机身份，管理员可在详情页确认后执行 Rejoin Device：
旧接入从 SSOT 移除，旧身份归档，新 ID 和新二维码沿用原名称、平台、职责与 grants。旧数据面凭据
随服务器应用签名配置撤销。该流程不复用已消费 token、不把新密钥绑定到旧 ID，也不
把本机删除解释为已完成远程停机。仍在 provisioning 的未完成身份及服务器职责的恢复
不走这一窄入口，须先处理其原事务。详见
[二维码重发与本机身份丢失](device-lifecycle-and-delivery.md#411-二维码重发与本机身份丢失)。

不需要替换时，详情页的 **Remove Device** 用一个中控事务移除纯 `use_loom` Device 的
SSOT membership 和专属数据面凭据，并立即把 enrollment identity 标为 revoked。它不要求
客户端在线或先消费 decommission，也不会声称已经清除客户端本机文件；旧连接在转发服务器
收敛到下一份 signed snapshot 后失效。包含 `forward` / `internet_egress` 的 Device 不走
该窄入口，因为删除前必须处理隧道、出口策略与依赖凭据。

### 9.3 稳态认证

首次加入使用客户端本地 P-256 密钥签发节点证书，供现有可信报告/陈述链使用；私钥
不进入中控。当前 pull 仍依赖 HTTPS 传输、独立平台签名和 generation 防回退，尚未
把客户端证书普遍接入 mTLS pull。无论后续是否启用 mTLS，客户端都必须验证平台签名
和 generation，不能把 TLS 当成配置内容签名的替代。

### 9.4 吊销

吊销设备需要同时产生两类结果：

1. 控制面拒绝该设备继续 pull 或上传；
2. 下一份服务器配置移除该设备凭据，阻止旧配置继续使用数据平面。

只做第一项不能阻止设备凭最后一份离线配置继续连服务器。吊销进入新签名快照，
传播完成前控制中心显示“吊销中”，不能提前显示完成。

---

## 10. 配置制品

### 10.1 两层制品

客户端包拆为平台无关期望态与平台安装层：

| 层 | 内容 | 是否跨平台 |
|---|---|---|
| common | 节点绑定、候选、声明、组件约束、签名/generation 元数据 | 是 |
| sing-box | 该设备的 inbounds、outbounds、route、DNS | 大部分可复用，需平台校验 |
| secrets map | 占位符到本机安全存储键的映射 | 语义复用，存储实现不同 |
| lifecycle | systemd / Windows Service / Android App profile | 否 |
| update policy | 最低客户端版本、兼容 schema、强制更新时间 | 语义复用，执行不同 |

同一 snapshot 可以含多个平台包，但每台设备只能下载并安装绑定给自己的包。

### 10.2 渲染目标必须显式

旧的 `desktop` 无法决定路径、服务管理器和安全存储，现已拆成不可含糊的部署目标：

```text
linux-server
windows-desktop
android
```

部署目标是输入事实，不是根据运行时猜测。校验器必须拒绝 Android + systemd、
Windows + `/etc/loom`、Linux server + TUN 等矛盾组合。

### 10.3 原子安装

所有平台都遵循同一事务语义：

```text
下载 → 验签/防回退 → secret hydrate → 平台预检
     → 写入新槽 → 启动验证 → 提交为 current
                          └失败→恢复 previous
```

配置文件不得在原路径上逐个覆盖。客户端至少保留 current 与 previous；失败日志
不得包含凭据明文。

---

## 11. 安全存储

| 平台 | 设备身份 | 访问凭据 | 配置状态 |
|---|---|---|---|
| Linux | root 0600 文件；有 TPM 时可增强 | root 0600 secrets 文件 | `/etc/loom` + `/var/lib/loom` |
| Windows Portable | 当前用户 DPAPI | 当前用户 DPAPI | `%LocalAppData%\LoomPortable` |
| Windows Installed（目标态） | CNG/DPAPI，优先机器范围不可导出密钥 | DPAPI machine scope | DPAPI candidate + ProgramData ACL |
| Android | Android Keystore，优先硬件支持 | Keystore 包装的应用私有存储 | app private storage |

日志、崩溃报告和持久 UI 状态都不得包含完整 token、私钥、密码或可直接导入的配置。
access-only 的加入二维码、截图、加入文件和剪贴板文本都携带同一个短时 bearer secret，
必须只交给目标设备，不得保存到相册、诊断导出、聊天记录或工单。诊断导出默认脱敏，
并由用户显式操作。

---

## 12. 配置更新与程序更新

配置更新和客户端程序更新不能混为一条通道。

| 平台 | 配置更新 | 程序更新 |
|---|---|---|
| Linux | Loom 签名 snapshot + pull/apply | Loom release/A-B 机制 |
| Windows | Loom 签名 snapshot | 代码签名安装包，服务级回滚 |
| Android | Loom 签名 profile/ranking | 商店、MDM 或同签名密钥 APK |

配置可以高频收敛；程序升级必须显式推进、验证兼容 schema 并控制爆炸半径。
Android 签名密钥是应用升级身份，必须备份和严格控制；丢失后不能把新 APK 当作
原应用升级。

---

## 13. 状态与观测

客户端 UI 至少区分以下状态：

- 应用/系统服务是否运行；
- TUN 或 mixed 是否已接管流量；
- 当前配置 snapshot 与 generation；
- 当前命中的只读规则、Service、声明和候选路径；
- 当前顶层路由模式；指定出口模式还显示目标节点及其在当前签名配置中的可用状态；
- 数据平面最近是否成功；
- 控制面最近是否成功 pull；
- 当前是否使用 previous/离线配置；
- 凭据是否临近过期或已被吊销。

“VPN 图标存在”不等于数据平面健康，“控制中心可达”也不等于用户流量可达。
健康结论必须包含至少一条代表性端到端探测。

客户端只上报调度与排障必要的 L4 信息：时间、候选、连接/握手结果、延迟、有限
吞吐和版本状态。默认不上传域名访问历史、URL、请求头、响应内容或应用清单。

---

## 14. 故障与恢复

| 故障 | 行为 |
|---|---|
| 控制中心不可达 | 继续 current，显示控制面离线 |
| 新配置签名失败 | 拒绝，不触碰 current |
| generation 回退 | 拒绝并产生安全事件 |
| hydrate 缺秘密 | 整包失败，不留下半成品 |
| sing-box 预检失败 | 不切换；保留 previous |
| TUN 启动后端到端失败 | 回滚 previous，必要时停 TUN 恢复系统网络 |
| 程序版本过旧读不懂 schema | 拒绝配置并提示升级客户端 |
| 设备被吊销 | 停止获取新配置；服务器侧凭据移除后数据面失败 |
| Android 被系统回收 | 按用户授权与系统规则恢复前台 VPN，不伪装成始终在线 |

Installed MSI 卸载停止并移除服务、程序和活动 TUN 路由；受限机器身份与操作用户记录
保留，重装继续使用同一 Device。主动清除身份须在客户端断开后确认“删除本机 Device”。
本机删除不等于中控吊销；需要重新加入时使用中控既有 Rejoin Device 流程生成替代身份与
二维码，不能手工修补 registry 或静默改绑。

Windows Portable 界面只在数据面已断开时启用“删除”操作，并二次确认后清除本机身份、
签名配置与运行状态；它不会伪装成中控吊销。操作者仍须在中控端下线并吊销原 Device。

---

## 15. 实施顺序

### 阶段 C0：拆分渲染目标（已完成，2026-09-02）

- 引入明确部署目标；
- 把 common/sing-box 与 lifecycle 产物分开；
- Android/Windows 包中禁止出现 systemd 和 Linux 路径；
- 为每个平台建立 golden 与矛盾配置校验。

**完成判据：** `phone` bundle 不再含 systemd、Linux Agent 和 `/etc/loom` 安装
假设；未知部署目标硬失败。参考矩阵与矛盾配置测试已覆盖 Android、Windows 和
Linux Server。

### 阶段 C1：固化 Linux 接入

- Linux Server 的加入、pull、一个 `1080` 日常 mixed、Agent、report、回滚形成安装流程；
- 将旧端口入口迁到命名明确的 Linux 兼容/高级覆盖，并验证不会扩权；
- 生成统一二进制分发包，并提供可重复安装和卸载路径；
- 不建设 Linux GUI 或托盘客户端。

**完成判据：** 新 Linux 设备从导入一次性加入码到首份可信在线状态无需手工复制秘密。

### 阶段 C2：设备加入与吊销（部分完成）

- 一次性加入码与二维码；
- 设备本地密钥生成；
- 设备绑定配置；
- 控制面和数据面双重吊销；
- 审计与过期处理。

**完成判据：** 被吊销设备即使保留旧配置，也在服务器收敛后无法继续使用。

**当前进度：** 加入码、二维码、本地 P-256 身份绑定，以及 access-only 的单步直接
移除/吊销和 Linux signed decommission → 移除/吊销 → 秘密清理/purge 已完成；服务器职责
和各移动端的通用控制面/数据面双重吊销尚未完成，因此 C2 不能整体标记为完成。Android
已接入同一 claim/ready 身份链，不再属于“尚无加入宿主”的缺口。

### 阶段 C3：Windows（进行中）

- 从 `cmd/loom` 拆出纯 Go `clientcore` 和独立 Windows 程序入口；
- Windows Service、路径和安全存储；
- 一个 mixed 首通，再完成 TUN；两种接入面渲染同一份中控规则；
- 客户端只读展示 matcher、Service、声明与路径，只提供 Direct / Auto / 指定出口；
- Portable 原生 GUI 直接读取用户态状态；Installed 托盘通过受限本机 IPC 读取 Service 状态；
- 签名安装器与 previous 恢复；
- Linux 交叉编译进入 CI，Windows VM/实体机完成安装、权限、驱动和签名验证。

已完成的前三个切面是纯 Go 三模式偏好状态机、Windows 原子偏好替换、独立 Service
handler，signed current → generation floor → snapshot 签名 → 节点 bundle 哈希的验证
下载与 current/previous 缓存，以及 DPAPI vault → 严格 secret hydrate → Windows 结构
预检 → DPAPI candidate current/previous 的候选提交。缓存消费者会重放完整本地信任链，
验证器拒绝错误签名、内容篡改、设备错绑、路径穿越、generation 回退、同代分叉、无可信
锚的高代首次接入和篡改后的缓存；候选预检还拒绝缺秘密、Linux 路径、公开监听、悬空
selector/detour/route 引用和非 fail-closed 配置。它能交叉编译为 amd64/arm64 PE。
组件链也已落地：控制端只接受代码内钉住 release/asset ID、ZIP SHA-256、版本和提交的
sing-box 1.11.4 与 Wintun 0.14.1 官方 ZIP，生成域隔离 Ed25519 签名包；Windows 端重验
清单、全部文件、PE 架构、sing-box Go build identity 和 Wintun Authenticode，再提交
immutable current/previous 槽，并只选择与签名 snapshot 版本相符的槽。真实 Windows x64
已执行 `sing-box check`、kill-on-close Job Object 终止试验，以及完整二维码解析 → 内部
身份绑定 → signed pull → TUN-free Mixed `run` → 停止事务。Installed 的普通用户托盘/IPC、
ProgramData ACL、MSI 升级/卸载/重装与身份保留，以及 amd64 真实 TUN 启停清理、宿主崩溃
恢复和健康上报已验收。ARM64 和不同物理环境仍需实测；无正式证书的制品保持预览标记。

**完成判据：** 睡眠、网络切换、服务重启和配置失败后都能恢复，卸载不残留活动
路由或服务。

### 阶段 C4：Android

- Kotlin/Compose `VpnService` 宿主与钉住版本的 sing-box libbox 集成；
- 二维码加入、Keystore、签名 pull；
- 最小排名/selector/离线能力；
- 按中控 package/domain/IP matcher 渲染规则，并提供 Direct / Auto / 指定出口；
- Emulator 覆盖 UI、权限和基本 TUN，真机覆盖前后台、网络切换与省电策略；
- 签名 APK 发布和升级演练。

前三项及候选配置离线缓存/恢复、可信健康上报已进入代码，并通过服务端纵向测试、
共享核心测试与 API 35 Emulator 基线；三态入口只使用签名候选，固定出口撤权会阻断，
Auto 已接入预算轮测、窗口和阈值。中控 package/IP matcher、生产受管配置真机故障切换、
真机前后台与 Wi-Fi/蜂窝切换、厂商省电限制、固定升级签名和覆盖升级仍未完成，不能把
开发签名 APK 或纯函数调度测试冒充为这些验收已经完成。

**完成判据：** 飞行模式、进程回收、重启、配置损坏和控制中心离线下均有可解释
状态，且不会泄露凭据或把系统网络留在不可用状态。

---

## 16. 测试矩阵

每个平台至少覆盖：

1. 首次加入、同一公钥幂等重试、其他公钥重复消费、过期加入码、未知平台，以及客户端
   拒绝安装部署目标不匹配的 bundle；
2. 正确签名、错误签名、内容篡改、generation 回退和未知 schema；
3. secret 缺失、凭据轮换与设备吊销；
4. current → candidate → previous 的原子安装与进程中断恢复；
5. 控制面离线但数据面继续工作；
6. TUN/mixed 的 DNS、IPv4、IPv6、局域网与回环行为；具名远端局域网另按
   [Local Network 专题](local-network.md)的显式作用域与 fail-closed 边界测试；
7. 睡眠、重启、网络切换、无网启动和系统时间异常；
8. 客户端旧版本配新配置、客户端新版本配旧配置；
9. 日志、诊断包、UI 和崩溃报告不含秘密；
10. 代表性真实目标端到端验证，而非只检查进程存活。
11. Windows 的 TUN 与 mixed 对相同请求应用相同顶层模式；Auto 模式命中相同
    Service/声明，Android matcher 与中控预览一致；除三态偏好外，本地新增规则或
    扩大出口集合必须被拒绝。
12. 多端口声明覆盖只在 Linux 兼容/高级模式出现，默认回环监听，且不能扩大目标
    授权或绕过 fail-closed。
13. Direct / Auto / 指定出口切换只复用现有入口；指定出口固定最后一跳但前置路径
    仍自动择优；控制面离线时可基于最后一份已验证配置切换，已撤权或非
    `egress_capable` 的固定出口必须 fail closed。
14. Current Paths 在所有模式下均为只读；任何路径选择或 Apply 控件都视为回归。

---

## 17. 尚需决定的问题

以下问题不阻塞 C0/C1，但必须在相应客户端开工前确定：

1. Windows 安装器与代码签名证书的持有、轮换和 CI 签名方式；
2. Android 分发使用应用商店、企业 MDM 还是私有签名 APK；
3. mTLS 何时进入客户端稳态通道，以及设备证书的签发和吊销格式；
4. 客户端规模是否仍是少量自建固定设备；若面向多用户，设备库存和授权关系不能
   继续全部塞进拓扑 SSOT，需要独立的设备/租户模型。
5. 三态本地偏好在系统升级、用户切换与配置回滚时的存储位置和恢复细节；它不是
   SSOT，也不复用 `default_declaration` 运维 API。

v1 已明确只提供 Direct / Auto / 指定出口这一项三态路由偏好，不提供 matcher、
Service、声明定义、fallback 或同域名多账号 profile 的本地编辑。若后续要引入这些
能力，必须新增模型、安全边界和决策记录，不能借用旧端口覆盖隐式实现。

在这些问题确定前，不启用会强迫所有平台 fork 客户端的自定义协议参数。

# Loom · 客户端接入设计

> **状态:** 设计生效；Linux 邀请、P-256 CSR 注册、节点预置与签名分发代码已实现，
> Windows/Android 宿主与设备吊销闭环待实现
>
> **日期:** 2026-08-30；开发与构建环境于 2026-08-31 核对
>
> **适用范围:** Windows、Linux Server 与 Android 接入设备；v1 不考虑 Linux Desktop
>
> **上位约束:** [设计文档](design.md)中的模型、安全边界与控制平面不变量仍是
> 当前实现的事实来源；统一 Device、Enrollment 和版本化对象图的迁移目标见
> [Device 生命周期与交付架构](device-lifecycle-and-delivery.md)，本文只展开平台客户端交付。
> 具名局域网访问是尚未实现的独立目标态，
> 见 [Local Network 专题](local-network.md)。若专题与设计文档冲突，以设计文档为准。

---

## 1. 结论

客户端不应实现三套独立网络栈。三类平台共用 sing-box 数据平面、Loom 的签名
配置格式、设备身份和调度语义，只为操作系统生命周期做薄适配。

| 平台 | 流量接管 | 客户端形态 | 结论 |
|---|---|---|---|
| Windows 桌面 | TUN 主接管 + 同规则的本地 `1080` mixed | Windows Service；托盘 UI 可分阶段交付 | 需要薄客户端；规则由中控下发 |
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

当前代码已经把接入方式分成 `android`、`desktop` 与 `linux-server`，并能按平台
生成 TUN 或 mixed inbound。Linux 侧已有中控 Clients 列表、一次性邀请、真实二维码
与邀请文件、可复制的 `loom://` URI、签名 `tar.gz` 分发包，以及从本地 P-256 CSR
到 SSOT 自动发布、ready bootstrap 和首次 signed pull 的安装闭环。是否已经部署到
生产应以[当前状态](status/current.md)为准，不能用仓库代码状态代替上线核验。

这不等于 Windows 和 Android 客户端已经可用：

| 能力 | Linux | Windows | Android |
|---|---|---|---|
| sing-box 配置渲染 | 已实现 | 配置形状部分可复用 | 已能生成 TUN 配置 |
| 系统生命周期 | systemd 已实现 | 未实现 Windows Service | 未实现 `VpnService` 宿主 |
| 配置 pull 与验签 | Loom CLI 已实现 | 未适配 | 未适配 |
| Agent 调参 | Go Agent 已实现 | 未适配服务与路径 | 设计要求内嵌最小能力，未实现 |
| 安全存储 | 0600 本地文件 | 未接 DPAPI/CNG | 未接 Android Keystore |
| 安装与升级 | 已有签名 `tar.gz`、校验与安装器；后续版本仍走 signed pull | 无安装器和代码签名流程 | 无 APK/商店发布流程 |
| 一次性注册/二维码 | 中控与 Linux CLI 已实现 | 客户端宿主未实现 | 客户端宿主未实现 |
| 设备吊销 | 未实现控制面与数据面双重收敛 | 未实现 | 未实现 |

当前渲染器会无条件给接入节点生成 systemd、`/etc/loom` 路径、Loom Agent 和
上报者。参考矩阵中的 `phone` 因此也带有 Linux unit。它只是验证候选与 sing-box
配置形状的 golden，不是可安装的 Android 制品。客户端实现前必须先拆开平台无关
配置与平台安装产物。

当前生产 Linux 已收敛为 `127.0.0.1:1080` 一个中控托管的 mixed 入口，1081–1083
不再监听。固定 SG/DE 由中控的 Service 选择对应声明，不再由客户端选端口。
底层模型、校验、sing-box 渲染和中控只读视图已经支持在同一 managed mixed/TUN
上复用设备 `default_declaration`；它只处理 Auto 模式下未命中 Service 的流量，
不是客户端顶层三模式。
Windows/Android 客户端与对应渲染迁移尚未完成；后续迁移仍必须保留旧端口原语义
或显式下线，不能把既有端口静默改成另一条规则。
中控已经提供需要运维会话的 `default_declaration` 查询/写入 API，并以 revision
保护 SSOT 原子更新；但它只修改 Auto 下未命中 Service 时的 catch-all，与客户端
本地 Direct / Auto / 指定出口三态无关。三态仍需客户端 selector、受保护的本地偏好
存储和状态展示；Windows/Android 客户端目前尚未实现这些能力，也不应调用该运维接口。
当前结构化 Service 与数据面只实现 exact hostname 和 `.suffix`；本文后续的 Windows
IP/CIDR 与 Android package matcher 是 v1 目标，尚未进入 SSOT 模型、校验或渲染，
不能把界面原型当成已交付能力。

---

## 3. 目标与非目标

### 3.1 目标

1. 用户通过一次短时注册动作完成设备接入，不经邮件或 IM 传明文配置。
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

签名配置包只包含 `${secret:...}` 引用。设备注册后取得的凭据只进入本机安全
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
                │ 注册邀请 / 设备身份      │
                │ 签名配置 / generation   │
                │ 排名与可信观测           │
                │ 吊销与凭据轮换           │
                └────────────┬────────────┘
                             │ HTTPS
                signed bundle│ 目标增强：mTLS
                             ▼
        ┌──────────────── 客户端公共逻辑 ────────────────┐
        │ 注册 · pull · 验签 · 防回退 · secret hydrate  │
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
| sing-box 核心 | TUN/mixed、DNS、出站协议、selector | 设备注册和应用更新 |
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
而是在注册完成后的首份签名 bundle 中通过现有事务安装。当前没有 deb/rpm 或通用
卸载器，Linux 也不开发独立客户端 GUI。具体操作见
[Linux 客户端安装](linux-client-install.md)。

### 8.2 Windows

Windows 不需要新的网络核心，但需要平台宿主：

**界面原型：** [Windows 客户端首页](../assets/client/windows/loom-client-home-misaka-v1.svg)

- Windows Service 以受控权限运行配置客户端和 sing-box；
- 托盘程序只调用本机受限控制接口，显示状态、启停和当前路径；
- `This PC` 页面只展示本机注册身份、操作系统与证书/配置状态，不是远端节点管理；
- TUN 用于系统流量主接管，`127.0.0.1:1080` mixed 用于明确设置代理的开发工具；
  两者使用同一份签名配置和同一个顶层路由模式；
- matcher、Service、声明定义和 fallback 只读展示；用户只可在签名配置给出的列表中
  选择 Direct / Auto / 指定出口，指定出口列表只含全部在役 `egress_capable` 节点；
- Current Paths 只读展示 Agent 当前结果，不提供路径选择或 Apply；
- 设备密钥和凭据使用 DPAPI/CNG 保护；
- 配置与状态放入 ProgramData，不写入用户下载目录；
- 安装器负责服务注册、TUN 驱动依赖、卸载与恢复；
- 程序和安装器必须经过 Windows 代码签名。

v1 产品形态是 Windows Service + TUN + 一个同规则 mixed；托盘 UI 可以后补。若
实现阶段先交付 mixed-only 预览，必须明确标注“非全局接管”，且不能宣称 v1 已完成
或设备已完全受 Loom 管理。

Windows 睡眠或网络切换后应重新探测，但沿用切换阻尼，不能把一次 Wi-Fi 重连当作
配置失效。服务升级与配置更新是两条流程：配置走 Loom 签名快照；程序升级走签名
安装包并保留可恢复版本。

**目标实现栈（尚未交付）：**

- 新增依赖收敛的纯 Go Windows 客户端入口，不把包含发布器、SSH 接入和 Linux
  生命周期的 `cmd/loom` 整体搬到 Windows；
- 后台使用 Windows Service，平台适配通过 `golang.org/x/sys/windows/svc` 和带
  `windows` build tag 的窄实现完成；
- 页面内容沿用当前控制中心的 HTML/CSS 与少量 JavaScript，由 Go `embed` 打入程序；
  UI 阶段优先使用薄 WebView2/托盘外壳，不再用 WPF/WinUI 重写一份界面和状态模型；
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
合理流程是 Linux 完成共享核心、页面、独立 Windows 入口和单元测试，再由 Windows
VM/实体机完成 Service、WebView2、TUN/Wintun、睡眠恢复、安装器和签名验证。

### 8.3 Android

Android 必须提供应用宿主，因为只有应用可以通过 `VpnService` 接管其他 App
流量并满足前台服务生命周期要求。

**界面原型：** [Android 客户端首页](../assets/client/android/loom-client-home-misaka-v1.svg)

Android App 包含：

- 注册二维码扫描与 `.loom-invite` 文件导入；
- Android Keystore 中的设备密钥；
- 配置 pull、平台验签、防回退和最后可用配置；
- sing-box Android 核心；
- `VpnService` 与常驻通知；
- 当前路径、连接状态、有限诊断与手动重连；
- 最小调度适配：读取候选/排名、执行切换、离线沿用、回传 L4 观测。
- 中控下发的 package/domain/IP matcher、Service 与声明关系；界面只读展示生效
  结果；用户只能选择 Direct / Auto / 指定出口三种顶层模式。

**目标实现栈（尚未交付）：**

- Kotlin + Gradle Kotlin DSL 作为平台宿主，Jetpack Compose 负责原生 UI；
- Android `VpnService` 建立系统 TUN，并按平台要求运行前台 Service 与常驻通知；
- 使用钉住版本的 sing-box `libbox.aar` 承担 TUN 和代理数据平面，不复制协议实现，
  也不把上游客户端的 profile/规则编辑模型带入 Loom；
- 将平台无关的 Loom 验签、generation floor、最后可用配置和 selector 状态机抽成窄
  Go 包；确需在 Android 复用时再评估通过 `gomobile bind` 生成独立 AAR，不为共享代码
  先引入整套绑定，也不在 Kotlin 中另写一套行为略有差异的验证器；
- 设备身份密钥进入 Android Keystore；应用私有目录只保存签名配置、状态和不能放进
  Keystore 的最小材料；
- Emulator 用于 Compose、注册、权限和基本 TUN 流程，真实 Android 设备负责扫码、
  移动网络/Wi-Fi 切换、Doze、厂商后台限制、重启和长期运行验证。

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
| Windows 页面 HTML/CSS/交互 | 可完整开发和浏览器测试 | WebView2、托盘、DPI 验证 | — | — |
| Windows TUN、DPAPI/CNG、MSI 与签名 | 只能准备输入 | 必须完成；签名也可在 Windows CI 完成 | — | — |
| Android APK/AAB | 可无界面构建 | Android Studio 开发最方便 | UI/权限/基本 VPN | 移动网络与生命周期终验 |

**推荐工作站：** 有真实 Windows 机器时，在 Windows 上 clone 同一仓库，用它同时
承担 Windows 原生客户端、Android Studio 和 Android Emulator。Windows 只构建明确
的客户端目标；当前含 Unix API 的全量 `cmd/loom` 与全仓后台测试继续在 Linux、WSL2
或 CI 运行。不要为两个平台复制 SSOT、matcher、Policy 或 selector 模型。

目标代码边界（尚未创建）应清晰到构建系统无需猜平台：

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

## 9. 设备注册

### 9.1 注册邀请

管理员在控制中心为设备和获授权中控规则范围创建通用注册邀请，不要求填写平台。
平台由已安装客户端按自身构建目标报告；中控只校验它是受支持的枚举值并完成绑定，
用于选择正确的部署目标和安装产物，不把它当作授权条件或人工选项。注册邀请本身不
携带路由模式或出口参数；注册完成后再由客户端选择 Direct / Auto / 指定出口。
邀请包含：

- 控制中心地址；
- 短 TTL、单次使用的随机 token；
- 过期时间和协议 schema。

创建成功后页面同时呈现一个二维码和同一份可复制的 `loom://enroll#…` URI，不按
Windows、Android、Linux 拆成三个注册入口。点击二维码直接下载包含同一 URI 的
`.loom-invite` 文件，供没有扫码入口的桌面或 Linux 服务器导入。二维码、URI 和邀请
文件只是同一次邀请的三种载体，共享 TTL 与单次消费状态；原始 token 只在创建结果
中出现，列表不能再次取回。URI 的 fragment 由客户端本地解析，token 随注册 POST
body 发送，不进入 HTTPS query。它们不包含长期凭据、平台信任根或设备私钥；分发包
仍须使用带外获得的平台公钥验证。邀请不得通过“浏览器指纹”绑定设备；设备绑定必须
基于客户端本地生成且不可导出的非对称密钥。

### 9.2 注册流程

```text
管理员创建邀请
    ↓
客户端展示控制中心与申请权限，用户确认
    ↓
设备在安全存储中生成 P-256 私钥，只上传签名有效的 PKCS#10 CSR
    ↓
控制中心校验平台和 CSR，原子消费邀请并绑定 device_id / platform / canonical SPKI 指纹
    ↓
先预置秘密、提交同一 SSOT，并等待现有 publisher 确认精确版本
    ↓
返回节点证书、CA、平台公钥、release authority、节点秘密与分发坐标
    ↓
客户端执行现有 signed pull，验签、hydrate、预检并原子安装
    ↓
客户端上报首份可信状态后，才可由运行态观测判定 online
```

注册不是日常连接动作：重连、网络切换、更新配置、更新程序和重新启动都继续使用
现有设备身份，不得要求重新注册。同一邀请、同一 CSR 身份与 request ID 的重试必须幂等，
以便从传输中断或发布失败处继续；其他 CSR 身份重复消费、未知/不受支持的平台、设备 ID
已被另一身份绑定、SSOT revision 冲突或签名验证失败都不得留下部分注册状态。
只有邀请在成功绑定前过期、设备身份密钥丢失/重置，或设备已被吊销后重新接入时，
才需要管理员生成新的邀请。

### 9.3 稳态认证

注册已使用客户端本地 P-256 密钥签发节点证书，供现有可信报告/陈述链使用；私钥
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

当前 `desktop` 同时覆盖不同桌面操作系统，无法决定路径、服务管理器和安全存储。
实现客户端前，模型必须增加不可含糊的部署目标，例如：

```text
linux-server
linux-desktop
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
| Windows | CNG/DPAPI，优先机器范围不可导出密钥 | DPAPI machine scope | ProgramData ACL |
| Android | Android Keystore，优先硬件支持 | Keystore 包装的应用私有存储 | app private storage |

日志、崩溃报告和持久 UI 状态都不得包含完整 token、私钥、密码或可直接导入的配置。
邀请二维码、二维码截图、邀请文件和剪贴板文本本身都携带同一个短时 bearer secret，
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

卸载默认移除服务、TUN/驱动配置和本机运行状态。是否删除设备身份与凭据需要用户
明确确认；删除后不可恢复，只能由管理员生成新邀请重新接入。

---

## 15. 实施顺序

### 阶段 C0：拆分渲染目标

- 引入明确部署目标；
- 把 common/sing-box 与 lifecycle 产物分开；
- Android/Windows 包中禁止出现 systemd 和 Linux 路径；
- 为每个平台建立 golden 与矛盾配置校验。

**完成判据：** `phone` bundle 不再含 systemd、Linux Agent 和 `/etc/loom` 安装
假设；未知部署目标硬失败。

### 阶段 C1：固化 Linux 接入

- Linux Server 的注册、pull、一个 `1080` 日常 mixed、Agent、report、回滚形成安装流程；
- 将旧端口入口迁到命名明确的 Linux 兼容/高级覆盖，并验证不会扩权；
- 生成统一二进制分发包，并提供可重复安装和卸载路径；
- 不建设 Linux GUI 或托盘客户端。

**完成判据：** 新 Linux 设备从一次注册到首份可信在线状态无需手工复制秘密。

### 阶段 C2：设备注册与吊销

- 一次性邀请与二维码；
- 设备本地密钥生成；
- 设备绑定配置；
- 控制面和数据面双重吊销；
- 审计与过期处理。

**完成判据：** 被吊销设备即使保留旧配置，也在服务器收敛后无法继续使用。

### 阶段 C3：Windows

- 从 `cmd/loom` 拆出纯 Go `clientcore` 和独立 Windows 程序入口；
- Windows Service、路径和安全存储；
- 一个 mixed 首通，再完成 TUN；两种接入面渲染同一份中控规则；
- 客户端只读展示 matcher、Service、声明与路径，只提供 Direct / Auto / 指定出口；
- HTML/CSS 页面与薄 WebView2/托盘外壳通过受限本机 IPC 读取 Service 状态；
- 签名安装器与 previous 恢复；
- Linux 交叉编译进入 CI，Windows VM/实体机完成安装、权限、驱动和签名验证。

**完成判据：** 睡眠、网络切换、服务重启和配置失败后都能恢复，卸载不残留活动
路由或服务。

### 阶段 C4：Android

- Kotlin/Compose `VpnService` 宿主与钉住版本的 sing-box libbox 集成；
- 二维码注册、Keystore、签名 pull；
- 最小排名/selector/离线能力；
- 按中控 package/domain/IP matcher 渲染规则，并提供 Direct / Auto / 指定出口；
- Emulator 覆盖 UI、权限和基本 TUN，真机覆盖前后台、网络切换与省电策略；
- 签名 APK 发布和升级演练。

**完成判据：** 飞行模式、进程回收、重启、配置损坏和控制中心离线下均有可解释
状态，且不会泄露凭据或把系统网络留在不可用状态。

---

## 16. 测试矩阵

每个平台至少覆盖：

1. 首次注册、同一公钥幂等重试、其他公钥重复消费、过期邀请、未知平台，以及客户端
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

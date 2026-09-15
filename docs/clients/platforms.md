# 客户端规范 · 平台宿主与开发环境

[客户端规范入口](README.md) · [文档地图](../README.md) · [源码能力](../development/implementation.md)

**规范状态：已批准的客户端契约。** 本文负责 平台宿主与开发环境；标为 v1 的内容仅适用于迁移输入，
v2 认证、对象与事务以[控制面规范](../protocols/control-plane/README.md)的对应条款定义。
平台运行情况由验收回执确认，正文不记录部署进度。

## 平台设计

### Linux Server

Linux Server 是交付优先的无 GUI 客户端形态；它与 Windows/Android 遵守同一
签名、授权、floor 和 certified 门禁。源码接线及具体缺口见[实现对照](../development/implementation.md)。

**v1 兼容部署形态：**

- `loom` 静态二进制；
- sing-box 固定版本；
- `loom-pull.timer`、`loom-agent.service`、`loom-report.service`；
- 一个由控制平面配置的 `127.0.0.1:1080` mixed 日常入口，不创建 TUN；
- 可选的 Linux 兼容/高级覆盖入口，仅用于既有脚本迁移或显式 CLI 强制出口；
- 配置位于 `/etc/loom`，运行状态位于 `/var/lib/loom`；
- 秘密文件 root 所有、0600。

应用通过环境变量、显式 SOCKS/HTTP 参数、容器环境或 systemd drop-in 接入。安装
工具不应自动修改全局 `HTTP_PROXY`，因为这会影响包管理、控制通道和无关服务。

Direct / Auto / 指定出口共用 `socks5h://127.0.0.1:1080`，不新增端口。指定出口
可以是任一在役 `egress_capable` 节点，但前置路径仍由 Agent 自动择优。

**v1 交付契约：** Linux 使用可校验的 `tar.gz`，包含 Loom、钉住版本的
sing-box、manifest、文件哈希与安装器。节点专属 systemd unit 不固化在通用包中，
而是在加入完成后的首份签名 bundle 中通过事务安装。v1 不要求 deb/rpm、通用
卸载器或独立客户端 GUI。实际制品状态由发布回执确认，操作见
[Linux v1 兼容安装](../operations/linux-v1-install.md)。

**v2 职责运行面：** 由 certified Device view 决定 `use_loom`、`forward`、`internet_egress`
及允许组合，`internet_egress` 蕴含 `forward`。其中 `use_loom` 同时提供签名规则下的 TUN 与
mixed，真实承载 TCP/UDP、IPv4/IPv6 与 DNS；只承担 forward 的 Device 不因“Linux 客户端”
这个发行名称而自动接管本机流量。永久 control/L3 overlay 按已认证逐边 LinkIntent 建立，
control 能力只来自 ControlSet，不由安装参数授予。

v1 的 mixed-only、“不创建 TUN”和旧 systemd 列表不能套到 v2。v2 的安装、私有配置/报告、
运行和恢复命令见[Linux 安装与运行](linux-install.md)；Linux Agent 仍使用自身候选预算，
不移植 Windows/Android 的网络代 registry。两版均复用既有身份及对应可信状态，
按[迁移完成条件](../protocols/control-plane/migration.md)完成替换后删除对应旧业务入口。

### Windows

Windows 不需要新的网络核心，但需要平台宿主：

**功能原型（定义布局与交互，不作为窗口逐像素实现）：**
[Windows 客户端首页 v2](../../assets/client/windows/loom-client-home-misaka-v2.svg) 与
[重命名、添加和连接状态 v2](../../assets/client/windows/loom-client-interactions-misaka-v2.svg)。
浅色 Misaka 外观采用紧凑配置侧栏、36 DIP 自绘标题栏、连接摘要和当前选路面板；各服务
在同一白色面板内逐行展示，用贯穿面板的细线分隔，测量标在对应连线上。交互沿用首页完整窗口、侧栏和单层白色
内容卡片：重命名只增加条目内编辑框，添加在右侧卡片直接排列表单，不嵌套上传面板；
连接中只更新原摘要状态。三个 edition
共用布局，以实际运行方式显示系统 TUN 或本地代理状态。原型中的 `demo-*` 身份与路径
与连线数值只用于说明结构，均为合成示例；[v1](../../assets/client/windows/loom-client-home-misaka-v1.svg)
保留为早期视觉参考，v2 原型定义交互与分段测量展示契约。
窗口标题和托盘提示统一为 `Loom (Portable TUN) 已连接 · demo-work`，随版本、
连接状态和名称更新；有连接正在运行时显示实际连接，未连接时显示当前查看的配置。
展开详情时按链路分组，标题 12 DIP、正文 11 DIP，时间与诊断信息另行排列。每个服务按
自身内容计算行高，不共享最长行高；当前选路右侧不再显示用途提示。详见
[选路详情原型](../../assets/client/windows/loom-client-route-details-misaka-v2.svg)。
出口列表打开时，滚轮在列表内浏览候选；移到右侧页面滚动时取消未确认的选择并收起列表，
不会切换出口。页面滚动直接批量平移控件，不重算详情行高；背景和子控件一并刷新。

- v1 产品契约由 Windows Service 以受控权限运行配置客户端和 sing-box；
- 托盘程序只调用本机受限控制接口，显示状态、启停和当前路径；
- 首次启动若尚未加入网络，前台界面显示“导入二维码”；该动作绑定控制平面已经创建的 Device；
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

v1 产品形态是 Windows Service + TUN + 一个同规则 mixed。若某发行只提供
mixed-only 预览，必须明确标注“非全局接管”，且不能宣称 v1 已完成
或设备已完全受 Loom 管理。

Windows 按 OS 报告维护底层网络代；睡眠恢复、Agent 重启或 profile 切换本身不能重置
[入口预算](observations.md#客户端消费边界)，网络重连也不表示已验证配置失效。
服务升级与配置更新是两条流程：配置走 Loom 签名快照，程序走签名安装包并保留可恢复版本。

**实现约束：**

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

**Linux/CI 开发边界：** 共享 Go 核心、三模式本地 selector、签名
pull/回滚状态机和本地控制协议可在 Linux/CI 验证，并通过依赖收敛的
Windows 专用入口交叉编译。包含发布、SSH、Linux Agent 和 Unix API 的全量
`cmd/loom` 不是 Windows 客户端构建目标；安装 MinGW 不能修正错误的程序边界。
GUI、Service、TUN/Wintun、睡眠恢复、安装器和 Authenticode 必须在 Windows
宿主终验；工具配置及已取得结果按[部署证据](../operations/local-deployment.md)核对。

### Android

Android 必须提供应用宿主，因为只有应用可以通过 `VpnService` 接管其他 App
流量并满足前台服务生命周期要求。

**界面目标设计：** 基于已安装版保留三个底部 Tab，分别提供
[连接](../../assets/client/android/connection.svg)、[配置](../../assets/client/android/configuration.svg)、
[诊断](../../assets/client/android/diagnostics.svg) 单屏 SVG；顶部图案为透明底纯黑。
连接页沿用状态卡和路径卡，用图标与连线展开实际选路详情；配置页扩展多配置管理并保留流量模式；
诊断页沿用网络与信任信息。选择使用原生底部面板，条目操作使用菜单，改名和删除使用原生对话框。

选中配置只切换查看，不自动连接；所有状态、更新与修改绑定相应身份。切换连接先停止原宿主，
同一时间只有一个 `VpnService`。新加入保持未连接，恢复事务沿用原身份；身份、配置、偏好与
防回退状态按配置隔离，入口 probe registry 按设备底层网络代共享，迁移保留已有身份。
原生宿主使用加密配置目录与各配置独立的 Keystore alias；原配置原位迁移。
安装与真机结果记录在[验收回执](../operations/local-deployment.md)中，原型不能代替运行验证。

**APK 交付：** 每次影响安装包的改动默认同步构建 Debug 与已签名 Release，默认下载为
`app-release.apk`；真机为保留已有签名和数据安装 Debug 时，仍须交付 Release 并明确安装变体。
执行入口与完成判定见 [Android 构建与交付规程](android-delivery.md)。

Android App 包含：

- 加入网络二维码扫描与 `.loom-invite` 文件导入；
- 静态 distribution bundle 验证、从当前 Android 网络对实际 HY2/TCP bootstrap
  入口做一次并行测量、短期 capability 隧道与私有 Enrollment；
- Android Keystore 中的设备密钥；
- 配置 pull、平台验签、防回退和最后可用配置；
- sing-box Android 核心；
- `VpnService` 与常驻通知；
- 当前路径、连接状态、有限诊断与手动重连；
- 目标界面保留 Android 连接 / 配置 / 诊断三页，在原卡片内补充路径详情和多配置管理；
- Auto 逐服务展示实际路径；FixedExit 展示一条统一上网路径；Direct 展示本机直连；
- 详细信息原位展开逐段证据、来源、时间与决策说明；未连接或读取失败不沿用旧路径；
- 各 Tab 独立纵向滚动，底部导航固定，触摸区域至少 48 dp，窄屏和大字体按内容换行或纵排；
- 最小调度适配：按[客户端消费规范](observations.md#客户端消费边界)使用入口与
  服务器证据，实际 selector 读回、离线沿用和实际路径状态上报。
- 中控下发的 package/domain/IP matcher、Service 与声明关系；界面只读展示生效
  结果；用户只能选择 Direct / Auto / 指定出口三种顶层模式。

**实现约束：**

- Kotlin + Gradle Kotlin DSL 作为平台宿主，Jetpack Compose 负责原生 UI；
- Android `VpnService` 建立系统 TUN，并按平台要求运行前台 Service 与常驻通知；
- 使用钉住版本的 sing-box `libbox.aar` 承担 TUN 和代理数据平面，不复制协议实现，
  也不把上游客户端的 profile/规则编辑模型带入 Loom；
- 应用的 A/AAAA 查询只接收持久化 FakeIP，连接进入 libbox 后恢复为 FQDN 并沿
  候选链传到最终出口解析；FakeIP 规则只匹配 `tun-in`，不会接管 libbox 自己的
  公网入口/bootstrap 解析；宿主对已经配置 TUN 地址但 libbox 未显式列路由的
  地址族补默认路由，保证 FakeIP 双栈都进入同一数据面；生产 TUN 显式使用 1500
  MTU，不能沿用上游 9000 默认值跨越普通移动/Wi-Fi underlay；
- `reverse_only` 只约束 WireGuard 发起方向。v1 latch 前，服务器在已验签 snapshot 中显式
  启用 `public_data_ingress` 时，移动端可获得到最终出口的一跳已配置 data-ingress transport
  候选（Hysteria2 或 Trojan）；v2 latch 后该布尔值单独无效，必须由 certified
  `PublicEndpointIntent` 和本 Device 的 `DataIngressEndpointSetV2` 授权。两跳国内中继
  保留兼容，但不得让同协议套叠的两跳候选压过同等健康的一跳路径；
- 继续使用现有窄 `mobile/loomcore` binding，通过 `gomobile bind` 与钉住的 libbox 一起
  生成 Android AAR，复用平台无关的 Loom 验签、generation floor、最后可用配置和
  selector 状态机；不得把完整 CLI/server core 绑定进应用，也不得在 Kotlin 中另写一套
  行为略有差异的验证器；
- 设备 P-256 identity/CSR signing key 与独立 wrapping key 都进入 Android Keystore；
  Enrollment PoP 只由 identity key 签名，wrapping key 只封装本机凭据。API 31+ wrapping
  使用不可导出 P-256 `AGREE_KEY`，API 26–30 使用 RSA-2048 `DECRYPT` + exact OAEP fallback，绝不
  导出软件 ECDH 私钥；应用私有目录只保存签名配置、状态和不能放进 Keystore 的最小材料；
- 首版 bootstrap 只实现 Hysteria2；可日常使用的正式版再加独立
  Trojan/TLS TCP fallback。两者的 `VpnService` socket 必须 `protect()` 以避免隧道回环；
  WireGuard 只在正式身份和视图取得后由同一 libbox/`VpnService` 宿主建立持久
  control/L3 overlay，不是首版 bootstrap，也不创建第二套系统 VPN；
- Emulator 用于 Compose、加入网络、权限和基本 TUN 流程，真实 Android 设备负责扫码、
  移动网络/Wi-Fi 切换、Doze、厂商后台限制、重启和长期运行验证。

v1 Android 必须先校验二维码平台 key 指纹，再以同一 Keystore key 绑定 CSR；signed pull
先持久化 generation floor，再验证 current/manifest/bundle。候选只经严格静态校验、secret hydrate、
libbox 配置预检、TUN/路由与 selector 本地启动验证后原子提交；这些本机检查不发送业务
DNS/HTTPS 请求，不等待入口或服务器观测才启动数据面。本地启动事务失败才恢复 previous。
canonical v5 与 self-check v1 由 Keystore 签名；移动计划必须与 selector、候选顺序、显式 chain 和授权一致。
Kotlin 宿主负责生命周期、Keystore 状态、回环 selector 事务，以及
[客户端消费规范](observations.md#客户端消费边界)要求的 OS 网络代与入口测量接口；
不在宿主另建探测调度器或完整路径窗口。

目标 v2 在入网前先以 bootstrap capability 建立只可达私有 Enrollment IP/port 的临时隧道，
再在内层 server-auth TLS 中发送 token、CSR 和 Keystore PoP。ControlSet 以 Raft CAS 保证一次消费；
完成后 App 原子安装正式 certificate/view/credentials，然后删除 token、capability、临时 profile 和隧道状态。
该流程复用同一 Device identity key 完成 PoP，并使用上述独立 wrapping key 解封凭据；
客户端原子保存 ControlSet checkpoint/transition、QC、
recovery/control/head/Device view 四组 floor（含 recovery policy hash）、bootstrap transition hash、
`protocol_latch=v2` 和带 TLS SPKI pin generation/overlap 的 EndpointSet，不要求清除身份或重新扫码。
稳态 private `device_config` 若只提升 authority 或 route plan，先在 candidate 槽应用 selector 再提交；
若 `android-runtime` bytes 改变，则先持久化 candidate、通过内嵌 libbox `checkConfig`，再由同一
`VpnService` 启动新 TUN/runtime 并读回 selector，最后才推进 current/floors。启动失败会删除
candidate 并重新启动仍为 current 的旧 LKG；进程在提交前中断也只会从旧 current 恢复。
原生宿主、服务端纵向测试、Emulator 和真机
的实际结果分别保存在[验收回执](../operations/local-deployment.md)中；开发签名 APK、模拟器成功或 HTTP 204
不能冒充生产手机已经入网和可靠性验收。

Android 不安装 Linux 版 Loom Agent、systemd unit、`/etc/loom` 路径或 Loom
二进制自更新器。应用更新通过应用商店、企业 MDM 或签名 APK 渠道完成；Loom 只
更新配置和排名。

Android 同时只能有一个活动 `VpnService`。因此它不启动独立
Tailscale/Headscale 客户端，也不建第二套系统 VPN；Loom 的正式 WG control/L3
overlay 和数据路由由同一 libbox/`VpnService` 宿主统一持有。Auto 模式由中控
规则按 package、domain 或 IP 匹配 Service；Direct 与指定出口是互斥的顶层覆盖。
相同 package 内同一域名的多账号无法由 L4/TUN 可靠区分，profile 能力不进入 v1。

### 开发、构建与验证环境

“能在某个系统生成制品”不等于“已经验证该平台语义”。平台无关逻辑尽量在 Linux
和 CI 中测试，操作系统生命周期、权限、驱动和安装事务必须在对应系统运行。

| 工作 | Linux / CI | Windows 实体机或 VM | Android Emulator | Android 真机 |
|---|---|---|---|---|
| 共享 Go 核心、配置验签与 selector 单测 | 主环境 | 原生复测 | 通过 AAR 间接验证 | 最终复测 |
| Windows Service 未签名 `.exe` | 可交叉编译 | 安装与运行验证 | — | — |
| Windows Portable 原生 GUI | 可交叉编译 | 文件选择、窗口生命周期与 DPI 布局验证 | — | — |
| Windows DPAPI、签名组件包、Wintun 与可执行预检 | 可交叉编译、验证 Loom 包签名和 PE/build identity | DPAPI、WinVerifyTrust、真实 `sing-box check` 与 Job Object 验证 | — | — |
| Windows TUN 激活、CNG、MSI 与 Loom 代码签名 | 只能准备共享逻辑和输入 | 必须完成管理员权限、驱动/路由恢复、安装和签名终验 | — | — |
| Android APK/AAB | 可无界面构建 | Android Studio 开发最方便 | UI/权限/基本 VPN | 移动网络与生命周期终验 |

原生测试必须分别覆盖 DPAPI machine/user scope、ACL、原子替换、SCM/LocalSystem、
WinVerifyTrust、`sing-box check`、Job Object、TUN/路由清理、MSI 升级及代码签名；一次
交叉编译或临时宿主验证不能替代其他项。已取得的证据和剩余终验按[部署记录](../operations/local-deployment.md)核对。

**推荐工作站：** 有真实 Windows 机器时，在 Windows 上 clone 同一仓库，用它同时
承担 Windows 原生客户端、Android Studio 和 Android Emulator。Windows 只构建明确
的客户端目标；含 Unix API 的全量 `cmd/loom` 与全仓后台测试在 Linux、WSL2
或 CI 运行。不要为两个平台复制 SSOT、matcher、Policy 或 selector 模型。

目标代码边界固定如下，使构建系统无需猜平台：

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

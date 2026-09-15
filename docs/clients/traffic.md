# 客户端规范 · 流量接管与 Windows 发行形态

[客户端规范入口](README.md) · [文档地图](../README.md) · [源码能力](../development/implementation.md)

**规范状态：已批准的客户端契约。** 本文负责 流量接管与 Windows 发行形态；标为 v1 的内容仅适用于迁移输入，
v2 认证、对象与事务以[控制面规范](../protocols/control-plane/README.md)的对应条款定义。
平台运行情况由验收回执确认，正文不记录部署进度。

## 流量接管方式

### TUN

TUN 适合无法逐个配置代理的应用，承担系统流量兜底。它需要系统权限，并必须排除：

- 客户端自身的控制面连接；
- sing-box 到第一跳服务器的连接；
- 本地回环与必要的局域网流量；
- 平台要求不能进入 VPN 的系统流量。

这里的“局域网排除”只是在避免 TUN 递归或破坏本机连接，不等于发布或访问远端
局域网。后者必须显式选择目标地址域，并受独立授权约束，见
[Local Network 专题](../proposals/local-network.md)。

错误的 TUN 路由可能造成控制连接递归或设备失联，因此新配置必须先离线预检，
启动失败时恢复上一个工作配置。

### mixed

mixed 同时提供本地 HTTP 与 SOCKS5 入口，适合浏览器、开发工具、CI、容器和
systemd 服务显式接入。v1 日常只提供 `127.0.0.1:1080` 一个遵循已验签 snapshot 规则的 mixed
入口；Windows 的 mixed 与 TUN 使用同一份 matcher → Service → `AccessDeclaration`
映射，Android 不提供 mixed。

Linux Server 默认只使用 mixed，避免改默认路由后锁死 SSH。应用使用
`socks5h://127.0.0.1:1080`，让代理端解析域名，避免本地 DNS 结果使出口判断失真。
HTTP 代理仍可复用同一个 mixed 监听。

旧“端口绑定声明”只在 Linux 作为命名明确、默认仅回环监听的兼容/高级覆盖保留，
用于迁移已有脚本或临时 CLI 强制出口。它仍受目标授权、候选集与 fail-closed 约束，
不得扩权，也不得出现在 Service 页面的主流程中。Windows/Android 不渲染或编辑
这类覆盖；生产既有端口迁移必须显式完成，不能静默复用端口号改变含义。

### 业务域名由最终出口解析

DNS 归属不因宿主平台变化。Direct 模式在接入设备本地解析并本地直连；Auto 和指定出口
必须把业务 FQDN 保留到实际候选链的最后一跳，由最终出口使用本机受管 resolver 解析，不能
把接入侧取得的 A/AAAA 沿链转发。Linux mixed 使用 `socks5h`；Windows/Android TUN 使用
FakeIP + 持久映射 + FQDN 恢复，或经过同一测试向量证明的等价机制。IP literal 保持原样。

公网 `DistributionEndpointSetV1`、`BootstrapIngressEndpointSetV1` 和 `DataIngressEndpointSetV2` 的
hostname 只用于建立受信传输，必须走与业务 FakeIP 分离的 underlay resolver/cache，并配合
hostname/WebPKI 或其已签 transport identity 及平台防回环。私有 control/enrollment/config/report
使用 overlay IP 和内部服务器证书，不发布公网 hostname。这些端点不能被送到某个业务出口解析；
反过来，业务域名也不能借 bootstrap resolver 提前固化成接入侧 IP。

### Windows Portable 与安装版

Portable 与 TUN/mixed 是两个维度：Portable 表示不通过 MSI 注册持久服务，TUN/mixed
表示流量接管方式。产品和测试说明必须使用完整名称，不能只写“Portable”让用户猜测
是否需要管理员权限或是否会修改系统网络。

| 运行形态 | 接管范围 | 管理员权限 | 系统改动 | 推荐用途 |
|---|---|---|---|---|
| **Portable Mixed** | 仅显式使用本机 HTTP/SOCKS 代理的应用 | 不需要 | 不创建虚拟网卡、不改系统路由 | 默认开发模式、浏览器、IDE、CLI |
| **Portable TUN** | 纳入 TUN 路由的系统 TCP/UDP/DNS 流量 | 导入二维码不需要；启用 TUN 前要求以管理员身份重启 | 加载 Wintun、创建虚拟网卡并修改路由；退出必须恢复 | 不支持代理的应用、UDP/QUIC、全局接管测试 |
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

Windows 打包契约生成 `installed`、`portable-mixed`、`portable-tun` 三种内嵌身份（各含
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
不成为服务器节点。展开详情分别显示当前底层网络代的单次入口证据、已验签服务器分段观测、
实际运行反馈、切换原因与读取时间。没有对应证据时保持未知；不显示“完整路径健康”、“最佳质量”或
客户端实测端到端 P50/P95，也不把服务器分段 RTT 冒充客户端测量。
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
静默覆盖。v1 发行物契约内嵌部署平台公钥；它是公开的迁移/发行验证锚，不是 Device 凭据、
连接密钥或控制端地址。干净首启只等待二维码，不读取该公钥；导入或恢复加入事务时才加载它。
提交一次性加入码前，客户端先完成组件签名/架构校验，再把二维码携带的平台公钥 SHA-256
指纹与发行包内嵌公钥在本地比对，避免拿错部署包
后才消费加入码，也不为此增加另一条公网 API 或反向代理依赖。schema 1 registry 中尚未
消费的旧邀请在服务端升级时全部失效，不保留缺少该字段的旧二维码兼容路径。
目标 v2 把该 key 只用于验证一次 bootstrap transition，之后由 DPAPI 原子保存 recovery
anchor、ControlSet checkpoint/transition chain、EndpointSet（含 TLS SPKI pin generation/overlap）、
recovery/control/head/Device view 四组 floor（含 recovery policy hash）、bootstrap transition hash 和
`protocol_latch=v2`；不能把任一新
controller 的单 key 重新钉成永久平台 key。
Portable v1 兼容契约把二维码 pending 数据、ready 恢复日志和身份放在操作用户
DPAPI 下保护；
中控只允许同一 token、CSR、request ID、平台和 Device facts 在一小时恢复窗口内重放，
下次启动可继续，`config\client.json` 提交后立即清除 pending token。Installed 经 Service
使用 machine-scope DPAPI 与 `%ProgramData%\Loom`；安装器将目录设为 SYSTEM/管理员独占。
服务启动时检查目录所有者、ACL、重解析点和硬链接，拒绝将用户可写的旧预览状态当成可信机器状态。
全局进程锁阻止两个 Windows GUI 同时运行或两个数据面争抢端口/TUN，最终完成标记使用
create-only 提交；数据面锁覆盖整个 joined workload，不在子进程更新切换间释放。

二维码解析、身份绑定、signed first pull、TUN/mixed 生命周期、MSI/IPC、代码签名及各架构
实机覆盖属于独立验收项；设计文档不记录其完成勾选。交叉构建、进程启动或测试签名不能
替代真实权限、网卡、升级和网络切换证据，结果按[部署证据](../operations/local-deployment.md)核对。

---

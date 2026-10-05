# 实施状态

实现与文档核对日期：2026-10-05。本文记录本轮代码、正式开发入口与实际运行证据；原生截图、VM 和
生产证据分别保留各自日期及范围，不定义第二套协议。完成须满足[正式入口与回读门禁](README.md#完成判定)。
本轮已按用户授权激活 schema 3 Linux 正式服务，完成节点配置、控制同步、业务及恢复回读；实体机终验仍未完成。
组件、测试和页面存在均不等于整个业务完成。

用户已明确将实体机测试留给自己；其余现行模型内的实现、同机虚拟机/模拟器验证、正式部署、业务回读
和旧路径清理由本轮执行持续完成。实体机未验不阻止推进其他工作，也不冒充实体机通过。
阶段性检查或进度汇报不构成停工点；只在具体外部条件或不可变现网材料冲突确实阻塞时说明缺项。

## 当前工作项：普通设备服务授权与撤权

状态：进行中，未通过完整业务验收，不能关闭。用户已授权按同一业务闭环连续推进实现。

- 必须结果：正式管理入口创建 Service 与固定所属 Policy，设备选择 Policy 并完成私有加入；认证 View
  原子持久化后由客户端及服务节点实际消费，运行、业务和管理页面分别回读；修改、deny、策略替换与撤权
  在应用失败和重启后均不恢复旧权限。
- 保留边界：现网身份、密钥、认证原始字节、floor、latch、既有管理员访问，以及三端有效交互和视觉资产。
  本项不新增协议号、第二权威、长期兼容路径、DNS provider 或 ACME。用户已于 2026-10-04 授权逐节点部署、
  检查运行、修复缺口并再次部署验证；现网保全、宿主网络与生产前向切换的门禁继续适用。
- 当前结果：同一 schema 3 的普通事实、唯一 Authority、正式 CLI/daemon 和 Web 授权入口已替换旧链；
  Service → Policy → 设备 PolicyIDs → 私有加入 → 认证 View/LKG → Linux 实际 Direct、本机出口及一跳 Hy2/Mixed 业务 →
  撤权后的拒绝配置 → 重启/执行失败 → 签名报告和管理 API 回读已在临时隔离环境实证。
  Android API 35 x86_64 临时模拟器也已从正常文件导入和系统 VPN 同意入口，完成 Hy2 HTTPS、撤权热替换、
  Keystore 重启恢复、重新授权及界面/私有签名报告回读。
  这是一条已运行的开发闭环，不是生产激活、全部传输能力或所有平台验收完成。
- 仍须连续推进：Linux 隔离 capture 与 Web SSH/sh 自动交付、`.loom` overlay、
  未实现的传输能力、动态成员及签名发布消费。Linux WG 中继、此次精确制品激活和旧运行入口退出已现场验证，见下文。
  动态成员多数链尚未实现，不能用初始成员表代替；Hy2、LAN、发布和全部平台能力不是简单 Direct 链的共同前置。
- 生产状态：获准的 Linux client、control、私有 relay 和透明 endpoint edge 已使用本轮同一精确制品。
  本机 access 使用显式 Mixed；初始 netns TUN 拒绝门禁保留。历史只读检查不是当前部署状态，
  切换、端口修复、恢复和删旧证据保存在被忽略的 `deploy/evidence/2026-10-04-service-switch/`。

完成时仍须逐项给出正式入口、认证处理、持久/重启、实际消费、用户回读、获准部署和删旧证据；
缺一项即保留本工作项未完成，不把内部检查点拆成可分别关闭的工作项。

### 已授权的正式服务替换

前期只读检查与候选自检保存在 `deploy/evidence/2026-10-04-node-rollout/`；用户随后明确要求解决客户端、
正式切换、真实业务验证，并确认 `.env` 指向 YAML。此次执行及原始回读均在受保护的
`deploy/evidence/2026-10-04-service-switch/`，节点别名、映射、摘要、原始材料和运行指标不进入本文。

- 正式 `loom config check -env .env` 已严格读取既存 YAML，原输入保持；六键 reader 和相应迁移入口删除。
  `.env` 只保留文件定位和可选 provider secret，不能改写控制权威。
- 旧设备签名密钥、control 签名密钥、管理员证书、数据面证书与 WG 密钥逐项核对保留；旧认证原字节、
  floor 和 latch 保全。经本次明确替换授权建立现行信任材料，沿正式 Invite/claim 完成原设备身份绑定及
  Service/Policy/资源/Link 映射。新旧签名域与序列不以数字相等替代证明，旧发布 floor 原文件摘要保持。
- 同一精确制品已接管正式 client、control、relay 和 endpoint edge。所有获准节点经正式公网设备认证
  入口取得 View，运行时实际消费并提交签名报告；临时加入入口经 draining/retired 退出，临时 SSH 通道移除。
  原管理员证书通过 mTLS 正式 CLI 写入、成员同步、重启持久回读和原值恢复；真实 Chrome 已打开回环管理页。
- 客户端 WG 所有权和异常清理已修复；真实隔离环境完成 WG TCP/UDP 与 Hy2→WG→Hy2→HTTPS。
  生产端口问题通过同轮双端抓包及普通 UDP 对照定位：旧端口回复缺失，操作者确认云端无出站 UDP 限制；
  从既有 YAML 映射区间选取经对端验证的空闲端口，通过管理员 `resource.put` 修正后恢复握手和私有传输。
  未登录或修改云网络、NAT、路由器或防火墙，也未把推测写成丢包原因。
- 生产 Mixed 已实际访问授权 HTTPS，固定出口与 Auto 分别回读。一个首跳失败后，同出口中继被自动选择，
  后续业务成功；经修复节点的中继业务也成功。历史脚本还执行了未经业务需求确定的出口/目标组合；
  这些失败保留为可达性诊断，不能列为功能缺口或上线阻碍。允许选择某出口不表示要求该出口访问所有目标成功。
- 故障节点及开发宿主完成正常停止、SIGKILL、精确 WG/子进程清理和重新启动。本机每阶段新建 SSH、
  LAN DNS、默认公网 HTTPS、经既有 WireGuard 的 HTTP proxy 均通过；非本 generation 的 route/rule、
  resolver、密钥和发布 floor 不变。当前 unit 使用 `Restart=no`，不以反复重启掩盖清理失败。
- 已替代的 helper、候选及旧 control/WG timer 启动项从 systemd 退出；旧安装目录中的可执行文件删除，
  正常 `loom` 命令指向当前制品。旧 authority、report 输入和必要签名原件移到受保护证据，不能再作运行输入。
  旧公网制品 handler 和静态分发树已退出实际入口；Nginx 配置检查、reload 与读回通过，既有网站/TLS 保留。

本轮未完成 `control.loom`：现有网站叶证书缺该 DNS SAN，认证 DNS overlay 也尚未接线。
回环浏览器成功不能抵扣它，也不改写用户已确认的笔记本访问历史。旧 HTTP 分发 URL 未伪装成 HTTPS；
原值留证据，新发布 catalog/floor 消费仍未实现。本次直接激活不声称该发布链或 Android/Windows 实体机完成。

### 认证解析器与具名客户端入口

本次补齐设备解析器配置、Linux 私有域名入口及 Android 具名 Endpoint/Hy2 的实际消费；
证据位于受保护的 `deploy/evidence/2026-10-04-client-dns/`，不改变上述完整工作项的未完成判定。

- 解析器复用 Invite 和设备授权中的可选 `dns_servers`，沿正式邀请/设备管理表单或 `loom control write`
  写入同一普通事实，投影到既有 `DeviceView.dns_servers`。首次加入直接取得配置；改名和改权保留未编辑的值。
  未配置的已签发字段继续省略，原始字节不变，没有新协议号、全局默认 store 或系统 resolver 运行回退。
- 私有设备连接只向认证的字面解析器查询；域名答案只作临时拨号地址，原 TLS 名称、SPKI 和证书身份保持。
  Linux 与 Android 的 Hy2 运行投影接入同一 DNS 配置；Android 的 Go 私有连接及 DNS socket 也在 VPN capture
  前调用平台 protect，关闭后撤销回调。纯渲染没有网络查询，未配置解析器的具名入口明确失败。
- 所有获准 Linux 节点先经原管理员 mTLS 配置各自原有解析器，再确认旧客户端已保存签名 View，随后切换
  client、control、relay 和 edge 的同一精确制品。新客户端经具名入口完成正式 sync 和签名报告；
  控制节点同步一致，普通 DNS 事实经 control 重启后回读，正式 Chrome 也回读设备表单中的同一值。
- 固定出口及 Auto 使用真实 HTTPS 验证。单个出口首次失败的原始记录保留，单独复测经同出口中继成功；
  此前将境内最终出口访问国际目标的失败列为未完成项，缺少业务需求依据，该判定撤回。
  正向验收先确定 Service、预期最终出口及业务链；境内节点作为入口/中继时，检查它到所选境外出口的转发。
  不可达请求只有在明确验证失败识别、报告或选路时才属于反例验收，不能要求把不适用的链路测到成功。
  客户端正常停止、owned WG 清理和重启后 Auto 业务通过；
  各阶段新建 SSH、LAN DNS、系统 DNS、默认公网及既有代理正常，路由/规则的配置值保持。
  RA 路由租约的自然倒计时单独剔除后比较，原始快照保留。设备身份、RuntimeKey、旧 floor、证书/密钥及
  已有 Material 原字节逐项核对保持，运行制品与最终源码的重建摘要一致。
- 独立 user/network/mount namespace 中的 Android API 35 x86_64 原生验证使用具名私有入口和具名 Hy2
  资源，完成正常文件导入、VPN 同意、真实业务、撤权拒绝、Keystore 重启恢复、重新授权、签名报告与界面回读。
  DNS 查询与接收端记录、截图、精确 APK 摘要保留；临时模拟器及 fixture 已退出，宿主未安装 DNS/路由规则。
- Go 全仓 build/test/vet、mobile test/vet、真实 Chrome 邀请与改权、双 ABI Android AAR、JVM/lint/APK 检查通过。
  Windows amd64/arm64 源码编译通过，未用它抵扣新版原生执行、交互桌面或实体机验收。

`.loom` 权威记录与 `control.loom` 网站证书/浏览器入口、Windows 新制品原生验证、
实体机及正式签名交付仍未完成；本段的认证解析器结果不替代这些能力。

### 内核 WireGuard 具名资源

沿现有资源与设备配置入口补齐认证解析器到内核端点的执行映射，证据保存在受保护的
`deploy/evidence/2026-10-04-wg-dns/`。本节只证明该项能力，不改变完整工作项的未完成判定。

- 具名 WG 发起端只使用当前 View 的认证解析器，内核收到精确 IP:port；回读严格核对该地址、端口和
  认证 peer key。删除原先“域名可以匹配任意 IP”的回读逻辑；纯投影、签名资源与持久 LKG 不保存 DNS 答案。
- 同次解析复用相同名称，保留仍有效的本代地址；刷新确需换地址时精确清理并重建，相关旧业务观测失效。
  临时解析失败不制造健康结果，也不借宿主 resolver；首次执行缺少认证解析器明确失败。
- 独立网络与挂载 namespace 内实际完成具名 Hy2→WG→Hy2→HTTPS，DNS 答案变更后读回新内核端点并恢复
  HTTPS。初始握手及连接恢复的失败尝试保留；接口启动和单独握手均未算作业务通过。
- 全部获准 Linux 节点激活同一制品；既有具名 WG 资源被实际消费，所有发起端的内核地址逐项与所有权记录
  相等。切换先由旧进程清理自身 generation，再启动新制品；已替代程序退出并删除。
- 明确选定境外最终出口访问对应国际 Service，以及 Auto 的真实 HTTPS 均通过，原 Auto 偏好恢复。
  本机正常停止、精确 WG 清理、同制品重启和认证报告通过；停止与恢复期间新建 SSH、LAN DNS、系统 DNS、
  默认公网和既有 WG 代理均通过。现网身份、RuntimeKey、密钥/证书、旧 floor 和认证原字节保持，宿主
  route/rule 配置值与基线一致。

### Windows 认证 DNS、Hy2 与撤权恢复

首次 bootstrap 原先验证 Invite 后仍调用系统 DNS，Windows 实际导入具名入口时失败；现已先验证 Invite，
再经其中签名的解析器拨号。未配置解析器及篡改 DNS 拒绝，失败和继续加入保留同一身份与 request ID。
加入后的私有通道使用当前 View 的 DNS，两条路径共用平台 underlay dialer；没有新增 wire 字段或重写认证材料。

原生运行还揭示 Windows 的旧 Direct 校验器不能消费 Hy2，且 DNS 已被共用适配器提前添加，重复进入 capture
派生。现在共用源只添加本机 API，Windows 按三种既定形态添加一次 DNS/capture，保留完整 Hy2 CA、名称、
凭据和 detour；不安全 TLS、未知字段、循环 detour 及扩宽 capture 仍拒绝。

同机 Windows 11 x64 的真实交互桌面已完成文件导入、同事务继续加入、CurrentUser DPAPI、具名 Hy2 HTTPS、
撤权应用、正常断开、进程重启后仍拒绝、同身份重新授权后业务恢复、正常停止；各阶段私有签名报告、GUI
及运行时回读相符，Mixed 前后路由不变。未配置业务探测池时 UI 保持 unknown；实际 HTTPS 由独立业务请求验证。
证据在 `deploy/evidence/2026-10-04-windows-current/hy2-summary.json` 与 `hy2-initial/`、`hy2-final/`。
原桌面 DPAPI 与 GUI 定向回归也已通过；固定出口文字的检查修正为识别现有绿色字形，没有修改产品样式或视觉基准。

共用 Go 定向 race 及全仓 build/test/vet、安全和格式检查通过；Android 双 ABI 核心、JVM、lint 与调试制品
构建通过。Windows 三形态 TUN/升级卸载仍须继续；不能把此处 Portable Mixed 的开发业务链当作三形态交付或
实体机终验。Android release 输入检查已覆盖共享 Go 与 staged 修改，
防止制品标注 HEAD 却包含未提交的共用修复。

源码 `58305b2b` 已提交推送，并按既有明确授权在全部部署节点激活同一精确制品。原身份、认证材料、
floor 与 latch 保留，宿主 route/rule 不变；新建 SSH、LAN DNS、系统 DNS、默认公网及原 WG HTTP proxy 回读通过，
指定既定境外出口和 Auto 的国际 HTTPS 业务通过。逐节点旧程序和临时上传已删除，受保护证据位于
`deploy/evidence/2026-10-04-bootstrap-windows/deployment-summary.json`；不是新的签名 catalog 激活。

同一提交的 Android 正式 APK 已使用既有发布签名生成并验签，两个 ABI 的 native library 与 AAR 逐字节一致。
API 35 x86_64 干净模拟器实际安装正式 APK，从 DocumentsUI 导入、私有加入和系统 VPN 同意入口完成具名 Hy2
HTTPS、撤权、Keystore 进程重启恢复、再授权、界面/私有报告回读及正常断开。制品、首次安装和保留身份重试的
独立记录分别位于上述证据目录的 `android-release-artifact.json`、`android-release-clean-install/` 与
`android-release-native/`。首次尝试的首个业务请求失败，没有充分诊断确定原因；原身份重试与独立干净安装均通过。
验收测试保留每次失败原因，并在限定时间内独立等待真实业务结果，不把 runtime ready 当作业务已成功。
ARM64、物理切网、睡眠及其他实体机终验仍由用户执行。

更新后的 Windows 六份 ZIP 与双架构 MSI 已生成；x64 MSI 经正常安装后 SCM 以 LocalSystem 运行，安装的程序
回读提交与摘要相符，VM 原有六份 DPAPI 文件逐字节保留。当前桌面回归中 deviceclient 14 项、client/broker 14 项、
DPAPI 3 项和 GUI 54 项通过。安装本身不抵扣实际 TUN、重启/升级/卸载业务验收；这些验证继续进行。

### TUN 域名传递与缓存恢复

实际 Installed MSI 已经通过正常加入、Machine DPAPI、TUN 启动和签名运行报告；随后 HTTPS 暴露域名
Service 被发送为 Hy2 IP 目标的问题。接收端按原 ACL 正确拒绝，没有放宽接收端、替换服务目标或改动宿主网络。
当次失败后 service 已停止且 TUN 清理，原身份保留用于修正后的重试；下述正式制品重新验证已通过。

共用 capture 现按 Service 域名 matcher 派生仅适用于 TUN A/AAAA 查询的地址映射，保持签名 View 和原 ACL；
原始 IP 不因 SNI 变成域名。独立 user/network namespace 中，真实 TUN DNS、IPv4/IPv6 域名还原、Hy2 TLS、
HTTPS、无 SNI 连接、字面 IP 和伪造 SNI 拒绝均通过；同名 underlay 查询仍到真实解析器，正常重启保留映射。
实测原数据面在立即强制退出后重用了旧地址，新增窄源码补丁已通过三次异常恢复及损坏缓存拒绝测试。
源码准备固定上游 module 校验和、commit 与补丁摘要；数据面制品修订不改变 schema 3。

记录位于 `deploy/evidence/2026-10-04-tun-domain/`。修正版 Linux/Windows 双架构数据面和 Android 双 ABI AAR
已构建。Android 正式签名 APK 已在干净 API 35 模拟器经正常文件导入和 VPN 同意完成仅域名 Service 的
Hy2 HTTPS、撤权拒绝、Keystore 进程重启恢复、再授权、私有签名报告及界面回读；接收端确认收到域名目标。
该包源码为 `a1392929`，双 ABI 库与审核的 AAR 逐项一致，实体机仍由用户验收。

Windows 原版组件 writer 已替换为[规范 schema 3 manifest](core/current-contract.md#windows-数据面-manifest-的规范字段)：
固定源码、补丁和精确双架构制品，附许可证与可独立复现的构建方法；发布代同值重试、同代异值和倒退拒绝。
旧 schema 1 解码与 previous 运行回退删除，现有旧指针和签名包必须显式保全后替换，不自动重解释。
独立空目录重建的四份数据面与审核摘要一致；同机 Windows 原生签名包安装、Wintun Authenticode、逐文件
回读及数据面预检通过。原生正式交付结果见下一节；尚未替换现网数据面或启用生产 catalog。

### Windows 三种正式制品的原生业务与恢复

源码 `9274181a` 的六份 ZIP 与双架构 MSI 已构建，保存在 `dist/windows-9274181a/`；下面的实际执行
均限于同机 Windows 11 x64 VM。数据面使用经 Ed25519 验签的源码修正版，Wintun 的 Authenticode 验证通过；
应用 EXE/MSI 仍遵循既有未签名预览策略，不冒充已取得外部代码签名。

- Installed：正常 MSI 升级保留七份 Machine DPAPI、profile catalog 和现行组件代指针；原身份实际完成
  域名 TUN → Hy2 → HTTPS。关闭 GUI 后服务仍承载业务；TUN 运行中正常卸载清理程序、SCM、虚拟网卡和路由，
  保留配置身份与恢复意图，重新安装后无需新邀请即可恢复业务，并从私有控制入口读回新的签名报告。
- Portable TUN：正式 ZIP 经正常 GUI 加入，保存操作者输入的配置名及 CurrentUser DPAPI，实际完成域名
  HTTPS。强制退出后 Job/TUN 清理，再次运行同一制品恢复原身份、连接意图和名称映射；撤权后拒绝业务，
  再次异常重启仍拒绝，再授权后业务恢复。各步均回读真实 UI 与新的私有签名报告。
- Portable Mixed：正式 ZIP 复用同一用户的既有配置，从显式回环代理完成域名 Hy2 HTTPS；撤权、进程异常
  重启及再授权均通过，未创建 TUN，正常断开后路由与基线一致。

Portable TUN 的正常断开及两次强制退出后，系统 DNS 已实际返回真实地址，新的默认 HTTPS 连接成功，
没有用额外清 DNS 或路由补丁完成恢复。Installed 的整机重启已在登录桌面前自动恢复原身份、TUN、
真实 HTTPS 与新的私有签名报告；随后桌面回读、正常断开和默认 HTTPS 也通过。重启使 Windows 网卡索引
重新编号，原始路由逐字节比较因此失败；按唯一且未变的直连子网核对一一对应后，全部路由、下一跳及
metric 相同。原始差异、对应关系和实际读回分别保存，没有更改来宾路由来取得通过结果。

旧 schema 1 组件指针和原签名包已先逐字节保全、验证，再按精确所有权替换；该处理没有改变身份、认证
floor 或 latch，也没有新增旧格式运行解码。现行组件指针保留此前已接受的制品版本坐标，使后续前向升级
能继续比较原发布代；不能用当前编译版本覆盖或抹掉该 floor。

受保护证据位于 `deploy/evidence/2026-10-04-tun-domain/` 的 `final-upgrade/`、`installed-lifecycle/`、
`installed-msi-lifecycle/`、`portable-tun/`、`portable-mixed/`、`portable-dns-recovery/` 和 `installed-reboot/`，
包括正常入口、精确制品、运行回读与清理结果。
较早的脚本失败单独保留，不计为通过。此处不抵扣 ARM64、物理切网、睡眠或显示硬件终验，也不表示生产
签名 catalog 已实现。

### Linux 正式安装、失败升级与整机恢复

正式 `install.sh` 现在交给同一 Loom CLI 验签和安装，不再保留另一份 shell manifest/floor decoder。
激活显式要求 Mixed，stdin 邀请、自定义 state、可选资源输入和当前 runtime 使用同一组本机路径。
签名包中的 systemd 模板只作投影输入；安装时核对实际 FragmentPath、drop-in、程序字节、所有者和文件类型。
旧部署及其发布 floor 仍须经前向切换，不作为空安装重建信任。

同机 Linux amd64 VM 从正常入口完成以下实际验证，证据在
`deploy/evidence/2026-10-04-linux-package/native-install/`；来宾有独立管理网卡与数据网卡，使用 QEMU
用户网络，没有向开发宿主添加 TUN、路由或防火墙规则：

- 带外公钥验证的包从 stdin 加入；正式 systemd 消费同一身份/LKG，实际域名 Mixed → Hy2 → HTTPS 成功，
  私有控制入口收到新签名报告。相同邀请重跑复用原 Device；带空格、百分号和美元符号的 state 路径从真实进程 argv 回读一致。
- SIGKILL 后 service 停止，手动重启恢复业务；撤权后业务拒绝，异常重启仍拒绝，再授权后恢复，逐阶段回读签名报告。
- 合法签名新包在代理端口被测试进程占用时通过 preflight、接受发布代，但实际运行失败；service 保持 disabled/inactive，
  接受的 current、设备公钥、加入 request ID、认证 floor 与 latch 保持。旧签名包降级拒绝，释放端口后同包重试恢复业务。
- 首次升级故障测试发现重试成功后遗留旧程序，原失败证据保留；修正版从已有签名清单识别同平台较低代，
  精确删除旧 Loom/sing-box，保留 manifest、签名及源码证据，没有增加 receipt 或第二发布 store。
- 未知 systemd drop-in 使安装拒绝，原 current、PID 和实际业务保持。单独隔离缓存测试证明 `--no-enroll`
  不改变已有 current/身份，也不启动 service；缓存程序篡改后拒绝复用。
- 最终制品整机重启后 systemd 自动恢复同一身份和接受代，新的私有报告与实际 HTTPS 成功；正常停止后代理释放。
  各阶段新建 SSH、系统 DNS 和默认 HTTPS 成功，路由/规则只剔除 RA 租约自然倒计时后相同，原始快照保留。

最终双架构签名包由干净提交 `576977b6` 生成，发布代为 5，位于 `dist/linux-576977b6/`；前序代及失败尝试
单独留证，未用更新后的结果覆盖原失败。arm64 完成真实 ELF/源码坐标与签名包验证，原生实体机由用户测试。
全仓 build/test/vet、格式、安全检查通过。VM 与临时接收端已正常停止，磁盘、身份及接受记录保留。
Web 发起的 SSH/sh 自动下载交付、隔离 TUN 生命周期和生产 signed-current 前向消费仍须继续。

### 签名目录与私有 Web 精确下载

本地 `loom release stage` 已从唯一部署 YAML 读取发布签发能力，验证 Linux 双架构 archive 和 Windows
双架构数据面 ZIP 的原规范包，再签署 schema 3 catalog。原 manifest、签名及包字节保持，整包摘要与包内
程序摘要分开；Windows 数据面没有冒充完整客户端。旧 schema 1 catalog reader 和未接入正式 CLI 的
publisher observation 拼接层删除，未恢复旧发布或安装 fallback。

本地审查目录实际完成独立进程回读、同值重试、比较旧指针后前进、并发锁、陈旧计划、降代、同代异值、
文件损坏及历史指针丢失拒绝。拒绝后原 current 保持；已缓存解析仍重新核验真实字节，删除缓存可重建同一结果。
私有测试 control 经正式 init/serve 读取该目录，真实 Chrome 使用管理员 mTLS 打开 Linux/Windows 两页，
实际点击下载的文件与目录摘要相符；下载后 Linux/Windows 正式 CLI 验签通过。无管理员证书请求被拒绝，
新 current 不改变旧页面绑定的精确下载，损坏 catalog 撤下卡片并拒绝下载，恢复原字节后才恢复。
daemon 重启后同一管理员与下载目录回读一致，权威原字节保持；全仓 build/test/vet、格式、安全检查及
真实双架构 Linux 包的独立签名元数据核验通过。

证据保存在 `deploy/evidence/2026-10-05-release-catalog/`。测试只绑定回环私有监听，浏览器信任和策略位于
独立挂载 namespace；没有改变宿主信任、DNS 或路由。较早测试辅助程序等待页面过早、CLI 参数错误和测试
成员证书名不符的失败分别留证，未作为通过结果。原生产服务、发布 floor、身份及公钥保持。

该结果接通本地签名目录和私有下载，不表示公网分发、YAML 全目标发布、节点期望组件、生产 catalog/floor
消费或 Web SSH/sh 安装已完成；后续通用 bootstrap 结果见下一节，Android APK 与 Windows 应用签名交付仍须继续。

### Web 一次粘贴脚本与 Linux 实际安装

通用公开脚本现在是同一 catalog 中的 Artifact，独立签名 manifest 引用原 Linux 包；它只识别架构、下载
并核对 archive，再调用既有唯一 installer。私有 sh 邀请页先验签并从认证 distribution_urls 实际读回脚本，
再显示完整命令和终端历史提示。复制不重签，Invite 只经 quoted heredoc/stdin 交给安装器，不进入公开脚本、
URL、argv 或环境；已完成事务不再返回命令。脚本和不同代 manifest 的缓存分别按两个摘要定位，避免相同
脚本内容导致不同签名代被混淆。

独立 Linux 来宾经控制台核对 SSH 主机密钥；浏览器使用真实管理员 mTLS 打开邀请页，点击 Copy command
取得与页面逐字相同的完整块。真实 HTTPS 返回错误字节时，该块拒绝执行，未创建身份或 unit；恢复原字节后
同一块完成正式签名安装、systemd Mixed、具名 Hy2 HTTPS 和私有签名报告。相同命令重试保留私钥、公钥和
原邀请；整机重启后自动恢复同一身份、服务、真实业务和新签名报告，正常停止释放代理。
安装和重启后的 route/rule 与来宾基线一致，仅剔除 RA 租约的自然倒计时。实际常驻 control 的已热缓存也已
验证同脚本字节、不同签名代的独立回读；全仓 build/test/vet、格式和安全检查通过。

证据在 `deploy/evidence/2026-10-05-release-catalog/shell/`，截图中的邀请内容模糊处理，原命令只留受保护文件。
公开测试服务器仅提供签名白名单制品，管理员/设备请求仍走原私有服务。来宾只安装独立测试分发 CA；宿主
hosts 与浏览器信任改动均限于独立挂载 namespace，没有修改宿主 DNS、route/rule、防火墙或真实服务。
测试辅助程序早期 SSH banner 解析和资源输入多余字段的失败留证，修正后才计入结果。

该独立环境的 sh 安装不抵扣生产交付；后续生产静态 HTTPS 分发与实际来宾验证见下一节。
YAML 全目标 executor、SSH 前置识别/执行与现网发布 floor 的前向消费仍未完成。

### 正式签名分发与生产邀请交付

本轮已沿严格 YAML 的全部发布目标分发 schema 3 目录。新 `release import` 只接受显式 catalog 摘要，
重新验证原包、manifest、签名和逐文件内容；目标 current 在排他锁内比较旧值后推进，重试不能降代或覆盖异值。
发布私钥始终留在工作站，独立公钥经已有管理通道固定；不可变文件实际写入后，公开 HTTPS 回读与私有下载
分别核验。此处 current 只选择下载目录，原运行发布 floor 保持原字节，不授权自动应用。

- 获准分发目标已接受同一新目录。公网 Nginx 只开放签名公开制品的精确内容地址，既有网站和 TLS 保留；
  私有控制面使用配置的目录与独立公钥，真实管理员浏览器下载 Linux 包和 Windows 数据面 ZIP 后逐字节相符。
  Windows 数据面包仍不是完整 Windows 应用，页面不把它显示成应用安装器。
- 新 Linux 制品包含审核后的数据面及完整复现材料；全部获准节点已先激活源码 `d047bb4b` 的程序与数据面，
  control 随后使用 `3c129381` 修复真实邀请签发的入口预检超时。同一 TLS 协议不再重复握手，独立 Web 协议
  仍单独验证；没有放宽证书、名称、SPKI 或业务认证。
- 真实生产浏览器已从 Add Device 提交 sh 邀请并复制完整安装块。首次来宾执行在下载时发生连接重置，
  尚未创建身份或安装程序；另一处已认证分发地址能正常返回同一脚本。源码 `ae991e61` 因此使脚本与 archive
  分别尝试当前已验证地址，逐次检查同一固定摘要，仍只调用一次原 installer。新脚本已先于控制面升级分发。
  原失败记录保留，已过期的原邀请通过正式操作取消，未删除签名事实或重置客户端身份。
- 控制节点已运行 `ae991e61`，签名报告、原身份/认证字节/旧 floor、宿主路由规则、固定境外出口和 Auto
  的真实 HTTPS 均已回读，旧程序删除。生产来宾经新命令完成安装和私有加入；首次选用的策略只允许中继入口，
  对普通新客户端没有候选，这是验收准备漏查入口条件，不能靠放宽原策略解决。正式设备页面已改为现有的
  指定境外出口/国际 Service 策略，原身份与 Invite 保留；普通境内首跳仍在未完成项中。
- 后续现场暴露 Linux 将单项业务不可用误作整个运行配置失败的问题。修正只增加本机 selector 的拒绝位置，
  保持认证字节和候选不变；真实隔离 sing-box 已验证失败时拒绝、进程保持、观测过期后 HTTPS 恢复与正常清理。
  该修正版尚未生产激活，来宾业务、升级与重启的正式回读继续进行。

逐节点切换、制品、公网/私有回读与失败原件在受保护的
`deploy/evidence/2026-10-05-release-distribution/`。下载目录发布与制品替换没有修改宿主 DNS、默认 route/rule
或 firewall；既有 WG 资源只沿本 generation 的精确所有权停止与恢复。目标 SSH 坐标与 YAML 有一处差异，
实际仍按 `.ssh_config` 连接，并与当前认证节点身份核对；原差异保存在受保护证据，没有倒写配置。

YAML 全目标正式 executor、SSH 前置识别/执行、期望组件事实与实际报告比较、现网发布 floor 的前向消费
仍未完成，不能以这次受保护执行和单目标 import 关闭完整工作项。生产来宾的安装、业务和重启结果继续回读。

### 本轮实现与实际验证

Linux 客户端制品已改用[规范 schema 3 manifest](core/current-contract.md#linux-客户端-manifest-的规范字段)，
显式发布代、带外公钥、逐文件摘要和规范 tar/gzip 均参与验证；源码修正版数据面、许可证与独立复现材料
随包交付。旧 schema 2 签名封装与旧 Linux catalog 写入器删除。amd64/arm64 的真实程序打包、验签、
规范往返和篡改拒绝已通过，记录在 `deploy/evidence/2026-10-04-linux-package/`。这只证明交付格式，
原生 Mixed 安装与恢复见上一节；隔离 TUN、Web SSH/sh 自动交付及生产发布 floor 的前向消费仍待完成。

- [规范编码](../internal/control/contract_encoding.go)、[规范值](../internal/control/contract_values.go)和
  [Material](../internal/control/model.go)使用唯一 schema 3、严格规范 JSON、逐事实签名及领域分隔符；
  未知/重复字段、非规范整数/转义、缺字段、null、非法集合顺序和旧格式均拒绝，不自动修复或重解释旧字节。
  Policy 固定 ServiceID，设备只选 PolicyIDs；同服务重复策略、无效引用和未经依赖证明的修改拒绝。
- [Authority](../internal/control/store.go)以系统排他锁保护签发序列及请求幂等，持久保存同一原始签名事实，
  文件和目录耐久提交后才回复；重启从完整事实重建唯一 Projection。初始化只接受显式新空目录和完整
  genesis，缺失/损坏或旧权威材料不自动初始化。初始任意成员数共用同一验证，第二个有效成员已实际签发普通事实。
- [同步与提交](../internal/control/cluster.go)已删除普通写入的 Raft/QC、全量 ID 轮询和旧 State 重放依赖，
  使用按签发键前沿的完整事实差量及精确依赖补取。真实双成员私有 TLS 同步通过；传输 CA 本身不授予成员资格。
  已认证缺依赖事实和同键分叉证据保留，受影响授权失败关闭，不选一个分叉赢家或复活祖先权限。
  新二进制已移除旧 SSOT 渲染、写入、发布激活、安装及回滚命令分派；离线验签/旧 current 取证和受保护
  备份恢复工具仍保留原字节，不授予新 Authority 重放资格；旧 client publish-linux catalog writer 也已从新 CLI
  删除。本地签名目录与私有下载已接通，生产自动发布尚不可用；现网已按本次直接替换授权切换，不以它冒充发布器验收。
- [正式设备链](../internal/control/device_http.go)接通 invite.issue、私有 claim/resume、绑定和 device.join；
  RuntimeKey 只在首次加入生成并随原事实持久化，同事务重试/重启复用原身份。device.put 只接公开字段，
  保留已验证的私钥关联和 RuntimeKey；内部 bind/join/expire 不能由通用管理请求伪造。
  初始 control 的同 NodeID 首次普通职责绑定已验证，设备签名键不得复用 control 键；distribution_urls 归设备授权。
- Invite 携带完整 genesis/成员证明和签名 Material，唯一交付编码为完整规范值经固定 zlib 压缩后 base64url，
  不裁剪证明、不接受旧未压缩 fallback。真实双成员及管理员叶证书的 URI、文件、二维码和剪贴板回读通过；
  QR 以整数像素模块生成，超过媒介容量明确拒绝。SSH/sh 目前交付签名邀请，自动安装执行仍未接通。
- [设备 View 与运行投影](../internal/control/runtime_projection.go)按 Service/Policy 生成 Direct、本机出口、一跳 Hy2 和显式 WG 中继候选，
  默认拒绝业务；最后一项授权移除、deny 或无分配产生合法拒绝配置。设备验证完整证明、签名、View 摘要和逐键前沿，
  同前沿不同 View 拒绝；唯一 LKG、高水位、latch、Preference 先耐久保存再执行，新配置执行失败不恢复旧权限。
  Linux、Windows 与 mobile 已改为消费同一 schema 3，旧 Head/runtime_contract/capability 运行分支不再作为 fallback。
  本机出口即使节点链为空，也保留本节点 FinalExit；只有 Direct 许可才满足 Direct 偏好，入口范围不伪限制本机出口。
  Android、Windows、Linux 与 Web 保留候选和选中结果的真实出口身份，未配置业务探测时路径仍为 unknown。
  客户端配置验证复用控制契约的唯一规范编码，证书 PEM 的换行不再被普通 JSON 的另一种转义形式误拒绝。
- [报告](../internal/control/observations.go)保存设备签名原值与单调序列；同序列不同内容保全为分叉，不能覆盖，
  索引可重建。当前报告必须与有效设备、认证 View 和精确观测范围一致才能进入当前 Web 投影；旧报告只作诊断。
  schema 3 区分认证 View 与实际 applied View，可真实表达运行错误，不伪造新配置 running 或已应用摘要。
- Web 保留样式、keyed DOM、草稿焦点及有效交互，Service、Policy、设备公开职责/PolicyIDs/distribution_urls、
  Invite 和报告已从唯一 Projection 接线；去掉旧 Head/State/SSOT/approve/base_head/quorum 投影。
  Chrome 正式 UI → AdminHandler → Authority 的测试已验证 Service/Policy 创建、草稿不被实时刷新覆盖、
  陈旧依赖拒绝及重新打开；邀请选项先于管理快照到达的反例也已验证，表单不会保留缺策略的初始草稿。
  真实 claim 后清空设备 PolicyIDs 会生成拒绝 View且不改变设备秘密，completed 邀请
  不再回吐可复用交付物。首次签发按模型进入邀请交付视图，再从明确链接进入同一 DeviceID 详情；两处复用
  同一个可丢弃交付/状态组件，没有独立进度或加入成功页。Chrome 验证首次交付→设备详情继续同一事务，
  二维码、下载、刷新/重开保持一致，实际私有加入后两处均移除交付并指向设备详情。事务刷新保留设备改权草稿，
  迟到 HTTP 快照不覆盖期间已接受的实时完成状态；这些交错已由真实 handler/Chrome 验证。设备详情只消费 schema 3 runtime
  的 state/applied_view_digest/error_code；签名 running/error、目标 URL、零/缺失 duration_ms 和四职责过滤
  均已浏览器回读，不再显示旧 overlay/exact/started 字段。部署 applied 无证据保持 unknown，业务观测不作全局健康归约。
- [Endpoint](../internal/control/endpoint_runtime.go)通过真实 advertised TLS 预检才允许 serving；
  prepared 新证书不挤掉有效旧 serving，draining 拒新连接并在明确期限关闭旧会话，retired 要求实际 Active 为零。
  取消、open 到期、设备撤权与证书到期会关闭既有连接；challenge 期间撤权也不能完成旧授权认证。
  completed 同绑定在 Invite 期限后仍可恢复，真实终结后拒绝。退出关闭未完成握手和本进程持有的连接；
  [TCP edge](../internal/control/endpoint_edge.go)也取消拨号并等待转发退出，清理错误传回调用方。
- [凭据派生](../internal/control/service_credential.go)的固定 HKDF-SHA256、规范输入与独立 HMAC 向量已验证，
  按网络、设备、Service、Policy、资源和接收节点隔离。[一跳投影](../internal/control/runtime_resources.go)把同一
  派生凭据交给 access outbound 和资源接收端，接收端不获得来源设备 RuntimeKey 或自身 access 分配。
  [Linux 服务端](../internal/linuxclient/resources.go)使用签名 CA/校验名与显式受保护本机证书引用；入站用户先排除
  其他已选 Service 的重叠目标，再执行允许范围，默认拒绝，不能以 SNI 扩大 IP 目标权限。
  接受新 View 后关闭旧进程及已认证 QUIC 会话；真实 owned UDP、TLS/认证和当前 ACL 摘要进入私有签名报告。
  父进程异常退出也终止子进程。删除资源停止数据面，空入站权限拒绝旧口令；运行失败与重启保留新 LKG。
  未新增授权 store、并行 writer 或版本，纯 server 不启动 access capture，server 与 access TUN 组合仍拒绝。

### 本轮检查及平台边界

- 正式 CLI 用真实随机测试密钥、双成员完整 genesis 和本地受保护输入执行 control init/serve/write/inspect、
  endpoint prepared→serving、client enroll/sync/inspect，验证请求幂等、daemon 重启、撤权与显式重新授权。
  证据：`deploy/evidence/demo-control-cli-20261003T191000Z.json`。测试 daemon 已按精确 PID 和程序路径核验后正常停止。
- Linux 在专用 user/network namespace 中，用同一正式 CLI、私有设备通道和真实 sing-box Mixed 执行授权业务、
  无关事实提高前沿且 sing-box 进程不重启、撤权拒绝、重启保留撤权、执行故障保留新 LKG、签名 runtime/error
  报告和 admin API 回读；停止后端口释放，
  隔离区路由不变，无配置业务目标仍为 unknown。证据：
  `deploy/evidence/demo-linux-formal-runtime-20261003T212743Z.json`；此前本轮记录保留其较早范围。没有在宿主初始 netns 启动 access TUN；
  此证据不抵扣 TUN、WireGuard 崩溃恢复、宿主安全或生产激活。
- 本机出口的正式隔离链还验证：Direct 偏好无法借空节点链使用本机出口，重启保持拒绝；指定本机出口通过显式
  reload 从同一 View 恢复，Auto 正常消费，撤销出网职责收口候选。偏好由正式 CLI 保存，reload 通知使用只指向
  该测试 PID 的临时适配器，没有调用宿主 systemd。证据：`deploy/evidence/demo-linux-local-egress-20261003T212737Z.json`。
- Hy2 的正式隔离链覆盖两节点私有加入、resource/Service/Policy 写入、一跳 HTTPS、selector/CLI/admin API 回读、
  错误 TLS 名/口令、越权 IP、借用合法 SNI 的 IP 请求，以及后来 Service 重叠时仍有效的旧凭据被接收端拒绝。
  旧 QUIC 会话及已打开流随 ACL 替换关闭；父进程 SIGKILL 后子进程退出，重启恢复当前 ACL；撤权和故障均不复权。
  资源删除后报告 stopped，监听释放，隔离路由不变。证据：`deploy/evidence/demo-linux-hy2-20261003T212729Z.json`。
  当前实测为 IP 资源拨号和 IP 业务，域名资源解析、跨实体网络、Android/Windows 原生 Hy2、安装与生产均未由此证明。
- control、deviceclient、clientjoin、mobile 和共享 clientruntime 的相关测试/race 检查已通过；mobile test/vet 通过。
  本轮 Go 全仓 build/test/vet 的检查记录在 `deploy/evidence/demo-schema3-go-final.json`；control、Linux、
  clientadapter、clientmodel、deviceclient 的 race 全部通过，其中 control 启用真实 Chrome 的正式 UI 入口。
  记录在 `deploy/evidence/demo-schema3-hy2-race.json`，不借此前检查点的旧通过记录抵扣。
  控制端连接级测试还覆盖成员身份验证、端点轮换/排空/撤销、认证中撤权、退出清理和失败关闭。
- Android 双 ABI AAR 与当前 Kotlin 的 34 项 JVM、lint、debug APK 构建通过；lint 为 11 warning、1 info、
  无 error，AAR/APK 内两 ABI libbox 的摘要逐项一致。证据：
  `deploy/evidence/2026-10-03-schema3-android/gradle-native.json`。
  原生测试发现并修复 Hy2 的 UDP underlay 重新进入 VPN：本机投影启用 libbox 平台接口控制，实际调用
  `VpnService.protect`；认证私有 Endpoint IP 精确排除，撤权后的更新和报告仍能通过同一私有通道。
  未接认证解析的 Endpoint 主机名明确拒绝，不借系统 resolver 绕过；此修复不放宽 Linux 初始 netns 门禁。
- Android 在专用 user/network namespace 中启动全新临时 API 35 x86_64 模拟器，保留已有 AVD；正常
  DocumentsUI 导入、私有加入、系统 VPN 同意、真实 Hy2 HTTPS 与接收端业务记录均通过。撤权后 VPN 自动
  应用拒绝 View、业务失败、选择清空；强制退出应用再启动恢复同一撤权 LKG，重新授权后同一身份恢复真实业务。
  各阶段都有私有签名报告和可见 UI 回读，最后正常断开；隔离路由恢复。
  证据：`deploy/evidence/2026-10-03-schema3-android/native-hy2-222242.json`；脚本、报告回读和原生截图保留在
  同目录 `native-hy2-method/`，所验 APK 摘要与上述构建记录一致。
  空路径已改为明确显示没有已选业务路径，诊断文字按 Service/目标/网络说明真实业务观测；样式与截图基准未重写。
  空配置原生 UI 回归也已通过首次通知同意入口；冒烟脚本删除已失效的旧测试入口、代理/DNS 修改与 VPN
  appops 授权。记录在同目录 `ui-smoke-native.json`。模拟器、独立 adb 和 fixture 进程已退出，专用 namespace
  无存活进程；清理回读在 `cleanup-final.json`，没有启停生产 service 或修改既有 AVD。
  实体机 Keystore、ARM64 原生运行、IPv6、物理切网和正式签名发行仍未验收，模拟器结果不抵扣这些边界。
- Windows amd64/arm64 应用及测试制品构建通过；VM 的 deviceclient 12 项、共享运行时 9 项通过，
  包含真实 Mixed 授权 TLS、错误 SNI 拒绝、拒绝配置替换及 Job 清理。最终 Windows 支持范围内 12 项通过，
  覆盖正式 broker 规范编码、Installed Machine DPAPI 撤权/无 access 恢复、同 View 更高前沿持久接受且不重启。
  该结果明确排除此前已记录失败的两项 Portable User DPAPI 测试，不能称整个客户端通过。
  另一个原生反例验证：配置拉取期间另一正式句柄先接受较高前沿，同 View 的旧网络响应不打断有效运行。
  证据分别位于 `deploy/evidence/windows-vm/demo-schema3-windows-final/evidence.zip` 与
  `deploy/evidence/windows-vm/demo-schema3-windows-frontier/evidence.zip`。CurrentUser DPAPI 在 SSH 会话被拒绝，
  现场没有已登录桌面，GUI/交互会话仍未验证；不改用机器 scope 绕过。VM 已正常 inactive，临时 ACL 精确恢复，
  无活跃测试。TUN 仅做三形态配置 check，未实际执行；VM 也不能抵扣 ARM64、睡眠、物理切网和实体显示器终验。
  本次 Hy2 共用源码更新后已重建双架构应用及测试制品，记录在 `deploy/evidence/demo-schema3-windows-hy2-build.json`；
  上述 VM 原生记录早于这次 Hy2 更新，不能声称新制品已在 Windows 原生执行 Hy2。
- 前期六键 loader 误拒绝用户已有的 `.env`→YAML，历史只读失败记录在
  `deploy/evidence/demo-config-readonly-20261003T200424Z/result.json`。该实现漂移现已删除；当前正式 loader
  严格解码唯一 YAML 引用并已消费原部署输入，定向测试及全仓检查通过。历史失败不再表示当前配置不可用。
- 本轮仓库安全及 diff 格式检查通过；现存控制 Go 文件格式检查无输出。最终提交仍须复核实际变更和制品范围。

### 前一检查点的独立记录

以下记录属于同日较早的 LKG 接受/纯函数阶段，不是本轮替换后源码或制品的复验：

- 当时已分离三端认证接受、preflight 与运行结果；新 LKG/floor 先提交，运行失败不复权。Linux/Windows
  持久读写共用文件锁，GUI Preference 不回写旧授权，Linux reader 不自动重写历史格式。
  删除硬编码公网探测回退；无目标/歧义保持 unknown，主动取消不记成业务失败。
- Linux WG 仅清理本进程创建且精确回读的对象，不恢复旧快照或接管未知既存接口；安装失败不自动启动旧 service。
  该内存所有权不能证明 SIGKILL、主进程崩溃、外部 namespace 清理与重启恢复安全。
- 当次 Go 全仓 build/test/vet、相关 race、格式、安全与 diff 检查通过；纯函数阶段另验证规范往返、严格拒绝、
  DNS/IP matcher 及 KDF，所引 `golang.org/x/net` 只用于严格 A-label 校验。这些结果不代表当时已有新普通控制链。
- 当次 Linux Mixed 的隔离 selector、DNS/TLS 名、授权/未授权目标、HUP 和退出检查保存在
  `deploy/evidence/linux-mixed-runtime/`，范围独立于上方本轮正式 CLI 链。
- 当次 Android 使用重建 AAR 完成 31 项 JVM、lint、debug APK 和 mobile Go test/vet；不包括真机或当前最终 APK。
- 当次 Windows 原生 deviceclient 18 项、客户端 15 项与 Machine DPAPI 2 项通过；CurrentUser DPAPI 在 SSH
  会话返回 Access is denied，交互任务没有完成标记。证据在 `deploy/evidence/windows-lkg-runtime/`，只对应当次制品。
  当次 VM 最初的磁盘路径错误实际为测试用户权限，按既有文档修复精确归属与父目录搜索权限后 verify 通过；
  当次结束已正常停机、读回 inactive 并恢复原 ACL/模式。该记录不推定其他时刻的 VM 或生产 service 状态；
  本轮最终 VM 回读见上文，生产服务以本轮正式替换证据为准。

## 已完成的局部结果

| 结果 | 已核实的范围 | 不代表 |
|---|---|---|
| 设计入口与单一目标契约 | [设计入口](README.md)、[控制模型](core/control-model.md)及[现行契约](core/current-contract.md)描述同一目标；schema 3 的普通链字段和严格往返已由当前实现消费。 | 动态成员、非 Direct 资源或已签名现网数据已经前向迁移。 |
| 普通授权开发闭环 | 正式 CLI/daemon、Chrome 管理操作、私有加入、耐久事实与 LKG、Linux 隔离 Mixed 和 Android 模拟器原生 Hy2 业务、撤权/重启/再授权、报告及管理 API 回读；Linux 另有执行失败保全。 | 生产激活、所有传输/中继或全部平台完成。 |
| 客户端与 Web 产品资产 | Web、Android、Windows 界面源码及既有视觉基准保留；本轮 Web 正式 Service/Policy/设备交互已验证。 | 三端所有目标稿、真机交互、签名发行或线上运行已验收。 |
| 2026-10-02 与 2026-10-03 文档/原型修订 | 职责、PolicyIDs、加入恢复、LKG/运行/业务分离及目标视觉已统一；详细历史记录见下方。 | 当时已执行业务实现或本轮重录原生视觉基准。 |
| 管理员现有访问 | 用户已确认原 P12/密码交付、证书安装及访问；本轮原证书通过新正式服务的 mTLS 写入、同步、重启回读和真实 Chrome 回环页面。 | 笔记本本轮复验、新领证交付或 control.loom 已可用；现有叶缺该名称的 DNS SAN。 |
| Linux 宿主事故处置 | [事故记录](incidents/2026-09-21-host-network-takeover.md#已落地防复发措施)的 TUN 门禁保留；本轮显式 Mixed 正式服务完成停止、SIGKILL、WG 清理和基础网络回读。 | 初始 netns TUN 可以启用、完整隔离 TUN installer 已完成，或有限连接覆盖所有物理网络情形。 |

## 未完成的业务结果

| 工作项 | 当前可确认的基础 | 尚缺的完成证据或结果 |
|---|---|---|
| 设备服务授权与管理 | Policy.ServiceID、allow/deny、any/only/none、PolicyIDs 和正式写入已接通；开发环境实际撤权、生产既有授权及 WG 中继消费通过。 | 完整 GUI revoke/regrant、其余传输和各平台原生端到端；不能为生产验证随意撤销用户正在使用的权限。 |
| 签名事实与同步 | 单 control 普通签名、每键序列/前哈希、声明依赖接收、差量前沿、真实成员 TLS、重启恢复和冲突失败关闭已实现；旧 Raft/QC 普通权威路径已替换。 | 分区/大规模反熵、双方已截断前沿时的完整分叉证据传播、只向受影响设备分发及生产多 control 长期回读；局部同步测试不抵扣这些结果。 |
| control 成员门禁 | 完整 genesis、任意 N 初始成员验证和唯一 ControlProof 已实现，成员数不是模式；后继消息字段已列明。 | 后继多数证书验证、持久承诺/票史、作废提案、封存证明、前沿例外、高水位保全、超限撤权重签和整体删除仍未执行实现。正式入口拒绝非空后继，不能用初表冒充。 |
| Invite 与节点生命周期 | 真实签名 Invite、私有绑定/加入、同事务恢复、RuntimeKey 一次生成、公开改权与初始 control 同 NodeID 绑定已接通；取消/撤权与跨事务身份冲突失败关闭有测试。 | SSH/sh 自动安装执行、申请新增 control 的多数链及所有节点删除依赖回读；open 邀请到期只失去连接资格，不凭时钟释放 ID，自动生成终结事实尚未接通。 |
| Endpoint 轮换与退出 | prepared→serving、draining/retired、撤销关连接已验证；生产设备入口已沿原映射激活并由所有获准节点认证，临时入口正式退休。 | 同监听不同证书并存、生产网站叶续签、control.loom；同代不能改写认证坐标，也不修改路由器。 |
| 可复用传输与中继链路 | 规范 KDF、共享 Hy2 listener、显式 WG LinkID、Hy2/WG 认证域名解析和真实 Hy2→WG→Hy2 HTTPS 已执行；WG 地址变化后的业务恢复通过。 | 其余现行模型内 transport、逐 Link 签名观测及实体平台；握手不替代业务健康，也不要求全部 transport 组合遍历。 |
| Direct／Auto／指定出口与业务探测 | 单个授权 HTTPS 目标按 Service 实测；生产 Auto、固定出口及首跳失败后同出口中继成功已回读。 | 多目标归约、其余观测算法和平台原生结果；诊断请求的不可达不能单独认定功能缺口，完成判定须对应已确定的业务链。 |
| DNS overlay | 精确 .loom、控制入口与权限分离的目标模型保留；端点 TLS/过期执行已有窄实现。 | 规范 DNS 事实/设备投影、私有解析器、受约束网站根与叶证书交付、CSR/手工续签、逐入口提醒、正式/回环两路径浏览器验链及生产读回。DNS provider、DNS-01 和 ACME 不在本项。 |
| 共享局域网 | 目标由 forward 声明、control 签发 IPv4 虚拟映射，经所属 Policy 与 PolicyIDs 授权；不作为简单 Direct 链前置。 | 分配/冲突重分配、网关 ACL、精确路由、DNAT/必要 SNAT、停止/删除及隔离实际运行。不得修改宿主初始 netns 或 LAN 路由器。 |
| 控制面 Web 与管理员领证 | 当前 UI 使用唯一 schema 3 Authority，原管理员叶及密钥保留；原证书的生产 mTLS 与真实 Chrome 回环访问通过。 | 新 P12 生成/交付、名单普通变更、正式 control.loom 及用户笔记本本轮复验。 |
| Android | mobile 共用 schema 3 状态/transport；双 ABI AAR、JVM、lint 与正式签名 APK 通过。正式包在干净 API 35 x86_64 模拟器已正常导入/私有加入、VPN/Hy2 HTTPS、撤权、Keystore 重启恢复、再授权和 UI/签名报告回读。 | 实体机 Keystore、ARM64/IPv6 原生运行与物理切网；模拟器不能抵扣实体终验，APK 签名也不等于 schema 3 发布 catalog。 |
| Linux | 获准节点 Mixed/Hy2/WG 正式服务已接管；同机 VM 的签名包 stdin 安装、同事务恢复、真实业务/撤权、失败升级保全与重试、删旧及整机恢复通过。 | 隔离 TUN capture、Web SSH/sh 自动交付及生产发布 floor 前向消费；物理网络变化由用户终验。 |
| Windows 既定交付 | 双架构正式制品已构建；x64 Installed、Portable TUN 与 Portable Mixed 已在同机 VM 实际完成域名 Hy2 HTTPS、撤权恢复、签名报告及 UI 回读；MSI 升级、运行中卸载、保留身份重装、整机重启及停止后 DNS/公网恢复通过。 | ARM64/睡眠/物理切网/显示硬件由用户实体终验，外部代码签名未启用；这些结果不抵扣发布 catalog。 |
| 本机 .env 与 YAML | 唯一 LOOM_DEPLOY_CONFIG 引用及可选 GANDI_PAT_TOKEN 严格解码；YAML 原始映射由正式检查和此次实际部署消费，六键漂移删除。 | 配置通过不证明业务成功，也不赋予修改云网络或路由器的权限。 |
| 签名发布闭环 | 旧发布/制品代码及 floor 保留独立取证边界，新二进制已禁旧 SSOT 发布激活入口；UI 无实际应用证据保持 unknown。 | schema 3 catalog、其余制品 manifest、期望组件事实、节点实际坐标与旧发布 floor 的可验证前向映射及生产读回；不能用普通授权闭环声称发布已替换，也不将发布设为 Direct 前置。 |
| 唯一规范输入 | 当前 Material、初始成员证明、Invite、View、报告和设备持久值唯一写读 schema 3；旧普通导入/恢复/协议 fallback 已删除或明确拒绝。 | 非空后继及未实现资源、DNS/LAN、发布边界仍须同版补齐；现网旧字节只保全，不能自动读成新格式。 |
| 字段级同构 | Direct/本机出口/Hy2/WG 中继已定义并消费跨层对应与严格往返；初始成员、节点绑定及 distribution_urls 已落实。 | 其他传输、动态成员和未定观测算法；旧 HTTP 分发坐标不自动转换成 HTTPS。 |
| 生产切换 | 本次明确授权的精确制品已接管正式服务，原身份/密钥/管理员/认证原件和 floor/latch 保全，旧运行入口退出。 | schema 3 签名发布 catalog 的单调消费、全部功能或全部平台已完成；旧证据不能恢复成运行权威。 |

## 后续连续推进边界

1. 当前生产普通控制链已替换旧 Raft/QC 权威；维持受保护前向映射及精确制品证据，不恢复旧协议作为 fallback。
2. 继续沿同一 Service/Policy 授权业务补实际平台与服务节点消费，按新增风险做必要验证；动态成员多数门禁
   保持明确未实现，不以新增治理模式、store 或另一版本绕开。
3. Linux 初始 netns 不能运行 access TUN。显式 Mixed 与仅有精确所有权的 WG 已通过此次宿主回读；隔离 TUN
   和未实测网络变化仍须按[事故门禁](incidents/2026-09-21-host-network-takeover.md)验证。
4. 管理页面、配置接受、运行、业务观测和发布应用分别回读；多目标算法未定时保持缺项可见。
   LAN、Hy2、发布和原型的全部场景不作为简单 Direct 链前置，也不能因该链通过就称它们完成。

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

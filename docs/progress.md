# 实施状态

实现与文档核对日期：2026-10-04。本文记录本轮代码、正式开发入口与实际运行证据；原生截图、VM 和
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
- 仍须连续推进：Windows 当前 Hy2/DNS 制品的原生消费、正式交付验证、`.loom` overlay、
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

### 本轮实现与实际验证

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
  删除。新签名发布能力尚不可用；现网已按本次直接替换授权切换，不以它冒充发布器验收。
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
| Android | mobile 共用 schema 3 状态/transport；双 ABI AAR、34 项 JVM、lint 与 APK 构建通过。API 35 x86_64 模拟器已正常导入/私有加入、原生 VPN/Hy2 HTTPS、撤权热替换、Keystore 重启恢复、再授权和 UI/签名报告回读。 | 实体机 Keystore、ARM64/IPv6 原生运行、物理切网及正式签名发行；模拟器不能抵扣实体终验。 |
| Linux | 获准节点正式服务已接管，Mixed、具名 Hy2/WG 中继、报告、停止/SIGKILL 清理和重新启动通过；开发宿主基础网络回读成立，初始 netns TUN 拒绝保留。 | 隔离 TUN capture 和自动安装失败流程；未实测物理网络变化不能由此次有限回读代替。 |
| Windows 既定交付 | 双架构构建、共享 schema 3 运行时、VM 真实 Mixed/拒绝配置与 Installed Machine DPAPI 撤权恢复通过；较高前沿接受/并发拉取不重启已原生验证，VM 已正常停止并恢复 ACL。 | 已失败的 Portable CurrentUser DPAPI、有效桌面 GUI、三形态正式安装链；TUN 仅 check，未运行；ARM64/睡眠/物理切网/显示硬件仍需实体终验，外部签名未启用。 |
| 本机 .env 与 YAML | 唯一 LOOM_DEPLOY_CONFIG 引用及可选 GANDI_PAT_TOKEN 严格解码；YAML 原始映射由正式检查和此次实际部署消费，六键漂移删除。 | 配置通过不证明业务成功，也不赋予修改云网络或路由器的权限。 |
| 签名发布闭环 | 旧发布/制品代码及 floor 保留独立取证边界，新二进制已禁旧 SSOT 发布激活入口；UI 无实际应用证据保持 unknown。 | schema 3 catalog/manifest、期望组件事实、节点实际坐标与旧发布 floor 的可验证前向映射及生产读回；不能用普通授权闭环声称发布已替换，也不将发布设为 Direct 前置。 |
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

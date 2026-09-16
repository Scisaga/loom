# 源码能力与接线缺口

本文描述本仓库源码的正常入口及已知缺口，随实现变化原位更新；不记录部署节点、运行版本或
历史流水账。只计入与本文件一同可从 Git 取得的已提交源码；其他分支、隔离工作区和未提交接线
不算这里的能力。工作区若有差异，先用 `git status` / `git diff` 核对，不能把它们当成可共享基线。
下列结论来自调用链阅读，不表示本轮运行了测试或生产验收。

- **规则来源：** [架构与不变量](../architecture/README.md)、[v2 控制面规范](../protocols/control-plane/README.md)、
  [客户端观测消费](../clients/observations.md#客户端消费边界)。
- **操作入口：** [控制面实施规程](control-plane.md)、
  [控制面运维](../operations/control-plane.md)、[本机部署配置与证据](../operations/local-deployment.md)。
- **实际运行：** 从 `.env` 所指部署配置、发布记录和 `deploy/evidence/` 的相关验收记录核对。
  配置表达操作输入；证据必须关联实际提交、制品和结果，不能从本表推断已部署。

## 正常入口对照

| 功能 | 正常入口与源码 | 已接通范围 / 具体缺口 |
|---|---|---|
| v1 模型、渲染与签名分发 | `loom validate/render/snapshot/release/publish/pull`；[模型](../../internal/model)、[渲染](../../internal/render)、[发布](../../internal/publish) | 既有严格 schema 和签名快照调用链存在；不能直接接收 v2 LinkIntent/ControlSet 字段。v2 替换必须保留存量身份与数据。 |
| N=1 私有控制服务 | `loom control bootstrap/serve/status/request`；[daemon](../../cmd/loom/control_runtime.go) | `serve()` 启动 overlay control API、loopback 浏览器入口和 Raft。启动配置强制单成员；operation registry 含 `control_ping`、`create_invite`、`publish_device_config` 与已有 DNS binding 操作；邀请与设备配置发布均有管理员签名 CLI。认证迁移后的 `serve()` 从同一日志启动独立的私有 Enrollment、配置与报告 listener，挂载 admission/approval peer RPC；Enrollment 使用实际持久 CA 和 sealed artifact store。Bootstrap 的认证发布、capability 同步与静态制品交付仍未接通，不能据此声称新设备能正常入网。 |
| 初始 v2 authority 与存量迁移 | [daemon bootstrap](../../cmd/loom/control_runtime.go)、[共享 bootstrap 验证器](../../internal/wire/recovery.go) | daemon 当前以 recovery/control epoch 1 初始化，并用小型运行配置和 cluster ID 派生占位承诺；目标初始 epoch 为 0。直接 v1 网络的 `BootstrapTransitionBundleV1ToV2` 与逐设备 floor migration package 尚未从生产输入生成。已有 N=1 日志通过 `control migrate` 验证原 SSOT/registry、当前管理员及原 owner/platform 双签后追加 `RuntimeActivationBundleV1`，耐久保存 exact 请求并恢复同一回执。不在用的独立客户端可明确暂存原身份，不能替代已加入身份、伪造 wrapping key 或成为 active v2 Device。`control export-migration` 从真实 activation/配置日志、原证书与原 signed current 导出设备迁移文件；缺材料时拒绝交付。`device_inputs` 已接通原请求/registry/服务器证书/signed current 验证、原权限投影和真实证书生成，并认证保留独立的原节点观测 CA，签发坐标取实际迁移日志；重启重试复用原结果。`control prepare-migration-input` 已接通原管理 TLS/Head/QC、真实证书与逐设备请求，生成完整 distribution preimage 并持久保存独立受限 issuer；`prepared` 从原日志与这些实际材料组装 application，校验原 authority 与可回读密钥；公网计划已可从现有材料生成并纳入迁移承诺；prepared listener daemon 已接线，认证 advertise/capability 更新、生产激活仍未完成。 |
| 管理员材料与浏览器入口 | `loom control export-admin/rotate-admin/enable-loopback`；[证书导出](../../cmd/loom/control_admin_certificate.go)、[轮换](../../cmd/loom/control_admin_rotation.go) | P-256 完整链、独立 browser TLS 和本机 N=1 certified 轮换有正式 CLI；浏览器实机通过须另有证据。 |
| 恢复材料与迁移门禁 | `loom control prepare-recovery`；[独立材料生成](../../cmd/loom/control_prepare_recovery.go)、[保管证明](../../internal/wire/recovery_custody.go) | 单保管人软件模式持久封装独立恢复 key，实际回读/解封签名后生成保管回执；刷新复用 key/密文。私有 application 重算完整保管树，迁移日志按实际提交时间拒绝缺失、伪造或过期回执。材料不随公开客户端证明交付；离线介质转存、多保管人仪式与灾难恢复实测不能从本机准备推断。 |
| Device/邀请与配置界面 | 私有 HTTPS → Unix socket → [Web UI](../../internal/webui/webui.go) → [邀请回调](../../internal/report/clients.go) | 管理员门禁已接通；旧公开 claim handler、证书签发、SSH 秘密预置及 bootstrap 响应链已删除。库存暂读历史 registry/SSOT，管理邀请和生命周期回调仍需改接认证 v2 事务；`control create-invite` CLI 已有，但 UI 尚未接入。 |
| v2 Enrollment 事务 | [私有服务](../../internal/enrollmentv2/private_service.go)、[Raft sequencer](../../internal/controlplane/enrollment_sequencer.go)、[首次签发持久化](../../internal/enrollmentv2/provisional_store.go) | 正式 `control serve` 已启动私有 Enrollment 服务，使用持久 CA、sealed artifact store 和同一认证日志；`use_loom` 的 reservation、首次签发、approval/completion 已接通，并原子生成客户端及承载服务器配置。新 `forward` 加入仍显式拒绝；bootstrap 认证发布、capability 同步和外部静态交付尚未接通，因此完整新加入尚未交付。 |
| v2 私有配置与报告 | [生成与封装](../../cmd/loom/control_prepare_client.go)、[device_config](../../internal/controlplane/device_config.go)、[device_report](../../internal/controlplane/device_report.go) | `control publish-client-config` 从当前认证网络生成 Linux/Android/Windows 运行制品和原 key 密文；移动/桌面客户端包含私有控制 WireGuard，正常发布同时认证承载分配；Linux 配置生产器消费当前分配并生成受限 userspace endpoint；发起端沿用原 WG key，通过现有 HY2 listener 的独立设备凭据承载，daemon 使用认证回环代理，reader 验证两端公钥、承载身份和精确放行/默认拒绝规则；本机真实 sing-box 隧道测试覆盖 HY2/WG 组合、两个允许服务、未授权端口和外层绕过拒绝，实际部署与验收按独立回执核对；数据面、selector 与 Agent 候选共同按当前 Device grants 收窄，出口授权只限制链尾，保留必要中继；缺授权时拒绝生成；与 `publish-device-config` 共用管理员签名、Device generation CAS、Raft/QC 和重启重放。凭据受 parent 认证 policy、真实 availability 证据及原 wrapping key 约束。认证迁移后由正式 `serve()` 加载实际专用封装 TLS 密钥、配置 reader、报告验签/持久 store 与已有观测回读，绑定独立私有 tuple；任一材料或绑定失败则整体启动失败。测试覆盖迁移身份通过完整 mTLS 链读取配置、报告持久化及重启后的序号续接。Linux `client serve-v2` 已接入配置同步、runtime 事务、持久报告和原始观测交接；服务器观测沿原周期和签名协议生成，保留原 WireGuard 接口身份，由本机缓存交给 `node-health` 私有报告，回执从已持久报告中按当前职责/原 key/新鲜度筛选，不再读取旧报告 socket；真实 TLS 测试覆盖验签、持久保存与重启续接；Linux 原服务退役已接入迁移部署事务：绑定旧文件摘要，在同一回滚边界停用并删除旧入口；报告身份读取与完整配置历史重算已分离；认证日志缓存绑定完整日志和当前 Head/QC，读前仍检查提交、认证及待处理事务边界。新 `use_loom` 入网已接通首次配置生产器：客户端自生成 WireGuard key，reservation/provisional/completion 在同一认证日志中固化首份证书、控制链路与密文；completion 同时更新网络、客户端和服务器接纳配置，失败重启复用原结果。未完成事务占用受影响服务器配置，到认证 retry deadline 后由下一次业务提交以 Raft/QC 终止并保留 token 占用和签发记录。新 `forward` 入网尚未接通且显式拒绝；公开制品分发、bootstrap 入口及生产新加入验收仍缺。部署与业务验收按独立回执核对。 |
| Bootstrap ingress | [HY2/Trojan 服务组件](../../internal/bootstrapaccess)、[客户端 bootstrap](../../internal/clientv2/bootstrap.go) | 传输、受限 capability 和验证组件存在；`certificate prepare-existing` 可在原节点校验并持久保存既有证书，独立于 DNS/ACME；`control prepare-bootstrap` 通过原管理 TLS/Head/QC 生成完整的 HY2/Trojan 私有安装计划，并纳入迁移状态认证。首次无旧代部署可原子进入 prepared；`control export-bootstrap` 通过私有管理入口交付安装部分证明，`bootstrap serve` 由原平台信任验证后启动真实 socket 并做本机 TLS/QUIC 验证。尚缺外部证据的 advertise 事务与实际 capability 更新，计划未认证发布时拒绝新邀请。正式静态 catalog/proof 发布与私有 Enrollment 的完整入网接线仍缺。旧公开动态入口的删除属于同一迁移。 |
| 托管 DNS 与公开证书 | [DNS provider](../../internal/dnsprovider)、[DNS-01](../../internal/certmanager/dns01.go)、[证书组件](../../internal/certmanager) | 共享基线主要为组件，未接通正式非 control executor、七字符名称分配/预留、存量迁移、事件任务与删除接管。DNS-01 的先读后整集合写/删存在并行 TXT 丢失窗口；本地 generation 不能代替 provider 原子保证。 |
| 动态 ControlSet | [成员账本](../../internal/controlplane/membership_ledger.go)、[joint leader](../../internal/controlplane/raft_joint_leader.go) | learner、成员和 quorum 组件存在；daemon 仍限制 N=1，没有正常晋升/移除入口，不能称多成员控制面已接通。 |
| Linux v2 客户端 | [client 子命令分发](../../cmd/loom/client.go)、[原身份迁移](../../cmd/loom/client_migration_linux.go)、[Linux v2 加入及运行](../../cmd/loom/client_v2_linux.go) | 安装器与 `client enroll` 只执行私有 v2 Enrollment；旧公开 claim/signed pull 安装分支已删除。`export-migration-request` 验证原证书后复用原 P-256 身份、保存独立 wrapping key；`import-migration` 验证原 floor、认证迁移和完整运行配置后安装独立 migration state，并经正常 runtime deploy 事务激活。完成态 Enrollment 与原身份迁移均激活 runtime 并安装 `loom-client-v2` 常驻服务；宿主先恢复 LKG，再同步、事务应用并按实际 unit 状态上报，共用持久报告队列及 exact 回执验证；Agent 经本机文件事件消费原始观测并继续验签，观测不触发额外网络轮询。配置与报告读同一 installation；迁移不伪造 Enrollment。正常生产入网仍依赖上述服务端接线及迁移包生成。当前要求 Linux amd64 原生验收；arm64 构建与静态检查另列。 |
| Windows 客户端 | [统一加入入口](../../clients/windows/join_windows.go)、[迁移入口](../../clients/windows/migration_windows.go)、[v2 运行](../../clients/windows/v2_runtime_windows.go) | GUI/剪贴板/Installed broker 只接收 v2 carrier；旧加入、current 轮询、Observation/presence 发送与恢复分支已删除。`--migration-request` 导出原身份签名请求，普通导入入口验证迁移包后安装独立的 v2 migration state，原 P-256 key 导入 CNG，原 DPAPI 与 floor 保留。迁移包已接通认证导出；新 Enrollment 的 bootstrap/capability/公开制品交付仍缺，新制品发布和原生实测分别核对，不能从交叉编译推断。 |
| Android 客户端 | [应用](../../clients/android/app/src)、[迁移安装](../../mobile/loomcore/migration_v2.go)、[v2 报告](../../mobile/loomcore/android_device_report_v2.go) | 原生 UI、多配置与 v2 桥接已接通；旧加入、公开报告/心跳、current 拉取和旧配置恢复已删除。历史配置提供迁移请求导出与文件导入，验证原平台签名、本机身份/floor、迁移证明后原子安装；Keystore 原身份保持。迁移包已接通认证导出，Enrollment 已使用正式 daemon 与签发器，外部 bootstrap 和制品交付仍未接通；私有配置/报告共用 Go TLS 1.3 的内部 CA、SPKI 和精确目的校验，原 Keystore 通过完整消息回调签名，私钥不导出，也不依赖系统 TLS 支持 Ed25519；私有健康报告可消费 exact 绑定回执中的原始服务器观测，仍走原 CA/签名校验；正式 daemon 已挂载回执 reader；只更新认证 Head 时原子接续运行记录，保留报告循环、selector 与当前网络代的入口预算，初次启动和进行中的探测均跟随新认证记录。v2 Android 运行配置显式使用绑定当前非 VPN Network 的 local DNS，业务 FakeIP 继续保留 FQDN 到最终出口；静态 DNS 与移动网络不匹配时，不改变出口业务解析。连接配置菜单可导入 `.loom-config`，复用在线 reader 与候选激活事务，不覆盖原迁移身份。实际私有配置/报告和 Head 更新后的连续运行以真机回执核对。Debug、Release 与实际安装分别核对，见[交付规程](../clients/android-delivery.md)。 |
| 客户端选路 | [入口 registry](../../internal/agent/entry_registry.go)、[观测缓存](../../internal/agent/observation_cache.go)、[Windows 进程入口](../../clients/windows/main_windows.go) | Windows 进程已订阅 OS 网络变化事件并沿宿主调用链更新网络代，同代复用 registry；Windows 原生实机验收仍须单独完成。Android 从实际 ICMP reply 读取 RTT，运行中 Direct→代理先应用 selector，再单批异步更新并拒绝旧 runtime/config/网络代结果；旧阻塞入口已删除。测试、构建和各宿主实机验收分别核对，以[观测复用契约](../clients/observations.md)为准；这些选路修复不补齐上述 v2 服务端和入网缺口。 |
| 浏览器管理界面 | [静态前端](../../internal/webui/static)、[JSON 业务接口](../../internal/webui/browser.go)、[结构化实时推送](../../internal/webui/device_inventory_live.go) | 顶层页面由浏览器渲染；设备职责筛选、条件表单和增量更新已接通。添加设备采用响应式双栏；详情按生命周期显示重发加入码、重新入网和删除操作，隐藏没有数据的链路面板。旧 SSR 页面及 HTML 推送已删除。流量复用已有 WireGuard 证据，不提供缺失的客户端应用流量。 |
| 客户端制品与发布页 | [签名目录](../../internal/clientrelease)、[构建目录工具](../../scripts/client-releases)、[发布工具](../../scripts/deploy-code)、[下载接口](../../internal/webui/releases.go) | Linux/Android/Windows 使用真实制品元数据、校验和及平台签名目录；部署工具只向配置的 distribution 位置增量复制，并在校验通过后激活控制节点目录。Android OS 签名与 Windows 预览状态分别展示；源码能力不证明某个制品已发布。 |
| 服务器观测与实时列表 | [私有报告](../../internal/controlplane/device_report.go)、[服务器 presence](../../internal/report/presence.go)、[UI socket](../../internal/report/control_ui_socket.go) | 旧公开客户端报告 handler 及 Unix 观测桥接已删除；原服务器采集、签名和邻居 gossip 继续使用。UI socket 仍提供既有列表投影，须与 v2 当前认证状态和持久报告统一；不能从旧列表推断私有报告序号。 |

Linux 完整配置生产器已与管理员签名发布接通，同时交付 LinkIntent、原 WireGuard、sing-box
和 Agent；reader 复核逐边资源及本机职责，原私钥留在节点，Linux 默认 mixed 模式不变。
共享入口用户与路由按当前 grants 收窄，Agent 配置不再引用旧 report HTTP。常驻同步、
报告和观测消费已接入正式命令；当前 Linux 配置生成只保留 mixed 模式，可选 TUN 仍缺。
显式离线配置递送与在线刷新共用原身份/Head/QC/密文校验，不复用初次迁移覆盖状态；不能从调用链与配置发布测试推断已完成生产迁移。

## 控制面迁移的下一处实际工作

Enrollment、device_config/device_report 已由正式 daemon 启动，`use_loom` 的真实签发器、
持久首次结果、本地 WireGuard key、双方配置原子发布及过期终止已接通并有流程测试。
新 `forward` 入网仍明确拒绝，不能从组件测试推断现网新设备加入成功。

补齐 Bootstrap prepared → 外部验证 → certified advertise、实时 capability 更新与静态 catalog 发布，
再将正常 UI 创建/恢复/删除入口连接到管理员认证事务。旧公开 claim handler 已删除；
继续按[迁移规则](../protocols/control-plane/migration.md#从当前实现迁移)替换 UI/CLI 的旧回调、
清理失效部署配置并完成正常新增设备验收，保留原身份与 floor。这些仍是本次替换的必需工作。

以上是已确认的接线缺口，不把其他工作区的组件或命令视作本仓库实现，也不把缺少 KMS/HSM 当作
外部阻碍；软件密钥方案适用，强化方案见[可选计划](../proposals/key-protection.md)。

## 更新本表时

1. 改正常入口、启动链、持久投影或客户端消费时，同步更新对应行和源码链接。
2. “组件存在”只有在正式入口使用实际依赖后才能改为“接通”；保留实际剩余缺口。
3. 提交和制品归属、部署结果、证书与节点坐标进入本机发布/验收记录，不复制到本表。
4. 删除过时结论，不追加按日期排列的进度段；设计理由合入对应规范。

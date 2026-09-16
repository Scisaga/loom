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
| N=1 私有控制服务 | `loom control bootstrap/serve/status/request`；[daemon](../../cmd/loom/control_runtime.go) | `serve()` 启动 overlay control API、loopback 浏览器入口和 Raft。启动配置强制单成员；operation registry 含 `control_ping`、`create_invite`、`publish_device_config` 与已有 DNS binding 操作；邀请与设备配置发布均有管理员签名 CLI。认证迁移后的 `serve()` 从同一日志启动独立的私有配置与报告 listener；Enrollment 的生产签发和启动仍未接通。 |
| 初始 v2 authority 与存量迁移 | [daemon bootstrap](../../cmd/loom/control_runtime.go)、[共享 bootstrap 验证器](../../internal/wire/recovery.go) | daemon 当前以 recovery/control epoch 1 初始化，并用小型运行配置和 cluster ID 派生占位承诺；目标初始 epoch 为 0。直接 v1 网络的 `BootstrapTransitionBundleV1ToV2` 与逐设备 floor migration package 尚未从生产输入生成。已有 N=1 日志通过 `control migrate` 验证原 SSOT/registry、当前管理员及原 owner/platform 双签后追加 `RuntimeActivationBundleV1`，耐久保存 exact 请求并恢复同一回执。不在用的独立客户端可明确暂存原身份，不能替代已加入身份、伪造 wrapping key 或成为 active v2 Device。`control export-migration` 从真实 activation/配置日志、原证书与原 signed current 导出设备迁移文件；缺材料时拒绝交付。生产 application、逐设备身份/floor 和 Linux 运行配置生成仍需接通。 |
| 管理员材料与浏览器入口 | `loom control export-admin/rotate-admin/enable-loopback`；[证书导出](../../cmd/loom/control_admin_certificate.go)、[轮换](../../cmd/loom/control_admin_rotation.go) | P-256 完整链、独立 browser TLS 和本机 N=1 certified 轮换有正式 CLI；浏览器实机通过须另有证据。 |
| 恢复材料与迁移门禁 | `loom control prepare-recovery`；[独立材料生成](../../cmd/loom/control_prepare_recovery.go)、[保管证明](../../internal/wire/recovery_custody.go) | 单保管人软件模式持久封装独立恢复 key，实际回读/解封签名后生成保管回执；刷新复用 key/密文。私有 application 重算完整保管树，迁移日志按实际提交时间拒绝缺失、伪造或过期回执。材料不随公开客户端证明交付；离线介质转存、多保管人仪式与灾难恢复实测不能从本机准备推断。 |
| Device/邀请与配置界面 | 私有 HTTPS → Unix socket → [Web UI](../../internal/webui/webui.go) → [邀请回调](../../internal/report/clients.go) | 管理员门禁已接通；业务回调仍使用 v1 registry/SSOT，尚未成为 v2 五阶段事务。v2 `control create-invite` CLI 已有，但 UI 尚未接入。 |
| v2 Enrollment 事务 | [私有服务](../../internal/enrollmentv2/private_service.go)、[Raft sequencer](../../internal/controlplane/enrollment_sequencer.go)、[首次签发持久化](../../internal/enrollmentv2/provisional_store.go) | 已有组件及测试；正式 `control serve` 未构造或启动 Enrollment 服务。真实 CA、封装、制品和共享认证状态仍需接入同一业务调用链。 |
| v2 私有配置与报告 | [生成与封装](../../cmd/loom/control_prepare_client.go)、[device_config](../../internal/controlplane/device_config.go)、[device_report](../../internal/controlplane/device_report.go) | `control publish-client-config` 从当前认证网络生成 Android/Windows 运行制品、私有控制 WireGuard 和原 key 密文；与 `publish-device-config` 共用管理员签名、Device generation CAS、Raft/QC 和重启重放。凭据受 parent 认证 policy、真实 availability 证据及原 wrapping key 约束。认证迁移后由正式 `serve()` 加载实际专用封装 TLS 密钥、配置 reader、报告验签/持久 store 与已有观测回读，绑定独立私有 tuple；任一材料或绑定失败则整体启动失败。测试覆盖迁移身份通过完整 mTLS 链读取配置、报告持久化及重启后的序号续接。Linux 生成、Enrollment provisioning、现网认证迁移/安装和生产验收仍未完成。 |
| Bootstrap ingress | [HY2/Trojan 服务组件](../../internal/bootstrapaccess)、[客户端 bootstrap](../../internal/clientv2/bootstrap.go) | 传输、受限 capability 和验证组件存在；正式静态 catalog/proof 发布与私有 Enrollment 的完整入网接线仍缺。旧公开动态入口的删除属于同一迁移。 |
| 托管 DNS 与公开证书 | [DNS provider](../../internal/dnsprovider)、[DNS-01](../../internal/certmanager/dns01.go)、[证书组件](../../internal/certmanager) | 共享基线主要为组件，未接通正式非 control executor、七字符名称分配/预留、存量迁移、事件任务与删除接管。DNS-01 的先读后整集合写/删存在并行 TXT 丢失窗口；本地 generation 不能代替 provider 原子保证。 |
| 动态 ControlSet | [成员账本](../../internal/controlplane/membership_ledger.go)、[joint leader](../../internal/controlplane/raft_joint_leader.go) | learner、成员和 quorum 组件存在；daemon 仍限制 N=1，没有正常晋升/移除入口，不能称多成员控制面已接通。 |
| Linux v2 客户端 | [client 子命令分发](../../cmd/loom/client.go)、[原身份迁移](../../cmd/loom/client_migration_linux.go)、[Linux v2 加入及运行](../../cmd/loom/client_v2_linux.go) | `export-migration-request` 验证原证书后复用原 P-256 身份、保存独立 wrapping key；`import-migration` 验证原 floor、认证迁移和完整运行配置后安装独立 migration state，并经正常 runtime deploy 事务激活。配置与报告读同一 installation；迁移不伪造 Enrollment。正常生产入网仍依赖上述服务端接线及迁移包生成。当前要求 Linux amd64 原生验收；arm64 构建与静态检查另列。 |
| Windows 客户端 | [统一加入入口](../../clients/windows/join_windows.go)、[迁移入口](../../clients/windows/migration_windows.go)、[v2 运行](../../clients/windows/v2_runtime_windows.go) | GUI/剪贴板/Installed broker 只接收 v2 carrier；旧加入、current 轮询、Observation/presence 发送与恢复分支已删除。`--migration-request` 导出原身份签名请求，普通导入入口验证迁移包后安装独立的 v2 migration state，原 P-256 key 导入 CNG，原 DPAPI 与 floor 保留。生产迁移包生成及服务端接线仍缺；新制品发布和原生实测分别核对，不能从交叉编译推断。 |
| Android 客户端 | [应用](../../clients/android/app/src)、[迁移安装](../../mobile/loomcore/migration_v2.go)、[v2 报告](../../mobile/loomcore/android_device_report_v2.go) | 原生 UI、多配置与 v2 桥接已接通；旧加入、公开报告/心跳、current 拉取和旧配置恢复已删除。历史配置提供迁移请求导出与文件导入，验证原平台签名、本机身份/floor、迁移证明后原子安装；Keystore 原身份保持。生产迁移包生成和 Enrollment 正式服务仍未接通；私有健康报告可消费 exact 绑定回执中的原始服务器观测，仍走原 CA/签名校验；正式 daemon 已挂载回执 reader，现网部署与真机 v2 报告仍未验收。Debug、Release 与实际安装分别核对，见[交付规程](../clients/android-delivery.md)。 |
| 客户端选路 | [入口 registry](../../internal/agent/entry_registry.go)、[观测缓存](../../internal/agent/observation_cache.go)、[Windows 进程入口](../../clients/windows/main_windows.go) | Windows 进程已订阅 OS 网络变化事件并沿宿主调用链更新网络代，同代复用 registry；Windows 原生实机验收仍须单独完成。Android 从实际 ICMP reply 读取 RTT，运行中 Direct→代理先应用 selector，再单批异步更新并拒绝旧 runtime/config/网络代结果；旧阻塞入口已删除。测试、构建和各宿主实机验收分别核对，以[观测复用契约](../clients/observations.md)为准；这些选路修复不补齐上述 v2 服务端和入网缺口。 |
| 浏览器管理界面 | [静态前端](../../internal/webui/static)、[JSON 业务接口](../../internal/webui/browser.go)、[结构化实时推送](../../internal/webui/device_inventory_live.go) | 顶层页面由浏览器渲染；设备职责筛选、条件表单和增量更新已接通。添加设备采用响应式双栏；详情按生命周期显示重发加入码、重新入网和删除操作，隐藏没有数据的链路面板。旧 SSR 页面及 HTML 推送已删除。流量复用已有 WireGuard 证据，不提供缺失的客户端应用流量。 |
| 客户端制品与发布页 | [签名目录](../../internal/clientrelease)、[构建目录工具](../../scripts/client-releases)、[发布工具](../../scripts/deploy-code)、[下载接口](../../internal/webui/releases.go) | Linux/Android/Windows 使用真实制品元数据、校验和及平台签名目录；部署工具只向配置的 distribution 位置增量复制，并在校验通过后激活控制节点目录。Android OS 签名与 Windows 预览状态分别展示；源码能力不证明某个制品已发布。 |
| 兼容上报与实时列表 | [报告 handler](../../internal/report/client_report.go)、[presence](../../internal/report/presence.go)、[UI socket](../../internal/report/control_ui_socket.go) | v1 Observation、独立心跳和列表通知路径仍存在；其成功状态不证明 v2 private report/sequence 已运行。 |

## 控制面迁移的下一处实际工作

先通过受验证的存量迁移构造共享 v2 reader 可接受的真实 bootstrap authority，固定初始 epoch、
旧 authority/floor、原身份与数据、PoP、initial payload/transition/Head/QC；不能只修改 epoch 数值
而继续使用占位承诺。随后在 `controlRuntime.serve()` 的正式生命周期内接入私有 Enrollment、device_config 和 device_report，
由同一受保护状态提供真实 issuer、持久密钥、封装与制品依赖。同步将正常管理入口连接到认证事务，
使 Device 配置实际生效并能回读有效报告。随后按[从当前实现迁移](../protocols/control-plane/migration.md#从当前实现迁移)
完成在用客户端接续、精确发布和已替换路径删除。

以上是已确认的接线缺口，不把其他工作区的组件或命令视作本仓库实现，也不把缺少 KMS/HSM 当作
外部阻碍；软件密钥方案适用，强化方案见[可选计划](../proposals/key-protection.md)。

## 更新本表时

1. 改正常入口、启动链、持久投影或客户端消费时，同步更新对应行和源码链接。
2. “组件存在”只有在正式入口使用实际依赖后才能改为“接通”；保留实际剩余缺口。
3. 提交和制品归属、部署结果、证书与节点坐标进入本机发布/验收记录，不复制到本表。
4. 删除过时结论，不追加按日期排列的进度段；设计理由合入对应规范。

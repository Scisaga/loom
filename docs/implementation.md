# 源码能力与接线缺口

本文描述本仓库源码的正常入口及已知缺口，随实现变化原位更新；不记录部署节点、运行版本或
历史流水账。只计入与本文件一同可从 Git 取得的已提交源码；其他分支、隔离工作区和未提交接线
不算这里的能力。工作区若有差异，先用 `git status` / `git diff` 核对，不能把它们当成可共享基线。
下列结论来自调用链阅读，不表示本轮运行了测试或生产验收。

- **规则来源：** [架构与不变量](design.md)、[v2 控制面规范](distributed-control-plane.md)、
  [客户端观测消费](client-observation-reuse.md#客户端消费边界)。
- **操作入口：** [控制面实施规程](control-plane-implementation-prompt.md)、
  [控制面运维](control-plane-operations.md)、[本机部署配置与证据](operations/local-deployment.md)。
- **实际运行：** 从 `.env` 所指部署配置、发布记录和 `deploy/evidence/` 的相关验收记录核对。
  配置表达操作输入；证据必须关联实际提交、制品和结果，不能从本表推断已部署。

## 正常入口对照

| 功能 | 正常入口与源码 | 已接通范围 / 具体缺口 |
|---|---|---|
| v1 模型、渲染与签名分发 | `loom validate/render/snapshot/release/publish/pull`；[模型](../internal/model/)、[渲染](../internal/render/)、[发布](../internal/publish/) | 既有严格 schema 和签名快照调用链存在；不能直接接收 v2 LinkIntent/ControlSet 字段。v2 替换必须保留存量身份与数据。 |
| N=1 私有控制服务 | `loom control bootstrap/serve/status/request`；[daemon](../cmd/loom/control_runtime.go) | `serve()` 启动 overlay control API、loopback 浏览器入口和 Raft。启动配置强制单成员；已提交 operation registry 与 `request` CLI 仅开放 `control_ping`。 |
| 管理员材料与浏览器入口 | `loom control export-admin/rotate-admin/enable-loopback`；[证书导出](../cmd/loom/control_admin_certificate.go)、[轮换](../cmd/loom/control_admin_rotation.go) | P-256 完整链、独立 browser TLS 和本机 N=1 certified 轮换有正式 CLI；浏览器实机通过须另有证据。 |
| Device/邀请与配置界面 | 私有 HTTPS → Unix socket → [Web UI](../internal/webui/webui.go) → [邀请回调](../internal/report/clients.go) | 管理员门禁已接通；业务回调仍使用 v1 registry/SSOT，尚未成为 v2 五阶段事务。没有正常 v2 create-invite CLI。 |
| v2 Enrollment 事务 | [私有服务](../internal/enrollmentv2/private_service.go)、[Raft sequencer](../internal/controlplane/enrollment_sequencer.go)、[首次签发持久化](../internal/enrollmentv2/provisional_store.go) | 已有组件及测试；正式 `control serve` 未构造或启动 Enrollment 服务。真实 CA、封装、制品和共享认证状态仍需接入同一业务调用链。 |
| v2 私有配置与报告 | [device_config](../internal/controlplane/device_config.go)、[device_report](../internal/controlplane/device_report.go)、[报告存储](../internal/controlplane/device_report_store.go) | 服务组件存在；正式 daemon 未挂载。certified Device 到实际 render/reconcile、凭据安装、有效报告和 inventory 回读未构成完整正常流程。 |
| Bootstrap ingress | [HY2/Trojan 服务组件](../internal/bootstrapaccess/)、[客户端 bootstrap](../internal/clientv2/bootstrap.go) | 传输、受限 capability 和验证组件存在；正式静态 catalog/proof 发布与私有 Enrollment 的完整入网接线仍缺。旧公开动态入口的删除属于同一迁移。 |
| 动态 ControlSet | [成员账本](../internal/controlplane/membership_ledger.go)、[joint leader](../internal/controlplane/raft_joint_leader.go) | learner、成员和 quorum 组件存在；daemon 仍限制 N=1，没有正常晋升/移除入口，不能称多成员控制面已接通。 |
| Linux v2 客户端 | [client 子命令分发](../cmd/loom/client.go)、[Linux v2 加入及运行](../cmd/loom/client_v2_linux.go) | 客户端 CLI 与私有协议消费代码存在；正常生产入网仍依赖上述服务端接线及存量迁移。当前要求 Linux amd64 原生验收；arm64 构建与静态检查另列。 |
| Windows 客户端 | [v2 加入](../clients/windows/v2_join_windows.go)、[v2 运行](../clients/windows/v2_runtime_windows.go)、[v1 报告](../clients/windows/report_windows.go)、[进程心跳](../clients/windows/presence_windows.go) | v2 与 v1 消费代码均存在；v1 进程心跳和分钟级完整报告是独立 worker。是否属于部署验收范围取决于在用设备及当前任务，不能从源码推断。 |
| Android 客户端 | [应用](../clients/android/app/src/)、[v2 配置安装](../mobile/loomcore/enrollment_config_v2.go)、[v2 报告](../mobile/loomcore/android_device_report_v2.go) | 原生 UI、多配置及协议桥接代码存在；v2 生产流程仍依赖正式服务端。Debug、Release 与实际安装分别核对，见[交付规程](android-client-delivery-prompt.md)。 |
| 客户端选路 | [入口 registry](../internal/agent/entry_registry.go)、[观测缓存](../internal/agent/observation_cache.go)、[Windows 进程入口](../clients/windows/main_windows.go) | 网络代 registry 和服务器观测消费实现存在；契约及跨平台入口见[观测复用说明](client-observation-reuse.md)。修改时核对目标、次数、并发与启动等待，不能以组件存在替代宿主验证。 |
| 兼容上报与实时列表 | [报告 handler](../internal/report/client_report.go)、[presence](../internal/report/presence.go)、[UI socket](../internal/report/control_ui_socket.go) | v1 Observation、独立心跳和列表通知路径仍存在；其成功状态不证明 v2 private report/sequence 已运行。 |

## 控制面迁移的下一处实际工作

在 `controlRuntime.serve()` 的正式生命周期内接入私有 Enrollment、device_config 和 device_report，
由同一受保护状态提供真实 issuer、持久密钥、封装与制品依赖。同步将正常管理入口连接到认证事务，
使 Device 配置实际生效并能回读有效报告。随后按[迁移规范 §19–§20](distributed-control-plane.md#19-从当前实现迁移)
完成在用客户端接续、精确发布和已替换路径删除。

以上是已确认的接线缺口，不把其他工作区的组件或命令视作本仓库实现，也不把缺少 KMS/HSM 当作
外部阻碍；软件密钥方案适用，强化方案见[可选计划](kms-hsm-hardening-plan.md)。

## 更新本表时

1. 改正常入口、启动链、持久投影或客户端消费时，同步更新对应行和源码链接。
2. “组件存在”只有在正式入口使用实际依赖后才能改为“接通”；保留实际剩余缺口。
3. 提交和制品归属、部署结果、证书与节点坐标进入本机发布/验收记录，不复制到本表。
4. 删除过时结论，不追加按日期排列的进度段；设计理由合入对应决策与规范。
